import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    Blockchain,
    BytesWriter,
    Calldata,
    SafeMath,
} from '@btc-vision/btc-runtime/runtime';
import { ReentrancyGuard } from '@btc-vision/btc-runtime/runtime/contracts/ReentrancyGuard';
import { StoredAddress } from '@btc-vision/btc-runtime/runtime/storage/StoredAddress';
import { StoredU256 } from '@btc-vision/btc-runtime/runtime/storage/StoredU256';
import { StoredBoolean } from '@btc-vision/btc-runtime/runtime/storage/StoredBoolean';
import { StoredMapU256 } from '@btc-vision/btc-runtime/runtime/storage/maps/StoredMapU256';
import { AddressMemoryMap } from '@btc-vision/btc-runtime/runtime/memory/AddressMemoryMap';
import { ADDRESS_BYTE_LENGTH } from '@btc-vision/btc-runtime/runtime/utils';
import { EMPTY_POINTER } from '@btc-vision/btc-runtime/runtime/math/bytes';
import { Revert } from '@btc-vision/btc-runtime/runtime/types/Revert';
import { encodeSelector } from '@btc-vision/btc-runtime/runtime/math/abi';
import { sha256 } from '@btc-vision/btc-runtime/runtime/env/global';
import { MLDSASecurityLevel } from '@btc-vision/btc-runtime/runtime/env/consensus/MLDSAMetadata';
import { UpdatablePlugin } from '@btc-vision/btc-runtime/runtime/plugins/UpdatablePlugin';

import {
    GovernorUpdated,
    WrappedTokenSet,
    SignerRotated,
    Paused,
    Unpaused,
    MintedFromVoucher,
    TokenModeSet,
    LockedForBridge,
    ReleasedFromVoucher,
    InventoryProvisionedOpNet,
    InventoryDrainedOpNet,
    FlowAdded,
    FlowStatusChanged,
    FlowCapChanged,
    FlowDailyLimitChanged,
    FlowMinAmountChanged,
    FlowFeeChanged,
    FlowTipCapUpdated,
    RelayerTipPaid,
    BurnConfirmed,
    FeesWithdrawn,
} from './events';

/**
 * SHA-256 selector of `claimMintWithVoucher(bytes,bytes)` — bound into the
 * preimage so a voucher can only be consumed by this method on this
 * contract.
 */
// SHA-256('claimMintWithVoucher(bytes,bytes)') first 4 bytes, as computed
// by the OPNet transform. Verified at build time — see npm run build output.
const CLAIM_MINT_WITH_VOUCHER_SELECTOR: u32 = 0x59893fe6;

/**
 * Canonical ML-DSA Level-2 byte sizes. Used as hard bounds when parsing the
 * sig blob so truncated / oversized payloads revert before any slicing.
 *   pubKey      = 1312 bytes
 *   raw sig     = 2420 bytes
 *   length prefix (u32 BE on pubLen) = 4 bytes
 *   total blob  = 3736 bytes
 */
const MLDSA_LEVEL2_PUBKEY_LEN: u32 = 1312;
const MLDSA_LEVEL2_SIG_LEN: u32 = 2420;
const MLDSA_SIG_BLOB_LEN: u32 = 4 + MLDSA_LEVEL2_PUBKEY_LEN + MLDSA_LEVEL2_SIG_LEN; // 3736

/**
 * Hard cap on the governor-settable wrap fee, in basis points
 * (1 bp = 0.01%). 1000 bps = 10%. Prevents a hostile or compromised
 * governor from making the bridge effectively un-usable via fee
 * inflation.
 */
const MAX_WRAP_FEE_BPS: u32 = 1000;

/**
 * Hard cap on per-flow `tipCapBps` (PR β.2.scaffold). 200 = 2%. Bounds
 * the permissionless relayer tip a flow can be configured to pay out.
 * Default per-flow tipCapBps is 0 — tipping disabled until governance
 * sets it. Mirrors EVM `BridgeEscrow.MAX_TIP_BPS`.
 */
const MAX_TIP_BPS: u32 = 200;

/**
 * PR α — flow status enum. Mirrors the EVM-side constants on
 * BridgeEscrow so a flow can be identified by the same status code on
 * either chain.
 */
const FLOW_STATUS_DISABLED: u32 = 0;
const FLOW_STATUS_ACTIVE: u32 = 1;
const FLOW_STATUS_PAUSED: u32 = 2;
const FLOW_STATUS_DRAINING: u32 = 3;

/**
 * PR γ.1 — rolling-window length for per-flow `dailyLimit`. 24 hours.
 * Hard-coded so a hostile governor cannot disable rate limiting by
 * setting it absurdly long. Mirrors EVM `FLOW_WINDOW_DURATION`.
 */
const FLOW_WINDOW_DURATION: u64 = 86400;

/**
 * Voucher preimage length in bytes.
 *
 * PR β.2.format — extended from the legacy 460B layout with two new fields
 * (`grossSrcAmount` u256, `relayerTip` u128) so the next sub-PR can wire
 * decimal-aware fee math + relayer tip payout. THIS PR only parses the new
 * fields; the mint/release amount continues to come from `netDstAmount`.
 *
 * Layout (byte-for-byte, MUST match server/src/voucher/opnet-voucher.ts):
 *   networkId           u256     32
 *   contractSelf        Address  32
 *   selector            u32       4
 *   recipient           Address  32
 *   sourceChainId       u256     32
 *   sourceBridgeAddr    Address  32   (EVM 20-byte addr right-padded to 32)
 *   sourceTokenAddr     Address  32   (EVM 20-byte addr right-padded to 32)
 *   sourceTxHash        u256     32
 *   sourceLogIndex      u32       4
 *   sourceDepositNonce  u256     32
 *   sourceBlockHash     u256     32
 *   wrappedToken        Address  32
 *   grossSrcAmount      u256     32   ← NEW
 *   grossDstAmount      u256     32   (was grossAmount)
 *   feeDstAmount        u256     32   (was feeAmount)
 *   netDstAmount        u256     32   (was netAmount)
 *   relayerTip          u128     16   ← NEW (uint128 BE)
 *   signerEpoch         u32       4
 *   voucherId           u256     32
 *   flowId              u256     32   ← NEW (#68 Tier B — route binding)
 *   ────────────────────────────────
 *   total                       540
 */
const VOUCHER_PREIMAGE_LEN: i32 = 540;

/**
 * PR γ.2b — BurnAttestation preimage length. 252 bytes total.
 * Layout in `BridgeDepository.confirmBurn` doc comment.
 */
const BURN_ATTESTATION_LEN: i32 = 252;

/**
 * SHA-256 selector of `confirmBurn(uint256,bytes,bytes)` first 4 bytes —
 * bound into the BurnAttestation preimage so an attestation can only be
 * consumed by this method. Verified by build-log: selector emitted by the
 * OPNet transform is 0x9cffeea6 (see CLAUDE.md §8 for the hash table).
 */
const CONFIRM_BURN_SELECTOR: u32 = 0x9cffeea6;

/**
 * BridgeDepository — mint authority for WrappedOP20.
 *
 * Users call `claimMintWithVoucher(voucher, mldsaSig)` paying their own gas.
 * The contract verifies:
 *   (1) parsed voucher length == 540 bytes
 *   (2) embedded signerEpoch matches current `_signerEpoch`
 *   (3) ML-DSA signature verifies against `_bridgeSignerHash[epoch]`
 *   (4) recipient == Blockchain.tx.sender  (front-run safe)
 *   (5) voucherId not previously consumed
 *   (6) (sourceTxHash, sourceLogIndex) not previously consumed
 *   (7) marks both used
 *   (8) calls WrappedOP20.mintTo(recipient, netAmount)
 *
 * STORAGE IS APPEND-ONLY. `_storageVersion` is declared FIRST so its slot id
 * is pinned across upgrades. Every subsequent field may never be reordered,
 * deleted, or retyped — new fields only appended at the end. See workspace
 * CLAUDE.md "Five Upgrade Commandments".
 */
@final
export class BridgeDepository extends ReentrancyGuard {
    // ─── STORAGE VERSION — MUST BE FIRST FIELD (append-only invariant) ──
    private _storageVersion: StoredU256 = new StoredU256(
        Blockchain.nextPointer,
        EMPTY_POINTER,
    );

    // ─── Voucher domain separator — OPNet network id ────────────────────
    // Set once at onDeployment from calldata so the same bytecode deploys to
    // testnet (id=2) and mainnet (id=1) without a code fork. The server
    // signer MUST produce the same u256 in its voucher builder.
    private _networkId: StoredU256 = new StoredU256(Blockchain.nextPointer, EMPTY_POINTER);

    // ─── Core references ─────────────────────────────────────────────────
    private _governor: StoredAddress = new StoredAddress(Blockchain.nextPointer);
    private _paused: StoredBoolean = new StoredBoolean(Blockchain.nextPointer, false);

    // ─── Wrapped token allowlist (wUSDC, wUSDT, ...) ─────────────────────
    // Map of address → u256.One if enabled. Populated by governor.
    private readonly _wrappedTokensPointer: u16 = Blockchain.nextPointer;
    private _wrappedTokens!: AddressMemoryMap;

    // ─── Signer epoch state ──────────────────────────────────────────────
    // Monotonic u32 epoch. Incremented on every rotateSigner call.
    private _signerEpoch: StoredU256 = new StoredU256(Blockchain.nextPointer, EMPTY_POINTER);
    // epoch (u32 widened to u256 key) → sha256(signerPubKey) as u256.
    private _bridgeSignerHashes: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);

    // ─── Replay guards ───────────────────────────────────────────────────
    // voucherId → u256.One once consumed.
    private _usedVoucherIds: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    // sha256(sourceTxHash || sourceLogIndex(4B BE)) → u256.One once consumed.
    private _usedSourceEvents: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);

    // ─── Phase 1.6 — voucher cancellation (Tier-3 refund support) ──────
    // voucherId → u256.One when explicitly cancelled by governor. Mirrors
    // the EVM `BridgeEscrow.cancelledVouchers` slot. Checked alongside the
    // standard replay guard in `claimMintWithVoucher`. Append-only — slot
    // assigned at end of declared storage to preserve upgrade discipline.
    private _cancelledVouchers: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);

    // ─── Phase 1.3 — M-of-N signer set ─────────────────────────────────
    // Set of authorized ML-DSA signer pubkey hashes for the CURRENT signer
    // epoch. Used as a `Set<u256>` via the StoredMapU256 contract:
    //   _signerKeyHashSet.get(hash) == u256.One  → authorized
    //   _signerKeyHashSet.get(hash).isZero()     → not authorized
    // The legacy `_bridgeSignerHashes[epoch]` slot is preserved in place
    // for the backward-compat single-sig blob path; new vouchers use this
    // set instead.
    private _signerKeyHashSet: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    // Required number of valid signatures (M in M-of-N). u256, but in
    // practice always small (1-5).
    private _requiredSignatures: StoredU256 = new StoredU256(
        Blockchain.nextPointer,
        EMPTY_POINTER,
    );
    // Cached count of authorized signers. Maintained in lockstep with the
    // set so we can sanity-check threshold ≤ count without iteration.
    private _signerCount: StoredU256 = new StoredU256(Blockchain.nextPointer, EMPTY_POINTER);
    // BridgeAuthority address authorized to call M-of-N admin methods on
    // top of the existing governor path. Set by the governor via
    // `setAuthorityAddress`. Zero by default.
    private _authorityAddress: StoredAddress = new StoredAddress(Blockchain.nextPointer);

    // ─── Modular wrap fee (governor-settable, capped at 10%) ──────────
    // Wrap fee, bps (1 bp = 0.01%). Charged on the EVM→OPNet wrap path
    // ("wrapping" canonical USDC/USDT into wUSDC/wUSDT). Default 0.
    // Hard-capped at MAX_WRAP_FEE_BPS = 1000 (10%) so a hostile or
    // compromised governor cannot trap user funds via fee inflation.
    //
    // The actual fee math runs server-side at sign time
    // (computeFee(gross, bps, minFee)) and is recorded as feeAmount /
    // netAmount in the 460-byte voucher preimage; the contract is the
    // source of truth for the bps value and the server reads it before
    // signing.
    private _wrapFeeBps: StoredU256 = new StoredU256(Blockchain.nextPointer, EMPTY_POINTER);
    // Per-wrapped-token minimum wrap fee. Keyed by sha256(wrappedToken
    // address) → u256 (token base units, 6 dec for wUSDC/wUSDT).
    // Whichever is higher between bps-derived and minFee is taken.
    // Default 0.
    private _wrapMinFee: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);

    // ─── Token bridging modes (5-mode dispatch) ────────────────────────
    // Per-token mode encoded as u256 (matching the EVM-side enum value
    // space):
    //   0 WRAPPED              — canonical on EVM, wrapped on OPNet (USDC/USDT)
    //   1 INVERSE_WRAPPED      — canonical on OPNet, wrapped on EVM
    //   2 NATIVE_BURN_MINT     — bridge issues both sides, burn-and-mint
    //   3 POOLED_LOCK_RELEASE  — lock+release on both, no minting; project
    //                            funds inventory (e.g. MOTO)
    //   4 POOLED_LOCK_VEST     — identical to mode 3 on OPNet (lock/release/
    //                            provision/inventory); differs only on the EVM
    //                            destination, where claim deposits into a
    //                            VestingVault that drips over a block window.
    // Set-once per token via `setTokenMode`. Default 0 (WRAPPED) so existing
    // wUSDC/wUSDT keep working.
    private _tokenMode: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _tokenModeFinalized: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    // For mode-2/3/4: 32-byte EVM counterpart identity, stored as u256.
    // Mode 1 leaves this at zero. Indexer-only — used to bind events
    // across chains.
    private _evmCounterpart: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);

    // ─── Mode-2/4 lock state (canonical OP20 escrow on OPNet) ──────────
    // Monotonic lock nonce — gives each lockForBridge a unique id.
    private _lockNonce: StoredU256 = new StoredU256(Blockchain.nextPointer, EMPTY_POINTER);
    // Replay guard for claimReleaseWithVoucher. Same shape as
    // _usedVoucherIds + _usedSourceEvents but separated so the two
    // claim paths can't accidentally share state.
    private _usedReleaseVoucherIds: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _usedEvmBurnEvents: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);

    // ─── PR α — Flow Registry (storage + governance only) ─────────────
    // A flow is the smallest atom of bridge routing — keyed by:
    //
    //   flowId = sha256(packed(mode || evmChainId || evmBridge ||
    //                          evmToken || opnetBridge || opnetToken))
    //
    // The same flowId is computed on the EVM side over the same byte
    // order so a single 32-byte identifier names a route end-to-end.
    //
    // No claim / lock path consumes flow data yet — that lands in PR γ.
    // For now: pure storage + admin layer. AssemblyScript has no
    // compound storage struct; one StoredMapU256 per scalar field
    // keeps each setter trivial and the gas cost of getFlow predictable.
    private _flowExists: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowMode: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowStatus: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowChainId: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowEvmBridge: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowEvmToken: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowEvmDecimals: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowOpnetBridge: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowOpnetToken: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowOpnetDecimals: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowFeeBps: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowMinFee: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowMinAmount: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowCap: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowDailyLimit: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowMintedToday: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowLastWindowStart: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    private _flowInventory: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    // PR β.2.scaffold — per-flow permissionless relayer tip cap (bps).
    // 0 = tipping disabled (default); ≤ MAX_TIP_BPS = 200 (2%); governor-set.
    // Appended at the end to preserve append-only storage discipline.
    private _flowTipCapBps: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    // Lifetime count (includes disabled flows) — for off-chain enumeration
    // hand-shaking. PR γ may extend with on-chain enumeration arrays if
    // needed.
    private _flowTotalCount: StoredU256 = new StoredU256(
        Blockchain.nextPointer,
        EMPTY_POINTER,
    );

    // ─── PR γ.2b — confirmBurn replay guard ────────────────────────────
    // depositId (u256) → u256.One when its EVM-side burn has been attested
    // to by the M-of-N signer set. Append-only — slot at the end.
    private _confirmedBurns: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);

    // ─── Bug #16b — governance-gated upgrade authority ─────────────────
    // PR closing Bug #16b: route the UpdatablePlugin upgrade authority
    // through BridgeAuthority instead of relying solely on the deployer
    // EOA gate inside `UpdatablePlugin.onlyDeployer`.
    //
    // The plugin's submit/apply/cancel selectors gate on
    // `Blockchain.contractDeployer == tx.sender` — a hard-coded single
    // EOA. Because the plugin's gate is `private` we cannot override it
    // directly. We instead enforce authorization at apply time inside
    // `onUpdate(...)` (which runs immediately before any new bytecode
    // takes effect). Apply is rejected unless one of the following holds:
    //
    //   1. `_upgradeAuthority` is unset (zero) AND tx.sender == deployer
    //      → legacy bootstrap path. Used only during the v1 deploy
    //      ceremony, before the governor calls `setUpgradeAuthority`.
    //   2. `_upgradeAuthority` is set AND `_pendingUpgradeAuthorized` is
    //      true AND tx.sender == deployer (still required by the plugin
    //      itself).
    //
    // The `_pendingUpgradeAuthorized` flag is a one-shot consumed by
    // every successful onUpdate — guardrails forces a fresh governance
    // hand-shake for each upgrade. Governance turns it on via
    // `proposeUpgrade()`; guardian/authority can flip it off via
    // `cancelProposedUpgrade()` for emergency veto.
    //
    // Append-only: slots at the end preserve the upgrade discipline.
    private _upgradeAuthority: StoredAddress = new StoredAddress(Blockchain.nextPointer);
    private _pendingUpgradeAuthorized: StoredBoolean = new StoredBoolean(
        Blockchain.nextPointer,
        false,
    );

    // ─── #62 — per-flow OPNet-source fee accrual ───────────────────────
    // Mirror of EVM `BridgeEscrow.FlowRecord.accruedFees`. The OPNet→EVM
    // (lockForBridge) direction takes the bridge fee on the OPNet source
    // side: the user locks `received` (gross), only the net is bridged to
    // the EVM counterpart, and the fee portion stays in the depository.
    // We record EXACTLY that fee portion here, keyed by flowId, so it can
    // be swept to the governor via the non-emergency `withdrawFees` path.
    //
    // This accumulator is the ENTIRE safety property of `withdrawFees`: a
    // withdrawal is strictly bounded by `_flowAccruedFees[flowId]` and can
    // therefore NEVER reach into user-locked principal or another flow's
    // reserves. There is no "withdraw excess balance" fallback.
    //
    // Append-only: declared as the LAST storage slot to preserve the
    // upgrade discipline (this contract is redeployed fresh on testnet, so
    // it ships baked into v1 storage, but the ordering rule still holds).
    private _flowAccruedFees: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);

    public constructor() {
        super();
        // AddressMemoryMap MUST be initialized in the constructor body.
        this._wrappedTokens = new AddressMemoryMap(this._wrappedTokensPointer);

        // Phase 2.2 — 7-day upgrade timelock.
        // Updatable-via-plugin: 1008 blocks (~7 days at 10min/block) timelock
        // between submitUpdate and applyUpdate. Gives users a full week to
        // exit before any upgrade lands, matching the EVM-side
        // TimelockController(604800s). Pointers allocated at the END of the
        // constructor body so they append after every previously declared
        // storage slot, preserving append-only discipline for future
        // upgrades.
        this.registerPlugin(new UpdatablePlugin(1008));
    }

    public override onDeployment(calldata: Calldata): void {
        super.onDeployment(calldata);

        this._governor.value = Blockchain.tx.sender;

        // Deployment calldata layout (reading in order):
        //   networkId (u256 BE) — 1=mainnet, 2=testnet. Required.
        // Further fields may be appended in future versions.
        // Regtest / test harnesses may deliver empty calldata on first
        // deploy — fall back to testnet (2) in that case so unit tests can
        // continue to run without synthesising deployment calldata.
        let networkId: u256 = u256.fromU32(2);
        if (calldata.byteLength >= 32) {
            networkId = calldata.readU256();
        }
        if (networkId.isZero()) {
            throw new Revert('BridgeDepository: zero networkId');
        }
        this._networkId.value = networkId;

        // Storage version 1 for fresh v1 deployments.
        this._storageVersion.value = u256.One;
        // Signer epoch starts at 1 so "epoch 0" is invalid by construction.
        this._signerEpoch.value = u256.One;
    }

    public override onUpdate(calldata: Calldata): void {
        super.onUpdate(calldata);

        // Only the original deployer may upgrade — this matches the
        // underlying UpdatablePlugin.onlyDeployer gate. The plugin still
        // enforces this on `applyUpdate`, but we re-check here so the
        // policy is co-located with the governance gate that follows.
        if (!Blockchain.tx.sender.equals(this.contractDeployer)) {
            throw new Revert('BridgeDepository: not deployer');
        }

        // ── Bug #16b — governance-gated upgrade authorization ──
        // Once the governor wires `_upgradeAuthority`, every subsequent
        // upgrade must be authorized via `proposeUpgrade()`. The flag is
        // consumed (cleared) here so each upgrade requires a fresh
        // hand-shake. Until the authority is wired, the legacy
        // deployer-only path remains active so the v1 bootstrap upgrade
        // (which seeds storageVersion → 2) can land without a chicken-
        // and-egg problem.
        const upgradeAuthority: Address = this._upgradeAuthority.value;
        if (!upgradeAuthority.isZero()) {
            if (!this._pendingUpgradeAuthorized.value) {
                throw new Revert('BridgeDepository: upgrade not authorized');
            }
            // Consume the flag — one-shot per upgrade.
            this._pendingUpgradeAuthorized.value = false;
        }

        // Append-only migrations gated by _storageVersion. Every branch
        // re-runs only once thanks to the version gate.
        const version = this._storageVersion.value;
        if (u256.lt(version, u256.fromU32(2))) {
            // Phase 1.3 migration — seed the M-of-N signer set from the
            // legacy single-signer state so the new claim path works
            // immediately after the upgrade.
            const epoch: u256 = this._signerEpoch.value;
            const legacyHash: u256 = this._bridgeSignerHashes.get(epoch);
            if (!legacyHash.isZero()) {
                this._signerKeyHashSet.set(legacyHash, u256.One);
                this._signerCount.value = u256.One;
            }
            this._requiredSignatures.value = u256.One;
            // _authorityAddress left zero — governor sets it via a
            // separate `setAuthorityAddress` call after upgrade.
            this._storageVersion.value = u256.fromU32(2);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Access control helpers
    // ═══════════════════════════════════════════════════════════════════════

    private onlyGovernor(): void {
        const gov = this._governor.value;
        if (gov.isZero()) {
            throw new Revert('BridgeDepository: governor not set');
        }
        if (!Blockchain.tx.sender.equals(gov)) {
            throw new Revert('BridgeDepository: not governor');
        }
    }

    private requireNotPaused(): void {
        if (this._paused.value) {
            throw new Revert('BridgeDepository: paused');
        }
    }

    /**
     * Phase 1.3 — `onlyGovernor()` extended to also accept the registered
     * BridgeAuthority address. Lets governor handoff happen via the
     * authority's PUSH path (`addBridgeSigner`, `removeBridgeSigner`,
     * `setBridgeThreshold`) without giving up the direct-governor path
     * for emergency operations.
     */
    private onlyGovernorOrAuthority(): void {
        const sender = Blockchain.tx.sender;
        const gov = this._governor.value;
        if (!gov.isZero() && sender.equals(gov)) return;
        const auth = this._authorityAddress.value;
        if (!auth.isZero() && sender.equals(auth)) return;
        throw new Revert('BridgeDepository: not governor or authority');
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor: wrapped-token allowlist
    // ═══════════════════════════════════════════════════════════════════════

    @method({ name: 'wrappedToken', type: ABIDataTypes.ADDRESS })
    @emit('WrappedTokenSet')
    public addWrappedToken(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const addr: Address = calldata.readAddress();
        if (addr.isZero()) {
            throw new Revert('BridgeDepository: zero wrappedToken');
        }
        this._wrappedTokens.set(addr, u256.One);
        this.emitEvent(new WrappedTokenSet(addr, true));
        return new BytesWriter(0);
    }

    @method({ name: 'wrappedToken', type: ABIDataTypes.ADDRESS })
    @emit('WrappedTokenSet')
    public removeWrappedToken(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const addr: Address = calldata.readAddress();
        this._wrappedTokens.set(addr, u256.Zero);
        this.emitEvent(new WrappedTokenSet(addr, false));
        return new BytesWriter(0);
    }

    @view
    @returns({ name: 'enabled', type: ABIDataTypes.BOOL })
    public isWrappedToken(calldata: Calldata): BytesWriter {
        const addr: Address = calldata.readAddress();
        const response = new BytesWriter(1);
        response.writeBoolean(!this._wrappedTokens.get(addr).isZero());
        return response;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor: signer rotation (epoch-based invalidation)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Rotate the bridge signer. Input is the ML-DSA public key of the new
     * signer. We store sha256(pubkey) as u256 rather than the raw key to
     * keep slot size fixed; the claim flow hashes the submitted pubkey and
     * compares.
     *
     * Old epoch does NOT have its signer hash deleted — we keep historical
     * hashes so future debugging / audits can correlate, but only vouchers
     * carrying the CURRENT epoch verify. This implements "epoch bump
     * invalidates unclaimed vouchers" per the plan, with no deadlines.
     */
    @method({ name: 'signerPubKey', type: ABIDataTypes.BYTES })
    @emit('SignerRotated')
    public rotateSigner(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const pubKey: Uint8Array = calldata.readBytesWithLength();
        if (pubKey.length == 0) {
            throw new Revert('BridgeDepository: empty signer pubkey');
        }

        const oldEpoch: u256 = this._signerEpoch.value;

        // Fix #7 — epoch narrows to u32 in the voucher preimage. Reject
        // rotations that would roll the counter past u32::MAX so we never
        // silently accept a voucher whose u32 epoch wrapped to a lower
        // value than the u256 on-chain state.
        const u32Max: u256 = u256.fromU64(<u64>u32.MAX_VALUE);
        if (u256.ge(oldEpoch, u32Max)) {
            throw new Revert('BridgeDepository: signer epoch exhausted');
        }

        const newEpoch: u256 = SafeMath.add(oldEpoch, u256.One);
        this._signerEpoch.value = newEpoch;

        const newHash: u256 = u256.fromUint8ArrayBE(sha256(pubKey));

        // v2 — also rotate the M-of-N set so the new claim path stays in
        // sync. This is a 1-of-1 rotation: clear the previous single
        // signer (if any) from the set, add the new one, keep threshold=1.
        const oldHash: u256 = this._bridgeSignerHashes.get(oldEpoch);
        if (!oldHash.isZero() && !this._signerKeyHashSet.get(oldHash).isZero()) {
            this._signerKeyHashSet.set(oldHash, u256.Zero);
            // _signerCount stays bounded — decrement only if it was tracking the old hash.
            if (!this._signerCount.value.isZero()) {
                this._signerCount.value = SafeMath.sub(this._signerCount.value, u256.One);
            }
        }
        this._signerKeyHashSet.set(newHash, u256.One);
        this._signerCount.value = SafeMath.add(this._signerCount.value, u256.One);
        if (this._requiredSignatures.value.isZero()) {
            this._requiredSignatures.value = u256.One;
        }

        this._bridgeSignerHashes.set(newEpoch, newHash);

        this.emitEvent(new SignerRotated(oldEpoch.toU32(), newEpoch.toU32(), newHash));
        return new BytesWriter(0);
    }

    /**
     * Set the signer pubkey for the CURRENT epoch (bootstrap shim).
     * v2: also seeds the M-of-N signer set so the new claim path
     * authorizes this pubkey. Governor-only; reverts if a signer is
     * already set for the current epoch.
     */
    @method({ name: 'signerPubKey', type: ABIDataTypes.BYTES })
    @emit('SignerRotated')
    public setInitialSigner(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const pubKey: Uint8Array = calldata.readBytesWithLength();
        if (pubKey.length == 0) {
            throw new Revert('BridgeDepository: empty signer pubkey');
        }
        const epoch: u256 = this._signerEpoch.value;
        if (!this._bridgeSignerHashes.get(epoch).isZero()) {
            throw new Revert('BridgeDepository: signer already set — use rotateSigner');
        }
        const signerHash: u256 = u256.fromUint8ArrayBE(sha256(pubKey));
        this._bridgeSignerHashes.set(epoch, signerHash);

        // v2 — seed the M-of-N set so claim() finds the signer.
        this._signerKeyHashSet.set(signerHash, u256.One);
        this._signerCount.value = SafeMath.add(this._signerCount.value, u256.One);
        if (this._requiredSignatures.value.isZero()) {
            this._requiredSignatures.value = u256.One;
        }

        this.emitEvent(new SignerRotated(epoch.toU32(), epoch.toU32(), signerHash));
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor: voucher cancellation (Phase 1.6 — Tier-3 refund support)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Mark a specific `voucherId` as cancelled so it can never be claimed.
     * Used in the three-tier refund flow (Tier-3) when an in-flight voucher
     * needs to be invalidated without rotating the entire signer set.
     *
     * Idempotent — calling on an already-cancelled voucher is a no-op.
     * Mirrors `BridgeEscrow.cancelVoucher(bytes32)` on the EVM side.
     */
    @method({ name: 'voucherId', type: ABIDataTypes.UINT256 })
    public cancelVoucher(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const voucherId: u256 = calldata.readU256();
        this._cancelledVouchers.set(voucherId, u256.One);
        return new BytesWriter(0);
    }

    @view
    @returns({ name: 'cancelled', type: ABIDataTypes.BOOL })
    public isVoucherCancelled(calldata: Calldata): BytesWriter {
        const voucherId: u256 = calldata.readU256();
        const response = new BytesWriter(1);
        response.writeBoolean(!this._cancelledVouchers.get(voucherId).isZero());
        return response;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Phase 1.3 — M-of-N signer set (governor or BridgeAuthority)
    //  These selectors are PUSH targets for BridgeAuthority. They are also
    //  callable directly by the governor for emergency operations.
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Register the BridgeAuthority address that's allowed to push M-of-N
     * admin updates. Governor-only. Set ONCE — re-pointing requires
     * un-setting first (governor-only escape hatch).
     */
    @method({ name: 'authority', type: ABIDataTypes.ADDRESS })
    public setAuthorityAddress(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        this._authorityAddress.value = calldata.readAddress();
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Bug #16b — governance-gated upgrade authority
    //
    //  The UpdatablePlugin.submitUpdate / applyUpdate / cancelUpdate
    //  selectors gate on `Blockchain.contractDeployer == tx.sender`. That
    //  EOA is now neutralized at the policy layer by enforcing a separate
    //  governance flag inside `onUpdate`. Governor (or BridgeAuthority)
    //  registers the upgrade authority via `setUpgradeAuthority`; from
    //  then on every applyUpdate call must be preceded by a successful
    //  `proposeUpgrade()` from governance, otherwise `onUpdate` reverts
    //  and the apply is rolled back before the new bytecode takes effect.
    //
    //  Note: the deployer EOA is still the only address the underlying
    //  plugin will accept for `submitUpdate / applyUpdate / cancelUpdate`,
    //  so the operator key is needed to physically queue/apply the call,
    //  but its authority is reduced to a "rubber stamp" of what governance
    //  has already authorized. A compromised deployer key alone can no
    //  longer push a malicious upgrade.
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Register the address authorized to gate upgrades for this contract.
     * Governor or registered authority. Set to zero to disable the gate
     * (legacy deployer-only path) — emergency hatch only.
     */
    @method({ name: 'newUpgradeAuthority', type: ABIDataTypes.ADDRESS })
    public setUpgradeAuthority(calldata: Calldata): BytesWriter {
        this.onlyGovernorOrAuthority();
        this._upgradeAuthority.value = calldata.readAddress();
        return new BytesWriter(0);
    }

    /**
     * Authorize the next upgrade. One-shot — consumed inside `onUpdate`
     * the moment the next `applyUpdate` lands. Callable by the governor,
     * the registered BridgeAuthority slot, or the registered upgrade
     * authority itself (which lets the authority contract self-arm
     * without going through the depository governor when it's the same
     * wallet). The plugin's 1008-block timelock still enforces the wait
     * between submit and apply.
     */
    @method()
    public proposeUpgrade(_calldata: Calldata): BytesWriter {
        const sender = Blockchain.tx.sender;
        const gov = this._governor.value;
        const auth = this._authorityAddress.value;
        const upAuth = this._upgradeAuthority.value;
        if (!gov.isZero() && sender.equals(gov)) {
            // ok
        } else if (!auth.isZero() && sender.equals(auth)) {
            // ok
        } else if (!upAuth.isZero() && sender.equals(upAuth)) {
            // ok
        } else {
            throw new Revert('BridgeDepository: not authorized to propose upgrade');
        }
        this._pendingUpgradeAuthorized.value = true;
        return new BytesWriter(0);
    }

    /**
     * Veto a previously proposed upgrade by clearing the authorization
     * flag. Can be called by governor, registered authority, or upgrade
     * authority. Pairs with the plugin's `cancelUpdate` (which cancels
     * the queued bytecode pointer); calling both gives a complete veto.
     */
    @method()
    public cancelProposedUpgrade(_calldata: Calldata): BytesWriter {
        const sender = Blockchain.tx.sender;
        const gov = this._governor.value;
        const auth = this._authorityAddress.value;
        const upAuth = this._upgradeAuthority.value;
        if (!gov.isZero() && sender.equals(gov)) {
            // ok
        } else if (!auth.isZero() && sender.equals(auth)) {
            // ok
        } else if (!upAuth.isZero() && sender.equals(upAuth)) {
            // ok
        } else {
            throw new Revert('BridgeDepository: not authorized to cancel upgrade');
        }
        this._pendingUpgradeAuthorized.value = false;
        return new BytesWriter(0);
    }

    @view
    @returns({ name: 'upgradeAuthority', type: ABIDataTypes.ADDRESS })
    public upgradeAuthority(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(ADDRESS_BYTE_LENGTH);
        r.writeAddress(this._upgradeAuthority.value);
        return r;
    }

    @view
    @returns({ name: 'pendingUpgradeAuthorized', type: ABIDataTypes.BOOL })
    public pendingUpgradeAuthorized(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(1);
        r.writeBoolean(this._pendingUpgradeAuthorized.value);
        return r;
    }

    /**
     * Modular wrap fee — governor-settable, capped at MAX_WRAP_FEE_BPS
     * (1000 bps = 10%). Default 0. The contract stores the bps; the
     * server reads it before signing each voucher and reflects the
     * resulting feeAmount in the 460-byte preimage.
     */
    @method({ name: 'bps', type: ABIDataTypes.UINT256 })
    public setWrapFeeBps(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const bps: u256 = calldata.readU256();
        if (u256.gt(bps, u256.fromU32(MAX_WRAP_FEE_BPS))) {
            throw new Revert('BridgeDepository: wrap fee bps too high');
        }
        this._wrapFeeBps.value = bps;
        return new BytesWriter(0);
    }

    /**
     * Per-wrapped-token minimum wrap fee. Whichever is higher between
     * bps-derived and minFee is the actual fee taken. No cap on minFee
     * (governor's responsibility to keep it well below typical user
     * amounts). Default 0.
     */
    @method(
        { name: 'wrappedToken', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
    )
    public setWrapMinFee(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const wrappedToken: Address = calldata.readAddress();
        if (wrappedToken.isZero()) {
            throw new Revert('BridgeDepository: zero wrappedToken');
        }
        const amount: u256 = calldata.readU256();
        const key: u256 = _wrapMinFeeKey(wrappedToken);
        this._wrapMinFee.set(key, amount);
        return new BytesWriter(0);
    }

    @view
    @returns({ name: 'bps', type: ABIDataTypes.UINT256 })
    public wrapFeeBps(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(32);
        r.writeU256(this._wrapFeeBps.value);
        return r;
    }

    @view
    @returns({ name: 'amount', type: ABIDataTypes.UINT256 })
    public wrapMinFee(calldata: Calldata): BytesWriter {
        const wrappedToken: Address = calldata.readAddress();
        const key: u256 = _wrapMinFeeKey(wrappedToken);
        const r = new BytesWriter(32);
        r.writeU256(this._wrapMinFee.get(key));
        return r;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Phase 1.5 — token mode dispatch (4 modes)
    //  WRAPPED (0) / INVERSE_WRAPPED (1) / NATIVE_BURN_MINT (2) /
    //  POOLED_LOCK_RELEASE (3)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Register a token's bridging mode. Set-once per token. The
     * `evmCounterpart` is the 32-byte EVM address (or for non-mode-1
     * tokens, a 32-byte identifier) of the EVM-side asset this token
     * pairs with — the indexer uses it to bind events across chains.
     */
    @method(
        { name: 'token', type: ABIDataTypes.ADDRESS },
        { name: 'mode', type: ABIDataTypes.UINT256 },
        { name: 'evmCounterpart', type: ABIDataTypes.UINT256 },
    )
    @emit('TokenModeSet')
    public setTokenMode(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const token: Address = calldata.readAddress();
        if (token.isZero()) throw new Revert('BridgeDepository: zero token');
        const mode: u256 = calldata.readU256();
        // 0..4 — POOLED_LOCK_VEST (4) shares OPNet semantics with
        // POOLED_LOCK_RELEASE (3); it only differs on the EVM destination.
        if (u256.gt(mode, u256.fromU32(4))) {
            throw new Revert('BridgeDepository: invalid token mode');
        }
        const evmCounterpart: u256 = calldata.readU256();
        const key: u256 = _addrKey(token);
        if (!this._tokenModeFinalized.get(key).isZero()) {
            throw new Revert('BridgeDepository: token mode finalized');
        }
        // Modes 1/2/3 require evmCounterpart; mode 0 (WRAPPED) does not.
        if (!mode.isZero() && evmCounterpart.isZero()) {
            throw new Revert('BridgeDepository: evmCounterpart required for non-WRAPPED');
        }
        this._tokenMode.set(key, mode);
        this._tokenModeFinalized.set(key, u256.One);
        this._evmCounterpart.set(key, evmCounterpart);
        this.emitEvent(new TokenModeSet(token, mode.toU32(), evmCounterpart));
        return new BytesWriter(0);
    }

    @view
    @returns({ name: 'mode', type: ABIDataTypes.UINT256 })
    public tokenMode(calldata: Calldata): BytesWriter {
        const token: Address = calldata.readAddress();
        const r = new BytesWriter(32);
        r.writeU256(this._tokenMode.get(_addrKey(token)));
        return r;
    }

    @view
    @returns({ name: 'counterpart', type: ABIDataTypes.UINT256 })
    public evmCounterpartOf(calldata: Calldata): BytesWriter {
        const token: Address = calldata.readAddress();
        const r = new BytesWriter(32);
        r.writeU256(this._evmCounterpart.get(_addrKey(token)));
        return r;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PR α — Flow Registry (storage + governance only; consumed by PR γ)
    // ═══════════════════════════════════════════════════════════════════════
    //
    // A flow is the smallest atom of bridge routing — uniquely defined by:
    //   (mode, evmChainId, evmBridge, evmToken, opnetBridge, opnetToken)
    //
    //   flowId = sha256(packed(mode_u8 || evmChainId_be64 ||
    //                          evmBridge_20 || evmToken_20 ||
    //                          opnetBridge_32 || opnetToken_32))
    //
    // Same flowId on EVM `BridgeEscrow.computeFlowId(...)` over the same
    // byte order so a single 32-byte identifier names a route end-to-end.
    //
    // Set-once-on-add (immutable for the lifetime of the flow):
    //   mode, evmChainId, evmBridge, evmToken, evmDecimals,
    //   opnetBridge, opnetToken, opnetDecimals
    // Mutable via `onlyGovernor` (timelocked through BridgeAuthority):
    //   feeBps, minFee, minAmount, cap, dailyLimit
    // Mutable via `onlyGovernor` (immediate, status semantics):
    //   status (pause / resume / drain)

    /**
     * Pure compute helper — anyone can call. Same byte order as the EVM
     * `BridgeEscrow.computeFlowId`. Used by tests and tooling.
     *
     * Calldata layout (113 bytes):
     *   mode             u8       1
     *   evmChainId       u64 BE   8
     *   evmBridge        20 byte 20   (EVM addr; left-pad zeros to 20 if shorter)
     *   evmToken         20 byte 20
     *   opnetBridge      u256    32   (OPNet identity, 32B)
     *   opnetToken       u256    32
     */
    @method(
        { name: 'mode', type: ABIDataTypes.UINT256 },
        { name: 'evmChainId', type: ABIDataTypes.UINT256 },
        { name: 'evmBridge', type: ABIDataTypes.UINT256 },
        { name: 'evmToken', type: ABIDataTypes.UINT256 },
        { name: 'opnetBridge', type: ABIDataTypes.UINT256 },
        { name: 'opnetToken', type: ABIDataTypes.UINT256 },
    )
    @returns({ name: 'flowId', type: ABIDataTypes.UINT256 })
    public computeFlowId(calldata: Calldata): BytesWriter {
        const mode: u32 = calldata.readU256().toU32();
        const chainId: u64 = calldata.readU256().toU64();
        const evmBridge: u256 = calldata.readU256();
        const evmToken: u256 = calldata.readU256();
        const opnetBridge: u256 = calldata.readU256();
        const opnetToken: u256 = calldata.readU256();

        const flowId: u256 = _computeFlowId(
            mode,
            chainId,
            evmBridge,
            evmToken,
            opnetBridge,
            opnetToken,
        );
        const r = new BytesWriter(32);
        r.writeU256(flowId);
        return r;
    }

    /**
     * Register a new flow. `onlyGovernor` — production deploys route this
     * through the BridgeAuthority → governor → 48h timelock chain.
     *
     * Set-once for all immutable identity fields. Initial status is
     * active. Hot fields (mintedToday, lastWindowStart, inventory) start
     * at zero.
     */
    @method(
        { name: 'mode', type: ABIDataTypes.UINT256 },
        { name: 'evmChainId', type: ABIDataTypes.UINT256 },
        { name: 'evmBridge', type: ABIDataTypes.UINT256 },
        { name: 'evmToken', type: ABIDataTypes.UINT256 },
        { name: 'evmDecimals', type: ABIDataTypes.UINT256 },
        { name: 'opnetBridge', type: ABIDataTypes.UINT256 },
        { name: 'opnetToken', type: ABIDataTypes.UINT256 },
        { name: 'opnetDecimals', type: ABIDataTypes.UINT256 },
        { name: 'feeBps', type: ABIDataTypes.UINT256 },
        { name: 'minFee', type: ABIDataTypes.UINT256 },
        { name: 'minAmount', type: ABIDataTypes.UINT256 },
        { name: 'cap', type: ABIDataTypes.UINT256 },
        { name: 'dailyLimit', type: ABIDataTypes.UINT256 },
        { name: 'tipCapBps', type: ABIDataTypes.UINT256 },
    )
    @returns({ name: 'flowId', type: ABIDataTypes.UINT256 })
    @emit('FlowAdded')
    public addFlow(calldata: Calldata): BytesWriter {
        this.onlyGovernor();

        const mode: u32 = calldata.readU256().toU32();
        const chainId: u64 = calldata.readU256().toU64();
        const evmBridge: u256 = calldata.readU256();
        const evmToken: u256 = calldata.readU256();
        const evmDecimals: u32 = calldata.readU256().toU32();
        const opnetBridge: u256 = calldata.readU256();
        const opnetToken: u256 = calldata.readU256();
        const opnetDecimals: u32 = calldata.readU256().toU32();
        const feeBps: u32 = calldata.readU256().toU32();
        const minFee: u256 = calldata.readU256();
        const minAmount: u256 = calldata.readU256();
        const cap: u256 = calldata.readU256();
        const dailyLimit: u256 = calldata.readU256();
        const tipCapBps: u32 = calldata.readU256().toU32();

        // 0..4 — mode 4 (POOLED_LOCK_VEST) is accepted here so its flowId
        // (which hashes `mode`) matches the EVM mode-4 flow end-to-end.
        if (mode > 4) throw new Revert('BridgeDepository: invalid flow mode');
        if (chainId == 0) throw new Revert('BridgeDepository: zero chainId');
        if (evmBridge.isZero() || evmToken.isZero()) {
            throw new Revert('BridgeDepository: zero EVM addr');
        }
        if (opnetBridge.isZero() || opnetToken.isZero()) {
            throw new Revert('BridgeDepository: zero OPNet addr');
        }
        if (evmDecimals == 0 || evmDecimals > 30) {
            throw new Revert('BridgeDepository: bad evmDecimals');
        }
        if (opnetDecimals == 0 || opnetDecimals > 30) {
            throw new Revert('BridgeDepository: bad opnetDecimals');
        }
        if (feeBps > MAX_WRAP_FEE_BPS) {
            throw new Revert('BridgeDepository: feeBps too high');
        }
        if (tipCapBps > MAX_TIP_BPS) {
            throw new Revert('BridgeDepository: tipCapBps too high');
        }
        // #62-fix invariant: if `minAmount` is set, it MUST exceed `minFee`.
        // Otherwise the public-facing minimum advertises a usable amount
        // that `lockForBridge` would reject with "fee exceeds amount"
        // (because `fee >= received`). `minAmount == 0` is the explicit
        // "no-floor" config and is allowed.
        if (!minAmount.isZero() && u256.le(minAmount, minFee)) {
            throw new Revert('BridgeDepository: minAmount <= minFee');
        }

        const flowId: u256 = _computeFlowId(
            mode,
            chainId,
            evmBridge,
            evmToken,
            opnetBridge,
            opnetToken,
        );
        if (!this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow already exists');
        }

        this._flowExists.set(flowId, u256.One);
        this._flowMode.set(flowId, u256.fromU32(mode));
        this._flowStatus.set(flowId, u256.fromU32(FLOW_STATUS_ACTIVE));
        this._flowChainId.set(flowId, u256.fromU64(chainId));
        this._flowEvmBridge.set(flowId, evmBridge);
        this._flowEvmToken.set(flowId, evmToken);
        this._flowEvmDecimals.set(flowId, u256.fromU32(evmDecimals));
        this._flowOpnetBridge.set(flowId, opnetBridge);
        this._flowOpnetToken.set(flowId, opnetToken);
        this._flowOpnetDecimals.set(flowId, u256.fromU32(opnetDecimals));
        this._flowFeeBps.set(flowId, u256.fromU32(feeBps));
        this._flowMinFee.set(flowId, minFee);
        this._flowMinAmount.set(flowId, minAmount);
        this._flowCap.set(flowId, cap);
        this._flowDailyLimit.set(flowId, dailyLimit);
        this._flowTipCapBps.set(flowId, u256.fromU32(tipCapBps));
        // mintedToday, lastWindowStart, inventory remain 0.

        this._flowTotalCount.value = SafeMath.add(this._flowTotalCount.value, u256.One);

        this.emitEvent(new FlowAdded(flowId, mode, chainId, evmToken, opnetToken));

        const r = new BytesWriter(32);
        r.writeU256(flowId);
        return r;
    }

    /**
     * Move a flow into status=PAUSED. Only allowed from active. Governor
     * gated — on EVM the equivalent is guardian-immediate, but on OPNet
     * the BridgeAuthority chain already short-circuits to a guardian
     * role; we keep the gate uniform.
     */
    @method({ name: 'flowId', type: ABIDataTypes.UINT256 })
    @emit('FlowStatusChanged')
    public pauseFlow(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const flowId: u256 = calldata.readU256();
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        const oldStatus: u32 = this._flowStatus.get(flowId).toU32();
        if (oldStatus != FLOW_STATUS_ACTIVE) {
            throw new Revert('BridgeDepository: invalid status transition');
        }
        this._flowStatus.set(flowId, u256.fromU32(FLOW_STATUS_PAUSED));
        this.emitEvent(new FlowStatusChanged(flowId, oldStatus, FLOW_STATUS_PAUSED));
        return new BytesWriter(0);
    }

    /**
     * Move a flow back to status=ACTIVE. Only allowed from paused.
     */
    @method({ name: 'flowId', type: ABIDataTypes.UINT256 })
    @emit('FlowStatusChanged')
    public resumeFlow(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const flowId: u256 = calldata.readU256();
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        const oldStatus: u32 = this._flowStatus.get(flowId).toU32();
        if (oldStatus != FLOW_STATUS_PAUSED) {
            throw new Revert('BridgeDepository: invalid status transition');
        }
        this._flowStatus.set(flowId, u256.fromU32(FLOW_STATUS_ACTIVE));
        this.emitEvent(new FlowStatusChanged(flowId, oldStatus, FLOW_STATUS_ACTIVE));
        return new BytesWriter(0);
    }

    /**
     * Move a flow into status=DRAINING — one-way wind-down. Allowed from
     * active or paused. PR γ: claim/release allowed; lock/mint rejected.
     */
    @method({ name: 'flowId', type: ABIDataTypes.UINT256 })
    @emit('FlowStatusChanged')
    public drainFlow(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const flowId: u256 = calldata.readU256();
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        const oldStatus: u32 = this._flowStatus.get(flowId).toU32();
        if (oldStatus != FLOW_STATUS_ACTIVE && oldStatus != FLOW_STATUS_PAUSED) {
            throw new Revert('BridgeDepository: invalid status transition');
        }
        this._flowStatus.set(flowId, u256.fromU32(FLOW_STATUS_DRAINING));
        this.emitEvent(new FlowStatusChanged(flowId, oldStatus, FLOW_STATUS_DRAINING));
        return new BytesWriter(0);
    }

    /**
     * Adjust the per-flow inventory ceiling. Cannot drop the cap below
     * the current `inventory` (would brick existing locks).
     */
    @method(
        { name: 'flowId', type: ABIDataTypes.UINT256 },
        { name: 'newCap', type: ABIDataTypes.UINT256 },
    )
    @emit('FlowCapChanged')
    public setFlowCap(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const flowId: u256 = calldata.readU256();
        const newCap: u256 = calldata.readU256();
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        const inv: u256 = this._flowInventory.get(flowId);
        if (u256.lt(newCap, inv)) {
            throw new Revert('BridgeDepository: cap below inventory');
        }
        const oldCap: u256 = this._flowCap.get(flowId);
        this._flowCap.set(flowId, newCap);
        this.emitEvent(new FlowCapChanged(flowId, oldCap, newCap));
        return new BytesWriter(0);
    }

    /**
     * Adjust the per-flow rolling 24h limit. Zero is allowed (acts as a
     * soft mint freeze paired with pause/drain).
     */
    @method(
        { name: 'flowId', type: ABIDataTypes.UINT256 },
        { name: 'newLimit', type: ABIDataTypes.UINT256 },
    )
    @emit('FlowDailyLimitChanged')
    public setFlowDailyLimit(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const flowId: u256 = calldata.readU256();
        const newLimit: u256 = calldata.readU256();
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        const oldLimit: u256 = this._flowDailyLimit.get(flowId);
        this._flowDailyLimit.set(flowId, newLimit);
        this.emitEvent(new FlowDailyLimitChanged(flowId, oldLimit, newLimit));
        return new BytesWriter(0);
    }

    /**
     * Adjust the per-flow minimum source-side amount. Helps reject dust
     * deposits.
     */
    @method(
        { name: 'flowId', type: ABIDataTypes.UINT256 },
        { name: 'newMin', type: ABIDataTypes.UINT256 },
    )
    @emit('FlowMinAmountChanged')
    public setFlowMinAmount(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const flowId: u256 = calldata.readU256();
        const newMin: u256 = calldata.readU256();
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        // #62-fix invariant: preserve addFlow's `minAmount > minFee` (when
        // minAmount is non-zero). Without this, lowering minAmount below the
        // current minFee would brick every lock at the advertised floor.
        if (!newMin.isZero() && u256.le(newMin, this._flowMinFee.get(flowId))) {
            throw new Revert('BridgeDepository: minAmount <= minFee');
        }
        const oldMin: u256 = this._flowMinAmount.get(flowId);
        this._flowMinAmount.set(flowId, newMin);
        this.emitEvent(new FlowMinAmountChanged(flowId, oldMin, newMin));
        return new BytesWriter(0);
    }

    /**
     * Adjust per-flow fee parameters. Hard-capped at MAX_WRAP_FEE_BPS.
     */
    @method(
        { name: 'flowId', type: ABIDataTypes.UINT256 },
        { name: 'newBps', type: ABIDataTypes.UINT256 },
        { name: 'newMinFee', type: ABIDataTypes.UINT256 },
    )
    @emit('FlowFeeChanged')
    public setFlowFee(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const flowId: u256 = calldata.readU256();
        const newBps: u32 = calldata.readU256().toU32();
        const newMinFee: u256 = calldata.readU256();
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        if (newBps > MAX_WRAP_FEE_BPS) {
            throw new Revert('BridgeDepository: feeBps too high');
        }
        // #62-fix invariant: if a positive minAmount is configured, raising
        // minFee at or above it would brick locks at the floor. Reject.
        const currentMinAmount: u256 = this._flowMinAmount.get(flowId);
        if (!currentMinAmount.isZero() && u256.le(currentMinAmount, newMinFee)) {
            throw new Revert('BridgeDepository: minAmount <= minFee');
        }
        const oldBps: u32 = this._flowFeeBps.get(flowId).toU32();
        const oldMinFee: u256 = this._flowMinFee.get(flowId);
        this._flowFeeBps.set(flowId, u256.fromU32(newBps));
        this._flowMinFee.set(flowId, newMinFee);
        this.emitEvent(new FlowFeeChanged(flowId, oldBps, newBps, oldMinFee, newMinFee));
        return new BytesWriter(0);
    }

    /**
     * PR β.2.scaffold — adjust the per-flow permissionless relayer tip
     * cap (bps). 0 = tipping disabled. Hard-capped at MAX_TIP_BPS (2%).
     * Storage + governance only; tip payout wiring lands in a follow-up.
     */
    @method(
        { name: 'flowId', type: ABIDataTypes.UINT256 },
        { name: 'newBps', type: ABIDataTypes.UINT256 },
    )
    @emit('FlowTipCapUpdated')
    public setFlowTipCap(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const flowId: u256 = calldata.readU256();
        const newBps: u32 = calldata.readU256().toU32();
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        if (newBps > MAX_TIP_BPS) {
            throw new Revert('BridgeDepository: tipCapBps too high');
        }
        const oldBps: u32 = this._flowTipCapBps.get(flowId).toU32();
        this._flowTipCapBps.set(flowId, u256.fromU32(newBps));
        this.emitEvent(new FlowTipCapUpdated(flowId, oldBps, newBps));
        return new BytesWriter(0);
    }

    @view
    @returns({ name: 'exists', type: ABIDataTypes.BOOL })
    public flowExists(calldata: Calldata): BytesWriter {
        const flowId: u256 = calldata.readU256();
        const r = new BytesWriter(1);
        r.writeBoolean(!this._flowExists.get(flowId).isZero());
        return r;
    }

    @view
    @returns({ name: 'count', type: ABIDataTypes.UINT256 })
    public flowCount(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(32);
        r.writeU256(this._flowTotalCount.value);
        return r;
    }

    /**
     * Read every field of a flow. Returns 18 × 32-byte words.
     * Layout (matches EVM `getFlow(flowId).FlowRecord` ordering):
     *   mode, status, chainId, evmBridge, evmToken, evmDecimals,
     *   opnetBridge, opnetToken, opnetDecimals, feeBps, minFee,
     *   minAmount, cap, dailyLimit, mintedToday, lastWindowStart,
     *   inventory, tipCapBps (PR β.2.scaffold — appended)
     */
    @view
    @returns({ name: 'flow', type: ABIDataTypes.BYTES })
    public getFlow(calldata: Calldata): BytesWriter {
        const flowId: u256 = calldata.readU256();
        // ABIDataTypes.BYTES return must be u32 length-prefixed.
        const payloadLen: u32 = 18 * 32;
        const r = new BytesWriter(4 + payloadLen);
        r.writeU32(payloadLen);
        r.writeU256(this._flowMode.get(flowId));
        r.writeU256(this._flowStatus.get(flowId));
        r.writeU256(this._flowChainId.get(flowId));
        r.writeU256(this._flowEvmBridge.get(flowId));
        r.writeU256(this._flowEvmToken.get(flowId));
        r.writeU256(this._flowEvmDecimals.get(flowId));
        r.writeU256(this._flowOpnetBridge.get(flowId));
        r.writeU256(this._flowOpnetToken.get(flowId));
        r.writeU256(this._flowOpnetDecimals.get(flowId));
        r.writeU256(this._flowFeeBps.get(flowId));
        r.writeU256(this._flowMinFee.get(flowId));
        r.writeU256(this._flowMinAmount.get(flowId));
        r.writeU256(this._flowCap.get(flowId));
        r.writeU256(this._flowDailyLimit.get(flowId));
        r.writeU256(this._flowMintedToday.get(flowId));
        r.writeU256(this._flowLastWindowStart.get(flowId));
        r.writeU256(this._flowInventory.get(flowId));
        r.writeU256(this._flowTipCapBps.get(flowId));
        return r;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Phase 1.5 — modes 2 + 4: lock canonical OP20 → bridge to EVM
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Lock canonical OP20 in the bridge's escrow so the user can claim
     * the EVM-side counterpart (mint WrappedERC20 in mode 2, release
     * pre-funded inventory in mode 4). Caller must have approved the
     * BridgeDepository for at least `amount` on the canonical token.
     *
     * `evmRecipient` is 32 bytes — for EVM destinations, left-pad the
     * 20-byte recipient address to 32 bytes (low 20 bytes = address).
     */
    @method(
        { name: 'flowId', type: ABIDataTypes.UINT256 },
        { name: 'canonicalToken', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
        { name: 'evmRecipient', type: ABIDataTypes.BYTES32 },
        { name: 'destChainId', type: ABIDataTypes.UINT32 },
    )
    @emit('LockedForBridge')
    @nonReentrant
    public lockForBridge(calldata: Calldata): BytesWriter {
        this.requireNotPaused();
        const flowId: u256 = calldata.readU256();
        const canonical: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();
        const evmRecipient: Uint8Array = calldata.readBytes(32);
        const destChainId: u32 = calldata.readU32();

        if (amount.isZero()) throw new Revert('BridgeDepository: zero amount');
        if (destChainId == 0) throw new Revert('BridgeDepository: zero destChainId');
        if (evmRecipient.length != 32) {
            throw new Revert('BridgeDepository: ethRecipient must be 32 bytes');
        }
        // #68 — mode-per-flow. The route's mode is read from the FLOW the
        // caller names, NOT from a per-token stamp. This lets one canonical
        // token participate in several pooled flows of different modes at
        // once (e.g. the same (evmToken, opnetToken) pair as mode 3 AND
        // mode 4, chosen per transfer by the flowId). The flowId is the
        // routing authority — it is set governor-only at addFlow time, and
        // the token + chain binding checks below tie the caller's args to
        // that flow, so a caller still cannot lock the wrong token/chain
        // into a flow.
        //
        // (Pre-#68 the mode came from `_tokenMode[canonical]` and was then
        // cross-checked against `_flowMode[flowId]`; that double enforcement
        // pinned a token to one global mode and is exactly what blocked the
        // same pair backing two pooled modes — the cross-check is now
        // redundant because the flow IS the mode authority.)
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        if (this._flowStatus.get(flowId).toU32() != FLOW_STATUS_ACTIVE) {
            throw new Revert('BridgeDepository: flow not active');
        }
        // Mode dispatch — only INVERSE_WRAPPED (1), POOLED_LOCK_RELEASE (3),
        // or POOLED_LOCK_VEST (4) accept lockForBridge. Modes 3 and 4 share
        // identical OPNet lock semantics; 4 only differs on the EVM
        // destination (deposits into a VestingVault there).
        const mode: u256 = this._flowMode.get(flowId);
        const isInverse: bool = u256.eq(mode, u256.fromU32(1));
        const isPooled: bool =
            u256.eq(mode, u256.fromU32(3)) || u256.eq(mode, u256.fromU32(4));
        if (!isInverse && !isPooled) {
            throw new Revert('BridgeDepository: flow not in lockable mode');
        }
        // #44 — explicit flow binding. lockForBridge names the flow it locks
        // into so the OPNet-side inventory ledger is credited coherently;
        // the canonical token + destChainId are validated against that flow.
        if (!u256.eq(this._flowOpnetToken.get(flowId), _opnetAddrToU256(canonical))) {
            throw new Revert('BridgeDepository: flow token mismatch');
        }
        if (this._flowChainId.get(flowId).toU64() != <u64>destChainId) {
            throw new Revert('BridgeDepository: flow chain mismatch');
        }

        // EVM destination padding check — for chainId 1 / 11155111, upper
        // 12 bytes must be zero.
        if (destChainId == 1 || destChainId == 11155111) {
            for (let i: i32 = 0; i < 12; i++) {
                if (evmRecipient[i] != 0) {
                    throw new Revert('BridgeDepository: EVM recipient upper 12 bytes must be zero');
                }
            }
        }

        // #46 — balance-delta accounting. The EVM side (BridgeEscrow.lock)
        // measures what the bridge actually received; mirror it here so a
        // non-standard OP20 (fee-on-transfer / rebasing) whitelisted in a
        // future pooled flow cannot make the bridge over-account. We
        // emit/sign the received delta, never the user-supplied `amount`.
        const balOfSelector: u32 = encodeSelector('balanceOf(address)');

        const balBeforeW = new BytesWriter(4 + ADDRESS_BYTE_LENGTH);
        balBeforeW.writeSelector(balOfSelector);
        balBeforeW.writeAddress(this.address);
        const balBefore: u256 = Blockchain.call(canonical, balBeforeW).data.readU256();

        // Pull `amount` of canonical OP20 from the user via OP20.transferFrom.
        // The caller (user) must have approved the BridgeDepository first.
        const transferFromSelector: u32 = encodeSelector('transferFrom(address,address,uint256)');
        const tfWriter = new BytesWriter(4 + ADDRESS_BYTE_LENGTH * 2 + 32);
        tfWriter.writeSelector(transferFromSelector);
        tfWriter.writeAddress(Blockchain.tx.sender);
        tfWriter.writeAddress(this.address);
        tfWriter.writeU256(amount);
        Blockchain.call(canonical, tfWriter);

        const balAfterW = new BytesWriter(4 + ADDRESS_BYTE_LENGTH);
        balAfterW.writeSelector(balOfSelector);
        balAfterW.writeAddress(this.address);
        const balAfter: u256 = Blockchain.call(canonical, balAfterW).data.readU256();

        // SafeMath.sub reverts if the balance somehow decreased.
        const received: u256 = SafeMath.sub(balAfter, balBefore);
        if (received.isZero()) throw new Revert('BridgeDepository: nothing received');

        // ─── #62 — per-flow OPNet-source fee accrual ──────────────────
        // Mirror of EVM `BridgeEscrow._bumpLockInventory`. lockForBridge is
        // the OPNet→EVM (source) leg: the user locks `received` (gross),
        // only the net crosses to the EVM counterpart, and the fee portion
        // stays in this depository's custody. Record that exact fee in
        // `_flowAccruedFees[flowId]` so the governor can sweep it via the
        // non-emergency `withdrawFees` path.
        //
        // SAME formula the server uses and the EVM side accrues:
        //   fee = max(minFee, received * feeBps / 10_000), clamped to received.
        // Computed on the realized balance-delta `received`, consistent with
        // the inventory bump below. Every mode lockForBridge admits (1/3/4)
        // is a fee-bearing source side, so no extra mode dispatch is needed.
        // A flow with feeBps == 0 AND minFee == 0 accrues nothing.
        //
        // NOTE: this accumulator names the sweepable fee portion of the
        // bridge's standing balance. Inventory credit below (mode 1) is the
        // NET portion (received - lockFee) — together they sum to the
        // physical balance per flow at all times. The lock continues to
        // sign/emit the full `received` gross to the EVM side (the fee
        // carve happens server-side at sign time).
        let lockFee: u256 = SafeMath.div(
            SafeMath.mul(received, this._flowFeeBps.get(flowId)),
            u256.fromU32(10000),
        );
        const lockMinFee: u256 = this._flowMinFee.get(flowId);
        if (u256.gt(lockMinFee, lockFee)) {
            lockFee = lockMinFee;
        }
        // #62-fix — fail-closed on all-fee locks. Mirrors the EVM
        // `FeeExceedsAmount` revert in `BridgeEscrow._bumpLockInventory`.
        // The previous defensive clamp (`if (lockFee > received) lockFee =
        // received`) papered over a misconfigured `minFee` and allowed locks
        // with zero bridgeable net. Reject those configs at lock time.
        if (u256.ge(lockFee, received)) {
            throw new Revert('BridgeDepository: fee exceeds amount');
        }
        if (!lockFee.isZero()) {
            const accruedBefore: u256 = this._flowAccruedFees.get(flowId);
            this._flowAccruedFees.set(flowId, SafeMath.add(accruedBefore, lockFee));
        }

        // #44 — mode-1 (INVERSE_WRAPPED) inventory production. The canonical
        // OP20 just entered the bridge; the NET portion backs the EVM-side
        // wrapped mint and must be releasable back via claimReleaseWithVoucher.
        // Credit `received - lockFee` (NOT gross) so a later `withdrawFees`
        // sweep that subtracts only from `_flowAccruedFees` doesn't leave
        // `_flowInventory` overstating the principal available for releases.
        // This is the SOLE mode-1 inventory producer (confirmBurn no longer
        // increments). Mode-3 (POOLED) locks are source-side only — the
        // release pool lives on the EVM counterpart — so they do NOT credit
        // OPNet inventory (provisioned via provisionInventoryOpNet).
        //
        // HIGH-002 (audit 2026-05-25): pre-fix this credited `received`
        // (gross), and every governor fee sweep widened the gap between
        // physical balance and inventory ledger by exactly the swept amount.
        if (isInverse) {
            const netReceived: u256 = SafeMath.sub(received, lockFee);
            const invBefore: u256 = this._flowInventory.get(flowId);
            const invAfter: u256 = SafeMath.add(invBefore, netReceived);
            if (u256.gt(invAfter, this._flowCap.get(flowId))) {
                throw new Revert('BridgeDepository: flow cap exceeded');
            }
            this._flowInventory.set(flowId, invAfter);
        }

        const nextNonce: u256 = SafeMath.add(this._lockNonce.value, u256.One);
        this._lockNonce.value = nextNonce;

        // Pack evmRecipient (32B) into a u256 for event encoding.
        const evmRecipU256: u256 = u256.fromUint8ArrayBE(evmRecipient);

        this.emitEvent(new LockedForBridge(
            canonical,
            Blockchain.tx.sender,
            received,
            evmRecipU256,
            destChainId,
            nextNonce,
            mode.toU32(),
            flowId, // FINDING-002 — appended so the OPNet scanner can persist
                    // flow_id without resolving from per-token state.
        ));

        const writer = new BytesWriter(32);
        writer.writeU256(nextNonce);
        return writer;
    }

    /**
     * Release canonical OP20 to the recipient against an ML-DSA voucher
     * signed by the M-of-N signer set. Used in modes 2 + 4 after the
     * user has burned their wrapped ERC20 on the EVM side.
     *
     * Reuses the 460-byte voucher preimage shape — `wrappedToken` field
     * here is overloaded to mean "the canonical OP20 being released."
     * The selector field binds the voucher to this specific entry point
     * so a release voucher can't be claimed via `claimMintWithVoucher`
     * or vice-versa.
     */
    @method(
        { name: 'voucher', type: ABIDataTypes.BYTES },
        { name: 'mldsaSig', type: ABIDataTypes.BYTES },
    )
    @emit('ReleasedFromVoucher', 'RelayerTipPaid')
    @nonReentrant
    public claimReleaseWithVoucher(calldata: Calldata): BytesWriter {
        this.requireNotPaused();

        const voucher: Uint8Array = calldata.readBytesWithLength();
        const sig: Uint8Array = calldata.readBytesWithLength();

        if (voucher.length != VOUCHER_PREIMAGE_LEN) {
            throw new Revert('BridgeDepository: bad voucher length');
        }
        const parsed = parseVoucher(voucher);

        if (!u256.eq(parsed.networkId, this._networkId.value)) {
            throw new Revert('BridgeDepository: wrong networkId');
        }
        if (!parsed.contractSelf.equals(this.address)) {
            throw new Revert('BridgeDepository: wrong contractSelf');
        }
        // Bind to a DIFFERENT selector than claimMintWithVoucher so a
        // mint voucher cannot be replayed against this method.
        const releaseSelector: u32 = encodeSelector('claimReleaseWithVoucher(bytes,bytes)');
        if (parsed.selector != releaseSelector) {
            throw new Revert('BridgeDepository: wrong selector');
        }

        // Mode dispatch — release path valid for INVERSE_WRAPPED (1),
        // POOLED_LOCK_RELEASE (3), or POOLED_LOCK_VEST (4). The `wrappedToken`
        // field is the canonical OP20 to release. Modes 3 and 4 release
        // identically from the OPNet pool (the vest is EVM-side only).
        // #68 Tier B — route mode derived from the voucher's flowId (NOT the
        // per-token `_tokenMode`). Require flow exists + ACTIVE + bound to the
        // wrappedToken before dispatching.
        if (this._flowExists.get(parsed.flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        if (this._flowStatus.get(parsed.flowId).toU32() != FLOW_STATUS_ACTIVE) {
            throw new Revert('BridgeDepository: flow not active');
        }
        if (!u256.eq(this._flowOpnetToken.get(parsed.flowId), _opnetAddrToU256(parsed.wrappedToken))) {
            throw new Revert('BridgeDepository: flow token mismatch');
        }
        const releaseMode: u256 = this._flowMode.get(parsed.flowId);
        const isInverse2: bool = u256.eq(releaseMode, u256.fromU32(1));
        const isPooled2: bool =
            u256.eq(releaseMode, u256.fromU32(3)) || u256.eq(releaseMode, u256.fromU32(4));
        if (!isInverse2 && !isPooled2) {
            throw new Revert('BridgeDepository: token not in releasable mode');
        }

        const currentEpoch: u256 = this._signerEpoch.value;
        if (parsed.signerEpoch != currentEpoch.toU32()) {
            throw new Revert('BridgeDepository: wrong signerEpoch');
        }

        // L-07 — mirror claimMintWithVoucher: enforce the recipient==sender
        // binding only for DIY claims (relayerTip == 0). A non-zero
        // relayerTip means the user opted into permissionless submission —
        // any tx.sender may relay; funds still go to the ML-DSA-bound
        // `parsed.recipient` (the release transfer below) and the relayer
        // collects the signed tip. Without this the relayer-tip path on the
        // release leg is unreachable (only the recipient could ever submit).
        if (parsed.relayerTip.isZero()) {
            const sender: Address = Blockchain.tx.sender;
            if (!parsed.recipient.equals(sender)) {
                throw new Revert('BridgeDepository: wrong recipient');
            }
        }

        const sum: u256 = SafeMath.add(parsed.feeAmount, parsed.netAmount);
        if (!u256.eq(sum, parsed.grossAmount)) {
            throw new Revert('BridgeDepository: gross != fee + net');
        }
        if (parsed.netAmount.isZero()) {
            throw new Revert('BridgeDepository: zero netAmount');
        }

        // PR γ.2b — M-of-N ML-DSA verification via shared helper.
        this._verifyMofN(sig, voucher);

        // Cancellation + replay guards
        if (!this._cancelledVouchers.get(parsed.voucherId).isZero()) {
            throw new Revert('BridgeDepository: voucher cancelled');
        }
        if (!this._usedReleaseVoucherIds.get(parsed.voucherId).isZero()) {
            throw new Revert('BridgeDepository: voucher already used');
        }
        const sourceKey: u256 = buildSourceEventKey(
            parsed.sourceChainId,
            parsed.sourceBridgeAddr,
            parsed.sourceTokenAddr,
            parsed.sourceTxHash,
            parsed.sourceLogIndex,
        );
        if (!this._usedEvmBurnEvents.get(sourceKey).isZero()) {
            throw new Revert('BridgeDepository: source event already used');
        }

        // CEI — mark used BEFORE the external transfer.
        this._usedReleaseVoucherIds.set(parsed.voucherId, u256.One);
        this._usedEvmBurnEvents.set(sourceKey, u256.One);

        // PR β.2.payout-opnet — flow lookup + tip payout (mode-1/3 inverse
        // path). Mirrors `claimMintWithVoucher` semantics: the relayer is
        // paid the tip in the same canonical OP20 being released; the
        // recipient receives `netAmount - tip`. `Blockchain.tx.sender` —
        // protocol-neutral, NOT a stored relayer.
        const flowIdRel: u256 = _flowIdFromVoucher(
            releaseMode.toU32(),
            parsed.sourceChainId,
            parsed.sourceBridgeAddr,
            parsed.sourceTokenAddr,
            this.address,
            parsed.wrappedToken,
        );
        // FINDING-003 (audit 2026-05-26): the early gate above validated
        // `parsed.flowId` (token binding, mode, status). All subsequent
        // effects (status/minAmount/dailyLimit/inventory/tip) read storage
        // keyed by `flowIdRel`, the value recomputed from the voucher's
        // source-chain fields. If those two flow ids disagree the contract
        // would mutate a DIFFERENT flow than the one the signer attested
        // to. Require equality so every effect is provably governed by the
        // signed flowId.
        if (!u256.eq(flowIdRel, parsed.flowId)) {
            throw new Revert('BridgeDepository: voucher flowId mismatch');
        }
        if (this._flowExists.get(flowIdRel).isZero()) {
            throw new Revert('BridgeDepository: flow not registered');
        }

        // PR γ.1 — flow consumption (release path: inventory decreases).
        // Order: status → minAmount → dailyLimit window → inventory check
        // + decrement → tip cap/carve → transfer.
        const flowStatusRel: u32 = this._flowStatus.get(flowIdRel).toU32();
        if (flowStatusRel != FLOW_STATUS_ACTIVE && flowStatusRel != FLOW_STATUS_DRAINING) {
            throw new Revert('BridgeDepository: flow not active');
        }
        const flowMinAmountRel: u256 = this._flowMinAmount.get(flowIdRel);
        if (u256.lt(parsed.grossSrcAmount, flowMinAmountRel)) {
            throw new Revert('BridgeDepository: amount below flow min');
        }
        const nowRel: u64 = Blockchain.block.medianTimestamp;
        const windowStartRel: u64 = this._flowLastWindowStart.get(flowIdRel).toU64();
        let mintedTodayRel: u256 = this._flowMintedToday.get(flowIdRel);
        if (nowRel - windowStartRel > FLOW_WINDOW_DURATION) {
            mintedTodayRel = u256.Zero;
            this._flowLastWindowStart.set(flowIdRel, u256.fromU64(nowRel));
        }
        const newMintedRel: u256 = SafeMath.add(mintedTodayRel, parsed.grossAmount);
        const flowDailyLimitRel: u256 = this._flowDailyLimit.get(flowIdRel);
        if (u256.gt(newMintedRel, flowDailyLimitRel)) {
            throw new Revert('BridgeDepository: daily limit exceeded');
        }
        this._flowMintedToday.set(flowIdRel, newMintedRel);

        // Inventory ↓ (release). Revert if insufficient.
        const inventoryRelBefore: u256 = this._flowInventory.get(flowIdRel);
        if (u256.lt(inventoryRelBefore, parsed.grossAmount)) {
            throw new Revert('BridgeDepository: insufficient flow inventory');
        }
        this._flowInventory.set(
            flowIdRel,
            SafeMath.sub(inventoryRelBefore, parsed.grossAmount),
        );

        // FINDING-004 (audit 2026-05-26): accrue the release-side fee.
        // Inventory was decremented by gross, but only `parsed.netAmount`
        // leaves the bridge (split into recipient + tip). The remainder
        // `parsed.feeAmount` (= gross - net, validated at the head of this
        // function) stays in the bridge's balance. Pre-fix this delta was
        // never recorded anywhere, so `withdrawFees` couldn't sweep it
        // and the per-flow invariant
        // `_flowInventory + _flowAccruedFees == bridge balance` drifted
        // upward on every release.
        if (!parsed.feeAmount.isZero()) {
            const accruedBeforeRel: u256 = this._flowAccruedFees.get(flowIdRel);
            this._flowAccruedFees.set(
                flowIdRel,
                SafeMath.add(accruedBeforeRel, parsed.feeAmount),
            );
        }

        let recipientNetAmountRel: u256 = parsed.netAmount;
        if (!parsed.relayerTip.isZero()) {
            // FINDING-006 (audit 2026-05-26): cross-multiply instead of
            // floored division so `tipCapBps == 0` cannot still permit a
            // sub-1-bp tip, and explicitly reject `tip > netAmount` so the
            // subtraction below cannot underflow on a malformed
            // signer-bound voucher.
            if (u256.gt(parsed.relayerTip, parsed.netAmount)) {
                throw new Revert('BridgeDepository: tip exceeds flow cap');
            }
            const tipCapBpsRel: u32 = this._flowTipCapBps.get(flowIdRel).toU32();
            const tipScaledRel: u256 = SafeMath.mul(parsed.relayerTip, u256.fromU32(10000));
            const capScaledRel: u256 = SafeMath.mul(parsed.netAmount, u256.fromU32(tipCapBpsRel));
            if (u256.gt(tipScaledRel, capScaledRel)) {
                throw new Revert('BridgeDepository: tip exceeds flow cap');
            }
            const relayerRel: Address = Blockchain.tx.sender;
            const transferSelectorTip: u32 = encodeSelector('transfer(address,uint256)');
            const tipWriter = new BytesWriter(4 + ADDRESS_BYTE_LENGTH + 32);
            tipWriter.writeSelector(transferSelectorTip);
            tipWriter.writeAddress(relayerRel);
            tipWriter.writeU256(parsed.relayerTip);
            Blockchain.call(parsed.wrappedToken, tipWriter);

            this.emitEvent(new RelayerTipPaid(flowIdRel, relayerRel, parsed.relayerTip));

            recipientNetAmountRel = SafeMath.sub(parsed.netAmount, parsed.relayerTip);
        }

        // Cross-contract call: OP20.transfer(recipient, netAmount - tip)
        // — bridge holds the canonical OP20 and sends to recipient.
        const transferSelector: u32 = encodeSelector('transfer(address,uint256)');
        const tWriter = new BytesWriter(4 + ADDRESS_BYTE_LENGTH + 32);
        tWriter.writeSelector(transferSelector);
        tWriter.writeAddress(parsed.recipient);
        tWriter.writeU256(recipientNetAmountRel);
        Blockchain.call(parsed.wrappedToken, tWriter);

        this.emitEvent(new ReleasedFromVoucher(
            parsed.recipient,
            parsed.wrappedToken,
            parsed.sourceChainId,
            parsed.sourceTxHash,
            parsed.sourceLogIndex,
            parsed.grossAmount,
            parsed.feeAmount,
            parsed.netAmount,
            parsed.voucherId,
            parsed.signerEpoch,
        ));

        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Phase 1.5 — mode-4 inventory provisioning (POOLED_LOCK_RELEASE)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Add `amount` of a flow's canonical OPNet token to that flow's
     * inventory pool. Used for INVERSE_WRAPPED / POOLED_LOCK_RELEASE flows
     * where the project pre-funds the OPNet-side release pool. Caller
     * (governor) must have approved the BridgeDepository for ≥ `amount`.
     *
     * #44 — flow-scoped + atomic. The `_flowInventory` ledger moves in the
     * SAME call as the token transfer (verify → effect → interaction), so
     * the ledger can never drift from custody. The pre-#44 form took only
     * `(token, amount)` and never touched `_flowInventory`, leaving the
     * pool unspendable by `claimReleaseWithVoucher`.
     */
    @method(
        { name: 'flowId', type: ABIDataTypes.UINT256 },
        { name: 'token', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
    )
    @emit('InventoryProvisionedOpNet')
    @nonReentrant
    public provisionInventoryOpNet(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const flowId: u256 = calldata.readU256();
        const token: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();
        if (token.isZero()) throw new Revert('BridgeDepository: zero token');
        if (amount.isZero()) throw new Revert('BridgeDepository: zero amount');
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        // Only INVERSE_WRAPPED (1) / POOLED_LOCK_RELEASE (3) /
        // POOLED_LOCK_VEST (4) hold an OPNet-side canonical pool that can be
        // provisioned. Mode 4 pools exactly like mode 3 on OPNet.
        const mode: u32 = this._flowMode.get(flowId).toU32();
        if (mode != 1 && mode != 3 && mode != 4) {
            throw new Revert('BridgeDepository: flow mode not provisionable');
        }
        // The passed token MUST be the flow's registered canonical token.
        if (!u256.eq(this._flowOpnetToken.get(flowId), _opnetAddrToU256(token))) {
            throw new Revert('BridgeDepository: token not flow canonical');
        }

        // FINDING-005 (audit 2026-05-26): balance-delta the transfer so the
        // ledger credit equals what the bridge ACTUALLY received. Pre-fix
        // this credited the caller-supplied `amount`; a non-standard OP20
        // (fee-on-transfer, rebasing, partial-fill) could leave
        // `_flowInventory` ahead of physical custody — the same drift class
        // that lockForBridge's pre-#46 form had. Mirrors the lockForBridge
        // balance-delta pattern, and is governor-only, so a misconfigured
        // token surfaces as a revert during provisioning rather than as
        // silent inventory inflation.
        const balOfSelector: u32 = encodeSelector('balanceOf(address)');

        const balBeforeW = new BytesWriter(4 + ADDRESS_BYTE_LENGTH);
        balBeforeW.writeSelector(balOfSelector);
        balBeforeW.writeAddress(this.address);
        const balBefore: u256 = Blockchain.call(token, balBeforeW).data.readU256();

        const transferFromSelector: u32 = encodeSelector('transferFrom(address,address,uint256)');
        const w = new BytesWriter(4 + ADDRESS_BYTE_LENGTH * 2 + 32);
        w.writeSelector(transferFromSelector);
        w.writeAddress(Blockchain.tx.sender);
        w.writeAddress(this.address);
        w.writeU256(amount);
        Blockchain.call(token, w);

        const balAfterW = new BytesWriter(4 + ADDRESS_BYTE_LENGTH);
        balAfterW.writeSelector(balOfSelector);
        balAfterW.writeAddress(this.address);
        const balAfter: u256 = Blockchain.call(token, balAfterW).data.readU256();

        const received: u256 = SafeMath.sub(balAfter, balBefore);
        if (received.isZero()) throw new Revert('BridgeDepository: nothing received');

        // Now credit + cap-check against actual received.
        const before: u256 = this._flowInventory.get(flowId);
        const after: u256 = SafeMath.add(before, received);
        if (u256.gt(after, this._flowCap.get(flowId))) {
            throw new Revert('BridgeDepository: flow cap exceeded');
        }
        this._flowInventory.set(flowId, after);

        this.emitEvent(
            new InventoryProvisionedOpNet(flowId, token, Blockchain.tx.sender, received),
        );
        return new BytesWriter(0);
    }

    /**
     * Drain `amount` of a flow's canonical OP20 inventory back to a
     * recipient. Governor-only, requires the bridge to be paused (matches
     * EVM emergencyWithdraw semantics). Used for orderly wind-down.
     *
     * #44 — flow-scoped + atomic. The `_flowInventory` ledger is debited
     * BEFORE the external transfer (verify → effect → interaction), and a
     * drain beyond the flow's recorded inventory reverts.
     */
    @method(
        { name: 'flowId', type: ABIDataTypes.UINT256 },
        { name: 'token', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
        { name: 'recipient', type: ABIDataTypes.ADDRESS },
    )
    @emit('InventoryDrainedOpNet')
    @nonReentrant
    public drainInventoryOpNet(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        if (!this._paused.value) {
            throw new Revert('BridgeDepository: must pause before drain');
        }
        const flowId: u256 = calldata.readU256();
        const token: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();
        const recipient: Address = calldata.readAddress();
        if (token.isZero() || recipient.isZero()) throw new Revert('BridgeDepository: zero addr');
        if (amount.isZero()) throw new Revert('BridgeDepository: zero amount');
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        if (!u256.eq(this._flowOpnetToken.get(flowId), _opnetAddrToU256(token))) {
            throw new Revert('BridgeDepository: token not flow canonical');
        }

        // Verify → effect → interaction (CEI). Ledger debit precedes the
        // external transfer; an over-drain reverts before any token moves.
        const before: u256 = this._flowInventory.get(flowId);
        if (u256.lt(before, amount)) {
            throw new Revert('BridgeDepository: insufficient flow inventory');
        }
        this._flowInventory.set(flowId, SafeMath.sub(before, amount));

        const transferSelector: u32 = encodeSelector('transfer(address,uint256)');
        const w = new BytesWriter(4 + ADDRESS_BYTE_LENGTH + 32);
        w.writeSelector(transferSelector);
        w.writeAddress(recipient);
        w.writeU256(amount);
        Blockchain.call(token, w);

        this.emitEvent(
            new InventoryDrainedOpNet(flowId, token, recipient, Blockchain.tx.sender, amount),
        );
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  #62 — non-emergency per-flow fee withdrawal (mirror of EVM
    //  BridgeEscrow.withdrawFees)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Withdraw accrued OPNet-source bridge fees for a flow. This is the
     * ROUTINE revenue-collection path — unlike `drainInventoryOpNet` it is
     * NOT pause-gated, so fees can be swept during normal operation.
     *
     * Governor-only, `@nonReentrant`, strict CEI. The withdrawable amount
     * is bounded STRICTLY by `_flowAccruedFees[flowId]` (the accumulator
     * incremented in `lockForBridge` by exactly the fee portion of each
     * lock) — this bound is the entire safety property. There is NO
     * "withdraw excess balance" fallback: a withdrawal can never reach into
     * user-locked principal or another flow's reserves.
     *
     * Recipient mirrors the EVM "treasury-only" discipline. The OPNet
     * depository has no set-once treasury slot, so fees are swept to the
     * governor (`_governor`) — the simplest safe choice on OPNet and the
     * same trust boundary that authorizes the call.
     *
     * Args mirror `provisionInventoryOpNet` / `drainInventoryOpNet`:
     *   (flowId, token, amount) — `token` MUST be the flow's registered
     *   canonical OPNet token (the asset the fee was accrued in).
     */
    @method(
        { name: 'flowId', type: ABIDataTypes.UINT256 },
        { name: 'token', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
    )
    @emit('FeesWithdrawn')
    @nonReentrant
    public withdrawFees(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const flowId: u256 = calldata.readU256();
        const token: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();

        if (token.isZero()) throw new Revert('BridgeDepository: zero token');
        if (amount.isZero()) throw new Revert('BridgeDepository: zero amount');
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        // Bind the passed token to the flow's registered canonical token —
        // a withdrawal can't be made against a different asset.
        if (!u256.eq(this._flowOpnetToken.get(flowId), _opnetAddrToU256(token))) {
            throw new Revert('BridgeDepository: token not flow canonical');
        }

        // Verify → effect → interaction (CEI). The accumulator is the sole
        // bound; decrement it BEFORE the external transfer. An over-withdraw
        // reverts before any token moves.
        const accrued: u256 = this._flowAccruedFees.get(flowId);
        if (u256.gt(amount, accrued)) {
            throw new Revert('BridgeDepository: insufficient accrued fees');
        }
        this._flowAccruedFees.set(flowId, SafeMath.sub(accrued, amount));

        // Recipient = governor (no treasury slot on OPNet).
        const recipient: Address = this._governor.value;

        const transferSelector: u32 = encodeSelector('transfer(address,uint256)');
        const w = new BytesWriter(4 + ADDRESS_BYTE_LENGTH + 32);
        w.writeSelector(transferSelector);
        w.writeAddress(recipient);
        w.writeU256(amount);
        Blockchain.call(token, w);

        this.emitEvent(
            new FeesWithdrawn(flowId, token, recipient, Blockchain.tx.sender, amount),
        );
        return new BytesWriter(0);
    }

    /**
     * @view — per-flow accrued OPNet-source fees (base units of the flow's
     * canonical OPNet token). Lets the server surface BOTH the EVM and OPNet
     * fee accumulators on a fee dashboard. Mirrors reading EVM
     * `getFlow(flowId).accruedFees`.
     */
    // #62-fix — was `@view` which always emits an empty-parens selector
    // (sha256('accruedFees()')) and ABI inputs: [], even though the impl
    // reads a `flowId` from calldata. Frontend typed-ABI consumers would be
    // wrong. Use `@method` so the generated ABI carries the `flowId` input
    // and the selector becomes sha256('accruedFees(uint256)').
    @method({ name: 'flowId', type: ABIDataTypes.UINT256 })
    @returns({ name: 'accrued', type: ABIDataTypes.UINT256 })
    public accruedFees(calldata: Calldata): BytesWriter {
        const flowId: u256 = calldata.readU256();
        const r = new BytesWriter(32);
        r.writeU256(this._flowAccruedFees.get(flowId));
        return r;
    }

    /**
     * Add a signer pubkey hash to the authorized set. Does NOT bump the
     * epoch — vouchers signed by the prior set remain valid (any sig from
     * the prior set is still in the new superset). Liveness-friendly.
     */
    @method({ name: 'pubKeyHash', type: ABIDataTypes.UINT256 })
    public addSignerToSet(calldata: Calldata): BytesWriter {
        this.onlyGovernorOrAuthority();
        const hash: u256 = calldata.readU256();
        if (hash.isZero()) throw new Revert('BridgeDepository: zero signer hash');
        if (!this._signerKeyHashSet.get(hash).isZero()) {
            throw new Revert('BridgeDepository: signer already in set');
        }
        this._signerKeyHashSet.set(hash, u256.One);
        this._signerCount.value = SafeMath.add(this._signerCount.value, u256.One);
        return new BytesWriter(0);
    }

    /**
     * Remove a signer from the set. Bumps the signer epoch — vouchers
     * signed exclusively by the removed signer (or the old set as a whole
     * via legacy single-sig path) immediately stop verifying. Reverts if
     * the removal would push count below threshold.
     */
    @method({ name: 'pubKeyHash', type: ABIDataTypes.UINT256 })
    @emit('SignerRotated')
    public removeSignerFromSet(calldata: Calldata): BytesWriter {
        this.onlyGovernorOrAuthority();
        const hash: u256 = calldata.readU256();
        if (this._signerKeyHashSet.get(hash).isZero()) {
            throw new Revert('BridgeDepository: not a signer');
        }
        const newCount: u256 = SafeMath.sub(this._signerCount.value, u256.One);
        if (u256.lt(newCount, this._requiredSignatures.value)) {
            throw new Revert('BridgeDepository: removal violates threshold');
        }
        this._signerKeyHashSet.set(hash, u256.Zero);
        this._signerCount.value = newCount;

        const oldEpoch: u256 = this._signerEpoch.value;
        const u32Max: u256 = u256.fromU64(<u64>u32.MAX_VALUE);
        if (u256.ge(oldEpoch, u32Max)) {
            throw new Revert('BridgeDepository: signer epoch exhausted');
        }
        const newEpoch: u256 = SafeMath.add(oldEpoch, u256.One);
        this._signerEpoch.value = newEpoch;
        this.emitEvent(new SignerRotated(oldEpoch.toU32(), newEpoch.toU32(), hash));
        return new BytesWriter(0);
    }

    /**
     * Update the M-of-N threshold. Bumps the signer epoch. Threshold must
     * be `1 ≤ m ≤ signerCount`.
     */
    @method({ name: 'threshold', type: ABIDataTypes.UINT256 })
    @emit('SignerRotated')
    public setRequiredSignatures(calldata: Calldata): BytesWriter {
        this.onlyGovernorOrAuthority();
        const m: u256 = calldata.readU256();
        if (m.isZero()) throw new Revert('BridgeDepository: zero threshold');
        if (u256.gt(m, this._signerCount.value)) {
            throw new Revert('BridgeDepository: threshold > signerCount');
        }
        this._requiredSignatures.value = m;

        const oldEpoch: u256 = this._signerEpoch.value;
        const u32Max: u256 = u256.fromU64(<u64>u32.MAX_VALUE);
        if (u256.ge(oldEpoch, u32Max)) {
            throw new Revert('BridgeDepository: signer epoch exhausted');
        }
        const newEpoch: u256 = SafeMath.add(oldEpoch, u256.One);
        this._signerEpoch.value = newEpoch;
        this.emitEvent(new SignerRotated(oldEpoch.toU32(), newEpoch.toU32(), m));
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PR γ.2b — atomic signer-set migration
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Atomic add/remove/setThreshold/epoch-bump for the M-of-N signer set.
     * Mirrors the EVM `BridgeEscrow.migrateSignerSet(toAdd[], toRemove[],
     * newThreshold)` so the rotation ceremony cannot land in a window where
     * `numSigs > newThreshold` is briefly inconsistent.
     *
     * Calldata layout (variable):
     *   addCount     u32 BE
     *   addHashes    u256[addCount]    — pubKey-hashes to authorize
     *   removeCount  u32 BE
     *   removeHashes u256[removeCount] — pubKey-hashes to deauthorize
     *   newThreshold u256              — new M (must satisfy 1 ≤ M ≤ count)
     *
     * Always bumps `_signerEpoch` exactly once at the end so vouchers signed
     * under the previous set immediately stop verifying — matching the
     * existing rotation pattern.
     */
    @method({ name: 'payload', type: ABIDataTypes.BYTES })
    @emit('SignerRotated')
    public migrateSignerSet(calldata: Calldata): BytesWriter {
        this.onlyGovernorOrAuthority();
        const payload: Uint8Array = calldata.readBytesWithLength();
        let off: u32 = 0;
        if (off + 4 > <u32>payload.length) {
            throw new Revert('BridgeDepository: bad migrate payload');
        }
        const addCount: u32 = readU32BE(payload, off); off += 4;
        if (addCount > 16) throw new Revert('BridgeDepository: too many adds');
        for (let i: u32 = 0; i < addCount; i++) {
            if (off + 32 > <u32>payload.length) {
                throw new Revert('BridgeDepository: truncated add');
            }
            const hash: u256 = readU256BE(payload, off); off += 32;
            if (hash.isZero()) throw new Revert('BridgeDepository: zero signer hash');
            if (this._signerKeyHashSet.get(hash).isZero()) {
                this._signerKeyHashSet.set(hash, u256.One);
                this._signerCount.value = SafeMath.add(this._signerCount.value, u256.One);
            }
        }
        if (off + 4 > <u32>payload.length) {
            throw new Revert('BridgeDepository: missing remove count');
        }
        const removeCount: u32 = readU32BE(payload, off); off += 4;
        if (removeCount > 16) throw new Revert('BridgeDepository: too many removes');
        for (let i: u32 = 0; i < removeCount; i++) {
            if (off + 32 > <u32>payload.length) {
                throw new Revert('BridgeDepository: truncated remove');
            }
            const hash: u256 = readU256BE(payload, off); off += 32;
            if (!this._signerKeyHashSet.get(hash).isZero()) {
                this._signerKeyHashSet.set(hash, u256.Zero);
                this._signerCount.value = SafeMath.sub(this._signerCount.value, u256.One);
            }
        }
        if (off + 32 > <u32>payload.length) {
            throw new Revert('BridgeDepository: missing newThreshold');
        }
        const newThreshold: u256 = readU256BE(payload, off); off += 32;
        if (off != <u32>payload.length) {
            throw new Revert('BridgeDepository: trailing migrate bytes');
        }
        if (newThreshold.isZero()) {
            throw new Revert('BridgeDepository: zero threshold');
        }
        if (u256.gt(newThreshold, this._signerCount.value)) {
            throw new Revert('BridgeDepository: threshold > signerCount');
        }
        this._requiredSignatures.value = newThreshold;

        // Atomic epoch bump — old vouchers immediately invalidate.
        const oldEpoch: u256 = this._signerEpoch.value;
        const u32Max: u256 = u256.fromU64(<u64>u32.MAX_VALUE);
        if (u256.ge(oldEpoch, u32Max)) {
            throw new Revert('BridgeDepository: signer epoch exhausted');
        }
        const newEpoch: u256 = SafeMath.add(oldEpoch, u256.One);
        this._signerEpoch.value = newEpoch;
        this.emitEvent(new SignerRotated(oldEpoch.toU32(), newEpoch.toU32(), newThreshold));
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PR γ.2b — confirmBurn (OPNet-side attestation of an EVM burn)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Confirm an EVM-side burn against an M-of-N attestation. Inventory
     * roles by mode (#44 — single-count invariant):
     *   - mode 3 (POOLED_LOCK_RELEASE): the OPNet inventory was held
     *     against an EVM lock that has now been burned ⇒ inventory --.
     *   - mode 1 (INVERSE_WRAPPED): NO inventory mutation. The mode-1
     *     ledger is produced exclusively by `lockForBridge` and consumed
     *     exclusively by `claimReleaseWithVoucher`; confirmBurn is a pure,
     *     replay-guarded attestation here. A pre-#44 revision incremented
     *     inventory on mode 1, double-counting against `lockForBridge`.
     *
     * BurnAttestation preimage layout (252 bytes total — see CLAUDE.md §8):
     *   networkId         u256     32   (0)
     *   contractSelf      Address  32   (32)
     *   selector          u32       4   (64)  — sha256('confirmBurn(bytes32,bytes,bytes)')
     *   flowId            u256     32   (68)
     *   depositId         u256     32   (100)
     *   evmTxHash         u256     32   (132)
     *   evmLogIndex       u32       4   (164)
     *   releasedAmount    u256     32   (168)
     *   evmBlockHash      u256     32   (200)
     *   signerEpoch       u32       4   (232)  — must equal current _signerSetEpoch
     *   relayerTip        u128     16   (236)
     *                                  = 252
     *
     * (252 ≠ the 220 hinted in the original spec — the field set agreed
     * upon during PR γ.2b yields exactly 252 bytes; documented here.)
     *
     * Tip is parsed and recorded but NOT paid. v1 confirmBurn is a pure
     * attestation: there is no on-chain tip-treasury yet, and minting OP20
     * out of thin air for relayers would break invariants. Once a tip
     * treasury exists this can route to it.
     */
    @method(
        { name: 'depositId', type: ABIDataTypes.UINT256 },
        { name: 'attestation', type: ABIDataTypes.BYTES },
        { name: 'mldsaSig', type: ABIDataTypes.BYTES },
    )
    @emit('BurnConfirmed')
    @nonReentrant
    public confirmBurn(calldata: Calldata): BytesWriter {
        this.requireNotPaused();

        const depositId: u256 = calldata.readU256();
        const attestation: Uint8Array = calldata.readBytesWithLength();
        const sig: Uint8Array = calldata.readBytesWithLength();

        if (attestation.length != BURN_ATTESTATION_LEN) {
            throw new Revert('BridgeDepository: bad attestation length');
        }

        // Parse the fixed-layout preimage.
        const networkId: u256 = readU256BE(attestation, 0);
        if (!u256.eq(networkId, this._networkId.value)) {
            throw new Revert('BridgeDepository: wrong networkId');
        }
        const contractSelf: Address = readAddress(attestation, 32);
        if (!contractSelf.equals(this.address)) {
            throw new Revert('BridgeDepository: wrong contractSelf');
        }
        const selector: u32 = readU32BE(attestation, 64);
        if (selector != CONFIRM_BURN_SELECTOR) {
            throw new Revert('BridgeDepository: wrong selector');
        }
        const flowId: u256 = readU256BE(attestation, 68);
        const parsedDepositId: u256 = readU256BE(attestation, 100);
        if (!u256.eq(parsedDepositId, depositId)) {
            throw new Revert('BridgeDepository: depositId mismatch');
        }
        // #45 — evmTxHash @ 132 + evmLogIndex @ 164 are now folded into the
        // replay key (full source-event identity), not just audit fields.
        const evmTxHash: u256 = readU256BE(attestation, 132);
        const evmLogIndex: u32 = readU32BE(attestation, 164);
        const releasedAmount: u256 = readU256BE(attestation, 168);
        if (releasedAmount.isZero()) {
            throw new Revert('BridgeDepository: zero releasedAmount');
        }
        // evmBlockHash @ 200 — opaque.
        const sigEpoch: u32 = readU32BE(attestation, 232);
        if (sigEpoch != this._signerEpoch.value.toU32()) {
            throw new Revert('BridgeDepository: wrong signerEpoch');
        }
        // relayerTip @ 236 — parsed but not paid in v1.

        // Replay guard — MED-002 / #45: keyed by the full source-event
        // identity, not depositId alone, so two legitimate burns from
        // different flows or future bridges cannot collide.
        const replayKey: u256 = buildBurnReplayKey(flowId, depositId, evmTxHash, evmLogIndex);
        if (!this._confirmedBurns.get(replayKey).isZero()) {
            throw new Revert('BridgeDepository: burn already confirmed');
        }

        // M-of-N verify.
        this._verifyMofN(sig, attestation);

        // Flow lookup + status check (active OR draining — burns may exit
        // during drain).
        if (this._flowExists.get(flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not registered');
        }
        const status: u32 = this._flowStatus.get(flowId).toU32();
        if (status != FLOW_STATUS_ACTIVE && status != FLOW_STATUS_DRAINING) {
            throw new Revert('BridgeDepository: flow not active');
        }

        // Inventory effect by mode (#44 — single-count invariant):
        //   mode 3 / 4 = decrement (release-side ack against the pooled OPNet
        //            inventory provisioned via provisionInventoryOpNet).
        //            POOLED_LOCK_VEST (4) pools identically to mode 3 here.
        //   mode 1 = NO inventory mutation. lockForBridge produces and
        //            claimReleaseWithVoucher consumes the mode-1 ledger;
        //            confirmBurn is attestation-only here.
        const mode: u32 = this._flowMode.get(flowId).toU32();
        if (mode == 3 || mode == 4) {
            const inv: u256 = this._flowInventory.get(flowId);
            if (u256.lt(inv, releasedAmount)) {
                throw new Revert('BridgeDepository: insufficient flow inventory');
            }
            this._flowInventory.set(flowId, SafeMath.sub(inv, releasedAmount));
        } else if (mode != 1) {
            throw new Revert('BridgeDepository: confirmBurn unsupported mode');
        }

        // CEI — mark replay before any further work (no external call here).
        this._confirmedBurns.set(replayKey, u256.One);

        this.emitEvent(new BurnConfirmed(flowId, depositId, releasedAmount, Blockchain.tx.sender));
        return new BytesWriter(0);
    }

    @view
    @returns({ name: 'confirmed', type: ABIDataTypes.BOOL })
    public isBurnConfirmed(calldata: Calldata): BytesWriter {
        // #45 — the replay guard is keyed by the full source-event
        // identity, so the view takes the same tuple. evmLogIndex is
        // passed as a u256 on the wire and narrowed.
        const flowId: u256 = calldata.readU256();
        const depositId: u256 = calldata.readU256();
        const evmTxHash: u256 = calldata.readU256();
        const evmLogIndex: u32 = calldata.readU256().toU32();
        const key: u256 = buildBurnReplayKey(flowId, depositId, evmTxHash, evmLogIndex);
        const r = new BytesWriter(1);
        r.writeBoolean(!this._confirmedBurns.get(key).isZero());
        return r;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PR γ.2b — _verifyMofN helper (deduped from claimMint/Release)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Verify the M-of-N ML-DSA envelope against `voucherOrAttestation` (a
     * preimage that this method sha256s before passing into the ML-DSA
     * verifier). Reverts on any structural / threshold / authorization
     * failure. Pure — no state mutation.
     *
     * Sig blob layout (must match what claimMint/Release/confirmBurn
     * produce server-side):
     *   [u32 BE numSigs]
     *   for each i:
     *     [u32 BE pubLen][pubKey][u32 BE sigLen][rawSig]
     */
    private _verifyMofN(sig: Uint8Array, voucherOrAttestation: Uint8Array): void {
        if (<u32>sig.length < 4) {
            throw new Revert('BridgeDepository: bad sig blob length');
        }
        const numSigs: u32 = readU32BE(sig, 0);
        if (numSigs == 0) throw new Revert('BridgeDepository: zero numSigs');
        if (numSigs > 16) throw new Revert('BridgeDepository: too many sigs');
        const required: u32 = this._requiredSignatures.value.toU32();
        if (required == 0) {
            throw new Revert('BridgeDepository: signer set not initialized');
        }
        const preimageHash: Uint8Array = sha256(voucherOrAttestation);
        const seen: Array<u256> = new Array<u256>(0);
        let validCount: u32 = 0;
        let off: u32 = 4;
        for (let i: u32 = 0; i < numSigs; i++) {
            if (off + 4 > <u32>sig.length) throw new Revert('BridgeDepository: truncated pubLen');
            const pubLen: u32 = readU32BE(sig, off); off += 4;
            if (pubLen != MLDSA_LEVEL2_PUBKEY_LEN) throw new Revert('BridgeDepository: bad pubLen');
            if (off + pubLen > <u32>sig.length) throw new Revert('BridgeDepository: truncated pubKey');
            const pubKey: Uint8Array = slice(sig, off, off + pubLen); off += pubLen;
            if (off + 4 > <u32>sig.length) throw new Revert('BridgeDepository: truncated sigLen');
            const sigLen: u32 = readU32BE(sig, off); off += 4;
            if (sigLen != MLDSA_LEVEL2_SIG_LEN) throw new Revert('BridgeDepository: bad sigLen');
            if (off + sigLen > <u32>sig.length) throw new Revert('BridgeDepository: truncated rawSig');
            const rawSig: Uint8Array = slice(sig, off, off + sigLen); off += sigLen;
            const pubHash: u256 = u256.fromUint8ArrayBE(sha256(pubKey));
            for (let j: i32 = 0; j < seen.length; j++) {
                if (u256.eq(seen[j], pubHash)) {
                    throw new Revert('BridgeDepository: duplicate signer');
                }
            }
            seen.push(pubHash);
            if (this._signerKeyHashSet.get(pubHash).isZero()) continue;
            if (Blockchain.verifyMLDSASignature(MLDSASecurityLevel.Level2, pubKey, rawSig, preimageHash)) {
                validCount++;
            }
        }
        if (off != <u32>sig.length) {
            throw new Revert('BridgeDepository: trailing sig bytes');
        }
        if (validCount < required) {
            throw new Revert('BridgeDepository: insufficient valid signatures');
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Phase 1.3 — M-of-N views
    // ═══════════════════════════════════════════════════════════════════════

    @view
    @returns({ name: 'authority', type: ABIDataTypes.ADDRESS })
    public authorityAddress(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(ADDRESS_BYTE_LENGTH);
        response.writeAddress(this._authorityAddress.value);
        return response;
    }

    @view
    @returns({ name: 'count', type: ABIDataTypes.UINT256 })
    public signerCount(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(32);
        response.writeU256(this._signerCount.value);
        return response;
    }

    @view
    @returns({ name: 'threshold', type: ABIDataTypes.UINT256 })
    public requiredSignatures(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(32);
        response.writeU256(this._requiredSignatures.value);
        return response;
    }

    @view
    @returns({ name: 'authorized', type: ABIDataTypes.BOOL })
    public isSignerAuthorized(calldata: Calldata): BytesWriter {
        const hash: u256 = calldata.readU256();
        const response = new BytesWriter(1);
        response.writeBoolean(!this._signerKeyHashSet.get(hash).isZero());
        return response;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor: pause
    // ═══════════════════════════════════════════════════════════════════════

    @method({ name: 'paused', type: ABIDataTypes.BOOL })
    @emit('Paused', 'Unpaused')
    public setPaused(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const paused: boolean = calldata.readBoolean();
        this._paused.value = paused;
        if (paused) {
            this.emitEvent(new Paused());
        } else {
            this.emitEvent(new Unpaused());
        }
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor: transfer
    // ═══════════════════════════════════════════════════════════════════════

    @method({ name: 'newGovernor', type: ABIDataTypes.ADDRESS })
    @emit('GovernorUpdated')
    public setGovernor(calldata: Calldata): BytesWriter {
        // Accept governor OR registered BridgeAuthority. The authority's
        // pushGovernor cascade calls into here every time the human governor
        // rotates — once we cascade alice in, this slot is no longer the
        // authority's address, so a future re-push from the same authority
        // would revert under a strict onlyGovernor gate. The authority
        // address is set-once via setAuthorityAddress (governor-only), so
        // accepting it here doesn't widen the trust surface — it just keeps
        // the cascade workable across multiple handoffs.
        this.onlyGovernorOrAuthority();
        const newGovernor: Address = calldata.readAddress();
        if (newGovernor.isZero()) {
            throw new Revert('BridgeDepository: zero governor');
        }
        const old = this._governor.value;
        this._governor.value = newGovernor;
        this.emitEvent(new GovernorUpdated(old, newGovernor));
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  User: claim mint with voucher (CEI + nonReentrant)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Consume a server-signed ML-DSA voucher and mint wrapped tokens to
     * `tx.sender`. Reverts on any mismatch, replay, wrong epoch, or invalid
     * signature.
     *
     * `voucher` is the full 460-byte preimage — the contract parses it
     * directly rather than taking typed args, so the bytes the server
     * signed are exactly the bytes we hash and verify (no re-serialization
     * risk).
     *
     * @param calldata voucher (bytesU32) || mldsaSig (bytesU32)
     */
    @method(
        { name: 'voucher', type: ABIDataTypes.BYTES },
        { name: 'mldsaSig', type: ABIDataTypes.BYTES },
    )
    @emit('MintedFromVoucher', 'RelayerTipPaid')
    @nonReentrant
    public claimMintWithVoucher(calldata: Calldata): BytesWriter {
        this.requireNotPaused();

        const voucher: Uint8Array = calldata.readBytesWithLength();
        const sig: Uint8Array = calldata.readBytesWithLength();

        // ── Step 1: parse & validate shape ──
        if (voucher.length != VOUCHER_PREIMAGE_LEN) {
            throw new Revert('BridgeDepository: bad voucher length');
        }

        // Parse the fixed-layout preimage. Every field is at a hard-coded
        // offset so there's no ambiguity with the server builder.
        const parsed = parseVoucher(voucher);

        // ── Step 2: network + selector + contract self binding ──
        if (!u256.eq(parsed.networkId, this._networkId.value)) {
            throw new Revert('BridgeDepository: wrong networkId');
        }
        if (!parsed.contractSelf.equals(this.address)) {
            throw new Revert('BridgeDepository: wrong contractSelf');
        }
        if (parsed.selector != CLAIM_MINT_WITH_VOUCHER_SELECTOR) {
            throw new Revert('BridgeDepository: wrong selector');
        }

        // ── Step 3: signer epoch binding ──
        const currentEpoch: u256 = this._signerEpoch.value;
        if (parsed.signerEpoch != currentEpoch.toU32()) {
            throw new Revert('BridgeDepository: wrong signerEpoch');
        }

        // ── Step 4: recipient binding (front-run safe) ──
        // #2 — the sender==recipient binding is enforced ONLY for DIY
        // claims (relayerTip == 0): a tip-less voucher signed for alice
        // cannot be claimed by bob. When the user signed a non-zero
        // relayerTip they explicitly opted into the relayer path — any
        // tx.sender may submit, the mint still goes to parsed.recipient
        // (Step 11) and tx.sender collects the signed tip (Step 10). The
        // voucher's ML-DSA signature already binds `recipient`, so funds
        // are never redirected — a stolen tip-bearing voucher only lets a
        // thief waste gas. The security relaxation is itself opt-in, per
        // voucher; tip-less vouchers keep the full theft-proof binding.
        if (parsed.relayerTip.isZero()) {
            const sender: Address = Blockchain.tx.sender;
            if (!parsed.recipient.equals(sender)) {
                throw new Revert('BridgeDepository: wrong recipient');
            }
        }

        // ── Step 5: wrappedToken must be allowlisted ──
        if (this._wrappedTokens.get(parsed.wrappedToken).isZero()) {
            throw new Revert('BridgeDepository: unknown wrappedToken');
        }

        // ── Step 5b: route mode derived from the voucher's flowId (#68 Tier B) ──
        // The signed voucher carries an explicit flowId; the claim mode comes
        // from `_flowMode[flowId]` (NOT the per-token `_tokenMode`). We require
        // the flow to exist + be ACTIVE and enforce a flowId ↔ wrappedToken
        // binding so one wrapped token's claims are pinned to a specific flow.
        // Valid for WRAPPED (0) and NATIVE_BURN_MINT (2) only.
        // INVERSE_WRAPPED (1) and POOLED_LOCK_RELEASE (3) use claimReleaseWithVoucher.
        if (this._flowExists.get(parsed.flowId).isZero()) {
            throw new Revert('BridgeDepository: flow not found');
        }
        if (this._flowStatus.get(parsed.flowId).toU32() != FLOW_STATUS_ACTIVE) {
            throw new Revert('BridgeDepository: flow not active');
        }
        if (!u256.eq(this._flowOpnetToken.get(parsed.flowId), _opnetAddrToU256(parsed.wrappedToken))) {
            throw new Revert('BridgeDepository: flow token mismatch');
        }
        const mintMode: u256 = this._flowMode.get(parsed.flowId);
        const isMintableWrapped: bool = mintMode.isZero();
        const isMintableNative: bool = u256.eq(mintMode, u256.fromU32(2));
        if (!isMintableWrapped && !isMintableNative) {
            throw new Revert('BridgeDepository: token not in mintable mode');
        }

        // ── Step 6: fee math invariant ──
        // gross must equal fee + net exactly. Prevents a rogue signer from
        // splitting a voucher into fields that don't add up.
        const sum: u256 = SafeMath.add(parsed.feeAmount, parsed.netAmount);
        if (!u256.eq(sum, parsed.grossAmount)) {
            throw new Revert('BridgeDepository: gross != fee + net');
        }
        if (parsed.netAmount.isZero()) {
            throw new Revert('BridgeDepository: zero netAmount');
        }

        // ── Step 7: ML-DSA signature verify ──
        // Signer pubkey is identified by the hash stored for the current
        // epoch. We don't accept an arbitrary pubkey from the voucher —
        // the caller hashes the pubkey off-chain and includes it in the
        // ML-DSA verify call; the hash must match the on-chain record.
        //
        // Blockchain.verifyMLDSASignature takes (level, pubkey, sig, hash).
        // We reconstruct the pubkey by requiring the caller to pass it
        // alongside the voucher — BUT that would let them swap signers.
        // Instead, we take the sig and require it to verify under the
        // stored pubkey-hash-bound signer. Since the runtime API needs a
        // concrete pubkey, we adopt the convention from the slohm
        // BondDepository: embed signer pubkey in the mldsaSig argument
        // structure. Concretely, `sig` here is the raw ML-DSA signature
        // bytes; the pubkey is pinned by epoch.
        //
        // OPNet's ReentrancyGuard base wraps every entry automatically, so
        // no further manual lock is required here. We still order state
        // writes BEFORE the external mintTo call (CEI).
        //
        // ── M-of-N ML-DSA verification (no-legacy v2) ──
        // Sig blob layout:
        //   [u32 BE numSigs]
        //   for each i in [0, numSigs):
        //     [u32 BE pubLen_i] [pubKey_i bytes] [u32 BE sigLen_i] [rawSig_i bytes]
        //
        // Each pubKey must be the canonical ML-DSA L2 size (1312) and each
        // rawSig the canonical sig size (2420). At numSigs=1 the total
        // blob is 3744 bytes; at numSigs=N it is 4 + N * (8 + 1312 + 2420).
        // Each signer must be in the authorized set, must not appear twice
        // in the same blob, and the count of valid recovers must be at
        // least `_requiredSignatures.value`.
        // PR γ.2b — M-of-N ML-DSA verification via shared helper.
        this._verifyMofN(sig, voucher);

        // ── Step 7b: voucher cancellation (Phase 1.6 — Tier-3 refund) ──
        // Cancellation is checked BEFORE the replay guard so a cancelled
        // voucher always surfaces a clear, distinct error.
        if (!this._cancelledVouchers.get(parsed.voucherId).isZero()) {
            throw new Revert('BridgeDepository: voucher cancelled');
        }

        // ── Step 8: voucherId replay guard ──
        if (!this._usedVoucherIds.get(parsed.voucherId).isZero()) {
            throw new Revert('BridgeDepository: voucher already used');
        }

        // ── Step 9: (sourceChainId, sourceBridgeAddr, sourceTokenAddr,
        //          sourceTxHash, sourceLogIndex) replay guard ──
        // Fix #5 — widen the replay key to the full source-event identity so
        // the same (txHash, logIndex) cannot collide across different EVM
        // chains or different bridge / token contracts once we expand beyond
        // Ethereum mainnet. 132 bytes hashed.
        const sourceKey: u256 = buildSourceEventKey(
            parsed.sourceChainId,
            parsed.sourceBridgeAddr,
            parsed.sourceTokenAddr,
            parsed.sourceTxHash,
            parsed.sourceLogIndex,
        );
        if (!this._usedSourceEvents.get(sourceKey).isZero()) {
            throw new Revert('BridgeDepository: source event already used');
        }

        // ── Step 10: mark both replay guards BEFORE the external mint call (CEI) ──
        this._usedVoucherIds.set(parsed.voucherId, u256.One);
        this._usedSourceEvents.set(sourceKey, u256.One);

        // ── Step 10b: PR β.2.payout-opnet + PR γ.1 — flow lookup + consumption ──
        // Derive the canonical flowId, enforce ALL per-flow knobs (status,
        // minAmount, cap, dailyLimit, inventory), then carve the tip and
        // mint. Order: flow lookup → status → minAmount → cap → dailyLimit
        // window → inventory bump → tip cap/carve → mint.
        const flowIdMint: u256 = _flowIdFromVoucher(
            mintMode.toU32(),
            parsed.sourceChainId,
            parsed.sourceBridgeAddr,
            parsed.sourceTokenAddr,
            this.address,
            parsed.wrappedToken,
        );
        // FINDING-003 (audit 2026-05-26): require the recomputed flowId
        // to equal `parsed.flowId` so every downstream effect on
        // `flowIdMint` (status/minAmount/dailyLimit/inventory/tip) is
        // provably the flow the signer signed for. See the matching gate
        // in claimReleaseWithVoucher for rationale.
        if (!u256.eq(flowIdMint, parsed.flowId)) {
            throw new Revert('BridgeDepository: voucher flowId mismatch');
        }
        if (this._flowExists.get(flowIdMint).isZero()) {
            throw new Revert('BridgeDepository: flow not registered');
        }

        // PR γ.1 — status enforced for ALL claims (tip-zero too). Mint
        // path requires ACTIVE; DRAINING blocks new mints (winding down).
        const flowStatusMint: u32 = this._flowStatus.get(flowIdMint).toU32();
        if (flowStatusMint != FLOW_STATUS_ACTIVE) {
            throw new Revert('BridgeDepository: flow not active');
        }

        // PR γ.1 — minAmount on source-side gross.
        const flowMinAmountMint: u256 = this._flowMinAmount.get(flowIdMint);
        if (u256.lt(parsed.grossSrcAmount, flowMinAmountMint)) {
            throw new Revert('BridgeDepository: amount below flow min');
        }

        // M-02 — mode-0/2 (mint-on-OPNet) flows have NO inventory-decrement
        // path on the OPNet side: burns happen on WrappedOP20, off the flow
        // ledger. The pre-M-02 code incremented `_flowInventory` on every
        // mint and capped against it, so `cap` acted as a LIFETIME ceiling
        // that permanently bricked the mint path once cumulative volume
        // reached it. `_flowInventory` is therefore left untouched for these
        // modes (stays 0 — unambiguous: "not tracked on this side"); the
        // rolling `dailyLimit` below is the mint bound, and the wrapped
        // token's own `maxSupply` is the hard supply ceiling.

        // PR γ.1 — rolling 24h dailyLimit. Reset bucket if older than
        // FLOW_WINDOW_DURATION (86400s); then assert and consume.
        const nowMint: u64 = Blockchain.block.medianTimestamp;
        const windowStartMint: u64 = this._flowLastWindowStart.get(flowIdMint).toU64();
        let mintedTodayMint: u256 = this._flowMintedToday.get(flowIdMint);
        if (nowMint - windowStartMint > FLOW_WINDOW_DURATION) {
            mintedTodayMint = u256.Zero;
            this._flowLastWindowStart.set(flowIdMint, u256.fromU64(nowMint));
        }
        const newMintedMint: u256 = SafeMath.add(mintedTodayMint, parsed.grossAmount);
        const flowDailyLimitMint: u256 = this._flowDailyLimit.get(flowIdMint);
        if (u256.gt(newMintedMint, flowDailyLimitMint)) {
            throw new Revert('BridgeDepository: daily limit exceeded');
        }
        this._flowMintedToday.set(flowIdMint, newMintedMint);

        // M-02 — no `_flowInventory` mutation for mint-on-OPNet modes
        // (see the note above the dailyLimit block).

        let recipientNetAmountMint: u256 = parsed.netAmount;
        if (!parsed.relayerTip.isZero()) {
            // FINDING-006 (audit 2026-05-26): cross-multiply instead of
            // floored division so `tipCapBps == 0` cannot still permit a
            // sub-1-bp tip, and explicitly reject `tip > netAmount` so the
            // subtraction below cannot underflow on a malformed
            // signer-bound voucher.
            if (u256.gt(parsed.relayerTip, parsed.netAmount)) {
                throw new Revert('BridgeDepository: tip exceeds flow cap');
            }
            const tipCapBpsMint: u32 = this._flowTipCapBps.get(flowIdMint).toU32();
            const tipScaledMint: u256 = SafeMath.mul(parsed.relayerTip, u256.fromU32(10000));
            const capScaledMint: u256 = SafeMath.mul(parsed.netAmount, u256.fromU32(tipCapBpsMint));
            if (u256.gt(tipScaledMint, capScaledMint)) {
                throw new Revert('BridgeDepository: tip exceeds flow cap');
            }
            // Mint tip to tx.sender FIRST, then mint residual to recipient.
            const relayer: Address = Blockchain.tx.sender;
            const mintSelectorTip = encodeSelector('mintTo(address,uint256)');
            const tipCalldata = new BytesWriter(4 + ADDRESS_BYTE_LENGTH + 32);
            tipCalldata.writeSelector(mintSelectorTip);
            tipCalldata.writeAddress(relayer);
            tipCalldata.writeU256(parsed.relayerTip);
            Blockchain.call(parsed.wrappedToken, tipCalldata);

            this.emitEvent(new RelayerTipPaid(flowIdMint, relayer, parsed.relayerTip));

            recipientNetAmountMint = SafeMath.sub(parsed.netAmount, parsed.relayerTip);
        }

        // ── Step 11: cross-contract mintTo(recipient, netAmount - tip) ──
        // mintTo(address,uint256) — Solidity-style selector.
        const mintSelector = encodeSelector('mintTo(address,uint256)');
        const mintCalldata = new BytesWriter(4 + ADDRESS_BYTE_LENGTH + 32);
        mintCalldata.writeSelector(mintSelector);
        mintCalldata.writeAddress(parsed.recipient);
        mintCalldata.writeU256(recipientNetAmountMint);
        Blockchain.call(parsed.wrappedToken, mintCalldata);

        this.emitEvent(new MintedFromVoucher(
            parsed.recipient,
            parsed.wrappedToken,
            parsed.sourceChainId,
            parsed.sourceTxHash,
            parsed.sourceLogIndex,
            parsed.grossAmount,
            parsed.feeAmount,
            parsed.netAmount,
            parsed.voucherId,
            parsed.signerEpoch,
        ));

        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Views
    // ═══════════════════════════════════════════════════════════════════════

    @view
    @returns({ name: 'governor', type: ABIDataTypes.ADDRESS })
    public governor(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(ADDRESS_BYTE_LENGTH);
        response.writeAddress(this._governor.value);
        return response;
    }

    @view
    @returns({ name: 'paused', type: ABIDataTypes.BOOL })
    public paused(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(1);
        response.writeBoolean(this._paused.value);
        return response;
    }

    @view
    @returns({ name: 'signerEpoch', type: ABIDataTypes.UINT256 })
    public signerEpoch(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(32);
        response.writeU256(this._signerEpoch.value);
        return response;
    }

    @view
    @returns({ name: 'signerHash', type: ABIDataTypes.UINT256 })
    public signerHashAtEpoch(calldata: Calldata): BytesWriter {
        const epoch: u256 = calldata.readU256();
        const response = new BytesWriter(32);
        response.writeU256(this._bridgeSignerHashes.get(epoch));
        return response;
    }

    @view
    @returns({ name: 'used', type: ABIDataTypes.BOOL })
    public isVoucherUsed(calldata: Calldata): BytesWriter {
        const voucherId: u256 = calldata.readU256();
        const response = new BytesWriter(1);
        response.writeBoolean(!this._usedVoucherIds.get(voucherId).isZero());
        return response;
    }

    @view
    @returns({ name: 'used', type: ABIDataTypes.BOOL })
    public isSourceEventUsed(calldata: Calldata): BytesWriter {
        const sourceChainId: u256 = calldata.readU256();
        const sourceBridgeAddr: Address = calldata.readAddress();
        const sourceTokenAddr: Address = calldata.readAddress();
        const sourceTxHash: u256 = calldata.readU256();
        const sourceLogIndex: u32 = calldata.readU32();
        const key = buildSourceEventKey(
            sourceChainId,
            sourceBridgeAddr,
            sourceTokenAddr,
            sourceTxHash,
            sourceLogIndex,
        );
        const response = new BytesWriter(1);
        response.writeBoolean(!this._usedSourceEvents.get(key).isZero());
        return response;
    }

    @view
    @returns({ name: 'storageVersion', type: ABIDataTypes.UINT256 })
    public storageVersion(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(32);
        response.writeU256(this._storageVersion.value);
        return response;
    }

    @view
    @returns({ name: 'networkId', type: ABIDataTypes.UINT256 })
    public networkId(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(32);
        response.writeU256(this._networkId.value);
        return response;
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Helpers (module-level so the test harness can reuse the same layout)
// ───────────────────────────────────────────────────────────────────────────

class ParsedVoucher {
    networkId: u256 = u256.Zero;
    contractSelf: Address = Address.zero();
    selector: u32 = 0;
    recipient: Address = Address.zero();
    sourceChainId: u256 = u256.Zero;
    sourceBridgeAddr: Address = Address.zero();
    sourceTokenAddr: Address = Address.zero();
    sourceTxHash: u256 = u256.Zero;
    sourceLogIndex: u32 = 0;
    sourceDepositNonce: u256 = u256.Zero;
    sourceBlockHash: u256 = u256.Zero;
    wrappedToken: Address = Address.zero();
    // PR β.2.format — source-side gross input. Parsed but not yet enforced.
    grossSrcAmount: u256 = u256.Zero;
    // Renamed from grossAmount → grossDstAmount in spec; field name kept as
    // `grossAmount` here so existing fee-math invariant code paths
    // (gross == fee + net) read naturally. Holds the destination-side gross.
    grossAmount: u256 = u256.Zero;
    feeAmount: u256 = u256.Zero;
    netAmount: u256 = u256.Zero;
    // PR β.2.format — relayer tip carved from netDst by the next sub-PR.
    // Parsed but ignored in this PR (no payout, no cap check).
    relayerTip: u256 = u256.Zero;
    signerEpoch: u32 = 0;
    voucherId: u256 = u256.Zero;
    // #68 Tier B — route binding. Appended LAST in the preimage so no
    // existing offsets shift. The claim leg derives its mode from
    // `_flowMode[flowId]` and binds `flowId ↔ wrappedToken`.
    flowId: u256 = u256.Zero;
}

function parseVoucher(buf: Uint8Array): ParsedVoucher {
    const p = new ParsedVoucher();
    let off: u32 = 0;
    p.networkId = readU256BE(buf, off); off += 32;
    p.contractSelf = readAddress(buf, off); off += 32;
    p.selector = readU32BE(buf, off); off += 4;
    p.recipient = readAddress(buf, off); off += 32;
    p.sourceChainId = readU256BE(buf, off); off += 32;
    p.sourceBridgeAddr = readAddress(buf, off); off += 32;
    p.sourceTokenAddr = readAddress(buf, off); off += 32;
    p.sourceTxHash = readU256BE(buf, off); off += 32;
    p.sourceLogIndex = readU32BE(buf, off); off += 4;
    p.sourceDepositNonce = readU256BE(buf, off); off += 32;
    p.sourceBlockHash = readU256BE(buf, off); off += 32;
    p.wrappedToken = readAddress(buf, off); off += 32;
    p.grossSrcAmount = readU256BE(buf, off); off += 32;
    p.grossAmount = readU256BE(buf, off); off += 32;
    p.feeAmount = readU256BE(buf, off); off += 32;
    p.netAmount = readU256BE(buf, off); off += 32;
    p.relayerTip = readU128BE(buf, off); off += 16;
    p.signerEpoch = readU32BE(buf, off); off += 4;
    p.voucherId = readU256BE(buf, off); off += 32;
    p.flowId = readU256BE(buf, off); off += 32;
    // Sanity check — if this fails the constant is out of sync.
    if (off != <u32>VOUCHER_PREIMAGE_LEN) {
        throw new Revert('BridgeDepository: parser off-by-one');
    }
    return p;
}

function readU32BE(buf: Uint8Array, off: u32): u32 {
    return ((<u32>buf[off]) << 24)
         | ((<u32>buf[off + 1]) << 16)
         | ((<u32>buf[off + 2]) << 8)
         |  (<u32>buf[off + 3]);
}

function readU256BE(buf: Uint8Array, off: u32): u256 {
    const tmp = new Uint8Array(32);
    for (let i: u32 = 0; i < 32; i++) {
        tmp[i] = buf[off + i];
    }
    return u256.fromUint8ArrayBE(tmp);
}

/**
 * Read a 16-byte (uint128) big-endian value into a u256. We use u256 as the
 * carrying type (rather than u128) so downstream fee-math, comparisons and
 * SafeMath ops compose with the rest of the contract without conversions.
 * Caller must ensure offsets stay within the 540-byte preimage bound.
 */
function readU128BE(buf: Uint8Array, off: u32): u256 {
    const tmp = new Uint8Array(32);
    // Place the 16 source bytes into the low half of a 32-byte buffer so
    // u256.fromUint8ArrayBE produces the correct value (high 16 bytes zero).
    for (let i: u32 = 0; i < 16; i++) {
        tmp[16 + i] = buf[off + i];
    }
    return u256.fromUint8ArrayBE(tmp);
}

function readAddress(buf: Uint8Array, off: u32): Address {
    const tmp = new Uint8Array(32);
    for (let i: u32 = 0; i < 32; i++) {
        tmp[i] = buf[off + i];
    }
    return Address.fromUint8Array(tmp);
}

function slice(src: Uint8Array, start: u32, end: u32): Uint8Array {
    const len: u32 = end - start;
    const out = new Uint8Array(len);
    for (let i: u32 = 0; i < len; i++) {
        out[i] = src[start + i];
    }
    return out;
}

/**
 * Composite-key hash for the full source-event identity:
 *   (sourceChainId, sourceBridgeAddr, sourceTokenAddr, sourceTxHash, sourceLogIndex)
 *
 * Widened from (txHash, logIndex) per audit Fix #5 so the same (txHash,
 * logIndex) cannot collide across EVM chains or across different bridge /
 * token contracts when we expand beyond Ethereum mainnet.
 *
 * Layout fed to sha256: 32 + 32 + 32 + 32 + 4 = 132 bytes.
 */
function buildSourceEventKey(
    sourceChainId: u256,
    sourceBridgeAddr: Address,
    sourceTokenAddr: Address,
    sourceTxHash: u256,
    sourceLogIndex: u32,
): u256 {
    const buf = new BytesWriter(32 + 32 + 32 + 32 + 4);
    buf.writeU256(sourceChainId);
    buf.writeAddress(sourceBridgeAddr);
    buf.writeAddress(sourceTokenAddr);
    buf.writeU256(sourceTxHash);
    buf.writeU32(sourceLogIndex);
    return u256.fromUint8ArrayBE(sha256(buf.getBuffer()));
}

/**
 * Composite-key hash for the confirmBurn replay guard.
 *
 * MED-002 / #45 — `_confirmedBurns` was keyed by `depositId` alone, which
 * is only globally unique while there is a single EVM bridge with one
 * nonce counter. A second EVM bridge instance, or per-flow counters, would
 * let two legitimate burns collide on `depositId` and the first
 * confirmation would permanently block the second. Keying by the full
 * source-event identity (flowId, depositId, evmTxHash, evmLogIndex) is
 * collision-proof. Mirrors `buildSourceEventKey`.
 *
 * Layout fed to sha256: 32 + 32 + 32 + 4 = 100 bytes.
 */
function buildBurnReplayKey(
    flowId: u256,
    depositId: u256,
    evmTxHash: u256,
    evmLogIndex: u32,
): u256 {
    const buf = new BytesWriter(32 + 32 + 32 + 4);
    buf.writeU256(flowId);
    buf.writeU256(depositId);
    buf.writeU256(evmTxHash);
    buf.writeU32(evmLogIndex);
    return u256.fromUint8ArrayBE(sha256(buf.getBuffer()));
}

/**
 * sha256 hash of a 32-byte address — used as the StoredMapU256 key for
 * `_wrapMinFee[wrappedToken]`.
 */
function _wrapMinFeeKey(wrappedToken: Address): u256 {
    return _addrKey(wrappedToken);
}

/**
 * Generic sha256 of a 32-byte address — keys for `_tokenMode`,
 * `_tokenModeFinalized`, `_evmCounterpart` (and `_wrapMinFee` via the
 * compat shim above).
 */
function _addrKey(addr: Address): u256 {
    const buf = new BytesWriter(32);
    buf.writeAddress(addr);
    return u256.fromUint8ArrayBE(sha256(buf.getBuffer()));
}

/**
 * PR α — canonical flowId derivation. Mirrors EVM
 * `BridgeEscrow.computeFlowId(...)` exactly so the same 32-byte
 * identifier names a route end-to-end.
 *
 * Packed byte layout (113 bytes total):
 *   mode_u8           1
 *   evmChainId_be64   8
 *   evmBridge_20     20  (low 20 bytes of the u256 big-endian rep)
 *   evmToken_20      20
 *   opnetBridge_32   32  (full u256 BE)
 *   opnetToken_32    32
 *
 * Then `flowId = sha256(packed) → u256(BE)`.
 */
function _computeFlowId(
    mode: u32,
    chainId: u64,
    evmBridge: u256,
    evmToken: u256,
    opnetBridge: u256,
    opnetToken: u256,
): u256 {
    const buf = new Uint8Array(113);
    buf[0] = <u8>mode;

    // chainId as 8 bytes big-endian.
    buf[1] = <u8>(chainId >> 56);
    buf[2] = <u8>(chainId >> 48);
    buf[3] = <u8>(chainId >> 40);
    buf[4] = <u8>(chainId >> 32);
    buf[5] = <u8>(chainId >> 24);
    buf[6] = <u8>(chainId >> 16);
    buf[7] = <u8>(chainId >> 8);
    buf[8] = <u8>chainId;

    // EVM addresses — extract low 20 bytes from u256 BE (bytes 12..32).
    const eb = evmBridge.toUint8Array(true);
    for (let i: u32 = 0; i < 20; i++) {
        buf[9 + i] = eb[12 + i];
    }
    const et = evmToken.toUint8Array(true);
    for (let i: u32 = 0; i < 20; i++) {
        buf[29 + i] = et[12 + i];
    }

    // OPNet addresses — full 32-byte big-endian.
    const ob = opnetBridge.toUint8Array(true);
    for (let i: u32 = 0; i < 32; i++) {
        buf[49 + i] = ob[i];
    }
    const ot = opnetToken.toUint8Array(true);
    for (let i: u32 = 0; i < 32; i++) {
        buf[81 + i] = ot[i];
    }

    return u256.fromUint8ArrayBE(sha256(buf));
}

/**
 * PR β.2.payout-opnet — convert an EVM-style 32-byte address field encoded
 * with right-padding (`addr in [0..20), zeros in [20..32)` — voucher
 * convention) into the left-padded u256 representation that `addFlow` /
 * `_computeFlowId` consume (`zeros in [0..12), addr in [12..32)`). The two
 * encodings carry the same 20-byte address but live in opposite halves of
 * the 32-byte word.
 */
function _evmAddrRightPadToLeftPadU256(rightPad: Address): u256 {
    const out = new Uint8Array(32);
    for (let i: u32 = 0; i < 20; i++) {
        out[12 + i] = rightPad[i];
    }
    return u256.fromUint8ArrayBE(out);
}

/**
 * PR β.2.payout-opnet — convert an OPNet 32-byte address into its u256 BE
 * representation. OPNet addresses are full 32-byte identities so the bytes
 * map directly to a u256.
 */
function _opnetAddrToU256(addr: Address): u256 {
    const out = new Uint8Array(32);
    for (let i: u32 = 0; i < 32; i++) {
        out[i] = addr[i];
    }
    return u256.fromUint8ArrayBE(out);
}

/**
 * PR β.2.payout-opnet — derive the canonical flowId for the route identified
 * by a parsed voucher. The voucher carries the EVM-side identities right-
 * padded (matching the EIP-712 / signing convention) so we re-encode them
 * into the addFlow convention before hashing.
 *
 * Caller passes `mode` (read from `_tokenMode[wrappedToken]`) and
 * `contractSelf` (this depository's identity, which `addFlow` consumed as
 * `opnetBridge`).
 */
function _flowIdFromVoucher(
    mode: u32,
    sourceChainId: u256,
    sourceBridgeAddr: Address,
    sourceTokenAddr: Address,
    contractSelf: Address,
    wrappedToken: Address,
): u256 {
    return _computeFlowId(
        mode,
        sourceChainId.toU64(),
        _evmAddrRightPadToLeftPadU256(sourceBridgeAddr),
        _evmAddrRightPadToLeftPadU256(sourceTokenAddr),
        _opnetAddrToU256(contractSelf),
        _opnetAddrToU256(wrappedToken),
    );
}
