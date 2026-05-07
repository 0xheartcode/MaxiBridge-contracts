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
 * Voucher preimage length in bytes.
 *
 * Layout (byte-for-byte, MUST match server/src/voucher.ts):
 *   networkId           u256     32
 *   contractSelf        Address  32
 *   selector            u32       4
 *   recipient           Address  32
 *   sourceChainId       u256     32
 *   sourceBridgeAddr    Address  32   (EVM 20-byte addr left-padded to 32)
 *   sourceTokenAddr     Address  32   (EVM 20-byte addr left-padded to 32)
 *   sourceTxHash        u256     32
 *   sourceLogIndex      u32       4
 *   sourceDepositNonce  u256     32
 *   sourceBlockHash     u256     32
 *   wrappedToken        Address  32
 *   grossAmount         u256     32
 *   feeAmount           u256     32
 *   netAmount           u256     32
 *   signerEpoch         u32       4
 *   voucherId           u256     32
 *   ────────────────────────────────
 *   total                       460
 */
const VOUCHER_PREIMAGE_LEN: i32 = 460;

/**
 * BridgeDepository — mint authority for WrappedOP20.
 *
 * Users call `claimMintWithVoucher(voucher, mldsaSig)` paying their own gas.
 * The contract verifies:
 *   (1) parsed voucher length == 460 bytes
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

    // ─── Token bridging modes (4-mode dispatch) ────────────────────────
    // Per-token mode encoded as u256 (matching the EVM-side enum value
    // space):
    //   0 WRAPPED              — canonical on EVM, wrapped on OPNet (USDC/USDT)
    //   1 INVERSE_WRAPPED      — canonical on OPNet, wrapped on EVM
    //   2 NATIVE_BURN_MINT     — bridge issues both sides, burn-and-mint
    //   3 POOLED_LOCK_RELEASE  — lock+release on both, no minting; project
    //                            funds inventory (e.g. MOTO)
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

        // Only the original deployer may upgrade.
        if (!Blockchain.tx.sender.equals(this.contractDeployer)) {
            throw new Revert('BridgeDepository: not deployer');
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
        if (u256.gt(mode, u256.fromU32(3))) {
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

        if (mode > 3) throw new Revert('BridgeDepository: invalid flow mode');
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
        { name: 'canonicalToken', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
        { name: 'evmRecipient', type: ABIDataTypes.BYTES32 },
        { name: 'destChainId', type: ABIDataTypes.UINT32 },
    )
    @emit('LockedForBridge')
    @nonReentrant
    public lockForBridge(calldata: Calldata): BytesWriter {
        this.requireNotPaused();
        const canonical: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();
        const evmRecipient: Uint8Array = calldata.readBytes(32);
        const destChainId: u32 = calldata.readU32();

        if (amount.isZero()) throw new Revert('BridgeDepository: zero amount');
        if (destChainId == 0) throw new Revert('BridgeDepository: zero destChainId');
        if (evmRecipient.length != 32) {
            throw new Revert('BridgeDepository: ethRecipient must be 32 bytes');
        }
        // Mode dispatch — only INVERSE_WRAPPED (1) or POOLED_LOCK_RELEASE (3)
        // accept lockForBridge.
        const mode: u256 = this._tokenMode.get(_addrKey(canonical));
        const isInverse: bool = u256.eq(mode, u256.fromU32(1));
        const isPooled: bool = u256.eq(mode, u256.fromU32(3));
        if (!isInverse && !isPooled) {
            throw new Revert('BridgeDepository: token not in lockable mode');
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

        // Pull `amount` of canonical OP20 from the user via OP20.transferFrom.
        // The caller (user) must have approved the BridgeDepository first.
        const transferFromSelector: u32 = encodeSelector('transferFrom(address,address,uint256)');
        const tfWriter = new BytesWriter(4 + ADDRESS_BYTE_LENGTH * 2 + 32);
        tfWriter.writeSelector(transferFromSelector);
        tfWriter.writeAddress(Blockchain.tx.sender);
        tfWriter.writeAddress(this.address);
        tfWriter.writeU256(amount);
        Blockchain.call(canonical, tfWriter);

        const nextNonce: u256 = SafeMath.add(this._lockNonce.value, u256.One);
        this._lockNonce.value = nextNonce;

        // Pack evmRecipient (32B) into a u256 for event encoding.
        const evmRecipU256: u256 = u256.fromUint8ArrayBE(evmRecipient);

        this.emitEvent(new LockedForBridge(
            canonical,
            Blockchain.tx.sender,
            amount,
            evmRecipU256,
            destChainId,
            nextNonce,
            mode.toU32(),
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
    @emit('ReleasedFromVoucher')
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

        // Mode dispatch — release path only valid for INVERSE_WRAPPED (1)
        // or POOLED_LOCK_RELEASE (3). The `wrappedToken` field is the
        // canonical OP20 to release.
        const releaseMode: u256 = this._tokenMode.get(_addrKey(parsed.wrappedToken));
        const isInverse2: bool = u256.eq(releaseMode, u256.fromU32(1));
        const isPooled2: bool = u256.eq(releaseMode, u256.fromU32(3));
        if (!isInverse2 && !isPooled2) {
            throw new Revert('BridgeDepository: token not in releasable mode');
        }

        const currentEpoch: u256 = this._signerEpoch.value;
        if (parsed.signerEpoch != currentEpoch.toU32()) {
            throw new Revert('BridgeDepository: wrong signerEpoch');
        }

        const sender: Address = Blockchain.tx.sender;
        if (!parsed.recipient.equals(sender)) {
            throw new Revert('BridgeDepository: wrong recipient');
        }

        const sum: u256 = SafeMath.add(parsed.feeAmount, parsed.netAmount);
        if (!u256.eq(sum, parsed.grossAmount)) {
            throw new Revert('BridgeDepository: gross != fee + net');
        }
        if (parsed.netAmount.isZero()) {
            throw new Revert('BridgeDepository: zero netAmount');
        }

        // M-of-N ML-DSA verification. Same blob format as
        // claimMintWithVoucher.
        if (<u32>sig.length < 4) throw new Revert('BridgeDepository: bad sig blob length');
        const numSigs: u32 = readU32BE(sig, 0);
        if (numSigs == 0 || numSigs > 16) throw new Revert('BridgeDepository: bad numSigs');
        const required: u32 = this._requiredSignatures.value.toU32();
        if (required == 0) throw new Revert('BridgeDepository: signer set not initialized');
        const voucherHash: Uint8Array = sha256(voucher);
        const seenR: Array<u256> = new Array<u256>(0);
        let validCountR: u32 = 0;
        let offR: u32 = 4;
        for (let i: u32 = 0; i < numSigs; i++) {
            if (offR + 4 > <u32>sig.length) throw new Revert('BridgeDepository: truncated pubLen');
            const pubLen: u32 = readU32BE(sig, offR); offR += 4;
            if (pubLen != MLDSA_LEVEL2_PUBKEY_LEN) throw new Revert('BridgeDepository: bad pubLen');
            if (offR + pubLen > <u32>sig.length) throw new Revert('BridgeDepository: truncated pubKey');
            const pubKey: Uint8Array = slice(sig, offR, offR + pubLen);
            offR += pubLen;
            if (offR + 4 > <u32>sig.length) throw new Revert('BridgeDepository: truncated sigLen');
            const sigLen: u32 = readU32BE(sig, offR); offR += 4;
            if (sigLen != MLDSA_LEVEL2_SIG_LEN) throw new Revert('BridgeDepository: bad sigLen');
            if (offR + sigLen > <u32>sig.length) throw new Revert('BridgeDepository: truncated rawSig');
            const rawSig: Uint8Array = slice(sig, offR, offR + sigLen);
            offR += sigLen;
            const pubHash: u256 = u256.fromUint8ArrayBE(sha256(pubKey));
            for (let j: i32 = 0; j < seenR.length; j++) {
                if (u256.eq(seenR[j], pubHash)) {
                    throw new Revert('BridgeDepository: duplicate signer');
                }
            }
            seenR.push(pubHash);
            if (this._signerKeyHashSet.get(pubHash).isZero()) continue;
            if (Blockchain.verifyMLDSASignature(MLDSASecurityLevel.Level2, pubKey, rawSig, voucherHash)) {
                validCountR++;
            }
        }
        if (offR != <u32>sig.length) throw new Revert('BridgeDepository: trailing sig bytes');
        if (validCountR < required) {
            throw new Revert('BridgeDepository: insufficient valid signatures');
        }

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

        // Cross-contract call: OP20.transfer(recipient, netAmount)
        // — bridge holds the canonical OP20 and sends to recipient.
        const transferSelector: u32 = encodeSelector('transfer(address,uint256)');
        const tWriter = new BytesWriter(4 + ADDRESS_BYTE_LENGTH + 32);
        tWriter.writeSelector(transferSelector);
        tWriter.writeAddress(parsed.recipient);
        tWriter.writeU256(parsed.netAmount);
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
     * Add `amount` of `canonicalToken` to the bridge's inventory pool.
     * Used for POOLED_LOCK_RELEASE tokens (e.g. MOTO) where the project
     * pre-funds the OPNet-side pool. Caller must have approved the
     * BridgeDepository for at least `amount`.
     */
    @method(
        { name: 'token', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
    )
    @emit('InventoryProvisionedOpNet')
    @nonReentrant
    public provisionInventoryOpNet(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const token: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();
        if (token.isZero()) throw new Revert('BridgeDepository: zero token');
        if (amount.isZero()) throw new Revert('BridgeDepository: zero amount');

        const transferFromSelector: u32 = encodeSelector('transferFrom(address,address,uint256)');
        const w = new BytesWriter(4 + ADDRESS_BYTE_LENGTH * 2 + 32);
        w.writeSelector(transferFromSelector);
        w.writeAddress(Blockchain.tx.sender);
        w.writeAddress(this.address);
        w.writeU256(amount);
        Blockchain.call(token, w);

        this.emitEvent(new InventoryProvisionedOpNet(token, Blockchain.tx.sender, amount));
        return new BytesWriter(0);
    }

    /**
     * Drain canonical OP20 inventory back to the governor. Governor-only,
     * requires the bridge to be paused (matches EVM emergencyWithdraw
     * semantics). Used for orderly wind-down of a token's pool.
     */
    @method(
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
        const token: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();
        const recipient: Address = calldata.readAddress();
        if (token.isZero() || recipient.isZero()) throw new Revert('BridgeDepository: zero addr');
        if (amount.isZero()) throw new Revert('BridgeDepository: zero amount');

        const transferSelector: u32 = encodeSelector('transfer(address,uint256)');
        const w = new BytesWriter(4 + ADDRESS_BYTE_LENGTH + 32);
        w.writeSelector(transferSelector);
        w.writeAddress(recipient);
        w.writeU256(amount);
        Blockchain.call(token, w);

        this.emitEvent(new InventoryDrainedOpNet(token, recipient, Blockchain.tx.sender, amount));
        return new BytesWriter(0);
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
        this.onlyGovernor();
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
    @emit('MintedFromVoucher')
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
        // Contract rebuilds this check against tx.sender, so a voucher
        // signed for alice cannot be claimed by bob.
        const sender: Address = Blockchain.tx.sender;
        if (!parsed.recipient.equals(sender)) {
            throw new Revert('BridgeDepository: wrong recipient');
        }

        // ── Step 5: wrappedToken must be allowlisted ──
        if (this._wrappedTokens.get(parsed.wrappedToken).isZero()) {
            throw new Revert('BridgeDepository: unknown wrappedToken');
        }

        // ── Step 5b: token must be in a mintable mode ──
        // Valid for WRAPPED (0) and NATIVE_BURN_MINT (2) only.
        // INVERSE_WRAPPED (1) and POOLED_LOCK_RELEASE (3) use claimReleaseWithVoucher.
        const mintMode: u256 = this._tokenMode.get(_addrKey(parsed.wrappedToken));
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
        if (<u32>sig.length < 4) {
            throw new Revert('BridgeDepository: bad sig blob length');
        }
        const numSigs: u32 = readU32BE(sig, 0);
        if (numSigs == 0) {
            throw new Revert('BridgeDepository: zero numSigs');
        }
        if (numSigs > 16) {
            throw new Revert('BridgeDepository: too many sigs');
        }

        const voucherHash: Uint8Array = sha256(voucher);
        const required: u32 = this._requiredSignatures.value.toU32();
        if (required == 0) {
            throw new Revert('BridgeDepository: signer set not initialized');
        }

        const seen: Array<u256> = new Array<u256>(0);
        let validCount: u32 = 0;
        let off: u32 = 4;

        for (let i: u32 = 0; i < numSigs; i++) {
            if (off + 4 > <u32>sig.length) {
                throw new Revert('BridgeDepository: truncated pubLen');
            }
            const pubLen: u32 = readU32BE(sig, off);
            off += 4;
            if (pubLen != MLDSA_LEVEL2_PUBKEY_LEN) {
                throw new Revert('BridgeDepository: bad pubLen');
            }
            if (off + pubLen > <u32>sig.length) {
                throw new Revert('BridgeDepository: truncated pubKey');
            }
            const pubKey: Uint8Array = slice(sig, off, off + pubLen);
            off += pubLen;

            if (off + 4 > <u32>sig.length) {
                throw new Revert('BridgeDepository: truncated sigLen');
            }
            const sigLen: u32 = readU32BE(sig, off);
            off += 4;
            if (sigLen != MLDSA_LEVEL2_SIG_LEN) {
                throw new Revert('BridgeDepository: bad sigLen');
            }
            if (off + sigLen > <u32>sig.length) {
                throw new Revert('BridgeDepository: truncated rawSig');
            }
            const rawSig: Uint8Array = slice(sig, off, off + sigLen);
            off += sigLen;

            // Bounded duplicate-signer check (numSigs ≤ 16 → ≤ 256 cmps).
            const pubHash: u256 = u256.fromUint8ArrayBE(sha256(pubKey));
            for (let j: i32 = 0; j < seen.length; j++) {
                if (u256.eq(seen[j], pubHash)) {
                    throw new Revert('BridgeDepository: duplicate signer');
                }
            }
            seen.push(pubHash);

            // Authorization check — silently skip non-members so callers
            // can include "candidate" sigs without aborting the whole
            // verification. (Threshold check below gates the final yes/no.)
            if (this._signerKeyHashSet.get(pubHash).isZero()) {
                continue;
            }

            const valid: boolean = Blockchain.verifyMLDSASignature(
                MLDSASecurityLevel.Level2,
                pubKey,
                rawSig,
                voucherHash,
            );
            if (valid) {
                validCount++;
            }
        }

        if (off != <u32>sig.length) {
            throw new Revert('BridgeDepository: trailing sig bytes');
        }
        if (validCount < required) {
            throw new Revert('BridgeDepository: insufficient valid signatures');
        }

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

        // ── Step 11: cross-contract mintTo(recipient, netAmount) ──
        // mintTo(address,uint256) — Solidity-style selector.
        const mintSelector = encodeSelector('mintTo(address,uint256)');
        const mintCalldata = new BytesWriter(4 + ADDRESS_BYTE_LENGTH + 32);
        mintCalldata.writeSelector(mintSelector);
        mintCalldata.writeAddress(parsed.recipient);
        mintCalldata.writeU256(parsed.netAmount);
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
    grossAmount: u256 = u256.Zero;
    feeAmount: u256 = u256.Zero;
    netAmount: u256 = u256.Zero;
    signerEpoch: u32 = 0;
    voucherId: u256 = u256.Zero;
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
    p.grossAmount = readU256BE(buf, off); off += 32;
    p.feeAmount = readU256BE(buf, off); off += 32;
    p.netAmount = readU256BE(buf, off); off += 32;
    p.signerEpoch = readU32BE(buf, off); off += 4;
    p.voucherId = readU256BE(buf, off); off += 32;
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
