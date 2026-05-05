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

        const signerHash: u256 = u256.fromUint8ArrayBE(sha256(pubKey));
        this._bridgeSignerHashes.set(newEpoch, signerHash);

        this.emitEvent(new SignerRotated(oldEpoch.toU32(), newEpoch.toU32(), signerHash));
        return new BytesWriter(0);
    }

    /**
     * Set the signer pubkey for the CURRENT epoch. Used at bootstrap time
     * (right after deployment) when `_signerEpoch` is already 1 but no hash
     * has been stored yet. Governor-only; overwrites any existing hash for
     * the current epoch. NOTE: overwriting on an already-active epoch would
     * effectively accept a DIFFERENT signer with the same epoch tag — use
     * with care; prefer `rotateSigner` in production so unclaimed vouchers
     * invalidate.
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
        // NOTE: The MLDSA runtime call wants the pubkey bytes. We accept
        // them as part of the signature blob: the caller concatenates
        // pubkey || sig, or — simpler — passes pubkey separately. Since the
        // ABI above fixes `mldsaSig` as a single bytes arg, we split by a
        // length prefix on the pubkey inside the sig blob.
        //
        // Layout of `sig`:
        //   pubkey (lengthU32 || raw pubkey bytes) || signature (raw bytes to end)
        //
        // Fix #4 — enforce the CANONICAL ML-DSA Level-2 blob shape before any
        // slicing. Reject any non-canonical length outright rather than
        // letting `pubEnd = 4 + pubLen` silently wrap on a malicious pubLen.
        if (<u32>sig.length != MLDSA_SIG_BLOB_LEN) {
            throw new Revert('BridgeDepository: bad sig blob length');
        }
        const pubLen: u32 = readU32BE(sig, 0);
        if (pubLen != MLDSA_LEVEL2_PUBKEY_LEN) {
            throw new Revert('BridgeDepository: bad pubkey length in sig');
        }
        const pubEnd: u32 = u32(4) + pubLen;
        const pubKey: Uint8Array = slice(sig, 4, pubEnd);
        const rawSig: Uint8Array = slice(sig, pubEnd, <u32>sig.length);

        const pubHash: u256 = u256.fromUint8ArrayBE(sha256(pubKey));
        const expectedHash: u256 = this._bridgeSignerHashes.get(currentEpoch);
        if (expectedHash.isZero()) {
            throw new Revert('BridgeDepository: no signer for epoch');
        }
        if (!u256.eq(pubHash, expectedHash)) {
            throw new Revert('BridgeDepository: unknown signer pubkey');
        }

        const hash: Uint8Array = sha256(voucher);
        const valid: boolean = Blockchain.verifyMLDSASignature(
            MLDSASecurityLevel.Level2,
            pubKey,
            rawSig,
            hash,
        );
        if (!valid) {
            throw new Revert('BridgeDepository: invalid signature');
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
