import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    Blockchain,
    BytesWriter,
    Calldata,
} from '@btc-vision/btc-runtime/runtime';
import { ReentrancyGuard } from '@btc-vision/btc-runtime/runtime/contracts/ReentrancyGuard';
import { StoredAddress } from '@btc-vision/btc-runtime/runtime/storage/StoredAddress';
import { StoredU256 } from '@btc-vision/btc-runtime/runtime/storage/StoredU256';
import { StoredBoolean } from '@btc-vision/btc-runtime/runtime/storage/StoredBoolean';
import { ADDRESS_BYTE_LENGTH } from '@btc-vision/btc-runtime/runtime/utils';
import { EMPTY_POINTER } from '@btc-vision/btc-runtime/runtime/math/bytes';
import { Revert } from '@btc-vision/btc-runtime/runtime/types/Revert';
import { encodeSelector } from '@btc-vision/btc-runtime/runtime/math/abi';
import { UpdatablePlugin } from '@btc-vision/btc-runtime/runtime/plugins/UpdatablePlugin';

import {
    AuthorityGovernorUpdated,
    AuthorityGuardianUpdated,
    AuthorityContractsSet,
    AuthorityPausedAll,
    AuthorityUnpausedAll,
    AuthoritySignerAdded,
    AuthoritySignerRemoved,
    AuthorityThresholdSet,
} from './events';

/**
 * BridgeAuthority — single trust root for the Bridge.
 *
 * Coordinates governance across the Bridge contracts:
 *   - BridgeDepository (mint authority)
 *   - WrappedOP20 wUSDC + wUSDT
 *
 * PUSH architecture: BridgeAuthority stores the addresses of its dependents
 * and forwards governance calls (`setGovernor`, `setPaused`, M-of-N signer
 * updates) via `Blockchain.call`. Cross-contract calls in OPNet are
 * fire-and-forget at the return-value level but propagate reverts — if any
 * dependent rejects the call the whole transaction reverts.
 *
 * Bootstrap-skip pattern: the FIRST call to `pushGovernor` / `pushGuardian`
 * succeeds without onlyGovernor (the slot is zero so no one to gate on).
 * Subsequent calls require `tx.sender == _governor` — write-once flags
 * enforce that the bootstrap window is single-shot.
 *
 * STORAGE IS APPEND-ONLY. `_storageVersion` is declared FIRST so its slot id
 * is pinned across upgrades. Every subsequent field may never be reordered,
 * deleted, or retyped — new fields only appended at the end. See workspace
 * CLAUDE.md "Five Upgrade Commandments".
 */
@final
export class BridgeAuthority extends ReentrancyGuard {
    // ─── STORAGE VERSION — MUST BE FIRST FIELD (append-only invariant) ──
    private _storageVersion: StoredU256 = new StoredU256(
        Blockchain.nextPointer,
        EMPTY_POINTER,
    );

    // ─── Roles ───────────────────────────────────────────────────────────
    private _governor: StoredAddress = new StoredAddress(Blockchain.nextPointer);
    private _guardian: StoredAddress = new StoredAddress(Blockchain.nextPointer);

    // ─── Bootstrap-skip flags (write-once) ───────────────────────────────
    private _governorSetOnce: StoredBoolean = new StoredBoolean(Blockchain.nextPointer, false);
    private _guardianSetOnce: StoredBoolean = new StoredBoolean(Blockchain.nextPointer, false);

    // ─── Managed contract addresses (push targets) ───────────────────────
    private _depository: StoredAddress = new StoredAddress(Blockchain.nextPointer);
    private _wusdc: StoredAddress = new StoredAddress(Blockchain.nextPointer);
    private _wusdt: StoredAddress = new StoredAddress(Blockchain.nextPointer);

    public constructor() {
        super();

        // Phase 2.2 — 7-day upgrade timelock (1008 blocks ≈ 7 days at
        // 10 min/block). Matches BridgeDepository.ts and WrappedOP20.ts.
        this.registerPlugin(new UpdatablePlugin(1008));
    }

    public override onDeployment(calldata: Calldata): void {
        super.onDeployment(calldata);

        // The deployer is the initial governor. They can hand off to a
        // multi-key wallet later via pushGovernor.
        this._governor.value = Blockchain.tx.sender;
        this._storageVersion.value = u256.One;
    }

    public override onUpdate(calldata: Calldata): void {
        super.onUpdate(calldata);

        const gov = this._governor.value;
        if (gov.isZero() || !Blockchain.tx.sender.equals(gov)) {
            throw new Revert('BridgeAuthority: not governor');
        }

        const version = this._storageVersion.value;
        if (u256.lt(version, u256.fromU32(2))) {
            this._storageVersion.value = u256.fromU32(2);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Access control
    // ═══════════════════════════════════════════════════════════════════════

    private onlyGovernor(): void {
        const gov = this._governor.value;
        if (gov.isZero()) throw new Revert('BridgeAuthority: governor not set');
        if (!Blockchain.tx.sender.equals(gov)) {
            throw new Revert('BridgeAuthority: not governor');
        }
    }

    private onlyGovernorOrGuardian(): void {
        const sender = Blockchain.tx.sender;
        const gov = this._governor.value;
        const guardian = this._guardian.value;
        if (!gov.isZero() && sender.equals(gov)) return;
        if (!guardian.isZero() && sender.equals(guardian)) return;
        throw new Revert('BridgeAuthority: not governor or guardian');
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor: register managed contracts
    // ═══════════════════════════════════════════════════════════════════════

    @method(
        { name: 'depository', type: ABIDataTypes.ADDRESS },
        { name: 'wusdc', type: ABIDataTypes.ADDRESS },
        { name: 'wusdt', type: ABIDataTypes.ADDRESS },
    )
    @emit('AuthorityContractsSet')
    @nonReentrant
    public setManagedContracts(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const depo: Address = calldata.readAddress();
        const wusdc: Address = calldata.readAddress();
        const wusdt: Address = calldata.readAddress();
        if (depo.isZero() || wusdc.isZero() || wusdt.isZero()) {
            throw new Revert('BridgeAuthority: zero address in managed contracts');
        }
        this._depository.value = depo;
        this._wusdc.value = wusdc;
        this._wusdt.value = wusdt;
        this.emitEvent(new AuthorityContractsSet(depo, wusdc, wusdt));
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor / bootstrap: push role updates
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Set the governor. The FIRST call (when `_governorSetOnce == false`)
     * succeeds without onlyGovernor — this is the bootstrap window so a
     * deploy script can wire the governor in one tx without first owning
     * the slot. After the first call the flag flips to true and every
     * subsequent call is `onlyGovernor`.
     */
    @method({ name: 'newGovernor', type: ABIDataTypes.ADDRESS })
    @emit('AuthorityGovernorUpdated')
    @nonReentrant
    public pushGovernor(calldata: Calldata): BytesWriter {
        const newGovernor: Address = calldata.readAddress();
        if (newGovernor.isZero()) throw new Revert('BridgeAuthority: zero governor');

        if (this._governorSetOnce.value) {
            this.onlyGovernor();
        }

        const old: Address = this._governor.value;
        this._governor.value = newGovernor;
        this._governorSetOnce.value = true;

        // Push the new governor to all three managed contracts so their
        // local `_governor` slot stays in sync. Skipped silently for any
        // dependent that hasn't been wired yet — the deployer can wire
        // them later via setManagedContracts + a follow-up pushGovernor.
        this._pushSetGovernor(this._depository.value, newGovernor);
        this._pushSetGovernor(this._wusdc.value, newGovernor);
        this._pushSetGovernor(this._wusdt.value, newGovernor);

        this.emitEvent(new AuthorityGovernorUpdated(old, newGovernor));
        return new BytesWriter(0);
    }

    /**
     * Set the guardian. Same bootstrap-skip pattern as pushGovernor: first
     * call open, subsequent calls onlyGovernor. The guardian role is local
     * to this contract — guardian membership doesn't need to push down to
     * dependents (it's a check inside `pauseAll` / `unpauseAll`).
     */
    @method({ name: 'newGuardian', type: ABIDataTypes.ADDRESS })
    @emit('AuthorityGuardianUpdated')
    @nonReentrant
    public pushGuardian(calldata: Calldata): BytesWriter {
        const newGuardian: Address = calldata.readAddress();
        if (newGuardian.isZero()) throw new Revert('BridgeAuthority: zero guardian');

        if (this._guardianSetOnce.value) {
            this.onlyGovernor();
        }

        const old: Address = this._guardian.value;
        this._guardian.value = newGuardian;
        this._guardianSetOnce.value = true;
        this.emitEvent(new AuthorityGuardianUpdated(old, newGuardian));
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor + Guardian: pause coordination
    // ═══════════════════════════════════════════════════════════════════════

    @method()
    @emit('AuthorityPausedAll')
    @nonReentrant
    public pauseAll(_calldata: Calldata): BytesWriter {
        this.onlyGovernorOrGuardian();
        this._pushSetPaused(this._depository.value, true);
        this._pushSetPaused(this._wusdc.value, true);
        this._pushSetPaused(this._wusdt.value, true);
        this.emitEvent(new AuthorityPausedAll());
        return new BytesWriter(0);
    }

    @method()
    @emit('AuthorityUnpausedAll')
    @nonReentrant
    public unpauseAll(_calldata: Calldata): BytesWriter {
        // Unpause is governor-only: a guardian can call pause for incident
        // response but not unpause — that's a positive action that requires
        // the higher trust tier.
        this.onlyGovernor();
        this._pushSetPaused(this._depository.value, false);
        this._pushSetPaused(this._wusdc.value, false);
        this._pushSetPaused(this._wusdt.value, false);
        this.emitEvent(new AuthorityUnpausedAll());
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor: M-of-N signer set (forwarded to BridgeDepository)
    // ═══════════════════════════════════════════════════════════════════════

    @method({ name: 'pubKeyHash', type: ABIDataTypes.UINT256 })
    @emit('AuthoritySignerAdded')
    @nonReentrant
    public addBridgeSigner(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const hash: u256 = calldata.readU256();
        this._pushAddSigner(this._depository.value, hash);
        this.emitEvent(new AuthoritySignerAdded(hash));
        return new BytesWriter(0);
    }

    @method({ name: 'pubKeyHash', type: ABIDataTypes.UINT256 })
    @emit('AuthoritySignerRemoved')
    @nonReentrant
    public removeBridgeSigner(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const hash: u256 = calldata.readU256();
        this._pushRemoveSigner(this._depository.value, hash);
        this.emitEvent(new AuthoritySignerRemoved(hash));
        return new BytesWriter(0);
    }

    @method({ name: 'threshold', type: ABIDataTypes.UINT256 })
    @emit('AuthorityThresholdSet')
    @nonReentrant
    public setBridgeThreshold(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const m: u256 = calldata.readU256();
        this._pushSetThreshold(this._depository.value, m);
        this.emitEvent(new AuthorityThresholdSet(m));
        return new BytesWriter(0);
    }

    /**
     * Atomic add+threshold migration — required for safe transitions like
     * 1-of-1 → 2-of-2 (no intermediate weakening). Submitted as a single
     * governance proposal so there's no window during which numSigs=2 and
     * threshold=1 (which would let either key sign alone).
     */
    @method(
        { name: 'addHash', type: ABIDataTypes.UINT256 },
        { name: 'newThreshold', type: ABIDataTypes.UINT256 },
    )
    @nonReentrant
    public migrateBridgeSignerSet(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const addHash: u256 = calldata.readU256();
        const newThreshold: u256 = calldata.readU256();
        const depo: Address = this._depository.value;
        if (depo.isZero()) throw new Revert('BridgeAuthority: depository not set');

        this._pushAddSigner(depo, addHash);
        this._pushSetThreshold(depo, newThreshold);

        this.emitEvent(new AuthoritySignerAdded(addHash));
        this.emitEvent(new AuthorityThresholdSet(newThreshold));
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Cross-contract push helpers
    // ═══════════════════════════════════════════════════════════════════════

    private _pushSetGovernor(target: Address, newGovernor: Address): void {
        if (target.isZero()) return;
        const selector: u32 = encodeSelector('setGovernor(address)');
        const writer = new BytesWriter(4 + ADDRESS_BYTE_LENGTH);
        writer.writeSelector(selector);
        writer.writeAddress(newGovernor);
        Blockchain.call(target, writer);
    }

    private _pushSetPaused(target: Address, paused: boolean): void {
        if (target.isZero()) return;
        const selector: u32 = encodeSelector('setPaused(bool)');
        const writer = new BytesWriter(4 + 1);
        writer.writeSelector(selector);
        writer.writeBoolean(paused);
        Blockchain.call(target, writer);
    }

    private _pushAddSigner(target: Address, hash: u256): void {
        if (target.isZero()) return;
        const selector: u32 = encodeSelector('addSignerToSet(uint256)');
        const writer = new BytesWriter(4 + 32);
        writer.writeSelector(selector);
        writer.writeU256(hash);
        Blockchain.call(target, writer);
    }

    private _pushRemoveSigner(target: Address, hash: u256): void {
        if (target.isZero()) return;
        const selector: u32 = encodeSelector('removeSignerFromSet(uint256)');
        const writer = new BytesWriter(4 + 32);
        writer.writeSelector(selector);
        writer.writeU256(hash);
        Blockchain.call(target, writer);
    }

    private _pushSetThreshold(target: Address, threshold: u256): void {
        if (target.isZero()) return;
        const selector: u32 = encodeSelector('setRequiredSignatures(uint256)');
        const writer = new BytesWriter(4 + 32);
        writer.writeSelector(selector);
        writer.writeU256(threshold);
        Blockchain.call(target, writer);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Views
    // ═══════════════════════════════════════════════════════════════════════

    @view
    @returns({ name: 'governor', type: ABIDataTypes.ADDRESS })
    public governor(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(ADDRESS_BYTE_LENGTH);
        r.writeAddress(this._governor.value);
        return r;
    }

    @view
    @returns({ name: 'guardian', type: ABIDataTypes.ADDRESS })
    public guardian(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(ADDRESS_BYTE_LENGTH);
        r.writeAddress(this._guardian.value);
        return r;
    }

    @view
    @returns({ name: 'depository', type: ABIDataTypes.ADDRESS })
    public depository(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(ADDRESS_BYTE_LENGTH);
        r.writeAddress(this._depository.value);
        return r;
    }

    @view
    @returns({ name: 'wusdc', type: ABIDataTypes.ADDRESS })
    public wusdc(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(ADDRESS_BYTE_LENGTH);
        r.writeAddress(this._wusdc.value);
        return r;
    }

    @view
    @returns({ name: 'wusdt', type: ABIDataTypes.ADDRESS })
    public wusdt(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(ADDRESS_BYTE_LENGTH);
        r.writeAddress(this._wusdt.value);
        return r;
    }

    @view
    @returns({ name: 'storageVersion', type: ABIDataTypes.UINT256 })
    public storageVersion(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(32);
        r.writeU256(this._storageVersion.value);
        return r;
    }
}
