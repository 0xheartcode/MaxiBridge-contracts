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
 * Governor bootstrap: `onDeployment` seeds `_governor = tx.sender`, so the
 * deployer is the first governor from block zero. `pushGovernor` /
 * `pushGuardian` are therefore ALWAYS `onlyGovernor` — there is no
 * unauthenticated bootstrap window (an open first call would let anyone
 * front-run the deploy ceremony and seize the trust root). Handoff to a
 * multi-key wallet happens via `pushGovernor`, signed by the deployer.
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

    // ─── Managed contract addresses (push targets) ───────────────────────
    private _depository: StoredAddress = new StoredAddress(Blockchain.nextPointer);
    private _wusdc: StoredAddress = new StoredAddress(Blockchain.nextPointer);
    private _wusdt: StoredAddress = new StoredAddress(Blockchain.nextPointer);

    // ── Option C (O-4 fix) — governance-gated upgrade authorization ──
    // Mirrors BridgeDepository so BOTH governance contracts authorize upgrades
    // identically. The stock UpdatablePlugin gates submit/applyUpdate on the
    // WELDED `contractDeployer`; on its own that means handing `_governor` to a
    // new wallet would leave deployer != governor and FREEZE upgrades — no
    // single sender could satisfy both the plugin's deployer gate AND a
    // `tx.sender == governor` onUpdate gate. So we do NOT require deployer ==
    // governor. Instead we split AUTHORIZE from EXECUTE: governance arms a
    // one-shot flag via `proposeUpgrade()`, the deployer EXECUTES `applyUpdate`,
    // and `onUpdate` consumes the flag. Deployer + governance form a 2-of-2 —
    // neither can upgrade alone, and the governor can be handed off freely.
    //
    // Append-only: appended AFTER `_wusdt` (the prior last slot) to preserve
    // the upgrade discipline. Unset slots read zero (Address.zero / false) =
    // correct fail-closed base: a zero `_upgradeAuthority` keeps the legacy
    // deployer-only bootstrap path active until the governor wires it via
    // `setUpgradeAuthority`.
    private _upgradeAuthority: StoredAddress = new StoredAddress(Blockchain.nextPointer);
    private _pendingUpgradeAuthorized: StoredBoolean = new StoredBoolean(
        Blockchain.nextPointer,
        false,
    );

    public constructor() {
        super();

        // 3-day upgrade timelock (432 blocks ≈ 3 days at 10 min/block) — matches
        // BridgeDepository's UpdatablePlugin(432) and the EVM
        // TimelockController(259200s), so users get the same 3-day exit window
        // on every governed contract. (WrappedOP20 is non-upgradeable and
        // registers no plugin.) Aligned from the prior 1008/7d on 2026-06-02.
        this.registerPlugin(new UpdatablePlugin(432));
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

        // Option C (O-4 fix) — deployer EXECUTES, governance PRE-AUTHORIZES.
        // Mirror BridgeDepository.onUpdate exactly (the two contracts MUST
        // authorize upgrades the same way). The underlying UpdatablePlugin
        // already gates `applyUpdate` on `onlyDeployer`; we re-check here so the
        // policy is co-located with the governance gate that follows. NOTE: this
        // gate is now the DEPLOYER, not the governor — gating on the governor
        // here (the prior behaviour) collided with the welded plugin deployer
        // gate and froze upgrades after any governor handoff.
        if (!Blockchain.tx.sender.equals(this.contractDeployer)) {
            throw new Revert('BridgeAuthority: not deployer');
        }

        // Once the governor wires `_upgradeAuthority`, every upgrade must be
        // authorized via `proposeUpgrade()` first. The one-shot flag is consumed
        // here so each upgrade needs a fresh hand-shake — a compromised deployer
        // key alone can no longer push an upgrade. Until the authority is wired,
        // the legacy deployer-only path stays open (v1 bootstrap window).
        const upgradeAuthority: Address = this._upgradeAuthority.value;
        if (!upgradeAuthority.isZero()) {
            if (!this._pendingUpgradeAuthorized.value) {
                throw new Revert('BridgeAuthority: upgrade not authorized');
            }
            this._pendingUpgradeAuthorized.value = false;
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

    private onlyGovernorOrUpgradeAuthority(): void {
        const sender = Blockchain.tx.sender;
        const gov = this._governor.value;
        const upAuth = this._upgradeAuthority.value;
        if (!gov.isZero() && sender.equals(gov)) return;
        if (!upAuth.isZero() && sender.equals(upAuth)) return;
        throw new Revert('BridgeAuthority: not governor or upgrade authority');
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
     * Set the governor. Always `onlyGovernor` — the deployer is seeded as
     * governor in `onDeployment`, so there is no unauthenticated bootstrap
     * call. Handoff to a multi-key wallet is signed by the current governor.
     */
    @method({ name: 'newGovernor', type: ABIDataTypes.ADDRESS })
    @emit('AuthorityGovernorUpdated')
    @nonReentrant
    public pushGovernor(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const newGovernor: Address = calldata.readAddress();
        if (newGovernor.isZero()) throw new Revert('BridgeAuthority: zero governor');

        const old: Address = this._governor.value;
        this._governor.value = newGovernor;

        // Push the new governor to the depository so its local `_governor`
        // slot stays in sync. The depository accepts the cascade via
        // onlyGovernorOrAuthority, so re-pushing on every human-governor
        // rotation works.
        //
        // We do NOT cascade to wusdc / wusdt: those are non-upgradeable and
        // their setGovernor is strict onlyGovernor (immutable code). Once we
        // cascade alice in, a follow-up push of bob would revert because the
        // wrapped's _governor is now alice and tx.sender is the authority.
        // Wrapped admin operations are gated on `onlyGovernorOrAuthority`
        // already (via the registered _authorityAddress), so the wrapped's
        // local _governor slot does not need to track human ownership.
        this._pushSetGovernor(this._depository.value, newGovernor);

        this.emitEvent(new AuthorityGovernorUpdated(old, newGovernor));
        return new BytesWriter(0);
    }

    /**
     * Set the guardian. Always `onlyGovernor` — the governor (seeded at
     * deployment) appoints the guardian. The guardian role is local to this
     * contract — guardian membership doesn't need to push down to dependents
     * (it's a check inside `pauseAll` / `unpauseAll`).
     */
    @method({ name: 'newGuardian', type: ABIDataTypes.ADDRESS })
    @emit('AuthorityGuardianUpdated')
    @nonReentrant
    public pushGuardian(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const newGuardian: Address = calldata.readAddress();
        if (newGuardian.isZero()) throw new Revert('BridgeAuthority: zero guardian');

        const old: Address = this._guardian.value;
        this._guardian.value = newGuardian;
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
    // N5-3 (PeckShield) — the body emits both events; declare them so the ABI
    // metadata matches (was missing the @emit annotation).
    @emit('AuthoritySignerAdded', 'AuthorityThresholdSet')
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
    //  Governance-gated upgrade authorization (Option C / O-4 fix)
    //  Mirrors BridgeDepository's setUpgradeAuthority / proposeUpgrade /
    //  cancelProposedUpgrade so both governance contracts authorize upgrades
    //  the SAME way. See the storage-field comment + `onUpdate` for the model.
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Register the address authorized to gate upgrades for this contract.
     * Governor-only. Zero disables the gate (legacy deployer-only path) —
     * emergency hatch only.
     */
    @method({ name: 'newUpgradeAuthority', type: ABIDataTypes.ADDRESS })
    @nonReentrant
    public setUpgradeAuthority(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        this._upgradeAuthority.value = calldata.readAddress();
        return new BytesWriter(0);
    }

    /**
     * Authorize the next upgrade. One-shot — consumed inside `onUpdate` the
     * moment the next `applyUpdate` lands. Callable by the governor or the
     * registered upgrade authority. The plugin's 1008-block timelock still
     * enforces the wait between submit and apply.
     */
    @method()
    @nonReentrant
    public proposeUpgrade(_calldata: Calldata): BytesWriter {
        this.onlyGovernorOrUpgradeAuthority();
        this._pendingUpgradeAuthorized.value = true;
        return new BytesWriter(0);
    }

    /**
     * Veto a previously proposed upgrade by clearing the authorization flag.
     * Callable by the governor or the registered upgrade authority. Pairs with
     * the plugin's `cancelUpdate` (which cancels the queued bytecode pointer);
     * calling both gives a complete veto.
     */
    @method()
    @nonReentrant
    public cancelProposedUpgrade(_calldata: Calldata): BytesWriter {
        this.onlyGovernorOrUpgradeAuthority();
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
