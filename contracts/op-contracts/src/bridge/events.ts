import { NetEvent } from '@btc-vision/btc-runtime/runtime/events/NetEvent';
import { BytesWriter } from '@btc-vision/btc-runtime/runtime/buffer/BytesWriter';
import { Address } from '@btc-vision/btc-runtime/runtime/types/Address';
import { u256 } from '@btc-vision/as-bignum/assembly';
import { ADDRESS_BYTE_LENGTH } from '@btc-vision/btc-runtime/runtime/utils';

// ─── Reference setters ─────────────────────────────────────────────────

export class GovernorUpdated extends NetEvent {
    constructor(oldGov: Address, newGov: Address) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2);
        data.writeAddress(oldGov);
        data.writeAddress(newGov);
        super('GovernorUpdated', data);
    }
}

/**
 * Roles PR — emitted when the dedicated pause role is set/rotated/disabled.
 * `oldPauser` -> `newPauser`; a zero `newPauser` disables the role.
 */
export class PauserSet extends NetEvent {
    constructor(oldPauser: Address, newPauser: Address) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2);
        data.writeAddress(oldPauser);
        data.writeAddress(newPauser);
        super('PauserSet', data);
    }
}

/**
 * Emitted when the dedicated treasury (fee-revenue + emergency-drain sink) is
 * set/rotated/disabled. `oldTreasury` -> `newTreasury`; a zero `newTreasury`
 * disables fee sweeps + emergency withdrawals (fail-closed). Mirrors the EVM
 * `BridgeEscrow.TreasurySet` role — SAME terminology on both chains.
 */
export class TreasurySet extends NetEvent {
    constructor(oldTreasury: Address, newTreasury: Address) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2);
        data.writeAddress(oldTreasury);
        data.writeAddress(newTreasury);
        super('TreasurySet', data);
    }
}

/**
 * Emitted when the dedicated guardian (incident-response) role is
 * set/rotated/disabled. `oldGuardian` -> `newGuardian`; a zero `newGuardian`
 * disables the role. Mirrors the EVM `BridgeEscrow.GuardianSet` role — SAME
 * terminology on both chains.
 */
export class GuardianSet extends NetEvent {
    constructor(oldGuardian: Address, newGuardian: Address) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2);
        data.writeAddress(oldGuardian);
        data.writeAddress(newGuardian);
        super('GuardianSet', data);
    }
}

/**
 * Emitted on `emergencyWithdraw` — the guardian drains `amount` of `token`
 * from the depository to the pinned `treasury` while paused. Mirrors the EVM
 * `BridgeEscrow.EmergencyWithdrawal(token, treasury, amount)` role.
 */
export class EmergencyWithdrawal extends NetEvent {
    constructor(token: Address, treasury: Address, amount: u256) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2 + 32);
        data.writeAddress(token);
        data.writeAddress(treasury);
        data.writeU256(amount);
        super('EmergencyWithdrawal', data);
    }
}

export class WrappedTokenSet extends NetEvent {
    constructor(wrappedToken: Address, enabled: bool) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH + 1);
        data.writeAddress(wrappedToken);
        data.writeBoolean(enabled);
        super('WrappedTokenSet', data);
    }
}

// ─── Signer management ─────────────────────────────────────────────────

/**
 * Emitted when the governor rotates the bridge ML-DSA signer. `oldEpoch` ->
 * `newEpoch`; every voucher signed at or below `oldEpoch` is invalidated.
 */
export class SignerRotated extends NetEvent {
    constructor(oldEpoch: u32, newEpoch: u32, newSignerHash: u256) {
        const data = new BytesWriter(4 + 4 + 32);
        data.writeU32(oldEpoch);
        data.writeU32(newEpoch);
        data.writeU256(newSignerHash);
        super('SignerRotated', data);
    }
}

// ─── Pause ─────────────────────────────────────────────────────────────

export class Paused extends NetEvent {
    constructor() {
        super('Paused', new BytesWriter(0));
    }
}

export class Unpaused extends NetEvent {
    constructor() {
        super('Unpaused', new BytesWriter(0));
    }
}

// ─── Voucher claim success ─────────────────────────────────────────────

/**
 * Emitted on successful claimMintWithVoucher. Indexed fields: recipient,
 * wrappedToken, voucherId. Net amount minted is `netAmount` (after fee).
 */
// OPN-M3: `flowId` appended LAST so off-chain indexers can correlate the
// mint event to the canonical route without re-deriving from token addresses.
// Old-format readers tolerant of trailing bytes still parse the first 264
// bytes; flow-aware readers parse 296. Compatible event NAME — data length only.
export class MintedFromVoucher extends NetEvent {
    constructor(
        recipient: Address,
        wrappedToken: Address,
        sourceChainId: u256,
        sourceTxHash: u256,
        sourceLogIndex: u32,
        grossAmount: u256,
        feeAmount: u256,
        netAmount: u256,
        voucherId: u256,
        signerEpoch: u32,
        flowId: u256, // OPN-M3 — appended LAST for backwards compat
    ) {
        // 2 addresses + 7 u256 + 2 u32 = 64 + 224 + 8 = 296
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2 + 32 * 7 + 4 * 2);
        data.writeAddress(recipient);
        data.writeAddress(wrappedToken);
        data.writeU256(sourceChainId);
        data.writeU256(sourceTxHash);
        data.writeU32(sourceLogIndex);
        data.writeU256(grossAmount);
        data.writeU256(feeAmount);
        data.writeU256(netAmount);
        data.writeU256(voucherId);
        data.writeU32(signerEpoch);
        data.writeU256(flowId); // OPN-M3 — appended LAST
        super('MintedFromVoucher', data);
    }
}

// ─── Mode-2/4 lock + release ─────────────────────────────────────────

/**
 * Emitted on lockForBridge — user locks canonical OP20 (modes 2/4) on
 * OPNet to bridge to EVM. Indexer picks this up and signs an EIP-712
 * MintIntent (mode 2) or ReleaseIntent (mode 4) for the EVM side.
 */
// FINDING-002 (audit 2026-05-26): `flowId` appended LAST so off-chain
// indexers can persist the canonical route identity without re-deriving
// from token addresses. Routing authority is per-flow (#68); flowId
// appended last for indexer compatibility. Old-format readers tolerant
// of trailing bytes still parse the first 168 bytes; flow-aware readers
// parse 200. Compatible event NAME — only the data length changes.
export class LockedForBridge extends NetEvent {
    constructor(
        canonicalToken: Address,
        user: Address,
        amount: u256,
        evmRecipient: u256, // bytes32 left-padded EVM addr
        destChainId: u32,
        lockNonce: u256,
        mode: u32,
        flowId: u256, // FINDING-002 — appended
    ) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2 + 32 + 32 + 4 + 32 + 4 + 32);
        data.writeAddress(canonicalToken);
        data.writeAddress(user);
        data.writeU256(amount);
        data.writeU256(evmRecipient);
        data.writeU32(destChainId);
        data.writeU256(lockNonce);
        data.writeU32(mode);
        data.writeU256(flowId); // FINDING-002 — appended LAST
        super('LockedForBridge', data);
    }
}

/**
 * Emitted on claimReleaseWithVoucher — bridge releases canonical OP20
 * (modes 2/4) to user against an ML-DSA voucher signed by the M-of-N
 * signer set, in response to an EVM-side burn.
 */
export class ReleasedFromVoucher extends NetEvent {
    constructor(
        recipient: Address,
        canonicalToken: Address,
        sourceChainId: u256,
        sourceTxHash: u256,
        sourceLogIndex: u32,
        grossAmount: u256,
        feeAmount: u256,
        netAmount: u256,
        voucherId: u256,
        signerEpoch: u32,
        flowId: u256,
    ) {
        // Same shape as MintedFromVoucher — 296 bytes total (264 + 32 for flowId).
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2 + 32 * 7 + 4 * 2);
        data.writeAddress(recipient);
        data.writeAddress(canonicalToken);
        data.writeU256(sourceChainId);
        data.writeU256(sourceTxHash);
        data.writeU32(sourceLogIndex);
        data.writeU256(grossAmount);
        data.writeU256(feeAmount);
        data.writeU256(netAmount);
        data.writeU256(voucherId);
        data.writeU32(signerEpoch);
        data.writeU256(flowId);
        super('ReleasedFromVoucher', data);
    }
}

export class InventoryProvisionedOpNet extends NetEvent {
    constructor(flowId: u256, token: Address, by: Address, amount: u256) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2 + 32 * 2);
        data.writeU256(flowId);
        data.writeAddress(token);
        data.writeAddress(by);
        data.writeU256(amount);
        super('InventoryProvisionedOpNet', data);
    }
}

export class InventoryDrainedOpNet extends NetEvent {
    constructor(flowId: u256, token: Address, to: Address, by: Address, amount: u256) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 3 + 32 * 2);
        data.writeU256(flowId);
        data.writeAddress(token);
        data.writeAddress(to);
        data.writeAddress(by);
        data.writeU256(amount);
        super('InventoryDrainedOpNet', data);
    }
}

/**
 * #62 — emitted on `withdrawFees`. The governor sweeps `amount` of a flow's
 * accrued OPNet-source bridge fees to `to` (the governor — there is no
 * set-once treasury slot on the OPNet depository). Mirrors EVM
 * `BridgeEscrow.FeesWithdrawn(flowId, token, treasury, amount)`. `by` is
 * `Blockchain.tx.sender` (the governor) for audit correlation.
 */
export class FeesWithdrawn extends NetEvent {
    constructor(flowId: u256, token: Address, to: Address, by: Address, amount: u256) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 3 + 32 * 2);
        data.writeU256(flowId);
        data.writeAddress(token);
        data.writeAddress(to);
        data.writeAddress(by);
        data.writeU256(amount);
        super('FeesWithdrawn', data);
    }
}

// ─── PR α — Flow Registry events ──────────────────────────────────────

/**
 * Emitted on `addFlow`. flowId is the sha256 of the canonical key tuple,
 * shared with EVM `BridgeEscrow.computeFlowId`.
 */
export class FlowAdded extends NetEvent {
    constructor(flowId: u256, mode: u32, evmChainId: u64, evmToken: u256, opnetToken: u256) {
        const data = new BytesWriter(32 + 4 + 8 + 32 + 32);
        data.writeU256(flowId);
        data.writeU32(mode);
        data.writeU64(evmChainId);
        data.writeU256(evmToken);
        data.writeU256(opnetToken);
        super('FlowAdded', data);
    }
}

export class FlowStatusChanged extends NetEvent {
    constructor(flowId: u256, oldStatus: u32, newStatus: u32) {
        const data = new BytesWriter(32 + 4 + 4);
        data.writeU256(flowId);
        data.writeU32(oldStatus);
        data.writeU32(newStatus);
        super('FlowStatusChanged', data);
    }
}

export class FlowCapChanged extends NetEvent {
    constructor(flowId: u256, oldCap: u256, newCap: u256) {
        const data = new BytesWriter(32 + 32 + 32);
        data.writeU256(flowId);
        data.writeU256(oldCap);
        data.writeU256(newCap);
        super('FlowCapChanged', data);
    }
}

export class FlowDailyLimitChanged extends NetEvent {
    constructor(flowId: u256, oldLimit: u256, newLimit: u256) {
        const data = new BytesWriter(32 + 32 + 32);
        data.writeU256(flowId);
        data.writeU256(oldLimit);
        data.writeU256(newLimit);
        super('FlowDailyLimitChanged', data);
    }
}

export class FlowMinAmountChanged extends NetEvent {
    constructor(flowId: u256, oldMin: u256, newMin: u256) {
        const data = new BytesWriter(32 + 32 + 32);
        data.writeU256(flowId);
        data.writeU256(oldMin);
        data.writeU256(newMin);
        super('FlowMinAmountChanged', data);
    }
}

export class FlowFeeChanged extends NetEvent {
    constructor(flowId: u256, oldBps: u32, newBps: u32, oldMinFee: u256, newMinFee: u256) {
        const data = new BytesWriter(32 + 4 + 4 + 32 + 32);
        data.writeU256(flowId);
        data.writeU32(oldBps);
        data.writeU32(newBps);
        data.writeU256(oldMinFee);
        data.writeU256(newMinFee);
        super('FlowFeeChanged', data);
    }
}

/**
 * PR β.2.scaffold — emitted when the per-flow tip cap is updated.
 * tipCapBps is bounded to MAX_TIP_BPS (200 = 2%) at the contract layer.
 */
export class FlowTipCapUpdated extends NetEvent {
    constructor(flowId: u256, oldBps: u32, newBps: u32) {
        const data = new BytesWriter(32 + 4 + 4);
        data.writeU256(flowId);
        data.writeU32(oldBps);
        data.writeU32(newBps);
        super('FlowTipCapUpdated', data);
    }
}

/**
 * PR β.2.payout-opnet — emitted when a relayer tip is paid out as part of a
 * successful claim (mint or release). `relayer` is `Blockchain.tx.sender`,
 * NOT a stored relayer address — keeps the protocol neutral. `tip` is in
 * destination-side base units of the wrapped/canonical token being paid.
 */
export class RelayerTipPaid extends NetEvent {
    constructor(flowId: u256, relayer: Address, tip: u256) {
        const data = new BytesWriter(32 + ADDRESS_BYTE_LENGTH + 32);
        data.writeU256(flowId);
        data.writeAddress(relayer);
        data.writeU256(tip);
        super('RelayerTipPaid', data);
    }
}

/**
 * PR γ.2b — emitted when an EVM-side burn is attested via `confirmBurn`.
 * The deposit-id replay guard is keyed by `depositId`; `releasedAmount` is
 * in source-side base units. `attester` is `Blockchain.tx.sender` —
 * permissionless, anyone holding a valid M-of-N attestation may submit.
 */
export class BurnConfirmed extends NetEvent {
    constructor(flowId: u256, depositId: u256, releasedAmount: u256, attester: Address) {
        const data = new BytesWriter(32 + 32 + 32 + ADDRESS_BYTE_LENGTH);
        data.writeU256(flowId);
        data.writeU256(depositId);
        data.writeU256(releasedAmount);
        data.writeAddress(attester);
        super('BurnConfirmed', data);
    }
}

// ─── Trustless stranded-lock refund (mirror of EVM BridgeEscrow) ────────

/**
 * Emitted when a stranded OPNet-source lock is marked refundable via a valid
 * M-of-N attestation (`markLockRefundable`). The lock moves LOCKED →
 * REFUNDABLE; the recorded locker may then call `refundLock`. Mirrors the EVM
 * `BridgeEscrow.DepositMarkedRefundable`.
 */
export class LockMarkedRefundable extends NetEvent {
    constructor(lockNonce: u256, flowId: u256) {
        const data = new BytesWriter(32 + 32);
        data.writeU256(lockNonce);
        data.writeU256(flowId);
        super('LockMarkedRefundable', data);
    }
}

/**
 * Emitted when a refundable lock's full gross principal is returned to the
 * recorded locker (`refundLock`). Mirrors the EVM
 * `BridgeEscrow.LockRefunded`. `amount` is the gross `received` recorded at
 * lock time (the fee is reversed from accrual, not promoted, so the user gets
 * the entire locked amount back).
 */
export class LockRefunded extends NetEvent {
    constructor(lockNonce: u256, user: Address, token: Address, amount: u256) {
        const data = new BytesWriter(32 + ADDRESS_BYTE_LENGTH * 2 + 32);
        data.writeU256(lockNonce);
        data.writeAddress(user);
        data.writeAddress(token);
        data.writeU256(amount);
        super('LockRefunded', data);
    }
}

// ─── #55 — Trustless burn-side recovery (attested re-mint) ───────────────

/**
 * Emitted when a permanently-cancelled burn's principal is RE-MINTED to the
 * original burner via a valid M-of-N BurnRefundAuthorization (`refundBurn`).
 * The burn-initiated counterpart of `LockRefunded`. `burnId` is the per-burn
 * replay key sha256(burnTxHash‖burnNonce); `amount` is the signer-attested
 * burned amount minted back to `burner`.
 *
 * ⚠️ This event marks a MINT-AUTHORITY action gated by M-of-N attestation +
 * a per-burn replay guard. Indexers should reconcile it against the cancelled
 * EVM destination voucher.
 */
export class BurnRefunded extends NetEvent {
    constructor(burnId: u256, burner: Address, wrappedToken: Address, amount: u256) {
        const data = new BytesWriter(32 + ADDRESS_BYTE_LENGTH * 2 + 32);
        data.writeU256(burnId);
        data.writeAddress(burner);
        data.writeAddress(wrappedToken);
        data.writeU256(amount);
        super('BurnRefunded', data);
    }
}
