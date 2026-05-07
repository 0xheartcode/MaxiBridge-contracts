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
    ) {
        // 2 addresses + 6 u256 + 2 u32 = 64 + 192 + 8 = 264
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2 + 32 * 6 + 4 * 2);
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
        super('MintedFromVoucher', data);
    }
}

// ─── Mode dispatch (Phase 1.5 — 4 modes) ───────────────────────────────

export class TokenModeSet extends NetEvent {
    constructor(token: Address, mode: u32, evmCounterpart: u256) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH + 4 + 32);
        data.writeAddress(token);
        data.writeU32(mode);
        data.writeU256(evmCounterpart);
        super('TokenModeSet', data);
    }
}

// ─── Mode-2/4 lock + release ─────────────────────────────────────────

/**
 * Emitted on lockForBridge — user locks canonical OP20 (modes 2/4) on
 * OPNet to bridge to EVM. Indexer picks this up and signs an EIP-712
 * MintIntent (mode 2) or ReleaseIntent (mode 4) for the EVM side.
 */
export class LockedForBridge extends NetEvent {
    constructor(
        canonicalToken: Address,
        user: Address,
        amount: u256,
        evmRecipient: u256, // bytes32 left-padded EVM addr
        destChainId: u32,
        lockNonce: u256,
        mode: u32,
    ) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2 + 32 + 32 + 4 + 32 + 4);
        data.writeAddress(canonicalToken);
        data.writeAddress(user);
        data.writeU256(amount);
        data.writeU256(evmRecipient);
        data.writeU32(destChainId);
        data.writeU256(lockNonce);
        data.writeU32(mode);
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
    ) {
        // Same shape as MintedFromVoucher — 264 bytes total.
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2 + 32 * 6 + 4 * 2);
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
        super('ReleasedFromVoucher', data);
    }
}

export class InventoryProvisionedOpNet extends NetEvent {
    constructor(token: Address, by: Address, amount: u256) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2 + 32);
        data.writeAddress(token);
        data.writeAddress(by);
        data.writeU256(amount);
        super('InventoryProvisionedOpNet', data);
    }
}

export class InventoryDrainedOpNet extends NetEvent {
    constructor(token: Address, to: Address, by: Address, amount: u256) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 3 + 32);
        data.writeAddress(token);
        data.writeAddress(to);
        data.writeAddress(by);
        data.writeU256(amount);
        super('InventoryDrainedOpNet', data);
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
