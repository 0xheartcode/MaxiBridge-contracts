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
