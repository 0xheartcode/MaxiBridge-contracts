import { NetEvent } from '@btc-vision/btc-runtime/runtime/events/NetEvent';
import { BytesWriter } from '@btc-vision/btc-runtime/runtime/buffer/BytesWriter';
import { Address } from '@btc-vision/btc-runtime/runtime/types/Address';
import { u256 } from '@btc-vision/as-bignum/assembly';
import { ADDRESS_BYTE_LENGTH } from '@btc-vision/btc-runtime/runtime/utils';

export class BridgeDepositoryUpdated extends NetEvent {
    constructor(oldAddr: Address, newAddr: Address) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2);
        data.writeAddress(oldAddr);
        data.writeAddress(newAddr);
        super('BridgeDepositoryUpdated', data);
    }
}

export class GovernorUpdated extends NetEvent {
    constructor(oldAddr: Address, newAddr: Address) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2);
        data.writeAddress(oldAddr);
        data.writeAddress(newAddr);
        super('GovernorUpdated', data);
    }
}

/**
 * Emitted by burnForRelease. EVM side matches on (burnNonce, user, amount,
 * ethRecipient, destChainId) plus (opnetTxHash, opnetEventIndex) captured
 * by the indexer.
 *
 * `ethRecipient` is 32 bytes to accommodate future non-EVM chains
 * (Solana/Cosmos/Polkadot recipients are 32 bytes). For v1 Ethereum the
 * caller left-pads their 20-byte EVM address with 12 zero bytes. The server
 * extracts the low 20 bytes when building the EIP-712 `ReleaseIntent.to`.
 */
// ─── Pause (Fix #6 — burnForRelease pause gate) ─────────────────────────

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

export class BurnedForRelease extends NetEvent {
    constructor(
        user: Address,
        amount: u256,
        ethRecipient: Uint8Array,
        destChainId: u32,
        burnNonce: u256,
    ) {
        // 32 (user) + 32 (amount) + 32 (ethRecipient) + 4 (destChainId) + 32 (burnNonce) = 132
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH + 32 + 32 + 4 + 32);
        data.writeAddress(user);
        data.writeU256(amount);
        for (let i: i32 = 0; i < 32; i++) {
            data.writeU8(ethRecipient[i]);
        }
        data.writeU32(destChainId);
        data.writeU256(burnNonce);
        super('BurnedForRelease', data);
    }
}
