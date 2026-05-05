import { NetEvent } from '@btc-vision/btc-runtime/runtime/events/NetEvent';
import { BytesWriter } from '@btc-vision/btc-runtime/runtime/buffer/BytesWriter';
import { Address } from '@btc-vision/btc-runtime/runtime/types/Address';
import { u256 } from '@btc-vision/as-bignum/assembly';
import { ADDRESS_BYTE_LENGTH } from '@btc-vision/btc-runtime/runtime/utils';

export class AuthorityGovernorUpdated extends NetEvent {
    constructor(oldGov: Address, newGov: Address) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2);
        data.writeAddress(oldGov);
        data.writeAddress(newGov);
        super('AuthorityGovernorUpdated', data);
    }
}

export class AuthorityGuardianUpdated extends NetEvent {
    constructor(oldGuardian: Address, newGuardian: Address) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 2);
        data.writeAddress(oldGuardian);
        data.writeAddress(newGuardian);
        super('AuthorityGuardianUpdated', data);
    }
}

export class AuthorityContractsSet extends NetEvent {
    constructor(depository: Address, wusdc: Address, wusdt: Address) {
        const data = new BytesWriter(ADDRESS_BYTE_LENGTH * 3);
        data.writeAddress(depository);
        data.writeAddress(wusdc);
        data.writeAddress(wusdt);
        super('AuthorityContractsSet', data);
    }
}

export class AuthorityPausedAll extends NetEvent {
    constructor() {
        super('AuthorityPausedAll', new BytesWriter(0));
    }
}

export class AuthorityUnpausedAll extends NetEvent {
    constructor() {
        super('AuthorityUnpausedAll', new BytesWriter(0));
    }
}

export class AuthoritySignerAdded extends NetEvent {
    constructor(pubKeyHash: u256) {
        const data = new BytesWriter(32);
        data.writeU256(pubKeyHash);
        super('AuthoritySignerAdded', data);
    }
}

export class AuthoritySignerRemoved extends NetEvent {
    constructor(pubKeyHash: u256) {
        const data = new BytesWriter(32);
        data.writeU256(pubKeyHash);
        super('AuthoritySignerRemoved', data);
    }
}

export class AuthorityThresholdSet extends NetEvent {
    constructor(threshold: u256) {
        const data = new BytesWriter(32);
        data.writeU256(threshold);
        super('AuthorityThresholdSet', data);
    }
}
