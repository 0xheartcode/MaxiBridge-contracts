import { Address, AddressMap, ExtendedAddressMap, SchnorrSignature } from '@btc-vision/transaction';
import { CallResult, OPNetEvent, IOP_NETContract } from 'opnet';

// ------------------------------------------------------------------
// Event Definitions
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// Call Results
// ------------------------------------------------------------------

/**
 * @description Represents the result of the mint function call.
 */
export type Mint = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the drip function call.
 */
export type Drip = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the storageVersion function call.
 */
export type StorageVersion = CallResult<
    {
        storageVersion: bigint;
    },
    OPNetEvent<never>[]
>;

// ------------------------------------------------------------------
// IMockOP20
// ------------------------------------------------------------------
export interface IMockOP20 extends IOP_NETContract {
    mint(to: Address, amount: bigint): Promise<Mint>;
    drip(): Promise<Drip>;
    storageVersion(): Promise<StorageVersion>;
}
