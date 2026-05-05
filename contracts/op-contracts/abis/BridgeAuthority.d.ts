import { Address, AddressMap, ExtendedAddressMap, SchnorrSignature } from '@btc-vision/transaction';
import { CallResult, OPNetEvent, IOP_NETContract } from 'opnet';

// ------------------------------------------------------------------
// Event Definitions
// ------------------------------------------------------------------
export type AuthorityContractsSetEvent = {
    readonly depository: Address;
    readonly wusdc: Address;
    readonly wusdt: Address;
};
export type AuthorityGovernorUpdatedEvent = {
    readonly oldGov: Address;
    readonly newGov: Address;
};
export type AuthorityGuardianUpdatedEvent = {
    readonly oldGuardian: Address;
    readonly newGuardian: Address;
};
export type AuthorityPausedAllEvent = {};
export type AuthorityUnpausedAllEvent = {};
export type AuthoritySignerAddedEvent = {
    readonly pubKeyHash: bigint;
};
export type AuthoritySignerRemovedEvent = {
    readonly pubKeyHash: bigint;
};
export type AuthorityThresholdSetEvent = {
    readonly threshold: bigint;
};

// ------------------------------------------------------------------
// Call Results
// ------------------------------------------------------------------

/**
 * @description Represents the result of the setManagedContracts function call.
 */
export type SetManagedContracts = CallResult<{}, OPNetEvent<AuthorityContractsSetEvent>[]>;

/**
 * @description Represents the result of the pushGovernor function call.
 */
export type PushGovernor = CallResult<{}, OPNetEvent<AuthorityGovernorUpdatedEvent>[]>;

/**
 * @description Represents the result of the pushGuardian function call.
 */
export type PushGuardian = CallResult<{}, OPNetEvent<AuthorityGuardianUpdatedEvent>[]>;

/**
 * @description Represents the result of the pauseAll function call.
 */
export type PauseAll = CallResult<{}, OPNetEvent<AuthorityPausedAllEvent>[]>;

/**
 * @description Represents the result of the unpauseAll function call.
 */
export type UnpauseAll = CallResult<{}, OPNetEvent<AuthorityUnpausedAllEvent>[]>;

/**
 * @description Represents the result of the addBridgeSigner function call.
 */
export type AddBridgeSigner = CallResult<{}, OPNetEvent<AuthoritySignerAddedEvent>[]>;

/**
 * @description Represents the result of the removeBridgeSigner function call.
 */
export type RemoveBridgeSigner = CallResult<{}, OPNetEvent<AuthoritySignerRemovedEvent>[]>;

/**
 * @description Represents the result of the setBridgeThreshold function call.
 */
export type SetBridgeThreshold = CallResult<{}, OPNetEvent<AuthorityThresholdSetEvent>[]>;

/**
 * @description Represents the result of the migrateBridgeSignerSet function call.
 */
export type MigrateBridgeSignerSet = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the governor function call.
 */
export type Governor = CallResult<
    {
        governor: Address;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the guardian function call.
 */
export type Guardian = CallResult<
    {
        guardian: Address;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the depository function call.
 */
export type Depository = CallResult<
    {
        depository: Address;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the wusdc function call.
 */
export type Wusdc = CallResult<
    {
        wusdc: Address;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the wusdt function call.
 */
export type Wusdt = CallResult<
    {
        wusdt: Address;
    },
    OPNetEvent<never>[]
>;

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
// IBridgeAuthority
// ------------------------------------------------------------------
export interface IBridgeAuthority extends IOP_NETContract {
    setManagedContracts(depository: Address, wusdc: Address, wusdt: Address): Promise<SetManagedContracts>;
    pushGovernor(newGovernor: Address): Promise<PushGovernor>;
    pushGuardian(newGuardian: Address): Promise<PushGuardian>;
    pauseAll(): Promise<PauseAll>;
    unpauseAll(): Promise<UnpauseAll>;
    addBridgeSigner(pubKeyHash: bigint): Promise<AddBridgeSigner>;
    removeBridgeSigner(pubKeyHash: bigint): Promise<RemoveBridgeSigner>;
    setBridgeThreshold(threshold: bigint): Promise<SetBridgeThreshold>;
    migrateBridgeSignerSet(addHash: bigint, newThreshold: bigint): Promise<MigrateBridgeSignerSet>;
    governor(): Promise<Governor>;
    guardian(): Promise<Guardian>;
    depository(): Promise<Depository>;
    wusdc(): Promise<Wusdc>;
    wusdt(): Promise<Wusdt>;
    storageVersion(): Promise<StorageVersion>;
}
