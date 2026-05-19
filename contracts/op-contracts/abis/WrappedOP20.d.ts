import { Address, AddressMap, ExtendedAddressMap, SchnorrSignature } from '@btc-vision/transaction';
import { CallResult, OPNetEvent, IOP_NETContract } from 'opnet';

// ------------------------------------------------------------------
// Event Definitions
// ------------------------------------------------------------------
export type BridgeDepositoryUpdatedEvent = {
    readonly oldAddr: Address;
    readonly newAddr: Address;
};
export type GovernorUpdatedEvent = {
    readonly oldAddr: Address;
    readonly newAddr: Address;
};
export type AuthorityAddressSetEvent = {
    readonly authority: Address;
};
export type MinterGrantedEvent = {
    readonly minter: Address;
};
export type MinterRevokedEvent = {
    readonly minter: Address;
};
export type PausedEvent = {};
export type UnpausedEvent = {};
export type SupportedDestChainSetEvent = {
    readonly destChainId: number;
    readonly enabled: boolean;
};
export type MintedEvent = {
    readonly to: Address;
    readonly amount: bigint;
    readonly to: Address;
    readonly amount: bigint;
};
export type BurnedForReleaseEvent = {
    readonly user: Address;
    readonly amount: bigint;
    readonly ethRecipient: Uint8Array;
    readonly destChainId: number;
    readonly burnNonce: bigint;
};

// ------------------------------------------------------------------
// Call Results
// ------------------------------------------------------------------

/**
 * @description Represents the result of the setBridgeDepository function call.
 */
export type SetBridgeDepository = CallResult<{}, OPNetEvent<BridgeDepositoryUpdatedEvent>[]>;

/**
 * @description Represents the result of the setGovernor function call.
 */
export type SetGovernor = CallResult<{}, OPNetEvent<GovernorUpdatedEvent>[]>;

/**
 * @description Represents the result of the setAuthorityAddress function call.
 */
export type SetAuthorityAddress = CallResult<{}, OPNetEvent<AuthorityAddressSetEvent>[]>;

/**
 * @description Represents the result of the grantMinter function call.
 */
export type GrantMinter = CallResult<{}, OPNetEvent<MinterGrantedEvent>[]>;

/**
 * @description Represents the result of the revokeMinter function call.
 */
export type RevokeMinter = CallResult<{}, OPNetEvent<MinterRevokedEvent>[]>;

/**
 * @description Represents the result of the isMinter function call.
 */
export type IsMinter = CallResult<
    {
        authorized: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the authorityAddress function call.
 */
export type AuthorityAddress = CallResult<
    {
        authority: Address;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the setPaused function call.
 */
export type SetPaused = CallResult<{}, OPNetEvent<PausedEvent | UnpausedEvent>[]>;

/**
 * @description Represents the result of the setSupportedDestChain function call.
 */
export type SetSupportedDestChain = CallResult<{}, OPNetEvent<SupportedDestChainSetEvent>[]>;

/**
 * @description Represents the result of the isSupportedDestChain function call.
 */
export type IsSupportedDestChain = CallResult<
    {
        supported: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the mintTo function call.
 */
export type MintTo = CallResult<{}, OPNetEvent<MintedEvent>[]>;

/**
 * @description Represents the result of the burnForRelease function call.
 */
export type BurnForRelease = CallResult<{}, OPNetEvent<BurnedForReleaseEvent>[]>;

/**
 * @description Represents the result of the bridgeDepository function call.
 */
export type BridgeDepository = CallResult<
    {
        depository: Address;
    },
    OPNetEvent<never>[]
>;

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
 * @description Represents the result of the burnNonce function call.
 */
export type BurnNonce = CallResult<
    {
        burnNonce: bigint;
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

/**
 * @description Represents the result of the paused function call.
 */
export type Paused = CallResult<
    {
        paused: boolean;
    },
    OPNetEvent<never>[]
>;

// ------------------------------------------------------------------
// IWrappedOP20
// ------------------------------------------------------------------
export interface IWrappedOP20 extends IOP_NETContract {
    setBridgeDepository(newBridge: Address): Promise<SetBridgeDepository>;
    setGovernor(newGovernor: Address): Promise<SetGovernor>;
    setAuthorityAddress(authority: Address): Promise<SetAuthorityAddress>;
    grantMinter(minter: Address): Promise<GrantMinter>;
    revokeMinter(minter: Address): Promise<RevokeMinter>;
    isMinter(): Promise<IsMinter>;
    authorityAddress(): Promise<AuthorityAddress>;
    setPaused(paused: boolean): Promise<SetPaused>;
    setSupportedDestChain(destChainId: number, enabled: boolean): Promise<SetSupportedDestChain>;
    isSupportedDestChain(): Promise<IsSupportedDestChain>;
    mintTo(to: Address, amount: bigint): Promise<MintTo>;
    burnForRelease(ethRecipient: Uint8Array, amount: bigint, destChainId: number): Promise<BurnForRelease>;
    bridgeDepository(): Promise<BridgeDepository>;
    governor(): Promise<Governor>;
    burnNonce(): Promise<BurnNonce>;
    storageVersion(): Promise<StorageVersion>;
    paused(): Promise<Paused>;
}
