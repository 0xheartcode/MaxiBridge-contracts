import { Address, AddressMap, ExtendedAddressMap, SchnorrSignature } from '@btc-vision/transaction';
import { CallResult, OPNetEvent, IOP_NETContract } from 'opnet';

// ------------------------------------------------------------------
// Event Definitions
// ------------------------------------------------------------------
export type WrappedTokenSetEvent = {
    readonly wrappedToken: Address;
    readonly enabled: boolean;
};
export type SignerRotatedEvent = {
    readonly oldEpoch: number;
    readonly newEpoch: number;
    readonly newSignerHash: bigint;
};
export type PausedEvent = {};
export type UnpausedEvent = {};
export type GovernorUpdatedEvent = {
    readonly oldGov: Address;
    readonly newGov: Address;
};
export type MintedFromVoucherEvent = {
    readonly recipient: Address;
    readonly wrappedToken: Address;
    readonly sourceChainId: bigint;
    readonly sourceTxHash: bigint;
    readonly sourceLogIndex: number;
    readonly grossAmount: bigint;
    readonly feeAmount: bigint;
    readonly netAmount: bigint;
    readonly voucherId: bigint;
    readonly signerEpoch: number;
};

// ------------------------------------------------------------------
// Call Results
// ------------------------------------------------------------------

/**
 * @description Represents the result of the addWrappedToken function call.
 */
export type AddWrappedToken = CallResult<{}, OPNetEvent<WrappedTokenSetEvent>[]>;

/**
 * @description Represents the result of the removeWrappedToken function call.
 */
export type RemoveWrappedToken = CallResult<{}, OPNetEvent<WrappedTokenSetEvent>[]>;

/**
 * @description Represents the result of the isWrappedToken function call.
 */
export type IsWrappedToken = CallResult<
    {
        enabled: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the rotateSigner function call.
 */
export type RotateSigner = CallResult<{}, OPNetEvent<SignerRotatedEvent>[]>;

/**
 * @description Represents the result of the setInitialSigner function call.
 */
export type SetInitialSigner = CallResult<{}, OPNetEvent<SignerRotatedEvent>[]>;

/**
 * @description Represents the result of the cancelVoucher function call.
 */
export type CancelVoucher = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the isVoucherCancelled function call.
 */
export type IsVoucherCancelled = CallResult<
    {
        cancelled: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the setAuthorityAddress function call.
 */
export type SetAuthorityAddress = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the addSignerToSet function call.
 */
export type AddSignerToSet = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the removeSignerFromSet function call.
 */
export type RemoveSignerFromSet = CallResult<{}, OPNetEvent<SignerRotatedEvent>[]>;

/**
 * @description Represents the result of the setRequiredSignatures function call.
 */
export type SetRequiredSignatures = CallResult<{}, OPNetEvent<SignerRotatedEvent>[]>;

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
 * @description Represents the result of the signerCount function call.
 */
export type SignerCount = CallResult<
    {
        count: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the requiredSignatures function call.
 */
export type RequiredSignatures = CallResult<
    {
        threshold: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the isSignerAuthorized function call.
 */
export type IsSignerAuthorized = CallResult<
    {
        authorized: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the setPaused function call.
 */
export type SetPaused = CallResult<{}, OPNetEvent<PausedEvent | UnpausedEvent>[]>;

/**
 * @description Represents the result of the setGovernor function call.
 */
export type SetGovernor = CallResult<{}, OPNetEvent<GovernorUpdatedEvent>[]>;

/**
 * @description Represents the result of the claimMintWithVoucher function call.
 */
export type ClaimMintWithVoucher = CallResult<{}, OPNetEvent<MintedFromVoucherEvent>[]>;

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
 * @description Represents the result of the paused function call.
 */
export type Paused = CallResult<
    {
        paused: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the signerEpoch function call.
 */
export type SignerEpoch = CallResult<
    {
        signerEpoch: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the signerHashAtEpoch function call.
 */
export type SignerHashAtEpoch = CallResult<
    {
        signerHash: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the isVoucherUsed function call.
 */
export type IsVoucherUsed = CallResult<
    {
        used: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the isSourceEventUsed function call.
 */
export type IsSourceEventUsed = CallResult<
    {
        used: boolean;
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
 * @description Represents the result of the networkId function call.
 */
export type NetworkId = CallResult<
    {
        networkId: bigint;
    },
    OPNetEvent<never>[]
>;

// ------------------------------------------------------------------
// IBridgeDepository
// ------------------------------------------------------------------
export interface IBridgeDepository extends IOP_NETContract {
    addWrappedToken(wrappedToken: Address): Promise<AddWrappedToken>;
    removeWrappedToken(wrappedToken: Address): Promise<RemoveWrappedToken>;
    isWrappedToken(): Promise<IsWrappedToken>;
    rotateSigner(signerPubKey: Uint8Array): Promise<RotateSigner>;
    setInitialSigner(signerPubKey: Uint8Array): Promise<SetInitialSigner>;
    cancelVoucher(voucherId: bigint): Promise<CancelVoucher>;
    isVoucherCancelled(): Promise<IsVoucherCancelled>;
    setAuthorityAddress(authority: Address): Promise<SetAuthorityAddress>;
    addSignerToSet(pubKeyHash: bigint): Promise<AddSignerToSet>;
    removeSignerFromSet(pubKeyHash: bigint): Promise<RemoveSignerFromSet>;
    setRequiredSignatures(threshold: bigint): Promise<SetRequiredSignatures>;
    authorityAddress(): Promise<AuthorityAddress>;
    signerCount(): Promise<SignerCount>;
    requiredSignatures(): Promise<RequiredSignatures>;
    isSignerAuthorized(): Promise<IsSignerAuthorized>;
    setPaused(paused: boolean): Promise<SetPaused>;
    setGovernor(newGovernor: Address): Promise<SetGovernor>;
    claimMintWithVoucher(voucher: Uint8Array, mldsaSig: Uint8Array): Promise<ClaimMintWithVoucher>;
    governor(): Promise<Governor>;
    paused(): Promise<Paused>;
    signerEpoch(): Promise<SignerEpoch>;
    signerHashAtEpoch(): Promise<SignerHashAtEpoch>;
    isVoucherUsed(): Promise<IsVoucherUsed>;
    isSourceEventUsed(): Promise<IsSourceEventUsed>;
    storageVersion(): Promise<StorageVersion>;
    networkId(): Promise<NetworkId>;
}
