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
export type FlowAddedEvent = {
    readonly flowId: bigint;
    readonly mode: number;
    readonly evmChainId: bigint;
    readonly evmToken: bigint;
    readonly opnetToken: bigint;
};
export type FlowStatusChangedEvent = {
    readonly flowId: bigint;
    readonly oldStatus: number;
    readonly newStatus: number;
};
export type FlowCapChangedEvent = {
    readonly flowId: bigint;
    readonly oldCap: bigint;
    readonly newCap: bigint;
};
export type FlowDailyLimitChangedEvent = {
    readonly flowId: bigint;
    readonly oldLimit: bigint;
    readonly newLimit: bigint;
};
export type FlowMinAmountChangedEvent = {
    readonly flowId: bigint;
    readonly oldMin: bigint;
    readonly newMin: bigint;
};
export type FlowFeeChangedEvent = {
    readonly flowId: bigint;
    readonly oldBps: number;
    readonly newBps: number;
    readonly oldMinFee: bigint;
    readonly newMinFee: bigint;
};
export type FlowTipCapUpdatedEvent = {
    readonly flowId: bigint;
    readonly oldBps: number;
    readonly newBps: number;
};
export type LockedForBridgeEvent = {
    readonly canonicalToken: Address;
    readonly user: Address;
    readonly amount: bigint;
    readonly evmRecipient: bigint;
    readonly destChainId: number;
    readonly lockNonce: bigint;
    readonly mode: number;
    readonly flowId: bigint;
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
    readonly flowId: bigint;
};
export type ReleasedFromVoucherEvent = {
    readonly recipient: Address;
    readonly canonicalToken: Address;
    readonly sourceChainId: bigint;
    readonly sourceTxHash: bigint;
    readonly sourceLogIndex: number;
    readonly grossAmount: bigint;
    readonly feeAmount: bigint;
    readonly netAmount: bigint;
    readonly voucherId: bigint;
    readonly signerEpoch: number;
    readonly flowId: bigint;
};
export type RelayerTipPaidEvent = {
    readonly flowId: bigint;
    readonly relayer: Address;
    readonly tip: bigint;
};
export type InventoryProvisionedOpNetEvent = {
    readonly flowId: bigint;
    readonly token: Address;
    readonly by: Address;
    readonly amount: bigint;
};
export type InventoryDrainedOpNetEvent = {
    readonly flowId: bigint;
    readonly token: Address;
    readonly to: Address;
    readonly by: Address;
    readonly amount: bigint;
};
export type EmergencyWithdrawalEvent = {
    readonly token: Address;
    readonly treasury: Address;
    readonly amount: bigint;
};
export type FeesWithdrawnEvent = {
    readonly flowId: bigint;
    readonly token: Address;
    readonly to: Address;
    readonly by: Address;
    readonly amount: bigint;
};
export type LockMarkedRefundableEvent = {
    readonly lockNonce: bigint;
    readonly flowId: bigint;
};
export type LockRefundedEvent = {
    readonly lockNonce: bigint;
    readonly user: Address;
    readonly token: Address;
    readonly amount: bigint;
};
export type LockSettledEvent = {
    readonly lockNonce: bigint;
    readonly flowId: bigint;
    readonly fee: bigint;
};
export type BurnRefundedEvent = {
    readonly burnId: bigint;
    readonly burner: Address;
    readonly wrappedToken: Address;
    readonly amount: bigint;
};
export type SignerAddedEvent = {
    readonly signerHash: bigint;
    readonly newCount: bigint;
};
export type SignerRemovedEvent = {
    readonly signerHash: bigint;
    readonly newCount: bigint;
};
export type BurnConfirmedEvent = {
    readonly flowId: bigint;
    readonly depositId: bigint;
    readonly releasedAmount: bigint;
    readonly attester: Address;
};
export type PausedEvent = {};
export type UnpausedEvent = {};
export type GovernorUpdatedEvent = {
    readonly oldGov: Address;
    readonly newGov: Address;
};
export type PauserSetEvent = {
    readonly oldPauser: Address;
    readonly newPauser: Address;
};
export type TreasurySetEvent = {
    readonly oldTreasury: Address;
    readonly newTreasury: Address;
};
export type GuardianSetEvent = {
    readonly oldGuardian: Address;
    readonly newGuardian: Address;
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
 * @description Represents the result of the setUpgradeAuthority function call.
 */
export type SetUpgradeAuthority = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the proposeUpgrade function call.
 */
export type ProposeUpgrade = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the cancelProposedUpgrade function call.
 */
export type CancelProposedUpgrade = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the upgradeAuthority function call.
 */
export type UpgradeAuthority = CallResult<
    {
        upgradeAuthority: Address;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the pendingUpgradeAuthorized function call.
 */
export type PendingUpgradeAuthorized = CallResult<
    {
        pendingUpgradeAuthorized: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the computeFlowId function call.
 */
export type ComputeFlowId = CallResult<
    {
        flowId: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the addFlow function call.
 */
export type AddFlow = CallResult<
    {
        flowId: bigint;
    },
    OPNetEvent<FlowAddedEvent>[]
>;

/**
 * @description Represents the result of the pauseFlow function call.
 */
export type PauseFlow = CallResult<{}, OPNetEvent<FlowStatusChangedEvent>[]>;

/**
 * @description Represents the result of the resumeFlow function call.
 */
export type ResumeFlow = CallResult<{}, OPNetEvent<FlowStatusChangedEvent>[]>;

/**
 * @description Represents the result of the drainFlow function call.
 */
export type DrainFlow = CallResult<{}, OPNetEvent<FlowStatusChangedEvent>[]>;

/**
 * @description Represents the result of the retireFlow function call.
 */
export type RetireFlow = CallResult<{}, OPNetEvent<FlowStatusChangedEvent>[]>;

/**
 * @description Represents the result of the setFlowCap function call.
 */
export type SetFlowCap = CallResult<{}, OPNetEvent<FlowCapChangedEvent>[]>;

/**
 * @description Represents the result of the setFlowDailyLimit function call.
 */
export type SetFlowDailyLimit = CallResult<{}, OPNetEvent<FlowDailyLimitChangedEvent>[]>;

/**
 * @description Represents the result of the setFlowMinAmount function call.
 */
export type SetFlowMinAmount = CallResult<{}, OPNetEvent<FlowMinAmountChangedEvent>[]>;

/**
 * @description Represents the result of the setFlowFee function call.
 */
export type SetFlowFee = CallResult<{}, OPNetEvent<FlowFeeChangedEvent>[]>;

/**
 * @description Represents the result of the setFlowTipCap function call.
 */
export type SetFlowTipCap = CallResult<{}, OPNetEvent<FlowTipCapUpdatedEvent>[]>;

/**
 * @description Represents the result of the flowExists function call.
 */
export type FlowExists = CallResult<
    {
        exists: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the flowCount function call.
 */
export type FlowCount = CallResult<
    {
        count: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getFlow function call.
 */
export type GetFlow = CallResult<
    {
        flow: Uint8Array;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the lockForBridge function call.
 */
export type LockForBridge = CallResult<{}, OPNetEvent<LockedForBridgeEvent>[]>;

/**
 * @description Represents the result of the claimWithVoucher function call.
 */
export type ClaimWithVoucher = CallResult<
    {},
    OPNetEvent<MintedFromVoucherEvent | ReleasedFromVoucherEvent | RelayerTipPaidEvent>[]
>;

/**
 * @description Represents the result of the provisionInventoryOpNet function call.
 */
export type ProvisionInventoryOpNet = CallResult<{}, OPNetEvent<InventoryProvisionedOpNetEvent>[]>;

/**
 * @description Represents the result of the drainInventoryOpNet function call.
 */
export type DrainInventoryOpNet = CallResult<{}, OPNetEvent<InventoryDrainedOpNetEvent>[]>;

/**
 * @description Represents the result of the emergencyWithdraw function call.
 */
export type EmergencyWithdraw = CallResult<{}, OPNetEvent<EmergencyWithdrawalEvent>[]>;

/**
 * @description Represents the result of the withdrawFees function call.
 */
export type WithdrawFees = CallResult<{}, OPNetEvent<FeesWithdrawnEvent>[]>;

/**
 * @description Represents the result of the accruedFees function call.
 */
export type AccruedFees = CallResult<
    {
        accrued: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the markLockRefundable function call.
 */
export type MarkLockRefundable = CallResult<{}, OPNetEvent<LockMarkedRefundableEvent>[]>;

/**
 * @description Represents the result of the refundLock function call.
 */
export type RefundLock = CallResult<{}, OPNetEvent<LockRefundedEvent>[]>;

/**
 * @description Represents the result of the settleLock function call.
 */
export type SettleLock = CallResult<{}, OPNetEvent<LockSettledEvent>[]>;

/**
 * @description Represents the result of the lockRecord function call.
 */
export type LockRecord = CallResult<
    {
        record: Uint8Array;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the isLockRefundable function call.
 */
export type IsLockRefundable = CallResult<
    {
        refundable: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the refundBurn function call.
 */
export type RefundBurn = CallResult<{}, OPNetEvent<BurnRefundedEvent>[]>;

/**
 * @description Represents the result of the isBurnRefunded function call.
 */
export type IsBurnRefunded = CallResult<
    {
        refunded: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the addSignerToSet function call.
 */
export type AddSignerToSet = CallResult<{}, OPNetEvent<SignerAddedEvent>[]>;

/**
 * @description Represents the result of the removeSignerFromSet function call.
 */
export type RemoveSignerFromSet = CallResult<{}, OPNetEvent<SignerRemovedEvent | SignerRotatedEvent>[]>;

/**
 * @description Represents the result of the setRequiredSignatures function call.
 */
export type SetRequiredSignatures = CallResult<{}, OPNetEvent<SignerRotatedEvent>[]>;

/**
 * @description Represents the result of the migrateSignerSet function call.
 */
export type MigrateSignerSet = CallResult<{}, OPNetEvent<SignerRotatedEvent>[]>;

/**
 * @description Represents the result of the confirmBurn function call.
 */
export type ConfirmBurn = CallResult<{}, OPNetEvent<BurnConfirmedEvent>[]>;

/**
 * @description Represents the result of the isBurnConfirmed function call.
 */
export type IsBurnConfirmed = CallResult<
    {
        confirmed: boolean;
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
 * @description Represents the result of the transferGovernor function call.
 */
export type TransferGovernor = CallResult<{}, OPNetEvent<GovernorUpdatedEvent>[]>;

/**
 * @description Represents the result of the setPauser function call.
 */
export type SetPauser = CallResult<{}, OPNetEvent<PauserSetEvent>[]>;

/**
 * @description Represents the result of the setTreasury function call.
 */
export type SetTreasury = CallResult<{}, OPNetEvent<TreasurySetEvent>[]>;

/**
 * @description Represents the result of the setGuardian function call.
 */
export type SetGuardian = CallResult<{}, OPNetEvent<GuardianSetEvent>[]>;

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
 * @description Represents the result of the pauser function call.
 */
export type Pauser = CallResult<
    {
        pauser: Address;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the treasury function call.
 */
export type Treasury = CallResult<
    {
        treasury: Address;
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
    setUpgradeAuthority(newUpgradeAuthority: Address): Promise<SetUpgradeAuthority>;
    proposeUpgrade(): Promise<ProposeUpgrade>;
    cancelProposedUpgrade(): Promise<CancelProposedUpgrade>;
    upgradeAuthority(): Promise<UpgradeAuthority>;
    pendingUpgradeAuthorized(): Promise<PendingUpgradeAuthorized>;
    computeFlowId(
        mode: bigint,
        evmChainId: bigint,
        evmBridge: bigint,
        evmToken: bigint,
        opnetBridge: bigint,
        opnetToken: bigint,
    ): Promise<ComputeFlowId>;
    addFlow(
        mode: bigint,
        evmChainId: bigint,
        evmBridge: bigint,
        evmToken: bigint,
        evmDecimals: bigint,
        opnetBridge: bigint,
        opnetToken: bigint,
        opnetDecimals: bigint,
        feeBps: bigint,
        minFee: bigint,
        minAmount: bigint,
        cap: bigint,
        dailyLimit: bigint,
        tipCapBps: bigint,
    ): Promise<AddFlow>;
    pauseFlow(flowId: bigint): Promise<PauseFlow>;
    resumeFlow(flowId: bigint): Promise<ResumeFlow>;
    drainFlow(flowId: bigint): Promise<DrainFlow>;
    retireFlow(flowId: bigint): Promise<RetireFlow>;
    setFlowCap(flowId: bigint, newCap: bigint): Promise<SetFlowCap>;
    setFlowDailyLimit(flowId: bigint, newLimit: bigint): Promise<SetFlowDailyLimit>;
    setFlowMinAmount(flowId: bigint, newMin: bigint): Promise<SetFlowMinAmount>;
    setFlowFee(flowId: bigint, newBps: bigint, newMinFee: bigint): Promise<SetFlowFee>;
    setFlowTipCap(flowId: bigint, newBps: bigint): Promise<SetFlowTipCap>;
    flowExists(): Promise<FlowExists>;
    flowCount(): Promise<FlowCount>;
    getFlow(): Promise<GetFlow>;
    lockForBridge(
        flowId: bigint,
        canonicalToken: Address,
        amount: bigint,
        evmRecipient: Uint8Array,
        destChainId: number,
    ): Promise<LockForBridge>;
    claimWithVoucher(voucher: Uint8Array, mldsaSig: Uint8Array): Promise<ClaimWithVoucher>;
    provisionInventoryOpNet(flowId: bigint, token: Address, amount: bigint): Promise<ProvisionInventoryOpNet>;
    drainInventoryOpNet(flowId: bigint, token: Address, amount: bigint): Promise<DrainInventoryOpNet>;
    emergencyWithdraw(token: Address, amount: bigint): Promise<EmergencyWithdraw>;
    withdrawFees(flowId: bigint, token: Address, amount: bigint): Promise<WithdrawFees>;
    accruedFees(flowId: bigint): Promise<AccruedFees>;
    markLockRefundable(lockNonce: bigint, sig: Uint8Array): Promise<MarkLockRefundable>;
    refundLock(lockNonce: bigint): Promise<RefundLock>;
    settleLock(lockNonce: bigint): Promise<SettleLock>;
    lockRecord(lockNonce: bigint): Promise<LockRecord>;
    isLockRefundable(): Promise<IsLockRefundable>;
    refundBurn(attestation: Uint8Array, mldsaSig: Uint8Array): Promise<RefundBurn>;
    isBurnRefunded(): Promise<IsBurnRefunded>;
    addSignerToSet(pubKeyHash: bigint): Promise<AddSignerToSet>;
    removeSignerFromSet(pubKeyHash: bigint): Promise<RemoveSignerFromSet>;
    setRequiredSignatures(threshold: bigint): Promise<SetRequiredSignatures>;
    migrateSignerSet(payload: Uint8Array): Promise<MigrateSignerSet>;
    confirmBurn(depositId: bigint, attestation: Uint8Array, mldsaSig: Uint8Array): Promise<ConfirmBurn>;
    isBurnConfirmed(): Promise<IsBurnConfirmed>;
    authorityAddress(): Promise<AuthorityAddress>;
    signerCount(): Promise<SignerCount>;
    requiredSignatures(): Promise<RequiredSignatures>;
    isSignerAuthorized(): Promise<IsSignerAuthorized>;
    setPaused(paused: boolean): Promise<SetPaused>;
    setGovernor(newGovernor: Address): Promise<SetGovernor>;
    transferGovernor(newGovernor: Address): Promise<TransferGovernor>;
    setPauser(newPauser: Address): Promise<SetPauser>;
    setTreasury(newTreasury: Address): Promise<SetTreasury>;
    setGuardian(newGuardian: Address): Promise<SetGuardian>;
    governor(): Promise<Governor>;
    paused(): Promise<Paused>;
    pauser(): Promise<Pauser>;
    treasury(): Promise<Treasury>;
    guardian(): Promise<Guardian>;
    signerEpoch(): Promise<SignerEpoch>;
    signerHashAtEpoch(): Promise<SignerHashAtEpoch>;
    isVoucherUsed(): Promise<IsVoucherUsed>;
    isSourceEventUsed(): Promise<IsSourceEventUsed>;
    storageVersion(): Promise<StorageVersion>;
    networkId(): Promise<NetworkId>;
}
