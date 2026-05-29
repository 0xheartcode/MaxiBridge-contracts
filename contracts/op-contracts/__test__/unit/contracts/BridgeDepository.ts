import { ABIDataTypes, Address, BinaryReader, BinaryWriter } from '@btc-vision/transaction';
import { BytecodeManager, ContractRuntime } from '@btc-vision/unit-test-framework';
import type { ContractDetails } from '@btc-vision/unit-test-framework';
import { encodeNumericSelector, encodeSelectorWithParams } from './utils.js';

export class BridgeDepository extends ContractRuntime {
    private readonly addWrappedTokenSelector: number = encodeSelectorWithParams(
        'addWrappedToken',
        ABIDataTypes.ADDRESS,
    );
    private readonly removeWrappedTokenSelector: number = encodeSelectorWithParams(
        'removeWrappedToken',
        ABIDataTypes.ADDRESS,
    );
    private readonly isWrappedTokenSelector: number = encodeNumericSelector('isWrappedToken()');

    private readonly setInitialSignerSelector: number = encodeSelectorWithParams(
        'setInitialSigner',
        ABIDataTypes.BYTES,
    );
    private readonly rotateSignerSelector: number = encodeSelectorWithParams(
        'rotateSigner',
        ABIDataTypes.BYTES,
    );
    private readonly setPausedSelector: number = encodeSelectorWithParams(
        'setPaused',
        ABIDataTypes.BOOL,
    );
    private readonly setGovernorSelector: number = encodeSelectorWithParams(
        'setGovernor',
        ABIDataTypes.ADDRESS,
    );
    private readonly transferGovernorSelector: number = encodeSelectorWithParams(
        'transferGovernor',
        ABIDataTypes.ADDRESS,
    );
    private readonly setPauserSelector: number = encodeSelectorWithParams(
        'setPauser',
        ABIDataTypes.ADDRESS,
    );
    private readonly pauserSelector: number = encodeNumericSelector('pauser()');

    private readonly claimMintWithVoucherSelector: number = encodeSelectorWithParams(
        'claimMintWithVoucher',
        ABIDataTypes.BYTES,
        ABIDataTypes.BYTES,
    );

    private readonly governorSelector: number = encodeNumericSelector('governor()');
    private readonly pausedSelector: number = encodeNumericSelector('paused()');
    private readonly signerEpochSelector: number = encodeNumericSelector('signerEpoch()');
    private readonly signerHashAtEpochSelector: number = encodeNumericSelector('signerHashAtEpoch()');
    private readonly isVoucherUsedSelector: number = encodeNumericSelector('isVoucherUsed()');
    private readonly isSourceEventUsedSelector: number = encodeNumericSelector('isSourceEventUsed()');
    private readonly cancelVoucherSelector: number = encodeSelectorWithParams(
        'cancelVoucher',
        ABIDataTypes.UINT256,
    );
    private readonly isVoucherCancelledSelector: number = encodeNumericSelector(
        'isVoucherCancelled()',
    );
    private readonly setAuthorityAddressSelector: number = encodeSelectorWithParams(
        'setAuthorityAddress',
        ABIDataTypes.ADDRESS,
    );
    private readonly addSignerToSetSelector: number = encodeSelectorWithParams(
        'addSignerToSet',
        ABIDataTypes.UINT256,
    );
    private readonly removeSignerFromSetSelector: number = encodeSelectorWithParams(
        'removeSignerFromSet',
        ABIDataTypes.UINT256,
    );
    private readonly setRequiredSignaturesSelector: number = encodeSelectorWithParams(
        'setRequiredSignatures',
        ABIDataTypes.UINT256,
    );
    private readonly authorityAddressSelector: number = encodeNumericSelector('authorityAddress()');
    private readonly signerCountSelector: number = encodeNumericSelector('signerCount()');
    private readonly requiredSignaturesSelector: number = encodeNumericSelector('requiredSignatures()');
    private readonly isSignerAuthorizedSelector: number = encodeNumericSelector('isSignerAuthorized()');
    private readonly storageVersionSelector: number = encodeNumericSelector('storageVersion()');
    private readonly networkIdSelector: number = encodeNumericSelector('networkId()');

    // Bug #16b — governance-gated upgrade authority selectors
    private readonly setUpgradeAuthoritySelector: number = encodeSelectorWithParams(
        'setUpgradeAuthority',
        ABIDataTypes.ADDRESS,
    );
    private readonly proposeUpgradeSelector: number = encodeNumericSelector('proposeUpgrade()');
    private readonly cancelProposedUpgradeSelector: number = encodeNumericSelector(
        'cancelProposedUpgrade()',
    );
    private readonly upgradeAuthoritySelector: number = encodeNumericSelector(
        'upgradeAuthority()',
    );
    private readonly pendingUpgradeAuthorizedSelector: number = encodeNumericSelector(
        'pendingUpgradeAuthorized()',
    );

    constructor(details: ContractDetails) {
        super(details);
    }

    private async getResponse(calldata: Uint8Array): Promise<BinaryReader> {
        const result = await this.execute({ calldata });
        if (result.error) throw result.error;
        return new BinaryReader(result.response);
    }

    public async addWrappedToken(addr: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.addWrappedTokenSelector);
        w.writeAddress(addr);
        await this.getResponse(w.getBuffer());
    }

    public async removeWrappedToken(addr: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.removeWrappedTokenSelector);
        w.writeAddress(addr);
        await this.getResponse(w.getBuffer());
    }

    public async isWrappedToken(addr: Address): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isWrappedTokenSelector);
        w.writeAddress(addr);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async setInitialSigner(signerPubKey: Uint8Array): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setInitialSignerSelector);
        w.writeBytesWithLength(signerPubKey);
        await this.getResponse(w.getBuffer());
    }

    public async rotateSigner(newSignerPubKey: Uint8Array): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.rotateSignerSelector);
        w.writeBytesWithLength(newSignerPubKey);
        await this.getResponse(w.getBuffer());
    }

    public async setPaused(paused: boolean): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setPausedSelector);
        w.writeBoolean(paused);
        await this.getResponse(w.getBuffer());
    }

    public async setGovernor(addr: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setGovernorSelector);
        w.writeAddress(addr);
        await this.getResponse(w.getBuffer());
    }

    public async transferGovernor(addr: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.transferGovernorSelector);
        w.writeAddress(addr);
        await this.getResponse(w.getBuffer());
    }

    public async setPauser(addr: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setPauserSelector);
        w.writeAddress(addr);
        await this.getResponse(w.getBuffer());
    }

    public async pauser(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.pauserSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async claimMintWithVoucher(voucher: Uint8Array, mldsaSig: Uint8Array): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.claimMintWithVoucherSelector);
        w.writeBytesWithLength(voucher);
        w.writeBytesWithLength(mldsaSig);
        await this.getResponse(w.getBuffer());
    }

    public async governor(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.governorSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async paused(): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.pausedSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async signerEpoch(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.signerEpochSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async signerHashAtEpoch(epoch: bigint): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.signerHashAtEpochSelector);
        w.writeU256(epoch);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async isVoucherUsed(voucherId: bigint): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isVoucherUsedSelector);
        w.writeU256(voucherId);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async isSourceEventUsed(
        sourceChainId: bigint,
        sourceBridgeAddr: Address,
        sourceTokenAddr: Address,
        sourceTxHash: bigint,
        sourceLogIndex: number,
    ): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isSourceEventUsedSelector);
        w.writeU256(sourceChainId);
        w.writeAddress(sourceBridgeAddr);
        w.writeAddress(sourceTokenAddr);
        w.writeU256(sourceTxHash);
        w.writeU32(sourceLogIndex);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async setAuthorityAddress(addr: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setAuthorityAddressSelector);
        w.writeAddress(addr);
        await this.getResponse(w.getBuffer());
    }

    // ─── Bug #16b — governance-gated upgrade authority ────────────────────

    public async setUpgradeAuthority(addr: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setUpgradeAuthoritySelector);
        w.writeAddress(addr);
        await this.getResponse(w.getBuffer());
    }

    public async proposeUpgrade(): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.proposeUpgradeSelector);
        await this.getResponse(w.getBuffer());
    }

    public async cancelProposedUpgrade(): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.cancelProposedUpgradeSelector);
        await this.getResponse(w.getBuffer());
    }

    public async upgradeAuthority(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.upgradeAuthoritySelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async pendingUpgradeAuthorized(): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.pendingUpgradeAuthorizedSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async addSignerToSet(hash: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.addSignerToSetSelector);
        w.writeU256(hash);
        await this.getResponse(w.getBuffer());
    }

    public async removeSignerFromSet(hash: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.removeSignerFromSetSelector);
        w.writeU256(hash);
        await this.getResponse(w.getBuffer());
    }

    public async setRequiredSignatures(threshold: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setRequiredSignaturesSelector);
        w.writeU256(threshold);
        await this.getResponse(w.getBuffer());
    }

    public async authorityAddress(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.authorityAddressSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async signerCount(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.signerCountSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async requiredSignatures(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.requiredSignaturesSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async isSignerAuthorized(hash: bigint): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isSignerAuthorizedSelector);
        w.writeU256(hash);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async cancelVoucher(voucherId: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.cancelVoucherSelector);
        w.writeU256(voucherId);
        await this.getResponse(w.getBuffer());
    }

    public async isVoucherCancelled(voucherId: bigint): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isVoucherCancelledSelector);
        w.writeU256(voucherId);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async storageVersion(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.storageVersionSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async networkId(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.networkIdSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    // ─── PR α — Flow Registry wrappers ────────────────────────────────

    private readonly computeFlowIdSelector: number = encodeSelectorWithParams(
        'computeFlowId',
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
    );
    private readonly addFlowSelector: number = encodeSelectorWithParams(
        'addFlow',
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
    );
    private readonly pauseFlowSelector: number = encodeSelectorWithParams(
        'pauseFlow',
        ABIDataTypes.UINT256,
    );
    private readonly resumeFlowSelector: number = encodeSelectorWithParams(
        'resumeFlow',
        ABIDataTypes.UINT256,
    );
    private readonly drainFlowSelector: number = encodeSelectorWithParams(
        'drainFlow',
        ABIDataTypes.UINT256,
    );
    private readonly retireFlowSelector: number = encodeSelectorWithParams(
        'retireFlow',
        ABIDataTypes.UINT256,
    );
    private readonly setFlowCapSelector: number = encodeSelectorWithParams(
        'setFlowCap',
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
    );
    private readonly setFlowDailyLimitSelector: number = encodeSelectorWithParams(
        'setFlowDailyLimit',
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
    );
    private readonly setFlowMinAmountSelector: number = encodeSelectorWithParams(
        'setFlowMinAmount',
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
    );
    private readonly setFlowFeeSelector: number = encodeSelectorWithParams(
        'setFlowFee',
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
    );
    private readonly setFlowTipCapSelector: number = encodeSelectorWithParams(
        'setFlowTipCap',
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
    );
    private readonly flowExistsSelector: number = encodeNumericSelector('flowExists()');
    private readonly flowCountSelector: number = encodeNumericSelector('flowCount()');
    private readonly getFlowSelector: number = encodeNumericSelector('getFlow()');

    public async computeFlowId(
        mode: bigint,
        chainId: bigint,
        evmBridge: bigint,
        evmToken: bigint,
        opnetBridge: bigint,
        opnetToken: bigint,
    ): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.computeFlowIdSelector);
        w.writeU256(mode);
        w.writeU256(chainId);
        w.writeU256(evmBridge);
        w.writeU256(evmToken);
        w.writeU256(opnetBridge);
        w.writeU256(opnetToken);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async addFlow(p: {
        mode: bigint;
        chainId: bigint;
        evmBridge: bigint;
        evmToken: bigint;
        evmDecimals: bigint;
        opnetBridge: bigint;
        opnetToken: bigint;
        opnetDecimals: bigint;
        feeBps: bigint;
        minFee: bigint;
        minAmount: bigint;
        cap: bigint;
        dailyLimit: bigint;
        tipCapBps?: bigint;
    }): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.addFlowSelector);
        w.writeU256(p.mode);
        w.writeU256(p.chainId);
        w.writeU256(p.evmBridge);
        w.writeU256(p.evmToken);
        w.writeU256(p.evmDecimals);
        w.writeU256(p.opnetBridge);
        w.writeU256(p.opnetToken);
        w.writeU256(p.opnetDecimals);
        w.writeU256(p.feeBps);
        w.writeU256(p.minFee);
        w.writeU256(p.minAmount);
        w.writeU256(p.cap);
        w.writeU256(p.dailyLimit);
        w.writeU256(p.tipCapBps ?? 0n);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async pauseFlow(flowId: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.pauseFlowSelector);
        w.writeU256(flowId);
        await this.getResponse(w.getBuffer());
    }

    public async resumeFlow(flowId: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.resumeFlowSelector);
        w.writeU256(flowId);
        await this.getResponse(w.getBuffer());
    }

    public async drainFlow(flowId: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.drainFlowSelector);
        w.writeU256(flowId);
        await this.getResponse(w.getBuffer());
    }

    public async retireFlow(flowId: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.retireFlowSelector);
        w.writeU256(flowId);
        await this.getResponse(w.getBuffer());
    }

    public async setFlowCap(flowId: bigint, newCap: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setFlowCapSelector);
        w.writeU256(flowId);
        w.writeU256(newCap);
        await this.getResponse(w.getBuffer());
    }

    public async setFlowDailyLimit(flowId: bigint, newLimit: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setFlowDailyLimitSelector);
        w.writeU256(flowId);
        w.writeU256(newLimit);
        await this.getResponse(w.getBuffer());
    }

    public async setFlowMinAmount(flowId: bigint, newMin: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setFlowMinAmountSelector);
        w.writeU256(flowId);
        w.writeU256(newMin);
        await this.getResponse(w.getBuffer());
    }

    public async setFlowFee(flowId: bigint, newBps: bigint, newMinFee: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setFlowFeeSelector);
        w.writeU256(flowId);
        w.writeU256(newBps);
        w.writeU256(newMinFee);
        await this.getResponse(w.getBuffer());
    }

    public async setFlowTipCap(flowId: bigint, newBps: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setFlowTipCapSelector);
        w.writeU256(flowId);
        w.writeU256(newBps);
        await this.getResponse(w.getBuffer());
    }

    public async flowExists(flowId: bigint): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.flowExistsSelector);
        w.writeU256(flowId);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async flowCount(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.flowCountSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    /**
     * Reads the 18-field flow record. Returns array of u256 values in
     * the order:
     *   [mode, status, chainId, evmBridge, evmToken, evmDecimals,
     *    opnetBridge, opnetToken, opnetDecimals, feeBps, minFee,
     *    minAmount, cap, dailyLimit, mintedToday, lastWindowStart,
     *    inventory, tipCapBps] (PR β.2.scaffold appended tipCapBps)
     */
    public async getFlow(flowId: bigint): Promise<bigint[]> {
        const w = new BinaryWriter();
        w.writeSelector(this.getFlowSelector);
        w.writeU256(flowId);
        const r = await this.getResponse(w.getBuffer());
        // Returned as ABIDataTypes.BYTES (length-prefixed). Read the
        // length prefix then 18 × u256 = 576 bytes.
        const blob = r.readBytesWithLength();
        const out: bigint[] = [];
        for (let i = 0; i < 18; i++) {
            // Each u256 is 32 bytes BE.
            let v = 0n;
            for (let j = 0; j < 32; j++) {
                v = (v << 8n) | BigInt(blob[i * 32 + j]!);
            }
            out.push(v);
        }
        return out;
    }

    // ─── confirmBurn / migrateSignerSet / flow inventory + lock ─

    private readonly confirmBurnSelector: number = encodeSelectorWithParams(
        'confirmBurn',
        ABIDataTypes.UINT256,
        ABIDataTypes.BYTES,
        ABIDataTypes.BYTES,
    );
    private readonly isBurnConfirmedSelector: number = encodeNumericSelector(
        'isBurnConfirmed()',
    );
    private readonly migrateSignerSetSelector: number = encodeSelectorWithParams(
        'migrateSignerSet',
        ABIDataTypes.BYTES,
    );
    private readonly provisionInventoryOpNetSelector: number =
        encodeSelectorWithParams(
            'provisionInventoryOpNet',
            ABIDataTypes.UINT256,
            ABIDataTypes.ADDRESS,
            ABIDataTypes.UINT256,
        );
    private readonly drainInventoryOpNetSelector: number =
        encodeSelectorWithParams(
            'drainInventoryOpNet',
            ABIDataTypes.UINT256,
            ABIDataTypes.ADDRESS,
            ABIDataTypes.UINT256,
            ABIDataTypes.ADDRESS,
        );
    private readonly lockForBridgeSelector: number = encodeSelectorWithParams(
        'lockForBridge',
        ABIDataTypes.UINT256,
        ABIDataTypes.ADDRESS,
        ABIDataTypes.UINT256,
        ABIDataTypes.BYTES32,
        ABIDataTypes.UINT32,
    );
    private readonly setTokenModeSelector: number = encodeSelectorWithParams(
        'setTokenMode',
        ABIDataTypes.ADDRESS,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
    );
    private readonly claimReleaseWithVoucherSelector: number = encodeSelectorWithParams(
        'claimReleaseWithVoucher',
        ABIDataTypes.BYTES,
        ABIDataTypes.BYTES,
    );

    public async confirmBurn(
        depositId: bigint,
        attestation: Uint8Array,
        mldsaSig: Uint8Array,
    ): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.confirmBurnSelector);
        w.writeU256(depositId);
        w.writeBytesWithLength(attestation);
        w.writeBytesWithLength(mldsaSig);
        await this.getResponse(w.getBuffer());
    }

    public async isBurnConfirmed(
        flowId: bigint,
        depositId: bigint,
        evmTxHash: bigint,
        evmLogIndex: bigint,
    ): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isBurnConfirmedSelector);
        w.writeU256(flowId);
        w.writeU256(depositId);
        w.writeU256(evmTxHash);
        w.writeU256(evmLogIndex);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async migrateSignerSet(payload: Uint8Array): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.migrateSignerSetSelector);
        w.writeBytesWithLength(payload);
        await this.getResponse(w.getBuffer());
    }

    public async provisionInventoryOpNet(
        flowId: bigint,
        token: Address,
        amount: bigint,
    ): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.provisionInventoryOpNetSelector);
        w.writeU256(flowId);
        w.writeAddress(token);
        w.writeU256(amount);
        await this.getResponse(w.getBuffer());
    }

    public async drainInventoryOpNet(
        flowId: bigint,
        token: Address,
        amount: bigint,
        recipient: Address,
    ): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.drainInventoryOpNetSelector);
        w.writeU256(flowId);
        w.writeAddress(token);
        w.writeU256(amount);
        w.writeAddress(recipient);
        await this.getResponse(w.getBuffer());
    }

    public async lockForBridge(
        flowId: bigint,
        canonicalToken: Address,
        amount: bigint,
        evmRecipient: Uint8Array,
        destChainId: number,
    ): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.lockForBridgeSelector);
        w.writeU256(flowId);
        w.writeAddress(canonicalToken);
        w.writeU256(amount);
        w.writeBytes(evmRecipient);
        w.writeU32(destChainId);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async setTokenMode(
        token: Address,
        mode: bigint,
        evmCounterpart: bigint,
    ): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setTokenModeSelector);
        w.writeAddress(token);
        w.writeU256(mode);
        w.writeU256(evmCounterpart);
        await this.getResponse(w.getBuffer());
    }

    public async claimReleaseWithVoucher(
        voucher: Uint8Array,
        mldsaSig: Uint8Array,
    ): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.claimReleaseWithVoucherSelector);
        w.writeBytesWithLength(voucher);
        w.writeBytesWithLength(mldsaSig);
        await this.getResponse(w.getBuffer());
    }

    // ─── Trustless stranded-lock refund ───────────────────────────────

    private readonly markLockRefundableSelector: number = encodeSelectorWithParams(
        'markLockRefundable',
        ABIDataTypes.UINT256,
        ABIDataTypes.BYTES,
    );
    private readonly refundLockSelector: number = encodeSelectorWithParams(
        'refundLock',
        ABIDataTypes.UINT256,
    );
    private readonly lockRecordSelector: number = encodeSelectorWithParams(
        'lockRecord',
        ABIDataTypes.UINT256,
    );
    private readonly isLockRefundableSelector: number = encodeNumericSelector(
        'isLockRefundable()',
    );

    // HARDENED: the contract rebuilds the RefundAuthorization preimage from
    // its own stored lock record + chain data; only the M-of-N sig blob is
    // sent on the wire (ABI signature `markLockRefundable(uint256,bytes)`
    // unchanged → selector stable).
    public async markLockRefundable(
        lockNonce: bigint,
        mldsaSig: Uint8Array,
    ): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.markLockRefundableSelector);
        w.writeU256(lockNonce);
        w.writeBytesWithLength(mldsaSig);
        await this.getResponse(w.getBuffer());
    }

    public async refundLock(lockNonce: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.refundLockSelector);
        w.writeU256(lockNonce);
        await this.getResponse(w.getBuffer());
    }

    // Returns [status, user, token, flowId, amount, fee, mode, blockNumber]
    // as 8 × u256.
    public async lockRecord(lockNonce: bigint): Promise<bigint[]> {
        const w = new BinaryWriter();
        w.writeSelector(this.lockRecordSelector);
        w.writeU256(lockNonce);
        const r = await this.getResponse(w.getBuffer());
        const blob = r.readBytesWithLength();
        const out: bigint[] = [];
        for (let i = 0; i < 8; i++) {
            let v = 0n;
            for (let j = 0; j < 32; j++) {
                v = (v << 8n) | BigInt(blob[i * 32 + j]!);
            }
            out.push(v);
        }
        return out;
    }

    public async isLockRefundable(lockNonce: bigint): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isLockRefundableSelector);
        w.writeU256(lockNonce);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    // ─── #55 — trustless burn-side recovery (attested re-mint) ──────────

    private readonly refundBurnSelector: number = encodeSelectorWithParams(
        'refundBurn',
        ABIDataTypes.BYTES,
        ABIDataTypes.BYTES,
    );
    private readonly isBurnRefundedSelector: number = encodeNumericSelector(
        'isBurnRefunded()',
    );

    // The attestation IS the signed 296-byte preimage; only it + the M-of-N
    // sig blob are sent on the wire (ABI signature `refundBurn(bytes,bytes)`).
    public async refundBurn(
        attestation: Uint8Array,
        mldsaSig: Uint8Array,
    ): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.refundBurnSelector);
        w.writeBytesWithLength(attestation);
        w.writeBytesWithLength(mldsaSig);
        await this.getResponse(w.getBuffer());
    }

    public async isBurnRefunded(
        burnTxHash: bigint,
        burnNonce: bigint,
    ): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isBurnRefundedSelector);
        w.writeU256(burnTxHash);
        w.writeU256(burnNonce);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    // ─── #62 — per-flow fee accounting + withdrawFees ─────────────────

    private readonly withdrawFeesSelector: number = encodeSelectorWithParams(
        'withdrawFees',
        ABIDataTypes.UINT256,
        ABIDataTypes.ADDRESS,
        ABIDataTypes.UINT256,
    );
    private readonly accruedFeesSelector: number = encodeNumericSelector('accruedFees(uint256)');

    public async withdrawFees(flowId: bigint, token: Address, amount: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.withdrawFeesSelector);
        w.writeU256(flowId);
        w.writeAddress(token);
        w.writeU256(amount);
        await this.getResponse(w.getBuffer());
    }

    private readonly setTreasurySelector: number = encodeSelectorWithParams(
        'setTreasury',
        ABIDataTypes.ADDRESS,
    );

    public async setTreasury(treasury: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setTreasurySelector);
        w.writeAddress(treasury);
        await this.getResponse(w.getBuffer());
    }

    private readonly treasurySelector: number = encodeNumericSelector('treasury()');

    public async treasury(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.treasurySelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    private readonly setGuardianSelector: number = encodeSelectorWithParams(
        'setGuardian',
        ABIDataTypes.ADDRESS,
    );

    public async setGuardian(guardian: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setGuardianSelector);
        w.writeAddress(guardian);
        await this.getResponse(w.getBuffer());
    }

    private readonly guardianSelector: number = encodeNumericSelector('guardian()');

    public async guardian(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.guardianSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    private readonly emergencyWithdrawSelector: number = encodeSelectorWithParams(
        'emergencyWithdraw',
        ABIDataTypes.ADDRESS,
        ABIDataTypes.UINT256,
    );

    public async emergencyWithdraw(token: Address, amount: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.emergencyWithdrawSelector);
        w.writeAddress(token);
        w.writeU256(amount);
        await this.getResponse(w.getBuffer());
    }

    public async accruedFees(flowId: bigint): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.accruedFeesSelector);
        w.writeU256(flowId);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public override async init(): Promise<void> {
        this.defineRequiredBytecodes();
        this._bytecode = BytecodeManager.getBytecode(this.address) as Buffer;
        return await Promise.resolve();
    }

    protected defineRequiredBytecodes(): void {
        BytecodeManager.loadBytecode('./build/BridgeDepository.wasm', this.address);
    }

    protected handleError(error: Error): Error {
        return new Error(`(in BridgeDepository: ${this.address}) OPNET: ${error.stack}`);
    }
}
