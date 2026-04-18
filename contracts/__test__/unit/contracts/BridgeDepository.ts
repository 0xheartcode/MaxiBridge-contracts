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
    private readonly storageVersionSelector: number = encodeNumericSelector('storageVersion()');
    private readonly networkIdSelector: number = encodeNumericSelector('networkId()');

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
