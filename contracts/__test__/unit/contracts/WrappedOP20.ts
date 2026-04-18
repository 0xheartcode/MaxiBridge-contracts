import { ABIDataTypes, Address, BinaryReader, BinaryWriter } from '@btc-vision/transaction';
import { BytecodeManager, ContractRuntime, OP20 } from '@btc-vision/unit-test-framework';
import type { ContractDetails } from '@btc-vision/unit-test-framework';
import { encodeNumericSelector, encodeSelectorWithParams } from './utils.js';

/**
 * Test harness for WrappedOP20 (wUSDC / wUSDT). Inherits OP20 so balanceOf,
 * totalSupply, transfer, etc. come for free.
 */
export class WrappedOP20 extends OP20 {
    private readonly setBridgeDepositorySelector: number = encodeSelectorWithParams(
        'setBridgeDepository',
        ABIDataTypes.ADDRESS,
    );
    private readonly setGovernorSelector: number = encodeSelectorWithParams(
        'setGovernor',
        ABIDataTypes.ADDRESS,
    );
    private readonly mintToSelector: number = encodeSelectorWithParams(
        'mintTo',
        ABIDataTypes.ADDRESS,
        ABIDataTypes.UINT256,
    );
    private readonly burnForReleaseSelector: number = encodeSelectorWithParams(
        'burnForRelease',
        ABIDataTypes.BYTES32,
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT32,
    );
    private readonly bridgeDepositorySelector: number = encodeNumericSelector('bridgeDepository()');
    private readonly governorSelector: number = encodeNumericSelector('governor()');
    private readonly burnNonceSelector: number = encodeNumericSelector('burnNonce()');
    private readonly storageVersionSelector: number = encodeNumericSelector('storageVersion()');
    private readonly pausedSelector: number = encodeNumericSelector('paused()');
    private readonly setPausedSelector: number = encodeSelectorWithParams(
        'setPaused',
        ABIDataTypes.BOOL,
    );

    constructor(details: ContractDetails) {
        super(details);
    }

    private async getResponse(calldata: Uint8Array): Promise<BinaryReader> {
        const result = await this.execute({ calldata });
        if (result.error) throw result.error;
        return new BinaryReader(result.response);
    }

    public async setBridgeDepository(newBridge: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setBridgeDepositorySelector);
        w.writeAddress(newBridge);
        await this.getResponse(w.getBuffer());
    }

    public async setGovernor(newGovernor: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setGovernorSelector);
        w.writeAddress(newGovernor);
        await this.getResponse(w.getBuffer());
    }

    public async mintTo(to: Address, amount: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.mintToSelector);
        w.writeAddress(to);
        w.writeU256(amount);
        await this.getResponse(w.getBuffer());
    }

    public async burnForRelease(
        ethRecipient: Uint8Array,
        amount: bigint,
        destChainId: number,
    ): Promise<bigint> {
        if (ethRecipient.length !== 32) {
            throw new Error(`ethRecipient must be 32 bytes (got ${ethRecipient.length})`);
        }
        const w = new BinaryWriter();
        w.writeSelector(this.burnForReleaseSelector);
        // BYTES32 is 32 raw bytes, no length prefix.
        w.writeBytes(ethRecipient);
        w.writeU256(amount);
        w.writeU32(destChainId);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async bridgeDepository(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.bridgeDepositorySelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async governor(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.governorSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async burnNonce(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.burnNonceSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async storageVersion(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.storageVersionSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async paused(): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.pausedSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async setPaused(paused: boolean): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setPausedSelector);
        w.writeBoolean(paused);
        await this.getResponse(w.getBuffer());
    }

    public override async init(): Promise<void> {
        this.defineRequiredBytecodes();
        this._bytecode = BytecodeManager.getBytecode(this.address) as Buffer;
        return await Promise.resolve();
    }

    protected defineRequiredBytecodes(): void {
        BytecodeManager.loadBytecode('./build/WrappedOP20.wasm', this.address);
    }

    protected handleError(error: Error): Error {
        return new Error(`(in WrappedOP20: ${this.address}) OPNET: ${error.stack}`);
    }
}
