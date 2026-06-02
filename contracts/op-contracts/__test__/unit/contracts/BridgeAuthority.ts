import { ABIDataTypes, Address, BinaryReader, BinaryWriter } from '@btc-vision/transaction';
import { BytecodeManager, ContractRuntime } from '@btc-vision/unit-test-framework';
import type { ContractDetails } from '@btc-vision/unit-test-framework';
import { encodeNumericSelector, encodeSelectorWithParams } from './utils.js';

export class BridgeAuthority extends ContractRuntime {
    private readonly setManagedContractsSelector: number = encodeSelectorWithParams(
        'setManagedContracts',
        ABIDataTypes.ADDRESS,
        ABIDataTypes.ADDRESS,
        ABIDataTypes.ADDRESS,
    );
    private readonly pushGovernorSelector: number = encodeSelectorWithParams(
        'pushGovernor',
        ABIDataTypes.ADDRESS,
    );
    private readonly pushGuardianSelector: number = encodeSelectorWithParams(
        'pushGuardian',
        ABIDataTypes.ADDRESS,
    );
    private readonly pauseAllSelector: number = encodeNumericSelector('pauseAll()');
    private readonly unpauseAllSelector: number = encodeNumericSelector('unpauseAll()');
    private readonly addBridgeSignerSelector: number = encodeSelectorWithParams(
        'addBridgeSigner',
        ABIDataTypes.UINT256,
    );
    private readonly removeBridgeSignerSelector: number = encodeSelectorWithParams(
        'removeBridgeSigner',
        ABIDataTypes.UINT256,
    );
    private readonly setBridgeThresholdSelector: number = encodeSelectorWithParams(
        'setBridgeThreshold',
        ABIDataTypes.UINT256,
    );
    private readonly migrateBridgeSignerSetSelector: number = encodeSelectorWithParams(
        'migrateBridgeSignerSet',
        ABIDataTypes.UINT256,
        ABIDataTypes.UINT256,
    );

    private readonly governorSelector: number = encodeNumericSelector('governor()');
    private readonly guardianSelector: number = encodeNumericSelector('guardian()');
    private readonly depositorySelector: number = encodeNumericSelector('depository()');
    private readonly wusdcSelector: number = encodeNumericSelector('wusdc()');
    private readonly wusdtSelector: number = encodeNumericSelector('wusdt()');
    private readonly storageVersionSelector: number = encodeNumericSelector('storageVersion()');

    // Option C (O-4) — governance-gated upgrade authorization surface.
    private readonly setUpgradeAuthoritySelector: number = encodeSelectorWithParams(
        'setUpgradeAuthority',
        ABIDataTypes.ADDRESS,
    );
    private readonly proposeUpgradeSelector: number = encodeNumericSelector('proposeUpgrade()');
    private readonly cancelProposedUpgradeSelector: number = encodeNumericSelector(
        'cancelProposedUpgrade()',
    );
    private readonly upgradeAuthoritySelector: number = encodeNumericSelector('upgradeAuthority()');
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

    public async setManagedContracts(
        depository: Address,
        wusdc: Address,
        wusdt: Address,
    ): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setManagedContractsSelector);
        w.writeAddress(depository);
        w.writeAddress(wusdc);
        w.writeAddress(wusdt);
        await this.getResponse(w.getBuffer());
    }

    public async pushGovernor(addr: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.pushGovernorSelector);
        w.writeAddress(addr);
        await this.getResponse(w.getBuffer());
    }

    public async pushGuardian(addr: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.pushGuardianSelector);
        w.writeAddress(addr);
        await this.getResponse(w.getBuffer());
    }

    public async pauseAll(): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.pauseAllSelector);
        await this.getResponse(w.getBuffer());
    }

    public async unpauseAll(): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.unpauseAllSelector);
        await this.getResponse(w.getBuffer());
    }

    public async addBridgeSigner(hash: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.addBridgeSignerSelector);
        w.writeU256(hash);
        await this.getResponse(w.getBuffer());
    }

    public async removeBridgeSigner(hash: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.removeBridgeSignerSelector);
        w.writeU256(hash);
        await this.getResponse(w.getBuffer());
    }

    public async setBridgeThreshold(threshold: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setBridgeThresholdSelector);
        w.writeU256(threshold);
        await this.getResponse(w.getBuffer());
    }

    public async migrateBridgeSignerSet(addHash: bigint, newThreshold: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.migrateBridgeSignerSetSelector);
        w.writeU256(addHash);
        w.writeU256(newThreshold);
        await this.getResponse(w.getBuffer());
    }

    public async governor(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.governorSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async guardian(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.guardianSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async depository(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.depositorySelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async wusdc(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.wusdcSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async wusdt(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.wusdtSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async storageVersion(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.storageVersionSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

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

    public override async init(): Promise<void> {
        this.defineRequiredBytecodes();
        this._bytecode = BytecodeManager.getBytecode(this.address) as Buffer;
        return await Promise.resolve();
    }

    protected defineRequiredBytecodes(): void {
        BytecodeManager.loadBytecode('./build/BridgeAuthority.wasm', this.address);
    }

    protected handleError(error: Error): Error {
        return new Error(`(in BridgeAuthority: ${this.address}) OPNET: ${error.stack}`);
    }
}
