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
    // #68 Tier C — flowId (UINT256) is now the FIRST param of burnForRelease.
    private readonly burnForReleaseSelector: number = encodeSelectorWithParams(
        'burnForRelease',
        ABIDataTypes.UINT256,
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
    private readonly setAuthorityAddressSelector: number = encodeSelectorWithParams(
        'setAuthorityAddress',
        ABIDataTypes.ADDRESS,
    );
    private readonly grantMinterSelector: number = encodeSelectorWithParams(
        'grantMinter',
        ABIDataTypes.ADDRESS,
    );
    private readonly revokeMinterSelector: number = encodeSelectorWithParams(
        'revokeMinter',
        ABIDataTypes.ADDRESS,
    );
    private readonly isMinterSelector: number = encodeNumericSelector('isMinter()');
    private readonly authorityAddressSelector: number = encodeNumericSelector('authorityAddress()');
    private readonly setSupportedDestChainSelector: number = encodeSelectorWithParams(
        'setSupportedDestChain',
        ABIDataTypes.UINT32,
        ABIDataTypes.BOOL,
        ABIDataTypes.BOOL,
    );
    private readonly isSupportedDestChainSelector: number = encodeNumericSelector(
        'isSupportedDestChain()',
    );

    // ─── OP20S (peg oracle) selectors ───────────────────────────────────────
    // Note: base-class methods are declared with @method() (no inputs) so the
    // selector uses empty parens, matching the Solidity-style convention.
    private readonly pegRateSelector: number = encodeNumericSelector('pegRate()');
    private readonly pegAuthoritySelector: number = encodeNumericSelector('pegAuthority()');
    private readonly pegUpdatedAtSelector: number = encodeNumericSelector('pegUpdatedAt()');
    private readonly maxStalenessSelector: number = encodeNumericSelector('maxStaleness()');
    private readonly isStaleSelector: number = encodeNumericSelector('isStale()');
    private readonly updatePegRateSelector: number = encodeSelectorWithParams(
        'updatePegRate',
        ABIDataTypes.UINT256,
    );
    private readonly updateMaxStalenessSelector: number = encodeSelectorWithParams(
        'updateMaxStaleness',
        ABIDataTypes.UINT64,
    );
    private readonly transferPegAuthoritySelector: number = encodeSelectorWithParams(
        'transferPegAuthority',
        ABIDataTypes.ADDRESS,
    );
    private readonly acceptPegAuthoritySelector: number = encodeNumericSelector(
        'acceptPegAuthority()',
    );
    private readonly renouncePegAuthoritySelector: number = encodeNumericSelector(
        'renouncePegAuthority()',
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
        // #68 Tier C — flowId is the contract's FIRST param. Kept LAST + optional
        // here so existing call sites stay valid; defaults to 0 (legacy / unbound).
        flowId: bigint = 0n,
    ): Promise<bigint> {
        if (ethRecipient.length !== 32) {
            throw new Error(`ethRecipient must be 32 bytes (got ${ethRecipient.length})`);
        }
        const w = new BinaryWriter();
        w.writeSelector(this.burnForReleaseSelector);
        // #68 Tier C — flowId FIRST (matches the contract @method order).
        w.writeU256(flowId);
        // BYTES32 is 32 raw bytes, no length prefix.
        w.writeBytes(ethRecipient);
        w.writeU256(amount);
        w.writeU32(destChainId);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    /**
     * #68 Tier C — same as `burnForRelease` but returns the raw emitted events
     * so a test can assert the BurnedForRelease event carries the flowId.
     */
    public async burnForReleaseEvents(
        ethRecipient: Uint8Array,
        amount: bigint,
        destChainId: number,
        flowId: bigint,
    ): Promise<{ type: string; data: Uint8Array }[]> {
        const w = new BinaryWriter();
        w.writeSelector(this.burnForReleaseSelector);
        w.writeU256(flowId);
        w.writeBytes(ethRecipient);
        w.writeU256(amount);
        w.writeU32(destChainId);
        const result = await this.execute({ calldata: w.getBuffer() });
        if (result.error) throw result.error;
        return result.events.map((e) => ({ type: e.type, data: e.data }));
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

    public async setAuthorityAddress(addr: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setAuthorityAddressSelector);
        w.writeAddress(addr);
        await this.getResponse(w.getBuffer());
    }

    public async grantMinter(minter: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.grantMinterSelector);
        w.writeAddress(minter);
        await this.getResponse(w.getBuffer());
    }

    public async revokeMinter(minter: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.revokeMinterSelector);
        w.writeAddress(minter);
        await this.getResponse(w.getBuffer());
    }

    public async isMinter(addr: Address): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isMinterSelector);
        w.writeAddress(addr);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async authorityAddress(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.authorityAddressSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    // ─── M-01: supported destination chains ─────────────────────────────────

    public async setSupportedDestChain(
        destChainId: number,
        enabled: boolean,
        isEvmFamily: boolean,
    ): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.setSupportedDestChainSelector);
        w.writeU32(destChainId);
        w.writeBoolean(enabled);
        w.writeBoolean(isEvmFamily);
        await this.getResponse(w.getBuffer());
    }

    public async isSupportedDestChain(destChainId: number): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isSupportedDestChainSelector);
        w.writeU32(destChainId);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    // ─── OP20S peg methods ──────────────────────────────────────────────────

    public async pegRate(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.pegRateSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU256();
    }

    public async pegAuthority(): Promise<Address> {
        const w = new BinaryWriter();
        w.writeSelector(this.pegAuthoritySelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readAddress();
    }

    public async pegUpdatedAt(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.pegUpdatedAtSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU64();
    }

    public async maxStaleness(): Promise<bigint> {
        const w = new BinaryWriter();
        w.writeSelector(this.maxStalenessSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readU64();
    }

    public async isStale(): Promise<boolean> {
        const w = new BinaryWriter();
        w.writeSelector(this.isStaleSelector);
        const r = await this.getResponse(w.getBuffer());
        return r.readBoolean();
    }

    public async updatePegRate(newRate: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.updatePegRateSelector);
        w.writeU256(newRate);
        await this.getResponse(w.getBuffer());
    }

    public async updateMaxStaleness(newStaleness: bigint): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.updateMaxStalenessSelector);
        w.writeU64(newStaleness);
        await this.getResponse(w.getBuffer());
    }

    public async transferPegAuthority(newAuthority: Address): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.transferPegAuthoritySelector);
        w.writeAddress(newAuthority);
        await this.getResponse(w.getBuffer());
    }

    public async acceptPegAuthority(): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.acceptPegAuthoritySelector);
        await this.getResponse(w.getBuffer());
    }

    public async renouncePegAuthority(): Promise<void> {
        const w = new BinaryWriter();
        w.writeSelector(this.renouncePegAuthoritySelector);
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
