/**
 * BridgeDepository — #62 per-flow OPNet-source fee accounting tests.
 *
 * Mirror of the EVM-side `BridgeEscrow` change (uint128 accruedFees on
 * FlowRecord + treasury-only withdrawFees). On OPNet the genuine
 * OPNet-SOURCE fee-retention point is `lockForBridge` (the OPNet→EVM lock
 * leg of mode 1 INVERSE_WRAPPED + mode 3 POOLED_LOCK_RELEASE): the user
 * locks `received` gross, only the net crosses to the EVM counterpart, and
 * the fee portion stays in the depository. We accrue that exact fee into
 * `_flowAccruedFees[flowId]` and expose:
 *   - `withdrawFees(flowId, token, amount)` — governor-only, NOT pause-gated,
 *     bounded strictly by the accumulator, transfers to the governor.
 *   - `accruedFees(flowId)` — @view read surface.
 *
 * Coverage:
 *   - accrual on lockForBridge (exact fee = max(minFee, received*bps/1e4),
 *     net/inventory unchanged by the accrual)
 *   - accumulation across multiple locks
 *   - zero-fee flow accrues nothing
 *   - withdrawFees transfers the fee to the governor + decrements the accumulator
 *   - bounded: revert when amount > accrued, and when amount == 0
 *   - governor-only: revert for a non-governor caller
 *   - works while NOT paused (routine sweep)
 *   - event args (FeesWithdrawn)
 *
 * Run: cd contracts/op-contracts && npm run build:depository &&
 *      npx tsx __test__/unit/tests/fee-accounting.ts
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address, Wallet } from '@btc-vision/transaction';

import { WrappedOP20 } from '../contracts/WrappedOP20.js';
import { BridgeDepository } from '../contracts/BridgeDepository.js';

const ETH_CHAIN_ID: bigint = 1n;

const deployer: Address = Blockchain.generateRandomAddress();
const alice: Address = Blockchain.generateRandomAddress();

function setSender(addr: Address): void {
    Blockchain.msgSender = addr;
    Blockchain.txOrigin = addr;
}

interface BridgeSetup {
    depository: BridgeDepository;
    depositoryAddress: Address;
    wusdc: WrappedOP20;
    wusdcAddress: Address;
    signerWallet: Wallet;
}

async function setupContracts(): Promise<BridgeSetup> {
    const depositoryAddress = Blockchain.generateRandomAddress();
    const wusdcAddress = Blockchain.generateRandomAddress();

    const wusdc = new WrappedOP20({
        file: './build/WrappedOP20.wasm',
        address: wusdcAddress,
        decimals: 6,
        deployer,
    });
    Blockchain.register(wusdc);
    await wusdc.init();

    const depository = new BridgeDepository({
        file: './build/BridgeDepository.wasm',
        address: depositoryAddress,
        deployer,
    });
    Blockchain.register(depository);
    await depository.init();

    setSender(deployer);
    await wusdc.setBridgeDepository(depositoryAddress);
    await depository.addWrappedToken(wusdcAddress);

    const signerWallet = Blockchain.generateRandomWallet();
    const pubKey = new Uint8Array(signerWallet.mldsaKeypair.publicKey);
    await depository.setInitialSigner(pubKey);

    return { depository, depositoryAddress, wusdc, wusdcAddress, signerWallet };
}

function disposeSetup(s: BridgeSetup): void {
    s.depository.dispose();
    s.wusdc.dispose();
    Blockchain.dispose();
}

function evmAddrRightPadToBigInt(addr: Address): bigint {
    const bytes = addr as unknown as Uint8Array;
    let v = 0n;
    for (let i = 0; i < 20; i++) v = (v << 8n) | BigInt(bytes[i]!);
    return v;
}

function opnetAddrToBigInt(addr: Address): bigint {
    const bytes = addr as unknown as Uint8Array;
    let v = 0n;
    for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]!);
    return v;
}

const DEFAULT_SOURCE_BRIDGE: Address = Blockchain.generateRandomAddress();
const DEFAULT_SOURCE_TOKEN: Address = Blockchain.generateRandomAddress();

interface FlowOpts {
    mode?: bigint;
    sourceBridgeAddr?: Address;
    sourceTokenAddr?: Address;
    feeBps?: bigint;
    minFee?: bigint;
    cap?: bigint;
    dailyLimit?: bigint;
}

// Register a flow whose canonical OPNet token is wusdc. Defaults to a
// mode-1 (INVERSE_WRAPPED) flow with feeBps = 50 (0.5%) so lockForBridge
// is reachable and a fee accrues.
async function registerFlow(setup: BridgeSetup, opts: FlowOpts = {}): Promise<bigint> {
    const sourceBridgeAddr = opts.sourceBridgeAddr ?? DEFAULT_SOURCE_BRIDGE;
    const sourceTokenAddr = opts.sourceTokenAddr ?? DEFAULT_SOURCE_TOKEN;
    return await setup.depository.addFlow({
        mode: opts.mode ?? 1n,
        chainId: ETH_CHAIN_ID,
        evmBridge: evmAddrRightPadToBigInt(sourceBridgeAddr),
        evmToken: evmAddrRightPadToBigInt(sourceTokenAddr),
        evmDecimals: 6n,
        opnetBridge: opnetAddrToBigInt(setup.depositoryAddress),
        opnetToken: opnetAddrToBigInt(setup.wusdcAddress),
        opnetDecimals: 6n,
        feeBps: opts.feeBps ?? 50n,
        minFee: opts.minFee ?? 0n,
        minAmount: 0n,
        cap: opts.cap ?? 1_000_000_000_000n,
        dailyLimit: opts.dailyLimit ?? 1_000_000_000_000n,
        tipCapBps: 0n,
    });
}

// Build a left-padded EVM recipient (upper 12 bytes zero), dest chainId 1.
function evmRecipient(): Uint8Array {
    const r = new Uint8Array(32);
    for (let i = 12; i < 32; i++) r[i] = 0xab;
    return r;
}

// Fund alice with `amount` canonical wusdc and approve the depository.
async function fundAndApprove(setup: BridgeSetup, amount: bigint): Promise<void> {
    const { wusdc, wusdcAddress, depositoryAddress } = setup;
    setSender(depositoryAddress); // only the bridge can mintTo
    await wusdc.mintTo(alice, amount);
    await wusdc.increaseAllowance(alice, depositoryAddress, amount);
}

// ════════════════════════════════════════════════════════════════════════════
// Accrual on lockForBridge
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository — #62 — fee accrual on lockForBridge', async (vm: OPNetUnit) => {
    let setup: BridgeSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        Blockchain.medianTimestamp = 1_000_000n;
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => disposeSetup(setup));

    await vm.it('mode-1 lock accrues exact bps fee; inventory == received - fee (HIGH-002)', async () => {
        const { depository, wusdcAddress } = setup;
        await depository.setTokenMode(wusdcAddress, 1n, 0xc0ffeen);
        const flowId = await registerFlow(setup, { mode: 1n, feeBps: 50n });

        await fundAndApprove(setup, 4_000_000n);
        setSender(alice);
        await depository.lockForBridge(flowId, wusdcAddress, 2_000_000n, evmRecipient(), 1);

        // fee = 2_000_000 * 50 / 10_000 = 10_000
        Assert.expect(await depository.accruedFees(flowId)).toEqual(10_000n);
        // HIGH-002 (audit 2026-05-25): inventory is credited with NET
        // (received - fee), NOT gross. Pre-fix this asserted == received and
        // every governor fee sweep widened the ledger-vs-balance gap by the
        // swept amount.
        const flow = await depository.getFlow(flowId);
        Assert.expect(flow[16]!).toEqual(1_990_000n);
    });

    await vm.it('mode-1 invariant: inventory + accruedFees == bridge balance, across lock + withdrawFees (HIGH-002)', async () => {
        // The full round-trip invariant the fix restores: after any sequence
        // of mode-1 locks AND a fee sweep, the per-flow ledger plus the
        // unswept fee accumulator equals the depository's token balance
        // attributable to this flow. Pre-fix the sweep dropped balance but
        // left inventory unchanged, breaking the equality.
        const { depository, depositoryAddress, wusdcAddress, wusdc } = setup;
        await depository.setTokenMode(wusdcAddress, 1n, 0xc0ffeen);
        const flowId = await registerFlow(setup, { mode: 1n, feeBps: 50n });

        await fundAndApprove(setup, 4_000_000n);
        setSender(alice);
        await depository.lockForBridge(flowId, wusdcAddress, 2_000_000n, evmRecipient(), 1);

        // Bridge balance after lock = received (gross) = 2_000_000.
        const balAfterLock = await wusdc.balanceOf(depositoryAddress);
        const flowAfterLock = await depository.getFlow(flowId);
        const accruedAfterLock = await depository.accruedFees(flowId);
        Assert.expect(flowAfterLock[16]! + accruedAfterLock).toEqual(balAfterLock);

        // Governor (deployer) sweeps the full accrued fee to the configured
        // fee recipient (deployer here, for the balance arithmetic below).
        setSender(deployer);
        await depository.setFeeRecipient(deployer);
        await depository.withdrawFees(flowId, wusdcAddress, accruedAfterLock);

        // Post-sweep: balance dropped by fee; inventory unchanged; accrued = 0.
        // Pre-fix: balance == 1_990_000, inventory == 2_000_000 → invariant
        // BROKEN. Post-fix: balance == 1_990_000, inventory == 1_990_000 → OK.
        const balAfterSweep = await wusdc.balanceOf(depositoryAddress);
        const flowAfterSweep = await depository.getFlow(flowId);
        const accruedAfterSweep = await depository.accruedFees(flowId);
        Assert.expect(accruedAfterSweep).toEqual(0n);
        Assert.expect(flowAfterSweep[16]! + accruedAfterSweep).toEqual(balAfterSweep);
    });

    await vm.it('minFee floor wins when bps-derived fee is lower', async () => {
        const { depository, wusdcAddress } = setup;
        await depository.setTokenMode(wusdcAddress, 1n, 0xc0ffeen);
        // bps fee on 1_000_000 @ 10bps = 1_000; minFee 7_500 dominates.
        const flowId = await registerFlow(setup, { mode: 1n, feeBps: 10n, minFee: 7_500n });

        await fundAndApprove(setup, 1_000_000n);
        setSender(alice);
        await depository.lockForBridge(flowId, wusdcAddress, 1_000_000n, evmRecipient(), 1);
        Assert.expect(await depository.accruedFees(flowId)).toEqual(7_500n);
    });

    await vm.it('zero-fee flow accrues nothing', async () => {
        const { depository, wusdcAddress } = setup;
        await depository.setTokenMode(wusdcAddress, 1n, 0xc0ffeen);
        const flowId = await registerFlow(setup, { mode: 1n, feeBps: 0n, minFee: 0n });

        await fundAndApprove(setup, 2_000_000n);
        setSender(alice);
        await depository.lockForBridge(flowId, wusdcAddress, 2_000_000n, evmRecipient(), 1);
        Assert.expect(await depository.accruedFees(flowId)).toEqual(0n);
    });

    await vm.it('accrual accumulates across multiple locks', async () => {
        const { depository, wusdcAddress } = setup;
        await depository.setTokenMode(wusdcAddress, 1n, 0xc0ffeen);
        const flowId = await registerFlow(setup, { mode: 1n, feeBps: 50n });

        await fundAndApprove(setup, 6_000_000n);
        setSender(alice);
        await depository.lockForBridge(flowId, wusdcAddress, 2_000_000n, evmRecipient(), 1);
        await depository.lockForBridge(flowId, wusdcAddress, 4_000_000n, evmRecipient(), 1);
        // 10_000 + 20_000 = 30_000
        Assert.expect(await depository.accruedFees(flowId)).toEqual(30_000n);
    });

    await vm.it('mode-3 (POOLED) lock also accrues a source-side fee', async () => {
        // Mode 3 keeps the canonical token mode at WRAPPED-incompatible? No —
        // lockForBridge dispatches on the TOKEN mode (_tokenMode). Set it to
        // mode 3 so the lock is admitted, and register a mode-3 flow.
        const { depository, wusdcAddress } = setup;
        await depository.setTokenMode(wusdcAddress, 3n, 0xc0ffeen);
        const flowId = await registerFlow(setup, { mode: 3n, feeBps: 50n });

        await fundAndApprove(setup, 2_000_000n);
        setSender(alice);
        await depository.lockForBridge(flowId, wusdcAddress, 2_000_000n, evmRecipient(), 1);
        Assert.expect(await depository.accruedFees(flowId)).toEqual(10_000n);
    });

    await vm.it('accruedFees is zero for a flow that never locked', async () => {
        const flowId = await registerFlow(setup, { mode: 1n });
        Assert.expect(await setup.depository.accruedFees(flowId)).toEqual(0n);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// withdrawFees
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository — #62 — withdrawFees', async (vm: OPNetUnit) => {
    let setup: BridgeSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        Blockchain.medianTimestamp = 1_000_000n;
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => disposeSetup(setup));

    // Common arrangement: a mode-1 flow with 10_000 accrued from a 2_000_000 lock.
    async function arrange(): Promise<bigint> {
        const { depository, wusdcAddress } = setup;
        await depository.setTokenMode(wusdcAddress, 1n, 0xc0ffeen);
        const flowId = await registerFlow(setup, { mode: 1n, feeBps: 50n });
        await fundAndApprove(setup, 2_000_000n);
        setSender(alice);
        await depository.lockForBridge(flowId, wusdcAddress, 2_000_000n, evmRecipient(), 1);
        return flowId;
    }

    await vm.it('transfers accrued fee to the dedicated feeRecipient (NOT the governor) + decrements (NOT paused)', async () => {
        const { depository, wusdc, wusdcAddress } = setup;
        const flowId = await arrange();

        // Bridge is NOT paused — routine sweep must succeed.
        Assert.expect(await depository.paused()).toEqual(false);

        // Dedicated fee sink, distinct from the governor (deployer).
        setSender(deployer); // governor
        await depository.setFeeRecipient(alice);

        const sinkBefore = await wusdc.balanceOf(alice);
        const govBefore = await wusdc.balanceOf(deployer);
        await depository.withdrawFees(flowId, wusdcAddress, 4_000n);

        Assert.expect(await depository.accruedFees(flowId)).toEqual(6_000n);
        // Fee landed on the feeRecipient, NOT the governor key.
        Assert.expect(await wusdc.balanceOf(alice)).toEqual(sinkBefore + 4_000n);
        Assert.expect(await wusdc.balanceOf(deployer)).toEqual(govBefore);

        // Sweep the remainder.
        await depository.withdrawFees(flowId, wusdcAddress, 6_000n);
        Assert.expect(await depository.accruedFees(flowId)).toEqual(0n);
        Assert.expect(await wusdc.balanceOf(alice)).toEqual(sinkBefore + 10_000n);
    });

    await vm.it('fee sweep is FAIL-CLOSED when feeRecipient is unset', async () => {
        const { depository, wusdcAddress } = setup;
        const flowId = await arrange();
        // feeRecipient never wired → withdrawFees must revert (no silent
        // zero-address burn of protocol revenue).
        setSender(deployer);
        await Assert.expect(async () => {
            await depository.withdrawFees(flowId, wusdcAddress, 1_000n);
        }).toThrow();
    });

    await vm.it('reverts when amount > accrued', async () => {
        const { depository, wusdcAddress } = setup;
        const flowId = await arrange();
        setSender(deployer);
        await Assert.expect(async () => {
            await depository.withdrawFees(flowId, wusdcAddress, 10_001n);
        }).toThrow();
    });

    await vm.it('reverts when amount == 0', async () => {
        const { depository, wusdcAddress } = setup;
        const flowId = await arrange();
        setSender(deployer);
        await Assert.expect(async () => {
            await depository.withdrawFees(flowId, wusdcAddress, 0n);
        }).toThrow();
    });

    await vm.it('reverts for a non-governor caller', async () => {
        const { depository, wusdcAddress } = setup;
        const flowId = await arrange();
        setSender(alice);
        await Assert.expect(async () => {
            await depository.withdrawFees(flowId, wusdcAddress, 1_000n);
        }).toThrow();
    });

    await vm.it('reverts on unknown flow', async () => {
        const { depository, wusdcAddress } = setup;
        await arrange();
        setSender(deployer);
        await Assert.expect(async () => {
            await depository.withdrawFees(0xdeadbeefn, wusdcAddress, 1n);
        }).toThrow();
    });

    await vm.it('reverts when token is not the flow canonical token', async () => {
        const { depository } = setup;
        const flowId = await arrange();
        const notCanonical = Blockchain.generateRandomAddress();
        setSender(deployer);
        await Assert.expect(async () => {
            await depository.withdrawFees(flowId, notCanonical, 1_000n);
        }).toThrow();
    });

    await vm.it('emits FeesWithdrawn (event set contains it) on a successful sweep', async () => {
        // The @emit('FeesWithdrawn') decorator makes emission part of the
        // method; we assert the event surfaces in the call's event set and
        // that its trailing amount word matches. Reading the raw execute
        // response keeps the assertion robust to the wrapper swallowing it.
        const { depository, wusdcAddress } = setup;
        const flowId = await arrange();
        setSender(deployer);

        const { BinaryWriter, ABIDataTypes } = await import('@btc-vision/transaction');
        const { encodeSelectorWithParams } = await import('../contracts/utils.js');
        const sel = encodeSelectorWithParams(
            'withdrawFees',
            ABIDataTypes.UINT256,
            ABIDataTypes.ADDRESS,
            ABIDataTypes.UINT256,
        );
        const w = new BinaryWriter();
        w.writeSelector(sel);
        w.writeU256(flowId);
        w.writeAddress(wusdcAddress);
        w.writeU256(2_000n);

        const runtime = depository as unknown as {
            execute: (a: { calldata: Uint8Array }) => Promise<{
                error?: Error;
                events?: { type?: string; eventType?: string; data?: Uint8Array; eventData?: Uint8Array }[];
            }>;
        };
        const res = await runtime.execute({ calldata: w.getBuffer() });
        if (res.error) throw res.error;

        const events = res.events ?? [];
        const evt = events.find(
            (e) => e.type === 'FeesWithdrawn' || e.eventType === 'FeesWithdrawn',
        );
        Assert.expect(evt !== undefined).toEqual(true);

        const data = (evt!.data ?? evt!.eventData)!;
        // Layout: flowId(32) token(32) to(32) by(32) amount(32) = 160 bytes.
        Assert.expect(data.length).toEqual(32 * 5);
        let amount = 0n;
        for (let i = 128; i < 160; i++) amount = (amount << 8n) | BigInt(data[i]!);
        Assert.expect(amount).toEqual(2_000n);
    });
});
