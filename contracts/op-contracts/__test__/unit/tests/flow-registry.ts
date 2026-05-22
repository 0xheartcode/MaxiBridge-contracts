/**
 * BridgeDepository — PR α FlowRegistry storage + governance tests.
 *
 * Mirrors `contracts/evm-contracts/test/FlowRegistry.t.sol` (29 cases).
 * Storage and admin layer only — no claim / lock / burn paths consume
 * flow data yet (PR γ does that).
 *
 * Run: cd contracts/op-contracts && npm run build && npx tsx __test__/unit/tests/flow-registry.ts
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address } from '@btc-vision/transaction';

import { BridgeDepository } from '../contracts/BridgeDepository.js';

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

const deployer: Address = Blockchain.generateRandomAddress();
const stranger: Address = Blockchain.generateRandomAddress();

function setSender(addr: Address): void {
    Blockchain.msgSender = addr;
    Blockchain.txOrigin = addr;
}

const ETH_CHAIN_ID: bigint = 1n;
const ARB_CHAIN_ID: bigint = 42161n;

// Synthetic placeholder addresses (u256 values; low 20 bytes = EVM addr,
// full 32 bytes for OPNet). The exact values don't matter for the
// registry — only that they're non-zero and distinct.
const EVM_BRIDGE: bigint = 0x000000000000000000000000_e5c0e5c0e5c0e5c0e5c0e5c0e5c0e5c0e5c0e5c0n;
const EVM_USDC: bigint = 0x000000000000000000000000_a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48n;
const EVM_USDT: bigint = 0x000000000000000000000000_dac17f958d2ee523a2206206994597c13d831ec7n;
const OPNET_BRIDGE: bigint = 0xdeadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafen;
const OPNET_WUSDC: bigint = 0xc0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0fen;
const OPNET_WUSDT: bigint = 0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefn;

const STATUS_DISABLED = 0n;
const STATUS_ACTIVE = 1n;
const STATUS_PAUSED = 2n;
const STATUS_DRAINING = 3n;

async function setupDepository(): Promise<BridgeDepository> {
    const depositoryAddress = Blockchain.generateRandomAddress();
    const depository = new BridgeDepository({
        file: './build/BridgeDepository.wasm',
        address: depositoryAddress,
        deployer,
    });
    Blockchain.register(depository);
    await depository.init();
    setSender(deployer);
    return depository;
}

function defaultParams(evmToken: bigint, opnetToken: bigint, mode: bigint = 0n, chainId: bigint = ETH_CHAIN_ID) {
    return {
        mode,
        chainId,
        evmBridge: EVM_BRIDGE,
        evmToken,
        evmDecimals: 6n,
        opnetBridge: OPNET_BRIDGE,
        opnetToken,
        opnetDecimals: 6n,
        feeBps: 50n,
        minFee: 0n,
        minAmount: 1_000_000n, // 1 USDC
        cap: 1_000_000_000_000n, // 1M USDC
        dailyLimit: 100_000_000_000n, // 100k USDC
    };
}

async function expectRevert(fn: () => Promise<unknown>, msg = ''): Promise<void> {
    try {
        await fn();
        throw new Error(`expected revert${msg ? ' (' + msg + ')' : ''} but call succeeded`);
    } catch (e) {
        // ok
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// computeFlowId
// ─────────────────────────────────────────────────────────────────────────────

await opnet('BridgeDepository — PR α — computeFlowId', async (vm: OPNetUnit) => {
    let depository: BridgeDepository;

    vm.beforeEach(async () => {
        depository = await setupDepository();
    });

    vm.afterAll(async () => {
        depository.dispose();
    });

    await vm.it('is deterministic', async () => {
        const a = await depository.computeFlowId(0n, ETH_CHAIN_ID, EVM_BRIDGE, EVM_USDC, OPNET_BRIDGE, OPNET_WUSDC);
        const b = await depository.computeFlowId(0n, ETH_CHAIN_ID, EVM_BRIDGE, EVM_USDC, OPNET_BRIDGE, OPNET_WUSDC);
        Assert.expect(a).toEqual(b);
    });

    await vm.it('differs by mode', async () => {
        const a = await depository.computeFlowId(0n, ETH_CHAIN_ID, EVM_BRIDGE, EVM_USDC, OPNET_BRIDGE, OPNET_WUSDC);
        const b = await depository.computeFlowId(2n, ETH_CHAIN_ID, EVM_BRIDGE, EVM_USDC, OPNET_BRIDGE, OPNET_WUSDC);
        Assert.expect(a !== b).toEqual(true);
    });

    await vm.it('differs by source chain', async () => {
        const a = await depository.computeFlowId(0n, ETH_CHAIN_ID, EVM_BRIDGE, EVM_USDC, OPNET_BRIDGE, OPNET_WUSDC);
        const b = await depository.computeFlowId(0n, ARB_CHAIN_ID, EVM_BRIDGE, EVM_USDC, OPNET_BRIDGE, OPNET_WUSDC);
        Assert.expect(a !== b).toEqual(true);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// addFlow — happy path + validation
// ─────────────────────────────────────────────────────────────────────────────

await opnet('BridgeDepository — PR α — addFlow', async (vm: OPNetUnit) => {
    let depository: BridgeDepository;

    vm.beforeEach(async () => {
        depository = await setupDepository();
    });

    vm.afterAll(async () => {
        depository.dispose();
    });

    await vm.it('happy path — record populated, count incremented, exists=true', async () => {
        const flowId = await depository.addFlow(defaultParams(EVM_USDC, OPNET_WUSDC));
        Assert.expect(flowId !== 0n).toEqual(true);
        Assert.expect(await depository.flowExists(flowId)).toEqual(true);
        Assert.expect(await depository.flowCount()).toEqual(1n);

        const f = await depository.getFlow(flowId);
        Assert.expect(f[0]).toEqual(0n); // mode
        Assert.expect(f[1]).toEqual(STATUS_ACTIVE); // status
        Assert.expect(f[2]).toEqual(ETH_CHAIN_ID);
        Assert.expect(f[5]).toEqual(6n); // evmDecimals
        Assert.expect(f[8]).toEqual(6n); // opnetDecimals
        Assert.expect(f[9]).toEqual(50n); // feeBps
        Assert.expect(f[11]).toEqual(1_000_000n); // minAmount
        Assert.expect(f[12]).toEqual(1_000_000_000_000n); // cap
        Assert.expect(f[13]).toEqual(100_000_000_000n); // dailyLimit
        Assert.expect(f[14]).toEqual(0n); // mintedToday
        Assert.expect(f[16]).toEqual(0n); // inventory
    });

    await vm.it('rejects duplicate', async () => {
        await depository.addFlow(defaultParams(EVM_USDC, OPNET_WUSDC));
        await expectRevert(() => depository.addFlow(defaultParams(EVM_USDC, OPNET_WUSDC)), 'duplicate');
    });

    await vm.it('rejects non-governor', async () => {
        setSender(stranger);
        await expectRevert(() => depository.addFlow(defaultParams(EVM_USDC, OPNET_WUSDC)), 'non-gov');
    });

    await vm.it('accepts mode 4 (POOLED_LOCK_VEST)', async () => {
        const p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.mode = 4n;
        const flowId = await depository.addFlow(p);
        Assert.expect(flowId !== 0n).toEqual(true);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[0]).toEqual(4n); // mode == POOLED_LOCK_VEST
    });

    await vm.it('rejects invalid mode', async () => {
        const p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.mode = 5n;
        await expectRevert(() => depository.addFlow(p), 'mode>4');
    });

    await vm.it('rejects zero chainId', async () => {
        const p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.chainId = 0n;
        await expectRevert(() => depository.addFlow(p), 'chainId=0');
    });

    await vm.it('rejects zero EVM addrs', async () => {
        let p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.evmBridge = 0n;
        await expectRevert(() => depository.addFlow(p), 'evmBridge=0');

        p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.evmToken = 0n;
        await expectRevert(() => depository.addFlow(p), 'evmToken=0');
    });

    await vm.it('rejects zero OPNet addrs', async () => {
        let p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.opnetBridge = 0n;
        await expectRevert(() => depository.addFlow(p), 'opnetBridge=0');

        p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.opnetToken = 0n;
        await expectRevert(() => depository.addFlow(p), 'opnetToken=0');
    });

    await vm.it('rejects bad decimals', async () => {
        let p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.evmDecimals = 0n;
        await expectRevert(() => depository.addFlow(p), 'evmDecimals=0');

        p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.evmDecimals = 31n;
        await expectRevert(() => depository.addFlow(p), 'evmDecimals=31');

        p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.opnetDecimals = 0n;
        await expectRevert(() => depository.addFlow(p), 'opnetDecimals=0');
    });

    await vm.it('rejects bps too high', async () => {
        const p = defaultParams(EVM_USDC, OPNET_WUSDC);
        p.feeBps = 1001n;
        await expectRevert(() => depository.addFlow(p), 'bps>1000');
    });

    await vm.it('allows multi-chain same OPNet token', async () => {
        const a = await depository.addFlow(defaultParams(EVM_USDT, OPNET_WUSDT));
        const b = await depository.addFlow(defaultParams(EVM_USDT, OPNET_WUSDT, 0n, ARB_CHAIN_ID));
        Assert.expect(a !== b).toEqual(true);
        Assert.expect(await depository.flowCount()).toEqual(2n);
    });

    await vm.it('allows multi-mode same (chain, token)', async () => {
        const a = await depository.addFlow(defaultParams(EVM_USDT, OPNET_WUSDT));
        const b = await depository.addFlow(defaultParams(EVM_USDT, OPNET_WUSDT, 3n));
        Assert.expect(a !== b).toEqual(true);
        Assert.expect(await depository.flowCount()).toEqual(2n);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// pause / resume / drain status transitions
// ─────────────────────────────────────────────────────────────────────────────

await opnet('BridgeDepository — PR α — status transitions', async (vm: OPNetUnit) => {
    let depository: BridgeDepository;
    let flowId: bigint;

    vm.beforeEach(async () => {
        depository = await setupDepository();
        flowId = await depository.addFlow(defaultParams(EVM_USDC, OPNET_WUSDC));
    });

    vm.afterAll(async () => {
        depository.dispose();
    });

    await vm.it('pauseFlow — governor only', async () => {
        setSender(stranger);
        await expectRevert(() => depository.pauseFlow(flowId), 'non-gov');

        setSender(deployer);
        await depository.pauseFlow(flowId);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[1]).toEqual(STATUS_PAUSED);
    });

    await vm.it('pauseFlow — rejects unknown flowId', async () => {
        await expectRevert(() => depository.pauseFlow(0xdeadbeefn), 'unknown');
    });

    await vm.it('pauseFlow — rejects already paused', async () => {
        await depository.pauseFlow(flowId);
        await expectRevert(() => depository.pauseFlow(flowId), 'already paused');
    });

    await vm.it('resumeFlow — paused → active', async () => {
        await depository.pauseFlow(flowId);
        await depository.resumeFlow(flowId);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[1]).toEqual(STATUS_ACTIVE);
    });

    await vm.it('resumeFlow — rejects from active', async () => {
        await expectRevert(() => depository.resumeFlow(flowId), 'not paused');
    });

    await vm.it('drainFlow — one-way (no resume back)', async () => {
        await depository.drainFlow(flowId);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[1]).toEqual(STATUS_DRAINING);

        await expectRevert(() => depository.resumeFlow(flowId), 'no resume from draining');
        await expectRevert(() => depository.pauseFlow(flowId), 'no pause from draining');
    });

    await vm.it('drainFlow — allowed from paused', async () => {
        await depository.pauseFlow(flowId);
        await depository.drainFlow(flowId);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[1]).toEqual(STATUS_DRAINING);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// setFlowCap / setFlowDailyLimit / setFlowMinAmount / setFlowFee
// ─────────────────────────────────────────────────────────────────────────────

await opnet('BridgeDepository — PR α — flow setters', async (vm: OPNetUnit) => {
    let depository: BridgeDepository;
    let flowId: bigint;

    vm.beforeEach(async () => {
        depository = await setupDepository();
        flowId = await depository.addFlow(defaultParams(EVM_USDC, OPNET_WUSDC));
    });

    vm.afterAll(async () => {
        depository.dispose();
    });

    await vm.it('setFlowCap — governor only, updates value', async () => {
        setSender(stranger);
        await expectRevert(() => depository.setFlowCap(flowId, 5_000_000n), 'non-gov');

        setSender(deployer);
        await depository.setFlowCap(flowId, 5_000_000n);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[12]).toEqual(5_000_000n);
    });

    await vm.it('setFlowCap — accepts cap=0 when inventory=0 (PR γ checks the lt)', async () => {
        await depository.setFlowCap(flowId, 0n);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[12]).toEqual(0n);
    });

    await vm.it('setFlowDailyLimit — allows zero', async () => {
        await depository.setFlowDailyLimit(flowId, 0n);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[13]).toEqual(0n);
    });

    await vm.it('setFlowMinAmount — rejects unknown flowId', async () => {
        await expectRevert(() => depository.setFlowMinAmount(0xdeadbeefn, 1n), 'unknown');
    });

    await vm.it('setFlowFee — rejects bps>1000', async () => {
        await expectRevert(() => depository.setFlowFee(flowId, 1001n, 0n), 'bps>1000');
    });

    await vm.it('setFlowFee — happy path updates both fields', async () => {
        await depository.setFlowFee(flowId, 75n, 1_000n);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[9]).toEqual(75n); // feeBps
        Assert.expect(f[10]).toEqual(1_000n); // minFee
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Read-only views
// ─────────────────────────────────────────────────────────────────────────────

await opnet('BridgeDepository — PR α — read views', async (vm: OPNetUnit) => {
    let depository: BridgeDepository;

    vm.beforeEach(async () => {
        depository = await setupDepository();
    });

    vm.afterAll(async () => {
        depository.dispose();
    });

    await vm.it('flowExists — false before add', async () => {
        const flowId = await depository.computeFlowId(0n, ETH_CHAIN_ID, EVM_BRIDGE, EVM_USDC, OPNET_BRIDGE, OPNET_WUSDC);
        Assert.expect(await depository.flowExists(flowId)).toEqual(false);
    });

    await vm.it('flowCount — starts at zero', async () => {
        Assert.expect(await depository.flowCount()).toEqual(0n);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// PR β.2.scaffold — per-flow tipCapBps storage + governance
// ─────────────────────────────────────────────────────────────────────────────

await opnet('BridgeDepository — PR β.2.scaffold — tipCapBps', async (vm: OPNetUnit) => {
    let depository: BridgeDepository;
    let flowId: bigint;

    vm.beforeEach(async () => {
        depository = await setupDepository();
    });

    vm.afterAll(async () => {
        depository.dispose();
    });

    await vm.it('addFlow — default tipCapBps is zero', async () => {
        flowId = await depository.addFlow(defaultParams(EVM_USDC, OPNET_WUSDC));
        const f = await depository.getFlow(flowId);
        Assert.expect(f[17]).toEqual(0n); // tipCapBps appended at index 17
    });

    await vm.it('addFlow — tipCapBps above 200 reverts', async () => {
        const p = { ...defaultParams(EVM_USDC, OPNET_WUSDC), tipCapBps: 201n };
        await expectRevert(() => depository.addFlow(p), 'tipCapBps>200');
    });

    await vm.it('addFlow — tipCapBps at MAX_TIP_BPS (200) succeeds', async () => {
        const p = { ...defaultParams(EVM_USDC, OPNET_WUSDC), tipCapBps: 200n };
        flowId = await depository.addFlow(p);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[17]).toEqual(200n);
    });

    await vm.it('setFlowTipCap — governor only', async () => {
        flowId = await depository.addFlow(defaultParams(EVM_USDC, OPNET_WUSDC));
        setSender(stranger);
        await expectRevert(() => depository.setFlowTipCap(flowId, 100n), 'non-gov');
    });

    await vm.it('setFlowTipCap — happy path updates value', async () => {
        flowId = await depository.addFlow(defaultParams(EVM_USDC, OPNET_WUSDC));
        await depository.setFlowTipCap(flowId, 100n);
        const f = await depository.getFlow(flowId);
        Assert.expect(f[17]).toEqual(100n);
    });

    await vm.it('setFlowTipCap — above MAX_TIP_BPS reverts', async () => {
        flowId = await depository.addFlow(defaultParams(EVM_USDC, OPNET_WUSDC));
        await expectRevert(() => depository.setFlowTipCap(flowId, 201n), 'tipCapBps>200');
    });

    await vm.it('setFlowTipCap — unknown flowId reverts', async () => {
        await expectRevert(() => depository.setFlowTipCap(0xdeadbeefn, 50n), 'unknown');
    });
});
