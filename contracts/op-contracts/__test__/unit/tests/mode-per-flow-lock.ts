/**
 * BridgeDepository — #68 mode-per-flow lock tests.
 *
 * Headline #68 capability: `lockForBridge` now reads the route mode from the
 * FLOW the caller names (`_flowMode[flowId]`), NOT from a per-token stamp
 * (`_tokenMode[canonical]`). The old `_flowMode == _tokenMode` cross-check is
 * gone, so ONE canonical OP20 token can be locked into TWO different-mode
 * pooled flows at once — e.g. the same (evmToken, opnetToken) pair registered
 * as BOTH mode 3 (POOLED_LOCK_RELEASE) and mode 4 (POOLED_LOCK_VEST), each
 * chosen per transfer by its distinct flowId.
 *
 * Pre-#68 the second lock reverted "flow mode mismatch". This suite proves
 * both locks now succeed, AND that the flow binding guards (token + chain +
 * existence + active) still hold.
 *
 * IMPORTANT: these tests deliberately do NOT call `setTokenMode` — the whole
 * point of #68 is that `lockForBridge` no longer depends on `_tokenMode`.
 *
 * Run: cd contracts/op-contracts && npm run build:depository &&
 *      npx tsx __test__/unit/tests/mode-per-flow-lock.ts
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

// Stable EVM-side identities shared by BOTH flows so the only differing
// addFlow field is `mode` — which is exactly what produces two distinct
// flowIds for the SAME (evmToken, opnetToken) pair.
const SOURCE_BRIDGE: Address = Blockchain.generateRandomAddress();
const SOURCE_TOKEN: Address = Blockchain.generateRandomAddress();

// Register a pooled flow on the shared (evmToken, opnetToken=wusdc) pair with
// the given mode. Returns the flowId. opnetToken is overridable for the
// negative "flow token mismatch" case.
async function registerFlow(
    setup: BridgeSetup,
    mode: bigint,
    opnetToken?: Address,
): Promise<bigint> {
    return await setup.depository.addFlow({
        mode,
        chainId: ETH_CHAIN_ID,
        evmBridge: evmAddrRightPadToBigInt(SOURCE_BRIDGE),
        evmToken: evmAddrRightPadToBigInt(SOURCE_TOKEN),
        evmDecimals: 6n,
        opnetBridge: opnetAddrToBigInt(setup.depositoryAddress),
        opnetToken: opnetAddrToBigInt(opnetToken ?? setup.wusdcAddress),
        opnetDecimals: 6n,
        feeBps: 50n,
        minFee: 0n,
        minAmount: 0n,
        cap: 1_000_000_000_000n,
        dailyLimit: 1_000_000_000_000n,
        tipCapBps: 0n,
    });
}

// Left-padded EVM recipient (upper 12 bytes zero), 20-byte addr in low bytes.
function evmRecipient(): Uint8Array {
    const r = new Uint8Array(32);
    for (let i = 12; i < 32; i++) r[i] = 0xab;
    return r;
}

// Fund alice with canonical wusdc and approve the depository for the lock pull.
async function fundAndApprove(setup: BridgeSetup, amount: bigint): Promise<void> {
    const { wusdc, wusdcAddress, depositoryAddress } = setup;
    setSender(depositoryAddress); // only the bridge can mintTo
    await wusdc.mintTo(alice, amount);
    await wusdc.increaseAllowance(alice, depositoryAddress, amount);
}

// ════════════════════════════════════════════════════════════════════════════
// #68 — one canonical token, two different-mode pooled flows
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository — #68 — mode-per-flow lock', async (vm: OPNetUnit) => {
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

    await vm.it('same (evmToken,opnetToken) pair locks into BOTH a mode-3 AND a mode-4 flow', async () => {
        const { depository, wusdcAddress } = setup;

        // Two flows differing ONLY by mode → distinct flowIds for one pair.
        // NO setTokenMode call: lock must no longer consult _tokenMode.
        const flow3 = await registerFlow(setup, 3n); // POOLED_LOCK_RELEASE
        const flow4 = await registerFlow(setup, 4n); // POOLED_LOCK_VEST
        Assert.expect(flow3 !== flow4).toEqual(true);

        await fundAndApprove(setup, 6_000_000n);
        setSender(alice);

        // Headline #68: both locks succeed. Pre-#68 the second reverted
        // "flow mode mismatch" because the token was pinned to one global mode.
        await depository.lockForBridge(flow3, wusdcAddress, 2_000_000n, evmRecipient(), 1);
        await depository.lockForBridge(flow4, wusdcAddress, 2_000_000n, evmRecipient(), 1);

        // Each flow accrued its own source-side fee independently — proof both
        // locks actually executed against their own flowId.
        Assert.expect(await depository.accruedFees(flow3)).toEqual(10_000n);
        Assert.expect(await depository.accruedFees(flow4)).toEqual(10_000n);
    });

    await vm.it('locking into a flow whose opnetToken != canonical reverts "flow token mismatch"', async () => {
        const { depository, wusdcAddress } = setup;

        // A mode-3 flow registered against a DIFFERENT opnet token than wusdc.
        const otherOpnetToken = Blockchain.generateRandomAddress();
        const wrongFlow = await registerFlow(setup, 3n, otherOpnetToken);

        await fundAndApprove(setup, 2_000_000n);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.lockForBridge(wrongFlow, wusdcAddress, 2_000_000n, evmRecipient(), 1);
        }).toThrow();
    });

    await vm.it('locking into a nonexistent flow reverts "flow not found"', async () => {
        const { depository, wusdcAddress } = setup;
        await fundAndApprove(setup, 2_000_000n);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.lockForBridge(0xdeadbeefn, wusdcAddress, 2_000_000n, evmRecipient(), 1);
        }).toThrow();
    });

    await vm.it('locking into a paused (inactive) flow reverts "flow not active"', async () => {
        const { depository, wusdcAddress } = setup;
        const flow3 = await registerFlow(setup, 3n);

        setSender(deployer);
        await depository.pauseFlow(flow3);

        await fundAndApprove(setup, 2_000_000n);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.lockForBridge(flow3, wusdcAddress, 2_000_000n, evmRecipient(), 1);
        }).toThrow();
    });
});
