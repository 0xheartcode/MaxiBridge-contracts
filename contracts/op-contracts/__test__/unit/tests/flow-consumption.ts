/**
 * BridgeDepository — PR γ.1 flow consumption tests.
 *
 * Mirrors EVM-side `FlowConsumption.t.sol`. Exercises per-flow knobs on the
 * OPNet claim paths:
 *   - status (ACTIVE only; PAUSED / DRAINING reject mint)
 *   - minAmount (gross-source floor)
 *   - cap (mint path: inventory + grossDst <= cap)
 *   - dailyLimit (rolling 24h window keyed off Blockchain.block.medianTimestamp)
 *   - inventory (mint path increments; release path checks ≥ grossDst)
 *
 * Mode-1 release happy paths require non-zero starting inventory, which is
 * γ.2 territory (burn-side / governor bootstrap). γ.1 tests cover the
 * insufficient-inventory revert for mode-1 release.
 *
 * Run: cd contracts/op-contracts && npm run build &&
 *      npx tsx __test__/unit/tests/flow-consumption.ts
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address, BinaryWriter, Wallet } from '@btc-vision/transaction';
import { sha256 } from '@noble/hashes/sha2.js';

import { WrappedOP20 } from '../contracts/WrappedOP20.js';
import { BridgeDepository } from '../contracts/BridgeDepository.js';

// ─── Constants — must mirror BridgeDepository.ts ──────────────────────
const VOUCHER_NETWORK_ID: bigint = 2n;
const CLAIM_MINT_WITH_VOUCHER_SELECTOR: number = 0x59893fe6;
const VOUCHER_PREIMAGE_LEN = 508;
const ETH_CHAIN_ID: bigint = 1n;
const FLOW_WINDOW_DURATION = 86400n;

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

// ─── Voucher helpers ──────────────────────────────────────────────────
interface VoucherFields {
    networkId?: bigint;
    contractSelf: Address;
    selector?: number;
    recipient: Address;
    sourceChainId?: bigint;
    sourceBridgeAddr?: Address;
    sourceTokenAddr?: Address;
    sourceTxHash: bigint;
    sourceLogIndex: number;
    sourceDepositNonce?: bigint;
    sourceBlockHash?: bigint;
    wrappedToken: Address;
    grossSrcAmount?: bigint;
    grossAmount: bigint;
    feeAmount: bigint;
    netAmount: bigint;
    relayerTip?: bigint;
    signerEpoch?: number;
    voucherId: bigint;
}

function writeU128BE(w: BinaryWriter, v: bigint): void {
    const buf = new Uint8Array(16);
    let x = v;
    for (let i = 15; i >= 0; i--) {
        buf[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    w.writeBytes(buf);
}

function buildVoucher(v: VoucherFields): { preimage: Uint8Array; hash: Uint8Array } {
    const w = new BinaryWriter();
    w.writeU256(v.networkId ?? VOUCHER_NETWORK_ID);
    w.writeAddress(v.contractSelf);
    w.writeSelector(v.selector ?? CLAIM_MINT_WITH_VOUCHER_SELECTOR);
    w.writeAddress(v.recipient);
    w.writeU256(v.sourceChainId ?? ETH_CHAIN_ID);
    w.writeAddress(v.sourceBridgeAddr ?? Blockchain.generateRandomAddress());
    w.writeAddress(v.sourceTokenAddr ?? Blockchain.generateRandomAddress());
    w.writeU256(v.sourceTxHash);
    w.writeU32(v.sourceLogIndex);
    w.writeU256(v.sourceDepositNonce ?? 0n);
    w.writeU256(v.sourceBlockHash ?? 0n);
    w.writeAddress(v.wrappedToken);
    w.writeU256(v.grossSrcAmount ?? v.grossAmount);
    w.writeU256(v.grossAmount);
    w.writeU256(v.feeAmount);
    w.writeU256(v.netAmount);
    writeU128BE(w, v.relayerTip ?? 0n);
    w.writeU32(v.signerEpoch ?? 1);
    w.writeU256(v.voucherId);

    const preimage = w.getBuffer();
    if (preimage.length !== VOUCHER_PREIMAGE_LEN) {
        throw new Error(
            `Voucher preimage length mismatch: got ${preimage.length}, expected ${VOUCHER_PREIMAGE_LEN}`,
        );
    }
    return { preimage, hash: sha256(preimage) };
}

function packSigBlob(pubKey: Uint8Array, rawSig: Uint8Array): Uint8Array {
    const total = 4 + 4 + pubKey.length + 4 + rawSig.length;
    const out = new Uint8Array(total);
    const view = new DataView(out.buffer);
    view.setUint32(0, 1, false);
    view.setUint32(4, pubKey.length, false);
    out.set(pubKey, 8);
    view.setUint32(8 + pubKey.length, rawSig.length, false);
    out.set(rawSig, 12 + pubKey.length);
    return out;
}

function signVoucher(wallet: Wallet, hash: Uint8Array): Uint8Array {
    const pubKey = new Uint8Array(wallet.mldsaKeypair.publicKey);
    const rawSig = wallet.mldsaKeypair.sign(hash);
    return packSigBlob(pubKey, rawSig);
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
    minAmount?: bigint;
    cap?: bigint;
    dailyLimit?: bigint;
    tipCapBps?: bigint;
}

async function registerFlow(setup: BridgeSetup, opts: FlowOpts = {}): Promise<bigint> {
    const sourceBridgeAddr = opts.sourceBridgeAddr ?? DEFAULT_SOURCE_BRIDGE;
    const sourceTokenAddr = opts.sourceTokenAddr ?? DEFAULT_SOURCE_TOKEN;
    return await setup.depository.addFlow({
        mode: opts.mode ?? 0n,
        chainId: ETH_CHAIN_ID,
        evmBridge: evmAddrRightPadToBigInt(sourceBridgeAddr),
        evmToken: evmAddrRightPadToBigInt(sourceTokenAddr),
        evmDecimals: 6n,
        opnetBridge: opnetAddrToBigInt(setup.depositoryAddress),
        opnetToken: opnetAddrToBigInt(setup.wusdcAddress),
        opnetDecimals: 6n,
        feeBps: 50n,
        minFee: 0n,
        minAmount: opts.minAmount ?? 0n,
        cap: opts.cap ?? 1_000_000_000_000n,
        dailyLimit: opts.dailyLimit ?? 100_000_000_000n,
        tipCapBps: opts.tipCapBps ?? 0n,
    });
}

function defaultFields(setup: BridgeSetup, recipient: Address, salt: bigint): VoucherFields {
    return {
        contractSelf: setup.depositoryAddress,
        recipient,
        sourceBridgeAddr: DEFAULT_SOURCE_BRIDGE,
        sourceTokenAddr: DEFAULT_SOURCE_TOKEN,
        sourceTxHash: salt,
        sourceLogIndex: Number(salt & 0xffffn),
        wrappedToken: setup.wusdcAddress,
        grossAmount: 1_000_000n,
        feeAmount: 5_000n,
        netAmount: 995_000n,
        voucherId: salt,
        signerEpoch: 1,
    };
}

// ════════════════════════════════════════════════════════════════════════════
// Mint path (claimMintWithVoucher) — flow consumption matrix
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository — PR γ.1 — flow consumption (mint path)', async (vm: OPNetUnit) => {
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

    await vm.it('grossSrcAmount below flow minAmount reverts', async () => {
        await registerFlow(setup, { minAmount: 2_000_000n });
        const { depository, signerWallet } = setup;
        // grossSrcAmount defaults to grossAmount (1_000_000) < minAmount.
        const fields = defaultFields(setup, alice, 0xa1n);
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }).toThrow();
    });

    await vm.it('grossSrcAmount at flow minAmount succeeds', async () => {
        await registerFlow(setup, { minAmount: 1_000_000n });
        const { depository, wusdc, signerWallet } = setup;
        const fields = defaultFields(setup, alice, 0xa2n);
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        Assert.expect(await wusdc.balanceOf(alice)).toEqual(fields.netAmount);
    });

    await vm.it('cap overflow on mint reverts', async () => {
        // cap = 1_500_000; first mint of 1_000_000 grossDst fits (inventory
        // becomes 1_000_000), second mint of 1_000_000 would push to
        // 2_000_000 > cap → revert.
        await registerFlow(setup, { cap: 1_500_000n });
        const { depository, signerWallet } = setup;
        const f1 = { ...defaultFields(setup, alice, 0xc1n) };
        const v1 = buildVoucher(f1);
        setSender(alice);
        await depository.claimMintWithVoucher(v1.preimage, signVoucher(signerWallet, v1.hash));
        const f2 = { ...defaultFields(setup, alice, 0xc2n) };
        const v2 = buildVoucher(f2);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(v2.preimage, signVoucher(signerWallet, v2.hash));
        }).toThrow();
    });

    await vm.it('dailyLimit first claim resets window and consumes', async () => {
        await registerFlow(setup, { dailyLimit: 5_000_000n });
        const { depository, wusdc, signerWallet } = setup;
        const fields = defaultFields(setup, alice, 0xd1n);
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        // First mint succeeds — 1_000_000 grossDst within 5_000_000 limit.
        Assert.expect(await wusdc.balanceOf(alice)).toEqual(fields.netAmount);
    });

    await vm.it('dailyLimit accumulates within window', async () => {
        await registerFlow(setup, { dailyLimit: 2_500_000n });
        const { depository, signerWallet } = setup;
        const f1 = { ...defaultFields(setup, alice, 0xd2n) };
        const v1 = buildVoucher(f1);
        setSender(alice);
        await depository.claimMintWithVoucher(v1.preimage, signVoucher(signerWallet, v1.hash));
        // Advance 1h — still inside window.
        Blockchain.medianTimestamp = 1_000_000n + 3600n;
        const f2 = { ...defaultFields(setup, alice, 0xd3n) };
        const v2 = buildVoucher(f2);
        await depository.claimMintWithVoucher(v2.preimage, signVoucher(signerWallet, v2.hash));
        // Bucket now at 2_000_000; a third 1_000_000 would push to 3_000_000 > 2_500_000.
        const f3 = { ...defaultFields(setup, alice, 0xd4n) };
        const v3 = buildVoucher(f3);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(v3.preimage, signVoucher(signerWallet, v3.hash));
        }).toThrow();
    });

    await vm.it('dailyLimit exceeded reverts', async () => {
        await registerFlow(setup, { dailyLimit: 500_000n });
        const { depository, signerWallet } = setup;
        const fields = defaultFields(setup, alice, 0xd5n);
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }).toThrow();
    });

    await vm.it('dailyLimit rolls over after 24h', async () => {
        await registerFlow(setup, { dailyLimit: 1_500_000n });
        const { depository, wusdc, signerWallet } = setup;
        const f1 = { ...defaultFields(setup, alice, 0xd6n) };
        const v1 = buildVoucher(f1);
        setSender(alice);
        await depository.claimMintWithVoucher(v1.preimage, signVoucher(signerWallet, v1.hash));
        // Advance > 24h — window rolls; bucket resets.
        Blockchain.medianTimestamp = 1_000_000n + FLOW_WINDOW_DURATION + 1n;
        const f2 = { ...defaultFields(setup, alice, 0xd7n) };
        const v2 = buildVoucher(f2);
        await depository.claimMintWithVoucher(v2.preimage, signVoucher(signerWallet, v2.hash));
        Assert.expect(await wusdc.balanceOf(alice)).toEqual(f1.netAmount + f2.netAmount);
    });

    await vm.it('status PAUSED rejects claim (tip-zero too)', async () => {
        const flowId = await registerFlow(setup);
        setSender(deployer);
        await setup.depository.pauseFlow(flowId);
        const { depository, signerWallet } = setup;
        const fields = { ...defaultFields(setup, alice, 0xe1n), relayerTip: 0n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }).toThrow();
    });

    await vm.it('status DRAINING rejects mint (winding down — no new mints)', async () => {
        const flowId = await registerFlow(setup);
        setSender(deployer);
        await setup.depository.drainFlow(flowId);
        const { depository, signerWallet } = setup;
        const fields = { ...defaultFields(setup, alice, 0xe2n), relayerTip: 0n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }).toThrow();
    });

    await vm.it('inventory growth tracked across mints (cap-tight invariant)', async () => {
        // Register a tight cap = 2_000_000 — fits two 1_000_000 grossDst
        // mints. Cumulative inventory after both is 2_000_000 (== cap).
        // A third mint of any positive grossDst must revert. This proves
        // inventory increments by grossDst on every mint.
        await registerFlow(setup, { cap: 2_000_000n });
        const { depository, signerWallet } = setup;
        setSender(alice);
        const f1 = { ...defaultFields(setup, alice, 0xf1n) };
        const v1 = buildVoucher(f1);
        await depository.claimMintWithVoucher(v1.preimage, signVoucher(signerWallet, v1.hash));
        const f2 = { ...defaultFields(setup, alice, 0xf2n) };
        const v2 = buildVoucher(f2);
        await depository.claimMintWithVoucher(v2.preimage, signVoucher(signerWallet, v2.hash));
        // Third mint — would push inventory to 3_000_000 > 2_000_000 cap.
        const f3 = { ...defaultFields(setup, alice, 0xf3n) };
        const v3 = buildVoucher(f3);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(v3.preimage, signVoucher(signerWallet, v3.hash));
        }).toThrow();
    });
});

// ════════════════════════════════════════════════════════════════════════════
// Release path (claimReleaseWithVoucher) — γ.1 enforces revert on
// insufficient inventory. Happy paths require γ.2 inventory bootstrap.
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository — PR γ.1 — flow consumption (release path)', async (vm: OPNetUnit) => {
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

    // Mode-1 inverse-wrapped release: inventory bootstrap is γ.2 territory.
    // γ.1 surface here is the new InsufficientFlowInventory revert when
    // inventory < grossDst. Covered alongside the existing relayer-tip
    // suite (`relayer-tip-opnet.ts`); we duplicate the assertion here
    // so the γ.1-specific failure mode is explicit in this file.
    //
    // Status / minAmount / dailyLimit checks are evaluated BEFORE the
    // inventory check, so we cover those branches too.

    await vm.it('release: status PAUSED reverts before inventory check', async () => {
        // Mode-1 flow with a paused status — guardian-style freeze.
        // claimReleaseWithVoucher should reject at the status gate.
        const releaseSrcBridge = Blockchain.generateRandomAddress();
        const releaseSrcToken = Blockchain.generateRandomAddress();
        const flowId = await registerFlow(setup, {
            mode: 1n,
            sourceBridgeAddr: releaseSrcBridge,
            sourceTokenAddr: releaseSrcToken,
        });
        setSender(deployer);
        await setup.depository.pauseFlow(flowId);
        // Build a voucher; we expect a revert from the status check.
        const releaseSelector = ((): number => {
            const enc = new TextEncoder();
            const b = sha256(enc.encode('claimReleaseWithVoucher(bytes,bytes)'));
            return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
        })();
        const fields: VoucherFields = {
            contractSelf: setup.depositoryAddress,
            selector: releaseSelector,
            recipient: alice,
            sourceBridgeAddr: releaseSrcBridge,
            sourceTokenAddr: releaseSrcToken,
            sourceTxHash: 0xfeed42n,
            sourceLogIndex: 1,
            wrappedToken: setup.wusdcAddress,
            grossAmount: 1_000_000n,
            feeAmount: 5_000n,
            netAmount: 995_000n,
            relayerTip: 0n,
            voucherId: 0xb42n,
        };
        const { preimage, hash } = buildVoucher(fields);
        const { ABIDataTypes } = await import('@btc-vision/transaction');
        const { encodeSelectorWithParams } = await import('../contracts/utils.js');
        const sel = encodeSelectorWithParams(
            'claimReleaseWithVoucher',
            ABIDataTypes.BYTES,
            ABIDataTypes.BYTES,
        );
        const w = new BinaryWriter();
        w.writeSelector(sel);
        w.writeBytesWithLength(preimage);
        w.writeBytesWithLength(signVoucher(setup.signerWallet, hash));
        setSender(alice);
        await Assert.expect(async () => {
            await (setup.depository as unknown as {
                execute: (a: { calldata: Uint8Array }) => Promise<{ error?: Error }>;
            })
                .execute({ calldata: w.getBuffer() })
                .then((r) => {
                    if (r.error) throw r.error;
                });
        }).toThrow();
    });
});
