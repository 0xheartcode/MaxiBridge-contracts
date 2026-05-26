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
 * The #44 section at the foot of this file covers the flow-scoped OPNet
 * inventory lifecycle end-to-end: provision / drain (mode 3) and the
 * lockForBridge → claimReleaseWithVoucher round trip (mode 1).
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
const VOUCHER_PREIMAGE_LEN = 540; // #68 Tier B — appended flowId u256
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
    flowId?: bigint; // #68 Tier B
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
    w.writeU256(v.flowId ?? _lastRegisteredFlowId); // #68 Tier B — appended LAST

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

// #68 Tier B — last-registered flowId; buildVoucher uses it as the default
// flowId so vouchers bind to the flow the test just registered.
let _lastRegisteredFlowId: bigint = 0n;

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
    const flowId = await setup.depository.addFlow({
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
    _lastRegisteredFlowId = flowId; // #68 Tier B
    return flowId;
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

    await vm.it('M-02: cap is NOT enforced on the mint path (cumulative > cap succeeds)', async () => {
        // M-02 removed the per-flow `cap` ceiling on mint-on-OPNet modes
        // (it acted as a LIFETIME limit that permanently bricked the flow).
        // cap = 1_500_000 but two 1_000_000-gross mints (cumulative
        // 2_000_000 > cap) must BOTH succeed — the rolling dailyLimit is
        // the only mint bound now.
        await registerFlow(setup, { cap: 1_500_000n, dailyLimit: 1_000_000_000_000n });
        const { depository, signerWallet } = setup;
        const f1 = { ...defaultFields(setup, alice, 0xc1n) };
        const v1 = buildVoucher(f1);
        setSender(alice);
        await depository.claimMintWithVoucher(v1.preimage, signVoucher(signerWallet, v1.hash));
        const f2 = { ...defaultFields(setup, alice, 0xc2n) };
        const v2 = buildVoucher(f2);
        // Pre-M-02 this reverted 'flow cap exceeded'. Now it must succeed.
        await depository.claimMintWithVoucher(v2.preimage, signVoucher(signerWallet, v2.hash));
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

    await vm.it('M-02: mint path does NOT increment _flowInventory (stays 0)', async () => {
        // M-02 — mint-on-OPNet modes no longer touch `_flowInventory`.
        // After three mints the flow's inventory ledger (getFlow index 16)
        // must still read 0 — "not tracked on this side". The cap is set
        // far below cumulative volume to also prove cap is unenforced.
        const flowId = await registerFlow(setup, {
            cap: 2_000_000n,
            dailyLimit: 1_000_000_000_000n,
        });
        const { depository, signerWallet } = setup;
        setSender(alice);
        const f1 = { ...defaultFields(setup, alice, 0xf1n) };
        const v1 = buildVoucher(f1);
        await depository.claimMintWithVoucher(v1.preimage, signVoucher(signerWallet, v1.hash));
        const f2 = { ...defaultFields(setup, alice, 0xf2n) };
        const v2 = buildVoucher(f2);
        await depository.claimMintWithVoucher(v2.preimage, signVoucher(signerWallet, v2.hash));
        const f3 = { ...defaultFields(setup, alice, 0xf3n) };
        const v3 = buildVoucher(f3);
        // Cumulative gross 3_000_000 > cap 2_000_000 — still succeeds.
        await depository.claimMintWithVoucher(v3.preimage, signVoucher(signerWallet, v3.hash));

        const flow = await depository.getFlow(flowId);
        Assert.expect(flow[16]!).toEqual(0n); // index 16 = inventory
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

// ════════════════════════════════════════════════════════════════════════════
// #44 — flow-scoped OPNet inventory.
//
// Regression cover for the OPNet half of audit issue #44. The inventory
// ledger MUST move atomically with token custody:
//   - provisionInventoryOpNet / drainInventoryOpNet (mode 3, POOLED) are
//     flow-scoped and credit / debit `_flowInventory` in the same call as
//     the token transfer.
//   - lockForBridge is the SOLE mode-1 (INVERSE_WRAPPED) inventory
//     producer; claimReleaseWithVoucher consumes it. confirmBurn no longer
//     increments mode-1 inventory (that double-count is removed).
// ════════════════════════════════════════════════════════════════════════════

const MODE1_EVM_COUNTERPART: bigint =
    0xc0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0fen;

function releaseSelector(): number {
    const enc = new TextEncoder();
    const b = sha256(enc.encode('claimReleaseWithVoucher(bytes,bytes)'));
    return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
}

await opnet('BridgeDepository — #44 — provision / drain inventory (mode 3 POOLED)',
    async (vm: OPNetUnit) => {
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

        await vm.it('provision moves tokens AND inventory atomically; drain reverses it', async () => {
            const flowId = await registerFlow(setup, { mode: 3n, cap: 10_000_000n });
            const { depository, wusdc, wusdcAddress, depositoryAddress } = setup;

            // Fund the governor with canonical wUSDC + approve the depository.
            setSender(depositoryAddress);
            await wusdc.mintTo(deployer, 5_000_000n);
            await wusdc.increaseAllowance(deployer, depositoryAddress, 5_000_000n);

            // Provision 3_000_000 — ledger + custody move together.
            setSender(deployer);
            await depository.provisionInventoryOpNet(flowId, wusdcAddress, 3_000_000n);
            let flow = await depository.getFlow(flowId);
            Assert.expect(flow[16]!).toEqual(3_000_000n); // index 16 = inventory
            Assert.expect(await wusdc.balanceOf(depositoryAddress)).toEqual(3_000_000n);

            // Drain 1_000_000 back out — requires the bridge paused.
            await depository.setPaused(true);
            await depository.drainInventoryOpNet(flowId, wusdcAddress, 1_000_000n, deployer);
            flow = await depository.getFlow(flowId);
            Assert.expect(flow[16]!).toEqual(2_000_000n);
            Assert.expect(await wusdc.balanceOf(depositoryAddress)).toEqual(2_000_000n);
        });

        await vm.it('provision past cap reverts', async () => {
            const flowId = await registerFlow(setup, { mode: 3n, cap: 2_000_000n });
            const { depository, wusdc, wusdcAddress, depositoryAddress } = setup;
            setSender(depositoryAddress);
            await wusdc.mintTo(deployer, 5_000_000n);
            await wusdc.increaseAllowance(deployer, depositoryAddress, 5_000_000n);
            setSender(deployer);
            await Assert.expect(async () => {
                await depository.provisionInventoryOpNet(flowId, wusdcAddress, 3_000_000n);
            }).toThrow();
        });

        await vm.it('drain past recorded inventory reverts', async () => {
            const flowId = await registerFlow(setup, { mode: 3n, cap: 10_000_000n });
            const { depository, wusdc, wusdcAddress, depositoryAddress } = setup;
            setSender(depositoryAddress);
            await wusdc.mintTo(deployer, 5_000_000n);
            await wusdc.increaseAllowance(deployer, depositoryAddress, 5_000_000n);
            setSender(deployer);
            await depository.provisionInventoryOpNet(flowId, wusdcAddress, 1_000_000n);
            await depository.setPaused(true);
            await Assert.expect(async () => {
                await depository.drainInventoryOpNet(flowId, wusdcAddress, 2_000_000n, deployer);
            }).toThrow();
        });

        await vm.it('provision rejects unknown flow / non-provisionable mode / wrong token', async () => {
            const { depository, wusdc, wusdcAddress, depositoryAddress } = setup;
            setSender(depositoryAddress);
            await wusdc.mintTo(deployer, 5_000_000n);
            await wusdc.increaseAllowance(deployer, depositoryAddress, 5_000_000n);
            setSender(deployer);

            // Unknown flowId.
            await Assert.expect(async () => {
                await depository.provisionInventoryOpNet(0xdeadn, wusdcAddress, 1n);
            }).toThrow();

            // Mode-0 (WRAPPED) flow has no OPNet pool — not provisionable.
            const mode0 = await registerFlow(setup, { mode: 0n });
            await Assert.expect(async () => {
                await depository.provisionInventoryOpNet(mode0, wusdcAddress, 1n);
            }).toThrow();

            // Wrong token (not the flow's registered canonical OPNet token).
            const mode3 = await registerFlow(setup, {
                mode: 3n,
                sourceBridgeAddr: Blockchain.generateRandomAddress(),
                sourceTokenAddr: Blockchain.generateRandomAddress(),
            });
            const notCanonical = Blockchain.generateRandomAddress();
            await Assert.expect(async () => {
                await depository.provisionInventoryOpNet(mode3, notCanonical, 1n);
            }).toThrow();
        });
    });

await opnet('BridgeDepository — #44 — lockForBridge → claimReleaseWithVoucher (mode 1)',
    async (vm: OPNetUnit) => {
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

        await vm.it('lock credits inventory; release draws it down; over-release reverts', async () => {
            const { depository, wusdc, wusdcAddress, depositoryAddress, signerWallet } = setup;
            const releaseSrcBridge = Blockchain.generateRandomAddress();
            const releaseSrcToken = Blockchain.generateRandomAddress();

            // Flip the canonical OPNet token to INVERSE_WRAPPED (mode 1).
            await depository.setTokenMode(wusdcAddress, 1n, MODE1_EVM_COUNTERPART);
            const flowId = await registerFlow(setup, {
                mode: 1n,
                sourceBridgeAddr: releaseSrcBridge,
                sourceTokenAddr: releaseSrcToken,
            });

            // Give alice a canonical balance + approve the depository.
            setSender(depositoryAddress);
            await wusdc.mintTo(alice, 4_000_000n);
            await wusdc.increaseAllowance(alice, depositoryAddress, 4_000_000n);

            // lockForBridge — the SOLE mode-1 inventory producer. evmRecipient
            // is a left-padded EVM address (upper 12 bytes zero). Default
            // feeBps for registerFlow is 50 (0.5%), so 3_000_000 lock accrues
            // a 15_000 fee and credits 2_985_000 NET to inventory (HIGH-002).
            const evmRecipient = new Uint8Array(32);
            for (let i = 12; i < 32; i++) evmRecipient[i] = 0xab;
            setSender(alice);
            await depository.lockForBridge(flowId, wusdcAddress, 3_000_000n, evmRecipient, 1);

            let flow = await depository.getFlow(flowId);
            Assert.expect(flow[16]!).toEqual(2_985_000n); // inventory == net (received - fee)

            // claimReleaseWithVoucher draws the ledger down by grossAmount.
            const buildRelease = (salt: bigint, gross: bigint, fee: bigint, net: bigint) =>
                buildVoucher({
                    contractSelf: depositoryAddress,
                    selector: releaseSelector(),
                    recipient: alice,
                    sourceBridgeAddr: releaseSrcBridge,
                    sourceTokenAddr: releaseSrcToken,
                    sourceTxHash: salt,
                    sourceLogIndex: Number(salt & 0xffffn),
                    wrappedToken: wusdcAddress,
                    grossAmount: gross,
                    feeAmount: fee,
                    netAmount: net,
                    voucherId: salt,
                });

            const r1 = buildRelease(0x7001n, 1_000_000n, 5_000n, 995_000n);
            await depository.claimReleaseWithVoucher(r1.preimage, signVoucher(signerWallet, r1.hash));
            flow = await depository.getFlow(flowId);
            // 2_985_000 (post-HIGH-002 net credit) − 1_000_000 release = 1_985_000.
            Assert.expect(flow[16]!).toEqual(1_985_000n);

            // Over-release — grossAmount 2_000_000 > remaining inventory 1_985_000.
            // (Pre-fix used 2_500_000 against a 2_000_000 floor; the net credit
            //  lowers the floor by exactly the fee, so the over-release boundary
            //  shifts too.)
            const r2 = buildRelease(0x7002n, 2_000_000n, 10_000n, 1_990_000n);
            await Assert.expect(async () => {
                await depository.claimReleaseWithVoucher(
                    r2.preimage, signVoucher(signerWallet, r2.hash),
                );
            }).toThrow();
        });

        await vm.it('lockForBridge rejects an unknown flowId before any token moves', async () => {
            const { depository, wusdc, wusdcAddress, depositoryAddress } = setup;
            await depository.setTokenMode(wusdcAddress, 1n, MODE1_EVM_COUNTERPART);
            await registerFlow(setup, { mode: 1n });
            setSender(depositoryAddress);
            await wusdc.mintTo(alice, 4_000_000n);
            await wusdc.increaseAllowance(alice, depositoryAddress, 4_000_000n);
            const evmRecipient = new Uint8Array(32);
            for (let i = 12; i < 32; i++) evmRecipient[i] = 0xab;
            setSender(alice);
            await Assert.expect(async () => {
                await depository.lockForBridge(
                    0xbadf100dn, wusdcAddress, 1_000_000n, evmRecipient, 1,
                );
            }).toThrow();
        });
    });
