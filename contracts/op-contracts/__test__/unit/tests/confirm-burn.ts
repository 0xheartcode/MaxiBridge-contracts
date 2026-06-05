/**
 * BridgeDepository.confirmBurn — M-of-N attestation tests (PR γ.2b).
 *
 * Coverage:
 *   ✓ confirmBurn mode-1 happy path is a pure attestation — valid M-of-N
 *     sigs set the replay guard but do NOT mutate flow inventory (#44 —
 *     the mode-1 ledger is owned by lockForBridge / claimReleaseWithVoucher)
 *   ✓ confirmBurn replay reverts (same depositId twice)
 *   ✓ confirmBurn with stale signerEpoch reverts
 *   ✓ confirmBurn with bad attestation length (≠ 252) reverts
 *   ✓ confirmBurn unknown flowId reverts
 *   ✓ confirmBurn on draining flow allowed (mode 1 — exit path)
 *   ✓ confirmBurn on inactive (paused) flow reverts
 *
 * The mode-1 lockForBridge → claimReleaseWithVoucher round trip lives in
 * flow-consumption.ts (confirmBurn no longer provisions mode-1 inventory).
 *
 * Note: tests use M=N=1 envelopes. Multi-signer envelopes are exercised in
 * the existing `bridge.ts` claimMintWithVoucher tests via packSigBlobMulti;
 * confirmBurn shares the same `_verifyMofN` helper so the M-of-N path is
 * already covered indirectly.
 *
 * Run: cd contracts/op-contracts && npm run build && \
 *      npx tsx __test__/unit/tests/confirm-burn.ts
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address, BinaryWriter, Wallet } from '@btc-vision/transaction';
import { sha256 } from '@noble/hashes/sha2.js';

import { WrappedOP20 } from '../contracts/WrappedOP20.js';
import { BridgeDepository } from '../contracts/BridgeDepository.js';

// ─── Constants — must mirror BridgeDepository.ts ──────────────────────────
const VOUCHER_NETWORK_ID: bigint = 2n;
const CLAIM_MINT_WITH_VOUCHER_SELECTOR: number = 0x6FBDC887; // sha256('claimWithVoucher(bytes,bytes)')[0:4]
const CONFIRM_BURN_SELECTOR: number = 0x9cffeea6;
const VOUCHER_PREIMAGE_LEN = 540; // #68 Tier B — appended flowId u256
const BURN_ATTESTATION_LEN = 252;
const ETH_CHAIN_ID: bigint = 1n;

// Both mint and release paths go through the unified claimWithVoucher entry point.
const CLAIM_RELEASE_WITH_VOUCHER_SELECTOR: number = 0x6FBDC887; // sha256('claimWithVoucher(bytes,bytes)')[0:4]

// ─── Harness ──────────────────────────────────────────────────────────────
const deployer: Address = Blockchain.generateRandomAddress();
const alice: Address = Blockchain.generateRandomAddress();

function setSender(addr: Address): void {
    Blockchain.msgSender = addr;
    Blockchain.txOrigin = addr;
}

interface Setup {
    depository: BridgeDepository;
    depositoryAddress: Address;
    wusdc: WrappedOP20;
    wusdcAddress: Address;
    signerWallet: Wallet;
}

async function setupContracts(): Promise<Setup> {
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

function dispose(s: Setup): void {
    s.depository.dispose();
    s.wusdc.dispose();
    Blockchain.dispose();
}

// ─── Helpers ──────────────────────────────────────────────────────────────

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

function writeU256BE(buf: Uint8Array, off: number, v: bigint): void {
    let x = v;
    for (let i = 31; i >= 0; i--) {
        buf[off + i] = Number(x & 0xffn);
        x >>= 8n;
    }
}

function writeU128BE_buf(buf: Uint8Array, off: number, v: bigint): void {
    let x = v;
    for (let i = 15; i >= 0; i--) {
        buf[off + i] = Number(x & 0xffn);
        x >>= 8n;
    }
}

function writeU32BE(buf: Uint8Array, off: number, v: number): void {
    buf[off] = (v >>> 24) & 0xff;
    buf[off + 1] = (v >>> 16) & 0xff;
    buf[off + 2] = (v >>> 8) & 0xff;
    buf[off + 3] = v & 0xff;
}

function writeAddress(buf: Uint8Array, off: number, addr: Address): void {
    const bytes = addr as unknown as Uint8Array;
    for (let i = 0; i < 32; i++) buf[off + i] = bytes[i]!;
}

interface AttestationFields {
    networkId?: bigint;
    contractSelf: Address;
    selector?: number;
    flowId: bigint;
    depositId: bigint;
    evmTxHash?: bigint;
    evmLogIndex?: number;
    releasedAmount: bigint;
    evmBlockHash?: bigint;
    signerEpoch?: number;
    relayerTip?: bigint;
}

function buildAttestation(f: AttestationFields): { preimage: Uint8Array; hash: Uint8Array } {
    const buf = new Uint8Array(BURN_ATTESTATION_LEN);
    writeU256BE(buf, 0, f.networkId ?? VOUCHER_NETWORK_ID);
    writeAddress(buf, 32, f.contractSelf);
    writeU32BE(buf, 64, f.selector ?? CONFIRM_BURN_SELECTOR);
    writeU256BE(buf, 68, f.flowId);
    writeU256BE(buf, 100, f.depositId);
    writeU256BE(buf, 132, f.evmTxHash ?? 0n);
    writeU32BE(buf, 164, f.evmLogIndex ?? 0);
    writeU256BE(buf, 168, f.releasedAmount);
    writeU256BE(buf, 200, f.evmBlockHash ?? 0n);
    writeU32BE(buf, 232, f.signerEpoch ?? 1);
    writeU128BE_buf(buf, 236, f.relayerTip ?? 0n);
    return { preimage: buf, hash: sha256(buf) };
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

function signAttestation(wallet: Wallet, hash: Uint8Array): Uint8Array {
    const pubKey = new Uint8Array(wallet.mldsaKeypair.publicKey);
    const rawSig = wallet.mldsaKeypair.sign(hash);
    return packSigBlob(pubKey, rawSig);
}

// Voucher helpers (same shape as bridge.ts).
interface VoucherFields {
    networkId?: bigint;
    contractSelf: Address;
    selector?: number;
    recipient: Address;
    sourceChainId?: bigint;
    sourceBridgeAddr: Address;
    sourceTokenAddr: Address;
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

function writeU128BE_writer(w: BinaryWriter, v: bigint): void {
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
    w.writeAddress(v.sourceBridgeAddr);
    w.writeAddress(v.sourceTokenAddr);
    w.writeU256(v.sourceTxHash);
    w.writeU32(v.sourceLogIndex);
    w.writeU256(v.sourceDepositNonce ?? 0n);
    w.writeU256(v.sourceBlockHash ?? 0n);
    w.writeAddress(v.wrappedToken);
    w.writeU256(v.grossSrcAmount ?? v.grossAmount);
    w.writeU256(v.grossAmount);
    w.writeU256(v.feeAmount);
    w.writeU256(v.netAmount);
    writeU128BE_writer(w, v.relayerTip ?? 0n);
    w.writeU32(v.signerEpoch ?? 1);
    w.writeU256(v.voucherId);
    w.writeU256(v.flowId ?? 0n); // #68 Tier B — appended LAST

    const preimage = w.getBuffer();
    if (preimage.length !== VOUCHER_PREIMAGE_LEN) {
        throw new Error(`bad voucher length: ${preimage.length}`);
    }
    return { preimage, hash: sha256(preimage) };
}

function signVoucher(wallet: Wallet, hash: Uint8Array): Uint8Array {
    const pubKey = new Uint8Array(wallet.mldsaKeypair.publicKey);
    const rawSig = wallet.mldsaKeypair.sign(hash);
    return packSigBlob(pubKey, rawSig);
}

// Register a flow given source addrs + mode. Returns flowId.
async function registerFlow(
    setup: Setup,
    opts: {
        mode: bigint;
        sourceBridgeAddr: Address;
        sourceTokenAddr: Address;
        cap?: bigint;
    },
): Promise<bigint> {
    return await setup.depository.addFlow({
        mode: opts.mode,
        chainId: ETH_CHAIN_ID,
        evmBridge: evmAddrRightPadToBigInt(opts.sourceBridgeAddr),
        evmToken: evmAddrRightPadToBigInt(opts.sourceTokenAddr),
        evmDecimals: 6n,
        opnetBridge: opnetAddrToBigInt(setup.depositoryAddress),
        opnetToken: opnetAddrToBigInt(setup.wusdcAddress),
        opnetDecimals: 6n,
        feeBps: 50n,
        minFee: 0n,
        minAmount: 0n,
        cap: opts.cap ?? 100_000_000_000n,
        dailyLimit: 50_000_000_000n,
        tipCapBps: 200n,
    });
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository.confirmBurn — happy path + replay + epoch + length',
    async (vm: OPNetUnit) => {
        let setup: Setup;
        let releaseSrcBridge: Address;
        let releaseSrcToken: Address;

        vm.beforeEach(async () => {
            Blockchain.dispose();
            Blockchain.clearContracts();
            await Blockchain.init();
            setSender(deployer);
            setup = await setupContracts();
            releaseSrcBridge = Blockchain.generateRandomAddress();
            releaseSrcToken = Blockchain.generateRandomAddress();
        });

        vm.afterEach(() => dispose(setup));

        await vm.it('mode-1 happy path is attestation-only — inventory unchanged', async () => {
            // #44 — confirmBurn for a mode-1 flow is a pure, replay-guarded
            // attestation. It MUST NOT touch flow inventory: the mode-1
            // ledger is produced by lockForBridge and consumed by
            // claimReleaseWithVoucher. A pre-#44 revision incremented here,
            // double-counting against lockForBridge.
            const flowId = await registerFlow(setup, {
                mode: 1n,
                sourceBridgeAddr: releaseSrcBridge,
                sourceTokenAddr: releaseSrcToken,
            });
            const depositId = 0xb01n;
            const releasedAmount = 1_500_000n;
            const { preimage, hash } = buildAttestation({
                contractSelf: setup.depositoryAddress,
                flowId,
                depositId,
                releasedAmount,
            });
            const sig = signAttestation(setup.signerWallet, hash);

            setSender(alice);
            await setup.depository.confirmBurn(depositId, preimage, sig);

            // Flow inventory must remain ZERO — confirmBurn mode-1 is
            // attestation-only. Layout index 16 = inventory.
            const flow = await setup.depository.getFlow(flowId);
            Assert.expect(flow[16]!).toEqual(0n);
            // The replay guard is still armed.
            Assert.expect(await setup.depository.isBurnConfirmed(flowId, depositId, 0n, 0n)).toEqual(true);
        });

        await vm.it('replay reverts (same depositId twice)', async () => {
            const flowId = await registerFlow(setup, {
                mode: 1n,
                sourceBridgeAddr: releaseSrcBridge,
                sourceTokenAddr: releaseSrcToken,
            });
            const depositId = 0xb02n;
            const { preimage, hash } = buildAttestation({
                contractSelf: setup.depositoryAddress,
                flowId,
                depositId,
                releasedAmount: 1_000_000n,
            });
            const sig = signAttestation(setup.signerWallet, hash);
            setSender(alice);
            await setup.depository.confirmBurn(depositId, preimage, sig);

            // Second call with same depositId reverts.
            await Assert.expect(async () => {
                await setup.depository.confirmBurn(depositId, preimage, sig);
            }).toThrow();
        });

        await vm.it('#45: same depositId across different flows does NOT collide', async () => {
            // MED-002 regression — the replay guard keys on the full
            // source-event identity, so two legitimate burns that share a
            // local depositId but come from different flows both confirm.
            const flowA = await registerFlow(setup, {
                mode: 1n,
                sourceBridgeAddr: releaseSrcBridge,
                sourceTokenAddr: releaseSrcToken,
            });
            const flowB = await registerFlow(setup, {
                mode: 1n,
                sourceBridgeAddr: Blockchain.generateRandomAddress(),
                sourceTokenAddr: Blockchain.generateRandomAddress(),
            });
            const depositId = 0xb09n;

            const a = buildAttestation({
                contractSelf: setup.depositoryAddress,
                flowId: flowA,
                depositId,
                releasedAmount: 1_000_000n,
            });
            const b = buildAttestation({
                contractSelf: setup.depositoryAddress,
                flowId: flowB,
                depositId,
                releasedAmount: 1_000_000n,
            });
            setSender(alice);
            await setup.depository.confirmBurn(
                depositId, a.preimage, signAttestation(setup.signerWallet, a.hash),
            );
            // Same depositId, different flow — must NOT be blocked.
            await setup.depository.confirmBurn(
                depositId, b.preimage, signAttestation(setup.signerWallet, b.hash),
            );

            Assert.expect(await setup.depository.isBurnConfirmed(flowA, depositId, 0n, 0n)).toEqual(true);
            Assert.expect(await setup.depository.isBurnConfirmed(flowB, depositId, 0n, 0n)).toEqual(true);
        });

        await vm.it('stale signerEpoch reverts', async () => {
            const flowId = await registerFlow(setup, {
                mode: 1n,
                sourceBridgeAddr: releaseSrcBridge,
                sourceTokenAddr: releaseSrcToken,
            });
            const depositId = 0xb03n;
            const { preimage, hash } = buildAttestation({
                contractSelf: setup.depositoryAddress,
                flowId,
                depositId,
                releasedAmount: 1_000_000n,
                signerEpoch: 99, // current epoch is 1
            });
            const sig = signAttestation(setup.signerWallet, hash);
            setSender(alice);
            await Assert.expect(async () => {
                await setup.depository.confirmBurn(depositId, preimage, sig);
            }).toThrow();
        });

        await vm.it('bad attestation length (≠ 252) reverts', async () => {
            const flowId = await registerFlow(setup, {
                mode: 1n,
                sourceBridgeAddr: releaseSrcBridge,
                sourceTokenAddr: releaseSrcToken,
            });
            const depositId = 0xb04n;
            const truncated = new Uint8Array(BURN_ATTESTATION_LEN - 1);
            // Fill in a valid header so the failure is the length gate, not
            // a zero-out fallthrough.
            writeU256BE(truncated, 0, VOUCHER_NETWORK_ID);
            writeAddress(truncated, 32, setup.depositoryAddress);
            writeU32BE(truncated, 64, CONFIRM_BURN_SELECTOR);
            writeU256BE(truncated, 68, flowId);
            writeU256BE(truncated, 100, depositId);
            const sig = signAttestation(setup.signerWallet, sha256(truncated));
            setSender(alice);
            await Assert.expect(async () => {
                await setup.depository.confirmBurn(depositId, truncated, sig);
            }).toThrow();
        });

        await vm.it('unknown flowId reverts', async () => {
            const depositId = 0xb05n;
            const bogusFlowId = 0xdeadbeefn;
            const { preimage, hash } = buildAttestation({
                contractSelf: setup.depositoryAddress,
                flowId: bogusFlowId,
                depositId,
                releasedAmount: 1_000_000n,
            });
            const sig = signAttestation(setup.signerWallet, hash);
            setSender(alice);
            await Assert.expect(async () => {
                await setup.depository.confirmBurn(depositId, preimage, sig);
            }).toThrow();
        });
    });

await opnet('BridgeDepository.confirmBurn — flow status: draining + paused',
    async (vm: OPNetUnit) => {
        let setup: Setup;
        let releaseSrcBridge: Address;
        let releaseSrcToken: Address;

        vm.beforeEach(async () => {
            Blockchain.dispose();
            Blockchain.clearContracts();
            await Blockchain.init();
            setSender(deployer);
            setup = await setupContracts();
            releaseSrcBridge = Blockchain.generateRandomAddress();
            releaseSrcToken = Blockchain.generateRandomAddress();
        });

        vm.afterEach(() => dispose(setup));

        await vm.it('on draining flow allowed (mode-1, exit path)', async () => {
            const flowId = await registerFlow(setup, {
                mode: 1n,
                sourceBridgeAddr: releaseSrcBridge,
                sourceTokenAddr: releaseSrcToken,
            });
            // Move flow to DRAINING.
            setSender(deployer);
            await setup.depository.drainFlow(flowId);

            const depositId = 0xd01n;
            const { preimage, hash } = buildAttestation({
                contractSelf: setup.depositoryAddress,
                flowId,
                depositId,
                releasedAmount: 800_000n,
            });
            const sig = signAttestation(setup.signerWallet, hash);
            setSender(alice);
            await setup.depository.confirmBurn(depositId, preimage, sig);

            Assert.expect(await setup.depository.isBurnConfirmed(flowId, depositId, 0n, 0n)).toEqual(true);
        });

        await vm.it('on inactive (paused) flow reverts', async () => {
            const flowId = await registerFlow(setup, {
                mode: 1n,
                sourceBridgeAddr: releaseSrcBridge,
                sourceTokenAddr: releaseSrcToken,
            });
            setSender(deployer);
            await setup.depository.pauseFlow(flowId);

            const depositId = 0xd02n;
            const { preimage, hash } = buildAttestation({
                contractSelf: setup.depositoryAddress,
                flowId,
                depositId,
                releasedAmount: 1_000_000n,
            });
            const sig = signAttestation(setup.signerWallet, hash);
            setSender(alice);
            await Assert.expect(async () => {
                await setup.depository.confirmBurn(depositId, preimage, sig);
            }).toThrow();
        });
    });
