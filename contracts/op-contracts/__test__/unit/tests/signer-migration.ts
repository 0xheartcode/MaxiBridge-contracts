/**
 * BridgeDepository.migrateSignerSet — atomic add/remove/threshold/epoch tests
 * (PR γ.2b).
 *
 * Coverage:
 *   ✓ migrateSignerSet adds, removes, sets threshold, bumps epoch atomically
 *   ✓ migrateSignerSet governor only
 *   ✓ migrateSignerSet rejects threshold > new size
 *   ✓ migrateSignerSet rejects threshold == 0
 *   ✓ old-epoch sigs immediately fail after migrate
 *
 * Run: cd contracts/op-contracts && npm run build && \
 *      npx tsx __test__/unit/tests/signer-migration.ts
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address, BinaryWriter, Wallet } from '@btc-vision/transaction';
import { sha256 } from '@noble/hashes/sha2.js';

import { WrappedOP20 } from '../contracts/WrappedOP20.js';
import { BridgeDepository } from '../contracts/BridgeDepository.js';

// ─── Constants ──────────────────────────────────────────────────────────────
const VOUCHER_NETWORK_ID: bigint = 2n;
const CLAIM_MINT_WITH_VOUCHER_SELECTOR: number = 0x59893fe6;
const VOUCHER_PREIMAGE_LEN = 540; // #68 Tier B — appended flowId u256
const ETH_CHAIN_ID: bigint = 1n;

// ─── Harness ────────────────────────────────────────────────────────────────
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

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Build the migrateSignerSet payload:
 *   addCount u32 BE | addHashes[u256...] |
 *   removeCount u32 BE | removeHashes[u256...] |
 *   newThreshold u256
 */
function buildMigratePayload(
    adds: bigint[],
    removes: bigint[],
    newThreshold: bigint,
): Uint8Array {
    const total = 4 + adds.length * 32 + 4 + removes.length * 32 + 32;
    const out = new Uint8Array(total);
    const view = new DataView(out.buffer);
    let off = 0;
    view.setUint32(off, adds.length, false); off += 4;
    for (const h of adds) {
        writeU256BE(out, off, h);
        off += 32;
    }
    view.setUint32(off, removes.length, false); off += 4;
    for (const h of removes) {
        writeU256BE(out, off, h);
        off += 32;
    }
    writeU256BE(out, off, newThreshold);
    return out;
}

function writeU256BE(buf: Uint8Array, off: number, v: bigint): void {
    let x = v;
    for (let i = 31; i >= 0; i--) {
        buf[off + i] = Number(x & 0xffn);
        x >>= 8n;
    }
}

function pubKeyHash(wallet: Wallet): bigint {
    const pubKey = new Uint8Array(wallet.mldsaKeypair.publicKey);
    const h = sha256(pubKey);
    let v = 0n;
    for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(h[i]!);
    return v;
}

// Minimal voucher builder for the "old-epoch sig fails" case.
interface VoucherFields {
    contractSelf: Address;
    recipient: Address;
    wrappedToken: Address;
    sourceTxHash: bigint;
    sourceLogIndex: number;
    sourceBridgeAddr: Address;
    sourceTokenAddr: Address;
    grossAmount: bigint;
    feeAmount: bigint;
    netAmount: bigint;
    voucherId: bigint;
    signerEpoch: number;
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
    w.writeU256(VOUCHER_NETWORK_ID);
    w.writeAddress(v.contractSelf);
    w.writeSelector(CLAIM_MINT_WITH_VOUCHER_SELECTOR);
    w.writeAddress(v.recipient);
    w.writeU256(ETH_CHAIN_ID);
    w.writeAddress(v.sourceBridgeAddr);
    w.writeAddress(v.sourceTokenAddr);
    w.writeU256(v.sourceTxHash);
    w.writeU32(v.sourceLogIndex);
    w.writeU256(0n);
    w.writeU256(0n);
    w.writeAddress(v.wrappedToken);
    w.writeU256(v.grossAmount);
    w.writeU256(v.grossAmount);
    w.writeU256(v.feeAmount);
    w.writeU256(v.netAmount);
    writeU128BE(w, 0n);
    w.writeU32(v.signerEpoch);
    w.writeU256(v.voucherId);
    w.writeU256(v.flowId ?? 0n); // #68 Tier B — appended LAST

    const preimage = w.getBuffer();
    if (preimage.length !== VOUCHER_PREIMAGE_LEN) {
        throw new Error(`bad voucher length: ${preimage.length}`);
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

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository.migrateSignerSet — atomic mutations', async (vm: OPNetUnit) => {
    let setup: Setup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => dispose(setup));

    await vm.it('adds, removes, sets threshold, bumps epoch atomically', async () => {
        const w1 = Blockchain.generateRandomWallet();
        const w2 = Blockchain.generateRandomWallet();
        const w3 = Blockchain.generateRandomWallet();
        const initialSignerHash = pubKeyHash(setup.signerWallet);

        const epochBefore = await setup.depository.signerEpoch();
        const countBefore = await setup.depository.signerCount();
        Assert.expect(epochBefore).toEqual(1n);
        Assert.expect(countBefore).toEqual(1n);

        // Add 3, remove 1, threshold = 2 — atomic.
        const payload = buildMigratePayload(
            [pubKeyHash(w1), pubKeyHash(w2), pubKeyHash(w3)],
            [initialSignerHash],
            2n,
        );
        setSender(deployer);
        await setup.depository.migrateSignerSet(payload);

        Assert.expect(await setup.depository.signerCount()).toEqual(3n);
        Assert.expect(await setup.depository.requiredSignatures()).toEqual(2n);
        Assert.expect(await setup.depository.signerEpoch()).toEqual(2n);

        // Adds authorized, remove deauthorized.
        Assert.expect(await setup.depository.isSignerAuthorized(pubKeyHash(w1))).toEqual(true);
        Assert.expect(await setup.depository.isSignerAuthorized(pubKeyHash(w2))).toEqual(true);
        Assert.expect(await setup.depository.isSignerAuthorized(pubKeyHash(w3))).toEqual(true);
        Assert.expect(await setup.depository.isSignerAuthorized(initialSignerHash)).toEqual(false);
    });

    await vm.it('governor only — non-governor reverts', async () => {
        const w1 = Blockchain.generateRandomWallet();
        const payload = buildMigratePayload([pubKeyHash(w1)], [], 1n);
        setSender(alice);
        await Assert.expect(async () => {
            await setup.depository.migrateSignerSet(payload);
        }).toThrow();
    });

    await vm.it('rejects threshold > new size', async () => {
        const w1 = Blockchain.generateRandomWallet();
        // After: signerCount = 2 (initial + w1). Threshold 3 is invalid.
        const payload = buildMigratePayload([pubKeyHash(w1)], [], 3n);
        setSender(deployer);
        await Assert.expect(async () => {
            await setup.depository.migrateSignerSet(payload);
        }).toThrow();
    });

    await vm.it('rejects threshold == 0', async () => {
        const w1 = Blockchain.generateRandomWallet();
        const payload = buildMigratePayload([pubKeyHash(w1)], [], 0n);
        setSender(deployer);
        await Assert.expect(async () => {
            await setup.depository.migrateSignerSet(payload);
        }).toThrow();
    });

    await vm.it('old-epoch sigs immediately fail after migrate', async () => {
        // Build a voucher signed under epoch 1 with the original signer.
        const recipient = alice;
        const sourceBridge = Blockchain.generateRandomAddress();
        const sourceToken = Blockchain.generateRandomAddress();

        // Need a registered flow for the claim path.
        const evmBridgeBigInt = (() => {
            const bytes = sourceBridge as unknown as Uint8Array;
            let v = 0n;
            for (let i = 0; i < 20; i++) v = (v << 8n) | BigInt(bytes[i]!);
            return v;
        })();
        const evmTokenBigInt = (() => {
            const bytes = sourceToken as unknown as Uint8Array;
            let v = 0n;
            for (let i = 0; i < 20; i++) v = (v << 8n) | BigInt(bytes[i]!);
            return v;
        })();
        const opnetBridgeBigInt = (() => {
            const bytes = setup.depositoryAddress as unknown as Uint8Array;
            let v = 0n;
            for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]!);
            return v;
        })();
        const opnetTokenBigInt = (() => {
            const bytes = setup.wusdcAddress as unknown as Uint8Array;
            let v = 0n;
            for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]!);
            return v;
        })();
        const migFlowId = await setup.depository.addFlow({
            mode: 0n,
            chainId: ETH_CHAIN_ID,
            evmBridge: evmBridgeBigInt,
            evmToken: evmTokenBigInt,
            evmDecimals: 6n,
            opnetBridge: opnetBridgeBigInt,
            opnetToken: opnetTokenBigInt,
            opnetDecimals: 6n,
            feeBps: 50n,
            minFee: 0n,
            minAmount: 0n,
            cap: 1_000_000_000n,
            dailyLimit: 100_000_000n,
            tipCapBps: 0n,
        });

        const fields: VoucherFields = {
            contractSelf: setup.depositoryAddress,
            recipient,
            wrappedToken: setup.wusdcAddress,
            sourceTxHash: 0xc0ffee01n,
            sourceLogIndex: 0,
            sourceBridgeAddr: sourceBridge,
            sourceTokenAddr: sourceToken,
            grossAmount: 1_000_000n,
            feeAmount: 5_000n,
            netAmount: 995_000n,
            voucherId: 0xfeed01n,
            signerEpoch: 1,
            // #68 Tier B — bind the voucher to the registered flow so the
            // claim reverts on the EPOCH mismatch (the test's intent), not on
            // a flow-not-found from a zero flowId.
            flowId: migFlowId,
        };
        const { preimage, hash } = buildVoucher(fields);
        const oldSigPub = new Uint8Array(setup.signerWallet.mldsaKeypair.publicKey);
        const oldSigRaw = setup.signerWallet.mldsaKeypair.sign(hash);
        const oldSigBlob = packSigBlob(oldSigPub, oldSigRaw);

        // Now migrate: rotate to a fresh signer.
        const newSigner = Blockchain.generateRandomWallet();
        const initialHash = pubKeyHash(setup.signerWallet);
        const payload = buildMigratePayload([pubKeyHash(newSigner)], [initialHash], 1n);
        setSender(deployer);
        await setup.depository.migrateSignerSet(payload);

        // Epoch is now 2; old voucher (epoch 1) must revert.
        Assert.expect(await setup.depository.signerEpoch()).toEqual(2n);
        setSender(recipient);
        await Assert.expect(async () => {
            await setup.depository.claimMintWithVoucher(preimage, oldSigBlob);
        }).toThrow();
    });
});

await opnet('BridgeDepository.migrateSignerSet — view sanity', async (vm: OPNetUnit) => {
    let setup: Setup;
    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });
    vm.afterEach(() => dispose(setup));

    await vm.it('migrate with empty add/remove just bumps epoch and threshold', async () => {
        // Threshold stays at 1, single signer remains, but epoch increments.
        const epochBefore = await setup.depository.signerEpoch();
        const payload = buildMigratePayload([], [], 1n);
        setSender(deployer);
        await setup.depository.migrateSignerSet(payload);
        Assert.expect(await setup.depository.signerEpoch()).toEqual(epochBefore + 1n);
        Assert.expect(await setup.depository.signerCount()).toEqual(1n);
        Assert.expect(await setup.depository.requiredSignatures()).toEqual(1n);
    });
});
