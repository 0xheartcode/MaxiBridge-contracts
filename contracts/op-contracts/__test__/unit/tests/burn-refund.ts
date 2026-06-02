/**
 * BridgeDepository — trustless burn-side recovery (attested re-mint) tests (#55).
 *
 * ⚠️ This exercises a MINT-AUTHORITY primitive. A user who burned wUSDC via
 * `WrappedOP20.burnForRelease` expecting an EVM release gets the burned amount
 * RE-MINTED to them iff the EVM destination voucher was PERMANENTLY cancelled
 * (reorg / fraud). The burn-initiated counterpart of the stranded-lock refund.
 *
 * The burn lives on the TOKEN, not the depository, so the M-of-N attestation is
 * SELF-CONTAINED: it carries burner / wrappedToken / amount / burnNonce /
 * burnTxHash / burnBlock / flowId / signerEpoch. The attestation IS the signed
 * 296-byte preimage (mirrors confirmBurn's attestation-is-preimage shape); the
 * contract parses it at fixed offsets, validates domain/selector/epoch + the
 * flow/token bindings, and verifies the M-of-N sig over the bytes directly.
 *
 * Trust model == vouchers: the SAME M-of-N signer set attests off-chain facts.
 * The per-burn replay guard `burnId = sha256(burnTxHash‖burnNonce)` is set
 * BEFORE the mint (CEI) and is the ONLY protection against a double/infinite
 * re-mint.
 *
 * Coverage:
 *   ✓ happy path: valid attestation → exact amount minted to burner; replay set
 *   ✓ replay: same burn id twice reverts; NO second mint
 *   ✓ wrong signerEpoch reverts (NO mint)
 *   ✓ identity drift — amount / burner / wrappedToken / flowId / burnNonce /
 *     burnTxHash / burnBlock tampered vs signed → reverts (NO mint)
 *   ✓ wrong networkId / contractSelf / selector reverts
 *   ✓ garbage (unsigned) sig reverts (NO mint)
 *   ✓ bad attestation length reverts
 *   ✓ unregistered wrappedToken reverts
 *   ✓ flowId ↔ wrappedToken mismatch reverts
 *   ✓ flow not found / not active reverts
 *   ✓ paused reverts (NO mint)
 *   ✓ zero amount reverts
 *
 * Run: cd contracts/op-contracts && npm run build && \
 *      npx tsx __test__/unit/tests/burn-refund.ts
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address, Wallet } from '@btc-vision/transaction';
import { sha256 } from '@noble/hashes/sha2.js';

import { WrappedOP20 } from '../contracts/WrappedOP20.js';
import { BridgeDepository } from '../contracts/BridgeDepository.js';

// ─── Constants — must mirror BridgeDepository.ts ──────────────────────────
const VOUCHER_NETWORK_ID: bigint = 2n;
const ETH_CHAIN_ID: bigint = 1n;
const BURN_REFUND_AUTHORIZATION_LEN = 296;
const REFUND_BURN_SELECTOR: number = 0xbe782e17;
const FEE_BPS = 50n;

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

// ─── Encoding helpers ─────────────────────────────────────────────────────

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

// ─── BurnRefundAuthorization preimage (296 bytes) ─────────────────────────
// networkId(32) ‖ contractSelf(32) ‖ selector(4) ‖ burner(32) ‖
// wrappedToken(32) ‖ amount(32) ‖ burnNonce(32) ‖ burnTxHash(32) ‖
// burnBlock(32) ‖ flowId(32) ‖ signerEpoch(4)
//
// The contract parses this EXACT layout at fixed offsets and verifies the
// M-of-N sig over these bytes (no rebuild step).
interface BurnRefundFields {
    networkId?: bigint;
    contractSelf: Address;
    selector?: number;
    burner: Address;
    wrappedToken: Address;
    amount: bigint;
    burnNonce: bigint;
    burnTxHash: bigint;
    burnBlock: bigint;
    flowId: bigint;
    signerEpoch?: number;
}

function buildBurnRefundAuth(f: BurnRefundFields): {
    preimage: Uint8Array;
    hash: Uint8Array;
} {
    const buf = new Uint8Array(BURN_REFUND_AUTHORIZATION_LEN);
    writeU256BE(buf, 0, f.networkId ?? VOUCHER_NETWORK_ID);
    writeAddress(buf, 32, f.contractSelf);
    writeU32BE(buf, 64, f.selector ?? REFUND_BURN_SELECTOR);
    writeAddress(buf, 68, f.burner);
    writeAddress(buf, 100, f.wrappedToken);
    writeU256BE(buf, 132, f.amount);
    writeU256BE(buf, 164, f.burnNonce);
    writeU256BE(buf, 196, f.burnTxHash);
    writeU256BE(buf, 228, f.burnBlock);
    writeU256BE(buf, 260, f.flowId);
    writeU32BE(buf, 292, f.signerEpoch ?? 1);
    return { preimage: buf, hash: sha256(buf) };
}

// M=N=1 sig blob — same packer the lock-refund / confirm-burn / voucher tests use.
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

function signAuth(wallet: Wallet, hash: Uint8Array): Uint8Array {
    const pubKey = new Uint8Array(wallet.mldsaKeypair.publicKey);
    const rawSig = wallet.mldsaKeypair.sign(hash);
    return packSigBlob(pubKey, rawSig);
}

const SOURCE_BRIDGE: Address = Blockchain.generateRandomAddress();
const SOURCE_TOKEN: Address = Blockchain.generateRandomAddress();

// Register a flow whose opnetToken == wUSDC. Mode 0 (WRAPPED) / 2
// (NATIVE_BURN_MINT) are the burn-initiated legs this recovery serves; the
// flow binding only checks existence + ACTIVE + opnetToken, so mode value is
// not load-bearing for refundBurn — use mode 0.
async function registerFlow(setup: Setup, mode: bigint): Promise<bigint> {
    return await setup.depository.addFlow({
        mode,
        chainId: ETH_CHAIN_ID,
        evmBridge: evmAddrRightPadToBigInt(SOURCE_BRIDGE),
        evmToken: evmAddrRightPadToBigInt(SOURCE_TOKEN),
        evmDecimals: 6n,
        opnetBridge: opnetAddrToBigInt(setup.depositoryAddress),
        opnetToken: opnetAddrToBigInt(setup.wusdcAddress),
        opnetDecimals: 6n,
        feeBps: FEE_BPS,
        minFee: 0n,
        minAmount: 0n,
        cap: 1_000_000_000_000n,
        dailyLimit: 1_000_000_000_000n,
        tipCapBps: 0n,
    });
}

const BURN_TX_HASH = 0xdeadbeefcafen;
const BURN_NONCE = 7n;
const BURN_BLOCK = 1234n;
const AMOUNT = 2_000_000n;

// Canonical (matching-the-contract) BurnRefundAuthorization fields for a flow.
function canonicalFields(setup: Setup, flowId: bigint): BurnRefundFields {
    return {
        contractSelf: setup.depositoryAddress,
        burner: alice,
        wrappedToken: setup.wusdcAddress,
        amount: AMOUNT,
        burnNonce: BURN_NONCE,
        burnTxHash: BURN_TX_HASH,
        burnBlock: BURN_BLOCK,
        flowId,
    };
}

// ════════════════════════════════════════════════════════════════════════════
// Happy path
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository.burn-refund — happy path', async (vm: OPNetUnit) => {
    let setup: Setup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        Blockchain.medianTimestamp = 1_000_000n;
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => dispose(setup));

    await vm.it('valid attestation → exact amount minted to burner; replay-guard set', async () => {
        const { depository } = setup;
        const flowId = await registerFlow(setup, 0n);

        const aliceBefore = await setup.wusdc.balanceOf(alice);
        Assert.expect(await depository.isBurnRefunded(setup.wusdcAddress, alice, BURN_TX_HASH, BURN_NONCE)).toEqual(false);

        const { hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const auth = buildBurnRefundAuth(canonicalFields(setup, flowId)).preimage;
        const sig = signAuth(setup.signerWallet, hash);

        // Permissionless — alice submits, but anyone could; funds go to the
        // signer-attested burner.
        setSender(alice);
        await depository.refundBurn(auth, sig);

        // Burner got EXACTLY the attested amount re-minted.
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(aliceBefore + AMOUNT);
        // Replay guard set.
        Assert.expect(await depository.isBurnRefunded(setup.wusdcAddress, alice, BURN_TX_HASH, BURN_NONCE)).toEqual(true);
    });

    await vm.it('replay: same burn id twice reverts; NO second mint', async () => {
        const { depository } = setup;
        const flowId = await registerFlow(setup, 0n);
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);

        setSender(alice);
        await depository.refundBurn(preimage, sig);
        const afterFirst = await setup.wusdc.balanceOf(alice);

        await Assert.expect(async () => {
            await depository.refundBurn(preimage, sig);
        }).toThrow();

        // No second mint.
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(afterFirst);
    });

    await vm.it('paused reverts; NO mint', async () => {
        const { depository } = setup;
        const flowId = await registerFlow(setup, 0n);
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);

        setSender(deployer);
        await depository.setPaused(true);

        const before = await setup.wusdc.balanceOf(alice);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.refundBurn(preimage, sig);
        }).toThrow();
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(before);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// Negative cases — each MUST revert with NO mint
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository.burn-refund — bad attestations (NO mint)', async (vm: OPNetUnit) => {
    let setup: Setup;
    let flowId: bigint;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        Blockchain.medianTimestamp = 1_000_000n;
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
        flowId = await registerFlow(setup, 0n);
        setSender(alice);
    });

    vm.afterEach(() => dispose(setup));

    // Submit an attestation expected to revert + assert the burner balance is
    // unchanged (NO mint occurred).
    async function expectNoMint(preimage: Uint8Array, sig: Uint8Array): Promise<void> {
        const before = await setup.wusdc.balanceOf(alice);
        await Assert.expect(async () => {
            await setup.depository.refundBurn(preimage, sig);
        }).toThrow();
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(before);
        // Replay guard must NOT have been set on a revert.
        Assert.expect(await setup.depository.isBurnRefunded(setup.wusdcAddress, alice, BURN_TX_HASH, BURN_NONCE)).toEqual(false);
    }

    await vm.it('wrong signerEpoch reverts', async () => {
        const { preimage, hash } = buildBurnRefundAuth({
            ...canonicalFields(setup, flowId),
            signerEpoch: 99,
        });
        await expectNoMint(preimage, signAuth(setup.signerWallet, hash));
    });

    await vm.it('amount drift (signed vs sent) reverts', async () => {
        // Sign over amount=AMOUNT but mutate the preimage's amount field — the
        // contract verifies the sig over the SENT bytes, so verify fails.
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);
        writeU256BE(preimage, 132, 999_999_999n); // tamper amount in transit
        await expectNoMint(preimage, sig);
    });

    await vm.it('burner drift IN TRANSIT reverts (sig binds the burner)', async () => {
        // Sign over alice as burner, then tamper the burner field in transit.
        // The sig is verified over the SENT bytes, so the ML-DSA verify fails →
        // revert, NO mint. (This is the security property: an attacker cannot
        // redirect a signed re-mint to themselves by editing the burner.)
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);
        writeAddress(preimage, 68, Blockchain.generateRandomAddress()); // tamper burner
        await expectNoMint(preimage, sig);
    });

    await vm.it('attestation for a DIFFERENT burner mints to THAT burner, not alice', async () => {
        // A genuinely-signed attestation naming bob is valid and mints to bob;
        // it must NEVER credit alice. (NOT a revert — it's a different, valid
        // authorization. Proves the burner field is honoured, not ignored.)
        const bob = Blockchain.generateRandomAddress();
        const { preimage, hash } = buildBurnRefundAuth({
            ...canonicalFields(setup, flowId),
            burner: bob,
        });
        const sig = signAuth(setup.signerWallet, hash);
        const aliceBefore = await setup.wusdc.balanceOf(alice);
        const bobBefore = await setup.wusdc.balanceOf(bob);
        await setup.depository.refundBurn(preimage, sig);
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(aliceBefore); // untouched
        Assert.expect(await setup.wusdc.balanceOf(bob)).toEqual(bobBefore + AMOUNT);
    });

    await vm.it('wrappedToken drift (unregistered token) reverts', async () => {
        const bogusToken = Blockchain.generateRandomAddress();
        const { preimage, hash } = buildBurnRefundAuth({
            ...canonicalFields(setup, flowId),
            wrappedToken: bogusToken,
        });
        await expectNoMint(preimage, signAuth(setup.signerWallet, hash));
    });

    await vm.it('flowId drift reverts (flow not found)', async () => {
        const { preimage, hash } = buildBurnRefundAuth({
            ...canonicalFields(setup, flowId),
            flowId: 0xdeadbeefn,
        });
        await expectNoMint(preimage, signAuth(setup.signerWallet, hash));
    });

    await vm.it('burnNonce drift reverts', async () => {
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);
        writeU256BE(preimage, 164, 999n);
        await expectNoMint(preimage, sig);
    });

    await vm.it('burnTxHash drift reverts', async () => {
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);
        writeU256BE(preimage, 196, 0x1234n);
        await expectNoMint(preimage, sig);
    });

    await vm.it('burnBlock drift (reorg-guard) reverts', async () => {
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);
        writeU256BE(preimage, 228, BURN_BLOCK + 1n);
        await expectNoMint(preimage, sig);
    });

    await vm.it('wrong networkId reverts', async () => {
        const { preimage, hash } = buildBurnRefundAuth({
            ...canonicalFields(setup, flowId),
            networkId: 1n, // mainnet, but this stack is testnet (2)
        });
        await expectNoMint(preimage, signAuth(setup.signerWallet, hash));
    });

    await vm.it('wrong contractSelf reverts', async () => {
        const { preimage, hash } = buildBurnRefundAuth({
            ...canonicalFields(setup, flowId),
            contractSelf: Blockchain.generateRandomAddress(),
        });
        await expectNoMint(preimage, signAuth(setup.signerWallet, hash));
    });

    await vm.it('wrong selector reverts', async () => {
        const { preimage, hash } = buildBurnRefundAuth({
            ...canonicalFields(setup, flowId),
            selector: 0xdeadbeef,
        });
        await expectNoMint(preimage, signAuth(setup.signerWallet, hash));
    });

    await vm.it('garbage (unsigned) sig reverts', async () => {
        const { preimage } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        // Sig over a DIFFERENT hash — ML-DSA verify fails.
        const badSig = signAuth(setup.signerWallet, sha256(new Uint8Array([1, 2, 3])));
        await expectNoMint(preimage, badSig);
    });

    await vm.it('bad attestation length reverts', async () => {
        const short = new Uint8Array(BURN_REFUND_AUTHORIZATION_LEN - 1);
        const sig = signAuth(setup.signerWallet, sha256(short));
        await expectNoMint(short, sig);
    });

    await vm.it('zero amount reverts', async () => {
        const { preimage, hash } = buildBurnRefundAuth({
            ...canonicalFields(setup, flowId),
            amount: 0n,
        });
        await expectNoMint(preimage, signAuth(setup.signerWallet, hash));
    });
});

await opnet('BridgeDepository.burn-refund — flow binding', async (vm: OPNetUnit) => {
    let setup: Setup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        Blockchain.medianTimestamp = 1_000_000n;
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => dispose(setup));

    await vm.it('flowId ↔ wrappedToken mismatch reverts; NO mint', async () => {
        // Register a flow whose opnetToken is a DIFFERENT (registered) token, so
        // the flow exists + is active but its opnetToken != the attested wUSDC.
        const otherTokenAddress = Blockchain.generateRandomAddress();
        const other = new WrappedOP20({
            file: './build/WrappedOP20.wasm',
            address: otherTokenAddress,
            decimals: 6,
            deployer,
        });
        Blockchain.register(other);
        await other.init();
        setSender(deployer);
        await other.setBridgeDepository(setup.depositoryAddress);
        await setup.depository.addWrappedToken(otherTokenAddress);

        const flowId = await setup.depository.addFlow({
            mode: 0n,
            chainId: ETH_CHAIN_ID,
            evmBridge: evmAddrRightPadToBigInt(SOURCE_BRIDGE),
            evmToken: evmAddrRightPadToBigInt(SOURCE_TOKEN),
            evmDecimals: 6n,
            opnetBridge: opnetAddrToBigInt(setup.depositoryAddress),
            opnetToken: opnetAddrToBigInt(otherTokenAddress), // NOT wUSDC
            opnetDecimals: 6n,
            feeBps: FEE_BPS,
            minFee: 0n,
            minAmount: 0n,
            cap: 1_000_000_000_000n,
            dailyLimit: 1_000_000_000_000n,
            tipCapBps: 0n,
        });

        // Attestation names wUSDC as wrappedToken but the flow's opnetToken is
        // `other` → mismatch.
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);

        const before = await setup.wusdc.balanceOf(alice);
        setSender(alice);
        await Assert.expect(async () => {
            await setup.depository.refundBurn(preimage, sig);
        }).toThrow();
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(before);

        other.dispose();
    });

    await vm.it('flow paused (not active) reverts; NO mint', async () => {
        const flowId = await registerFlow(setup, 0n);
        setSender(deployer);
        await setup.depository.pauseFlow(flowId);

        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);

        const before = await setup.wusdc.balanceOf(alice);
        setSender(alice);
        await Assert.expect(async () => {
            await setup.depository.refundBurn(preimage, sig);
        }).toThrow();
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(before);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// H-2 — mode allowlist (refundBurn only mints where bridge holds mint authority)
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository.burn-refund — H-2 mode gate', async (vm: OPNetUnit) => {
    let setup: Setup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        Blockchain.medianTimestamp = 1_000_000n;
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => dispose(setup));

    // The bridge can only re-mint where it holds OPNet mint authority: mode 0
    // (WRAPPED) and mode 2 (NATIVE_BURN_MINT). Defense-in-depth: even if a
    // signer set were ever cajoled into signing an attestation for a mode-1/3
    // flow whose _flowOpnetToken happens to be an allowlisted wrapped, the
    // contract must reject it at this gate, NOT mint.
    await vm.it('mode-1 (INVERSE_WRAPPED) flow reverts: token not in mintable mode', async () => {
        const flowId = await registerFlow(setup, 1n);
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);

        const before = await setup.wusdc.balanceOf(alice);
        setSender(alice);
        await Assert.expect(async () => {
            await setup.depository.refundBurn(preimage, sig);
        }).toThrow();
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(before);
        Assert.expect(await setup.depository.isBurnRefunded(setup.wusdcAddress, alice, BURN_TX_HASH, BURN_NONCE)).toEqual(false);
    });

    await vm.it('mode-3 (POOLED_LOCK_RELEASE) flow reverts: token not in mintable mode', async () => {
        const flowId = await registerFlow(setup, 3n);
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);

        const before = await setup.wusdc.balanceOf(alice);
        setSender(alice);
        await Assert.expect(async () => {
            await setup.depository.refundBurn(preimage, sig);
        }).toThrow();
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(before);
        Assert.expect(await setup.depository.isBurnRefunded(setup.wusdcAddress, alice, BURN_TX_HASH, BURN_NONCE)).toEqual(false);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// A-1 — rolling-window dailyLimit on refundBurn (mint-bound parity)
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository.burn-refund — A-1 daily limit', async (vm: OPNetUnit) => {
    let setup: Setup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        Blockchain.medianTimestamp = 1_000_000n;
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => dispose(setup));

    async function registerFlowWithDailyLimit(s: Setup, dailyLimit: bigint): Promise<bigint> {
        return await s.depository.addFlow({
            mode: 0n,
            chainId: ETH_CHAIN_ID,
            evmBridge: evmAddrRightPadToBigInt(SOURCE_BRIDGE),
            evmToken: evmAddrRightPadToBigInt(SOURCE_TOKEN),
            evmDecimals: 6n,
            opnetBridge: opnetAddrToBigInt(s.depositoryAddress),
            opnetToken: opnetAddrToBigInt(s.wusdcAddress),
            opnetDecimals: 6n,
            feeBps: FEE_BPS,
            minFee: 0n,
            minAmount: 0n,
            cap: 1_000_000_000_000n,
            dailyLimit,
            tipCapBps: 0n,
        });
    }

    // A-1 — without rolling-window dailyLimit consumption here, refundBurn is
    // an unbounded mint primitive. A single AMOUNT-sized refund against a
    // flow whose dailyLimit is AMOUNT-1 must revert → NO mint.
    await vm.it('amount above flow dailyLimit reverts; NO mint', async () => {
        const flowId = await registerFlowWithDailyLimit(setup, AMOUNT - 1n);
        const { preimage, hash } = buildBurnRefundAuth(canonicalFields(setup, flowId));
        const sig = signAuth(setup.signerWallet, hash);

        const before = await setup.wusdc.balanceOf(alice);
        setSender(alice);
        await Assert.expect(async () => {
            await setup.depository.refundBurn(preimage, sig);
        }).toThrow();
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(before);
        // Replay guard must not have been set on revert (state rolled back).
        Assert.expect(await setup.depository.isBurnRefunded(setup.wusdcAddress, alice, BURN_TX_HASH, BURN_NONCE)).toEqual(false);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// O-2 (Codex pre-audit, 2026-06-01) — burnId binds wrappedToken + burner
// ════════════════════════════════════════════════════════════════════════════
//
// `burnNonce` is a counter LOCAL to each WrappedOP20, so two distinct wrapped
// tokens can legitimately produce burns sharing the SAME (burnTxHash,
// burnNonce). With the pre-fix key `sha256(burnTxHash‖burnNonce)`, refunding
// the first burn permanently blocked the second token's legitimate recovery.
// Binding the wrappedToken (and burner) makes the two refunds independent.

await opnet('BridgeDepository.burn-refund — O-2: burnId binds wrappedToken', async (vm: OPNetUnit) => {
    let setup: Setup;
    let wusdt: WrappedOP20;
    let wusdtAddress: Address;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        Blockchain.medianTimestamp = 1_000_000n;
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();

        // Deploy + wire a SECOND wrapped token under the same depository.
        wusdtAddress = Blockchain.generateRandomAddress();
        wusdt = new WrappedOP20({
            file: './build/WrappedOP20.wasm',
            address: wusdtAddress,
            decimals: 6,
            deployer,
        });
        Blockchain.register(wusdt);
        await wusdt.init();
        setSender(deployer);
        await wusdt.setBridgeDepository(setup.depositoryAddress);
        await setup.depository.addWrappedToken(wusdtAddress);
    });

    vm.afterEach(() => {
        wusdt.dispose();
        dispose(setup);
    });

    await vm.it('two wrapped tokens sharing (burnTxHash, burnNonce) refund independently', async () => {
        const { depository, signerWallet } = setup;

        // Flow A — opnetToken = wUSDC.
        const flowA = await registerFlow(setup, 0n);
        // Flow B — opnetToken = wUSDT (distinct flowId: opnetToken differs).
        const flowB = await depository.addFlow({
            mode: 0n,
            chainId: ETH_CHAIN_ID,
            evmBridge: evmAddrRightPadToBigInt(SOURCE_BRIDGE),
            evmToken: evmAddrRightPadToBigInt(SOURCE_TOKEN),
            evmDecimals: 6n,
            opnetBridge: opnetAddrToBigInt(setup.depositoryAddress),
            opnetToken: opnetAddrToBigInt(wusdtAddress),
            opnetDecimals: 6n,
            feeBps: FEE_BPS,
            minFee: 0n,
            minAmount: 0n,
            cap: 1_000_000_000_000n,
            dailyLimit: 1_000_000_000_000n,
            tipCapBps: 0n,
        });

        // Refund the wUSDC burn at (BURN_TX_HASH, BURN_NONCE).
        const aAuth = buildBurnRefundAuth(canonicalFields(setup, flowA));
        setSender(alice);
        await depository.refundBurn(aAuth.preimage, signAuth(signerWallet, aAuth.hash));
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(AMOUNT);

        // Refund the wUSDT burn at the SAME (BURN_TX_HASH, BURN_NONCE).
        // Pre-fix: reverts "burn already refunded". Post-fix: succeeds.
        const bAuth = buildBurnRefundAuth({
            ...canonicalFields(setup, flowB),
            wrappedToken: wusdtAddress,
        });
        setSender(alice);
        await depository.refundBurn(bAuth.preimage, signAuth(signerWallet, bAuth.hash));
        Assert.expect(await wusdt.balanceOf(alice)).toEqual(AMOUNT);

        // Both recorded independently under their own identity key.
        Assert.expect(
            await depository.isBurnRefunded(setup.wusdcAddress, alice, BURN_TX_HASH, BURN_NONCE),
        ).toEqual(true);
        Assert.expect(
            await depository.isBurnRefunded(wusdtAddress, alice, BURN_TX_HASH, BURN_NONCE),
        ).toEqual(true);
    });
});
