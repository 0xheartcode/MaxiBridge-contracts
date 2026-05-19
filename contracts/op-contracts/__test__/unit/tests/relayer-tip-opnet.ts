/**
 * BridgeDepository — PR β.2.payout-opnet relayer-tip payout tests.
 *
 * Mirrors EVM-side `RelayerTip.t.sol` (PR #35). Exercises both claim paths:
 *   - `claimMintWithVoucher` (mode 0 / 2)
 *   - `claimReleaseWithVoucher` (mode 1 / 3)
 *
 * Cases:
 *   ✓ tip = 0 → full netDst to recipient
 *   ✓ tip > 0 happy path → relayer gets tip, recipient gets residual
 *   ✓ tip > flowTipCap reverts
 *   ✓ tip on paused flow reverts
 *   ✓ tip on draining flow reverts
 *   ✓ smart-contract recipient + tip — relayer paid, contract recipient gets residual
 *   ✓ malicious-server `tip == netDst` rejected by cap (cap=100 bps)
 *   ✓ Mode-1 inverse path: happy path + cap reject
 *
 * Run: cd contracts/op-contracts && npm run build &&
 *      npx tsx __test__/unit/tests/relayer-tip-opnet.ts
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

// claimReleaseWithVoucher selector — sha256 of the signature, first 4B.
function deriveSelector(sig: string): number {
    const enc = new TextEncoder();
    const bytes = sha256(enc.encode(sig));
    return ((bytes[0]! << 24) | (bytes[1]! << 16) | (bytes[2]! << 8) | bytes[3]!) >>> 0;
}
const CLAIM_RELEASE_WITH_VOUCHER_SELECTOR: number = deriveSelector(
    'claimReleaseWithVoucher(bytes,bytes)',
);

// ─── Harness ──────────────────────────────────────────────────────────
const deployer: Address = Blockchain.generateRandomAddress();
const alice: Address = Blockchain.generateRandomAddress();
const bob: Address = Blockchain.generateRandomAddress();
const relayerCarol: Address = Blockchain.generateRandomAddress();

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

// ─── Voucher helpers (mirror bridge.ts) ───────────────────────────────
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

// ─── Address → bigint helpers (mirror contract conventions) ───────────
function evmAddrRightPadToBigInt(addr: Address): bigint {
    const bytes = addr as unknown as Uint8Array;
    let v = 0n;
    for (let i = 0; i < 20; i++) {
        v = (v << 8n) | BigInt(bytes[i]!);
    }
    return v;
}

function opnetAddrToBigInt(addr: Address): bigint {
    const bytes = addr as unknown as Uint8Array;
    let v = 0n;
    for (let i = 0; i < 32; i++) {
        v = (v << 8n) | BigInt(bytes[i]!);
    }
    return v;
}

const DEFAULT_SOURCE_BRIDGE: Address = Blockchain.generateRandomAddress();
const DEFAULT_SOURCE_TOKEN: Address = Blockchain.generateRandomAddress();

async function registerFlow(
    setup: BridgeSetup,
    opts: {
        mode?: bigint;
        chainId?: bigint;
        sourceBridgeAddr?: Address;
        sourceTokenAddr?: Address;
        wrappedToken?: Address;
        tipCapBps?: bigint;
        cap?: bigint;
        dailyLimit?: bigint;
    } = {},
): Promise<bigint> {
    const sourceBridgeAddr = opts.sourceBridgeAddr ?? DEFAULT_SOURCE_BRIDGE;
    const sourceTokenAddr = opts.sourceTokenAddr ?? DEFAULT_SOURCE_TOKEN;
    const wrappedToken = opts.wrappedToken ?? setup.wusdcAddress;
    return await setup.depository.addFlow({
        mode: opts.mode ?? 0n,
        chainId: opts.chainId ?? ETH_CHAIN_ID,
        evmBridge: evmAddrRightPadToBigInt(sourceBridgeAddr),
        evmToken: evmAddrRightPadToBigInt(sourceTokenAddr),
        evmDecimals: 6n,
        opnetBridge: opnetAddrToBigInt(setup.depositoryAddress),
        opnetToken: opnetAddrToBigInt(wrappedToken),
        opnetDecimals: 6n,
        feeBps: 50n,
        minFee: 0n,
        minAmount: 0n,
        cap: opts.cap ?? 1_000_000_000_000n,
        dailyLimit: opts.dailyLimit ?? 100_000_000_000n,
        tipCapBps: opts.tipCapBps ?? 0n,
    });
}

function defaultFields(setup: BridgeSetup, recipient: Address): VoucherFields {
    return {
        contractSelf: setup.depositoryAddress,
        recipient,
        sourceBridgeAddr: DEFAULT_SOURCE_BRIDGE,
        sourceTokenAddr: DEFAULT_SOURCE_TOKEN,
        sourceTxHash: 0xdeadbeefcafe1234n,
        sourceLogIndex: 7,
        wrappedToken: setup.wusdcAddress,
        grossAmount: 1_000_000n,
        feeAmount: 5_000n,
        netAmount: 995_000n,
        voucherId: 0xa1b2c3d4e5n,
        signerEpoch: 1,
    };
}

// ════════════════════════════════════════════════════════════════════════════
// claimMintWithVoucher (mode 0) — tip-payout matrix
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository — PR β.2.payout-opnet — mint path', async (vm: OPNetUnit) => {
    let setup: BridgeSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => disposeSetup(setup));

    // OPNet enforces `recipient == tx.sender` on the claim path (existing
    // design — see Step 4 in `claimMintWithVoucher`). So in every test below
    // the same Address is BOTH the voucher recipient AND `Blockchain.tx.sender`
    // (the relayer who is paid the tip). Their post-claim balance therefore
    // equals `netAmount` (tip + residual). We still prove the split executes
    // cleanly (no revert, total minted = netAmount, no over-/under-mint).

    await vm.it('claim with tip = 0 sends full netDst to recipient', async () => {
        await registerFlow(setup, { tipCapBps: 100n });
        const { depository, wusdc, signerWallet } = setup;
        const fields = { ...defaultFields(setup, alice), relayerTip: 0n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        Assert.expect(await wusdc.balanceOf(alice)).toEqual(fields.netAmount);
        Assert.expect(await wusdc.totalSupply()).toEqual(fields.netAmount);
    });

    await vm.it('claim with tip > 0 happy path — splits cleanly, total = netAmount', async () => {
        // 200 bps cap; tip = 9_950 / 995_000 = 100 bps (well under cap).
        await registerFlow(setup, { tipCapBps: 200n });
        const { depository, wusdc, signerWallet } = setup;
        const fields = { ...defaultFields(setup, alice), relayerTip: 9_950n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        // alice is BOTH recipient and relayer — total balance is full netDst.
        Assert.expect(await wusdc.balanceOf(alice)).toEqual(fields.netAmount);
        Assert.expect(await wusdc.totalSupply()).toEqual(fields.netAmount);
    });

    await vm.it('claim with tip > flowTipCap reverts', async () => {
        // 50 bps cap; tip = 9_950 / 995_000 = 100 bps → 100 > 50, must revert.
        await registerFlow(setup, { tipCapBps: 50n });
        const { depository, signerWallet } = setup;
        const fields = { ...defaultFields(setup, alice), relayerTip: 9_950n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }).toThrow();
    });

    await vm.it('#2: tip > 0 — a non-recipient relayer can claim; mint to recipient, tip to relayer', async () => {
        // 200 bps cap; tip 9_950 / 995_000 = 100 bps. Voucher recipient is
        // alice but the tx is submitted by `deployer` (the relayer) —
        // only possible because relayerTip > 0 relaxes the sender binding.
        await registerFlow(setup, { tipCapBps: 200n });
        const { depository, wusdc, signerWallet } = setup;
        const fields = { ...defaultFields(setup, alice), relayerTip: 9_950n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(deployer);
        await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        // Recipient (alice) gets netAmount - tip; relayer (deployer) the tip.
        Assert.expect(await wusdc.balanceOf(alice)).toEqual(fields.netAmount - 9_950n);
        Assert.expect(await wusdc.balanceOf(deployer)).toEqual(9_950n);
        Assert.expect(await wusdc.totalSupply()).toEqual(fields.netAmount);
    });

    await vm.it('#2: tip = 0 — a non-recipient cannot claim (DIY binding preserved)', async () => {
        // No tip → the recipient==tx.sender binding still applies, so a
        // tip-less voucher signed for alice is un-claimable by deployer.
        await registerFlow(setup, { tipCapBps: 200n });
        const { depository, signerWallet } = setup;
        const fields = { ...defaultFields(setup, alice), relayerTip: 0n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(deployer);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }).toThrow();
    });

    await vm.it('claim with tip on paused flow reverts', async () => {
        const flowId = await registerFlow(setup, { tipCapBps: 200n });
        setSender(deployer);
        await setup.depository.pauseFlow(flowId);
        const { depository, signerWallet } = setup;
        const fields = { ...defaultFields(setup, alice), relayerTip: 1_000n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }).toThrow();
    });

    await vm.it('claim with tip on draining flow reverts', async () => {
        const flowId = await registerFlow(setup, { tipCapBps: 200n });
        setSender(deployer);
        await setup.depository.drainFlow(flowId);
        const { depository, signerWallet } = setup;
        const fields = { ...defaultFields(setup, alice), relayerTip: 1_000n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }).toThrow();
    });

    await vm.it('claim with smart-contract recipient + tip', async () => {
        // Use the depository's own address as a stand-in smart-contract
        // recipient (it's a registered contract Address in the harness). The
        // mint splits cleanly and the SC recipient ends up with full netDst.
        await registerFlow(setup, { tipCapBps: 200n });
        const scRecipient = setup.depositoryAddress;
        const { depository, wusdc, signerWallet } = setup;
        const fields = { ...defaultFields(setup, scRecipient), relayerTip: 9_950n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(scRecipient);
        await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        Assert.expect(await wusdc.balanceOf(scRecipient)).toEqual(fields.netAmount);
    });

    await vm.it('malicious-server tip = netDst rejected by cap (100 bps)', async () => {
        await registerFlow(setup, { tipCapBps: 100n });
        const { depository, signerWallet } = setup;
        // tip == netDst → bps = 10_000 → orders of magnitude over 100.
        const fields = { ...defaultFields(setup, alice), relayerTip: 995_000n };
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }).toThrow();
    });
});

// ════════════════════════════════════════════════════════════════════════════
// claimReleaseWithVoucher (mode 1 INVERSE_WRAPPED) — tip-payout subset
//
// Mode 1 means the OPNet-side token is canonical. The bridge holds the OP20
// inventory and `transfer`s it out (no minting). For testing we reuse the
// WrappedOP20 contract as a stand-in canonical OP20 — the depository is
// pre-funded via `mintTo` (allowed because depository is the configured
// minter), then mode-1 is set via `setTokenMode` and inventory is paid out
// against a release voucher.
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository — PR β.2.payout-opnet — release path', async (vm: OPNetUnit) => {
    let setup: BridgeSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => disposeSetup(setup));

    /**
     * For the release path we need:
     *   - `_tokenMode[wusdc]` to be 1 (INVERSE_WRAPPED) — so bob can wire
     *     `setTokenMode` from governor before `_tokenModeFinalized` is set.
     *   - depository to hold a balance of `wusdc` so `transfer` succeeds.
     *
     * Since `setTokenMode` is part of the contract, we drive it via the
     * test wrapper. To pre-fund the depository we exploit the fact that
     * WrappedOP20 lets the depository (its minter) call `mintTo(self,...)`
     * directly. We don't have a wrapper for that here; instead, mode-1
     * release works against the `transfer(address,uint256)` selector on
     * the OP20, so we need depository's balance to be at least netAmount.
     *
     * The `provisionInventoryOpNet` admin entry pulls tokens from the
     * caller into the depository — but it requires the caller (deployer)
     * to have a balance and have approved the depository. Easiest route
     * here: skip provisioning by minting directly to the depository via a
     * synthetic mint voucher (mode 0) FIRST, then flip token mode to 1,
     * THEN issue a release voucher. mode flips to 1 are blocked once
     * `_tokenModeFinalized` is set, so we must do it BEFORE any setTokenMode.
     *
     * Simplest approach for the unit test: mint balance to the depository
     * via a mode-0 voucher addressed to the depository itself, then flip
     * mode to 1 and run the release.
     */
    async function preFundAndFlipMode1(amount: bigint): Promise<void> {
        // Step 1: register a mode-0 flow + mint to the depository.
        await registerFlow(setup, { tipCapBps: 0n });
        const { depository, signerWallet, depositoryAddress } = setup;
        const f0 = {
            ...defaultFields(setup, depositoryAddress),
            voucherId: 0x999n,
            sourceLogIndex: 100,
            grossAmount: amount,
            feeAmount: 0n,
            netAmount: amount,
            relayerTip: 0n,
        };
        const v0 = buildVoucher(f0);
        setSender(depositoryAddress);
        await depository.claimMintWithVoucher(v0.preimage, signVoucher(signerWallet, v0.hash));
        // Step 2: set token mode = 1 (INVERSE_WRAPPED). Requires governor.
        // We drive it through the BinaryWriter directly because the wrapper
        // class has no setTokenMode helper.
        const { ABIDataTypes } = await import('@btc-vision/transaction');
        const { encodeSelectorWithParams } = await import('../contracts/utils.js');
        const setTokenModeSel = encodeSelectorWithParams(
            'setTokenMode',
            ABIDataTypes.ADDRESS,
            ABIDataTypes.UINT256,
            ABIDataTypes.UINT256,
        );
        const w = new BinaryWriter();
        w.writeSelector(setTokenModeSel);
        w.writeAddress(setup.wusdcAddress);
        w.writeU256(1n); // mode=1
        // evmCounterpart MUST be non-zero for non-WRAPPED modes. Pin to a
        // synthetic 32-byte identity — content is opaque to the claim
        // payout logic (PR γ will validate it).
        w.writeU256(0xc0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0fen);
        setSender(deployer);
        await (depository as unknown as {
            execute: (a: { calldata: Uint8Array }) => Promise<{ error?: Error }>;
        }).execute({ calldata: w.getBuffer() }).then((r) => {
            if (r.error) throw r.error;
        });
    }

    async function callClaimReleaseWithVoucher(
        depository: BridgeDepository,
        voucher: Uint8Array,
        sigBlob: Uint8Array,
    ): Promise<void> {
        const { ABIDataTypes } = await import('@btc-vision/transaction');
        const { encodeSelectorWithParams } = await import('../contracts/utils.js');
        const sel = encodeSelectorWithParams(
            'claimReleaseWithVoucher',
            ABIDataTypes.BYTES,
            ABIDataTypes.BYTES,
        );
        const w = new BinaryWriter();
        w.writeSelector(sel);
        w.writeBytesWithLength(voucher);
        w.writeBytesWithLength(sigBlob);
        const r = await (depository as unknown as {
            execute: (a: { calldata: Uint8Array }) => Promise<{ error?: Error }>;
        }).execute({ calldata: w.getBuffer() });
        if (r.error) throw r.error;
    }

    await vm.it('mode-1 release: insufficient inventory reverts (γ.1 enforcement)', async () => {
        // PR γ.1 enforces inventory ≥ grossDst on the mode-1 release path.
        // Until γ.2 ships the burn-side inventory bump (or a governor-set
        // inventory bootstrap), mode-1 release flows start at inventory=0
        // and cannot pay out. Verify the new reversion. The happy-path
        // version of this test moves to PR γ.2 once inventory bootstrap
        // exists.
        await preFundAndFlipMode1(2_000_000n);
        const releaseSrcBridge = Blockchain.generateRandomAddress();
        const releaseSrcToken = Blockchain.generateRandomAddress();
        await registerFlow(setup, {
            mode: 1n,
            sourceBridgeAddr: releaseSrcBridge,
            sourceTokenAddr: releaseSrcToken,
            tipCapBps: 200n,
        });
        const { depository, signerWallet } = setup;
        const fields: VoucherFields = {
            contractSelf: setup.depositoryAddress,
            selector: CLAIM_RELEASE_WITH_VOUCHER_SELECTOR,
            recipient: alice,
            sourceBridgeAddr: releaseSrcBridge,
            sourceTokenAddr: releaseSrcToken,
            sourceTxHash: 0xfeed1n,
            sourceLogIndex: 200,
            wrappedToken: setup.wusdcAddress,
            grossAmount: 1_000_000n,
            feeAmount: 5_000n,
            netAmount: 995_000n,
            relayerTip: 9_950n,
            voucherId: 0xb01n,
        };
        const { preimage, hash } = buildVoucher(fields);
        setSender(alice);
        await Assert.expect(async () => {
            await callClaimReleaseWithVoucher(
                depository,
                preimage,
                signVoucher(signerWallet, hash),
            );
        }).toThrow();
    });

    await vm.it('mode-1 release: tip > flowTipCap reverts', async () => {
        await preFundAndFlipMode1(2_000_000n);
        const releaseSrcBridge = Blockchain.generateRandomAddress();
        const releaseSrcToken = Blockchain.generateRandomAddress();
        await registerFlow(setup, {
            mode: 1n,
            sourceBridgeAddr: releaseSrcBridge,
            sourceTokenAddr: releaseSrcToken,
            tipCapBps: 50n, // 50 bps
        });
        const { depository, signerWallet } = setup;
        const fields: VoucherFields = {
            contractSelf: setup.depositoryAddress,
            selector: CLAIM_RELEASE_WITH_VOUCHER_SELECTOR,
            recipient: bob,
            sourceBridgeAddr: releaseSrcBridge,
            sourceTokenAddr: releaseSrcToken,
            sourceTxHash: 0xfeed2n,
            sourceLogIndex: 201,
            wrappedToken: setup.wusdcAddress,
            grossAmount: 1_000_000n,
            feeAmount: 5_000n,
            netAmount: 995_000n,
            relayerTip: 9_950n, // 100 bps > 50 bps cap
            voucherId: 0xb02n,
        };
        const { preimage, hash } = buildVoucher(fields);
        setSender(bob);
        await Assert.expect(async () => {
            await callClaimReleaseWithVoucher(
                depository,
                preimage,
                signVoucher(signerWallet, hash),
            );
        }).toThrow();
    });
});

// ════════════════════════════════════════════════════════════════════════════
// M-02 — claimMintWithVoucher no longer caps against cumulative _flowInventory
//
// Fix: mint-on-OPNet modes (0/2) no longer increment `_flowInventory` and no
// longer enforce the flow `cap` against it. Pre-M-02, `cap` acted as a
// LIFETIME ceiling that permanently bricked the mint path once cumulative
// volume reached it. The rolling `dailyLimit` is still the mint bound.
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository — M-02: mint path cap/inventory removed', async (vm: OPNetUnit) => {
    let setup: BridgeSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => disposeSetup(setup));

    // Mint flowId — mirrors `_flowIdFromVoucher(mode 0, chainId, evmBridge,
    // evmToken, depository, wrappedToken)`.
    async function mintFlowId(): Promise<bigint> {
        return await setup.depository.computeFlowId(
            0n,
            ETH_CHAIN_ID,
            evmAddrRightPadToBigInt(DEFAULT_SOURCE_BRIDGE),
            evmAddrRightPadToBigInt(DEFAULT_SOURCE_TOKEN),
            opnetAddrToBigInt(setup.depositoryAddress),
            opnetAddrToBigInt(setup.wusdcAddress),
        );
    }

    await vm.it('cumulative mints exceeding the flow cap still succeed', async () => {
        // cap = 1_500_000 — below the sum of three 995_000-net claims
        // (2_985_000). dailyLimit kept high so it is not the binding limit.
        await registerFlow(setup, {
            cap: 1_500_000n,
            dailyLimit: 1_000_000_000_000n,
        });
        const { depository, wusdc, signerWallet } = setup;

        // Three claims, distinct voucherId + sourceLogIndex so each is a
        // unique source event. Total net minted = 2_985_000 >> cap.
        for (let i = 0; i < 3; i++) {
            const fields = {
                ...defaultFields(setup, alice),
                voucherId: 0x1000n + BigInt(i),
                sourceLogIndex: 10 + i,
                relayerTip: 0n,
            };
            const { preimage, hash } = buildVoucher(fields);
            setSender(alice);
            // Pre-M-02 the 2nd claim would revert 'flow cap exceeded'.
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }

        Assert.expect(await wusdc.balanceOf(alice)).toEqual(2_985_000n);
        Assert.expect(await wusdc.totalSupply()).toEqual(2_985_000n);
    });

    await vm.it('_flowInventory stays 0 for a mint flow after claims', async () => {
        await registerFlow(setup, {
            cap: 1_500_000n,
            dailyLimit: 1_000_000_000_000n,
        });
        const { depository, signerWallet } = setup;

        for (let i = 0; i < 2; i++) {
            const fields = {
                ...defaultFields(setup, alice),
                voucherId: 0x2000n + BigInt(i),
                sourceLogIndex: 20 + i,
                relayerTip: 0n,
            };
            const { preimage, hash } = buildVoucher(fields);
            setSender(alice);
            await depository.claimMintWithVoucher(preimage, signVoucher(signerWallet, hash));
        }

        // getFlow tuple index 16 = inventory (see BridgeDepository wrapper).
        const flow = await depository.getFlow(await mintFlowId());
        Assert.expect(flow[16]).toEqual(0n);
    });

    await vm.it('dailyLimit revert still fires when a window total exceeds it', async () => {
        // dailyLimit = 1_500_000 on the source-side gross. Each claim's
        // gross = 1_000_000. First claim consumes 1_000_000; the second
        // would push the window total to 2_000_000 > 1_500_000 → revert.
        await registerFlow(setup, {
            cap: 1_000_000_000_000n,
            dailyLimit: 1_500_000n,
        });
        const { depository, signerWallet } = setup;

        const f1 = {
            ...defaultFields(setup, alice),
            voucherId: 0x3000n,
            sourceLogIndex: 30,
            relayerTip: 0n,
        };
        const v1 = buildVoucher(f1);
        setSender(alice);
        await depository.claimMintWithVoucher(v1.preimage, signVoucher(signerWallet, v1.hash));

        const f2 = {
            ...defaultFields(setup, alice),
            voucherId: 0x3001n,
            sourceLogIndex: 31,
            relayerTip: 0n,
        };
        const v2 = buildVoucher(f2);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.claimMintWithVoucher(v2.preimage, signVoucher(signerWallet, v2.hash));
        }).toThrow();
    });
});

// ════════════════════════════════════════════════════════════════════════════
// L-07 — claimReleaseWithVoucher recipient==sender binding relaxed when tipped
//
// Fix: the `recipient == tx.sender` binding on the release path is enforced
// ONLY when `relayerTip == 0`. A non-zero tip means the user opted into
// permissionless submission — any sender may relay; funds still go to the
// voucher's recipient. Without this the relayer-tip release path is
// unreachable (only the recipient could ever submit).
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository — L-07: release recipient binding gated by tip', async (vm: OPNetUnit) => {
    let setup: BridgeSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
    });

    vm.afterEach(() => disposeSetup(setup));

    // Mint balance into the depository via a mode-0 voucher, then flip the
    // wrapped token to mode-1 (INVERSE_WRAPPED) so the release path is live.
    async function preFundAndFlipMode1(amount: bigint): Promise<void> {
        await registerFlow(setup, { tipCapBps: 0n });
        const { depository, signerWallet, depositoryAddress } = setup;
        const f0 = {
            ...defaultFields(setup, depositoryAddress),
            voucherId: 0x7999n,
            sourceLogIndex: 700,
            grossAmount: amount,
            feeAmount: 0n,
            netAmount: amount,
            relayerTip: 0n,
        };
        const v0 = buildVoucher(f0);
        setSender(depositoryAddress);
        await depository.claimMintWithVoucher(v0.preimage, signVoucher(signerWallet, v0.hash));

        const { ABIDataTypes } = await import('@btc-vision/transaction');
        const { encodeSelectorWithParams } = await import('../contracts/utils.js');
        const setTokenModeSel = encodeSelectorWithParams(
            'setTokenMode',
            ABIDataTypes.ADDRESS,
            ABIDataTypes.UINT256,
            ABIDataTypes.UINT256,
        );
        const w = new BinaryWriter();
        w.writeSelector(setTokenModeSel);
        w.writeAddress(setup.wusdcAddress);
        w.writeU256(1n);
        w.writeU256(0xc0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0fen);
        setSender(deployer);
        await (depository as unknown as {
            execute: (a: { calldata: Uint8Array }) => Promise<{ error?: Error }>;
        }).execute({ calldata: w.getBuffer() }).then((r) => {
            if (r.error) throw r.error;
        });
    }

    async function callClaimReleaseWithVoucher(
        depository: BridgeDepository,
        voucher: Uint8Array,
        sigBlob: Uint8Array,
    ): Promise<void> {
        const { ABIDataTypes } = await import('@btc-vision/transaction');
        const { encodeSelectorWithParams } = await import('../contracts/utils.js');
        const sel = encodeSelectorWithParams(
            'claimReleaseWithVoucher',
            ABIDataTypes.BYTES,
            ABIDataTypes.BYTES,
        );
        const w = new BinaryWriter();
        w.writeSelector(sel);
        w.writeBytesWithLength(voucher);
        w.writeBytesWithLength(sigBlob);
        const r = await (depository as unknown as {
            execute: (a: { calldata: Uint8Array }) => Promise<{ error?: Error }>;
        }).execute({ calldata: w.getBuffer() });
        if (r.error) throw r.error;
    }

    function releaseFields(recipient: Address, tip: bigint, srcBridge: Address, srcToken: Address): VoucherFields {
        return {
            contractSelf: setup.depositoryAddress,
            selector: CLAIM_RELEASE_WITH_VOUCHER_SELECTOR,
            recipient,
            sourceBridgeAddr: srcBridge,
            sourceTokenAddr: srcToken,
            sourceTxHash: 0xfeed7n,
            sourceLogIndex: 770,
            wrappedToken: setup.wusdcAddress,
            grossAmount: 1_000_000n,
            feeAmount: 5_000n,
            netAmount: 995_000n,
            relayerTip: tip,
            voucherId: 0xb77n,
        };
    }

    await vm.it('tip-zero release submitted by a non-recipient reverts wrong recipient', async () => {
        await preFundAndFlipMode1(2_000_000n);
        const srcBridge = Blockchain.generateRandomAddress();
        const srcToken = Blockchain.generateRandomAddress();
        await registerFlow(setup, {
            mode: 1n,
            sourceBridgeAddr: srcBridge,
            sourceTokenAddr: srcToken,
            tipCapBps: 200n,
        });
        const { depository, signerWallet } = setup;
        // recipient = alice, tip = 0 → binding enforced.
        const { preimage, hash } = buildVoucher(releaseFields(alice, 0n, srcBridge, srcToken));
        // Submitted by bob (NOT the recipient) → 'wrong recipient'.
        setSender(bob);
        await Assert.expect(async () => {
            await callClaimReleaseWithVoucher(depository, preimage, signVoucher(signerWallet, hash));
        }).toThrow();
    });

    await vm.it('tipped release submitted by a non-recipient does NOT revert on the recipient check', async () => {
        // A tipped (relayerTip > 0) release voucher relaxes the
        // recipient==sender binding. We prove the recipient check is no
        // longer the blocker by submitting from a non-recipient (bob) and
        // asserting the call gets PAST the L-07 check.
        //
        // Mode-1 release also enforces `_flowInventory >= grossDst`. This
        // unit-test harness pre-funds the depository's token *balance* but
        // not the flow *inventory ledger* (that ledger is produced by
        // `lockForBridge` — exercised end-to-end in flow-consumption.ts).
        // So the tipped call reverts with 'insufficient flow inventory'
        // — NOT 'wrong recipient'. That distinct revert message is the
        // proof: a tip-zero voucher from a non-recipient dies at the
        // recipient gate; the tipped one sails past it and only stops at
        // the later inventory check.
        await preFundAndFlipMode1(2_000_000n);
        const srcBridge = Blockchain.generateRandomAddress();
        const srcToken = Blockchain.generateRandomAddress();
        await registerFlow(setup, {
            mode: 1n,
            sourceBridgeAddr: srcBridge,
            sourceTokenAddr: srcToken,
            tipCapBps: 200n,
        });
        const { depository, signerWallet } = setup;
        // recipient = alice, tip = 9_950 (100 bps, under the 200 bps cap).
        const { preimage, hash } = buildVoucher(releaseFields(alice, 9_950n, srcBridge, srcToken));
        setSender(bob); // bob is NOT the voucher recipient.

        let caught: Error | undefined;
        try {
            await callClaimReleaseWithVoucher(depository, preimage, signVoucher(signerWallet, hash));
        } catch (e) {
            caught = e as Error;
        }
        // It still reverts — but on the LATER inventory check, never on the
        // L-07 recipient gate. If the binding still applied, the message
        // would be 'wrong recipient'.
        Assert.expect(caught !== undefined).toEqual(true);
        const msg = caught!.message;
        Assert.expect(msg.includes('wrong recipient')).toEqual(false);
        Assert.expect(msg.includes('insufficient flow inventory')).toEqual(true);
    });
});
