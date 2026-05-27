/**
 * BridgeDepository — trustless stranded-lock refund tests.
 *
 * Mirrors the EVM `BridgeEscrow.markDepositRefundable` + `refundLockedDeposit`
 * lattice on the OPNet side: an OPNet-source lock (`lockForBridge`, modes
 * 1/3/4) whose EVM far-leg was cancelled / never claimed can be recovered by
 * the user, gated by an M-of-N attestation from the bridge signer set (the
 * SAME trust model that authorizes vouchers + confirmBurn).
 *
 * Two steps:
 *   1. markLockRefundable(lockNonce, sig) — permissionless with a valid M-of-N
 *      RefundAuthorization. HARDENED: the contract REBUILDS the 264-byte
 *      preimage from the stored lock record's IDENTITY (user/token/amount/
 *      lockBlock) + flowId + chain data, so the signature binds the lock's full
 *      identity + a reorg guard. LOCKED → REFUNDABLE.
 *   2. refundLock(lockNonce) — returns the FULL gross principal to the
 *      recorded locker; reverses the mode-1 inventory credit + the carved fee
 *      (fee NOT promoted), preserving `inventory + accruedFees == balance`.
 *
 * Coverage:
 *   ✓ mode-1 happy path: lock → mark → refund returns funds, inventory
 *     decremented to 0, accruedFees reversed, invariant holds
 *   ✓ mode-3 happy path: lock (no inventory credit) → mark → refund returns
 *     gross, accruedFees reversed, inventory untouched
 *   ✓ refundLock before markLockRefundable reverts
 *   ✓ double-refundLock reverts
 *   ✓ markLockRefundable twice reverts (already refundable)
 *   ✓ markLockRefundable with wrong signerEpoch reverts
 *   ✓ markLockRefundable with wrong flowId (identity drift) reverts
 *   ✓ markLockRefundable with wrong user (identity drift) reverts
 *   ✓ markLockRefundable with wrong amount (identity drift) reverts
 *   ✓ identity-mismatch / replay: a sig built for lock A is rejected against
 *     lock B (different record) — the reorg/replay guard
 *   ✓ markLockRefundable with unsigned (garbage) sig reverts
 *   ✓ markLockRefundable / refundLock on non-existent lockNonce reverts
 *
 * Run: cd contracts/op-contracts && npm run build && \
 *      npx tsx __test__/unit/tests/stranded-lock-refund.ts
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address, Wallet } from '@btc-vision/transaction';
import { sha256 } from '@noble/hashes/sha2.js';

import { WrappedOP20 } from '../contracts/WrappedOP20.js';
import { BridgeDepository } from '../contracts/BridgeDepository.js';

// ─── Constants — must mirror BridgeDepository.ts ──────────────────────────
const VOUCHER_NETWORK_ID: bigint = 2n;
const ETH_CHAIN_ID: bigint = 1n;
const REFUND_AUTHORIZATION_LEN = 264;
const MARK_LOCK_REFUNDABLE_SELECTOR: number = 0xcdcd9059;

const FEE_BPS = 50n; // 0.5%

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

// ─── RefundAuthorization preimage (264 bytes) ─────────────────────────────
// networkId(32) ‖ contractSelf(32) ‖ selector(4) ‖ lockNonce(32) ‖
// flowId(32) ‖ user(32) ‖ canonicalToken(32) ‖ amount(32) ‖
// lockBlockNumber(32) ‖ signerEpoch(4)
//
// The CONTRACT rebuilds this exact layout from its stored lock record + chain
// data; the test signs over the SAME bytes. Identity fields (user/token/amount/
// lockBlock) come from the on-chain `lockRecord` (see `authFromRecord`).
interface RefundAuthFields {
    networkId?: bigint;
    contractSelf: Address;
    selector?: number;
    lockNonce: bigint;
    flowId: bigint;
    user: bigint;
    token: bigint;
    amount: bigint;
    lockBlock: bigint;
    signerEpoch?: number;
}

function buildRefundAuth(f: RefundAuthFields): { preimage: Uint8Array; hash: Uint8Array } {
    const buf = new Uint8Array(REFUND_AUTHORIZATION_LEN);
    writeU256BE(buf, 0, f.networkId ?? VOUCHER_NETWORK_ID);
    writeAddress(buf, 32, f.contractSelf);
    writeU32BE(buf, 64, f.selector ?? MARK_LOCK_REFUNDABLE_SELECTOR);
    writeU256BE(buf, 68, f.lockNonce);
    writeU256BE(buf, 100, f.flowId);
    writeU256BE(buf, 132, f.user);
    writeU256BE(buf, 164, f.token);
    writeU256BE(buf, 196, f.amount);
    writeU256BE(buf, 228, f.lockBlock);
    writeU32BE(buf, 260, f.signerEpoch ?? 1);
    return { preimage: buf, hash: sha256(buf) };
}

// Build the canonical (matching-the-contract) RefundAuthorization from the
// on-chain lock record. `rec` is the 8 × u256 lockRecord array:
//   [0]status [1]user [2]token [3]flowId [4]amount [5]fee [6]mode [7]blockNumber
function authFromRecord(
    contractSelf: Address,
    lockNonce: bigint,
    rec: bigint[],
    overrides: Partial<RefundAuthFields> = {},
): { preimage: Uint8Array; hash: Uint8Array } {
    return buildRefundAuth({
        contractSelf,
        lockNonce,
        flowId: rec[3]!,
        user: rec[1]!,
        token: rec[2]!,
        amount: rec[4]!,
        lockBlock: rec[7]!,
        ...overrides,
    });
}

// M=N=1 sig blob — same packer the confirm-burn / voucher tests use.
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

function evmRecipient(): Uint8Array {
    const r = new Uint8Array(32);
    for (let i = 12; i < 32; i++) r[i] = 0xab;
    return r;
}

const SOURCE_BRIDGE: Address = Blockchain.generateRandomAddress();
const SOURCE_TOKEN: Address = Blockchain.generateRandomAddress();

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

// Fund alice + approve, returns the lockNonce.
async function fundLock(setup: Setup, flowId: bigint, amount: bigint): Promise<bigint> {
    const { wusdc, wusdcAddress, depositoryAddress } = setup;
    setSender(depositoryAddress);
    await wusdc.mintTo(alice, amount);
    await wusdc.increaseAllowance(alice, depositoryAddress, amount);
    setSender(alice);
    return await setup.depository.lockForBridge(
        flowId, wusdcAddress, amount, evmRecipient(), 1,
    );
}

// Bridge wUSDC balance (held inventory + accrued fee back the physical bal).
async function bridgeBalance(setup: Setup): Promise<bigint> {
    return await setup.wusdc.balanceOf(setup.depositoryAddress);
}

// getFlow layout index 16 = inventory (matches confirm-burn.ts).
async function flowInventory(setup: Setup, flowId: bigint): Promise<bigint> {
    const flow = await setup.depository.getFlow(flowId);
    return flow[16]!;
}

// ════════════════════════════════════════════════════════════════════════════
// Happy paths
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository.stranded-lock-refund — mode-1 happy path', async (vm: OPNetUnit) => {
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

    await vm.it('lock → mark → refund returns full gross; inventory + fee reversed; invariant holds', async () => {
        const { depository } = setup;
        const flowId = await registerFlow(setup, 1n);
        const amount = 2_000_000n;
        const fee = (amount * FEE_BPS) / 10_000n; // 10_000
        const net = amount - fee; // 1_990_000

        const lockNonce = await fundLock(setup, flowId, amount);

        // After lock: mode-1 credited NET to inventory, FEE to accruedFees.
        Assert.expect(await flowInventory(setup, flowId)).toEqual(net);
        Assert.expect(await depository.accruedFees(flowId)).toEqual(fee);
        // Bridge physically holds the full gross (invariant: inv + fee == bal).
        Assert.expect(await bridgeBalance(setup)).toEqual(amount);
        Assert.expect(net + fee).toEqual(await bridgeBalance(setup));

        // Lock record sanity.
        const rec = await depository.lockRecord(lockNonce);
        Assert.expect(rec[0]!).toEqual(1n); // LOCKED
        Assert.expect(rec[4]!).toEqual(amount); // gross
        Assert.expect(rec[5]!).toEqual(fee);
        Assert.expect(rec[6]!).toEqual(1n); // mode
        Assert.expect(await depository.isLockRefundable(lockNonce)).toEqual(false);

        // Mark refundable with a valid M-of-N attestation — signed over the
        // identity-bound preimage rebuilt from the on-chain lock record.
        const { hash } = authFromRecord(setup.depositoryAddress, lockNonce, rec);
        const sig = signAuth(setup.signerWallet, hash);
        // Permissionless — alice (the locker) submits, but anyone could.
        setSender(alice);
        await depository.markLockRefundable(lockNonce, sig);
        Assert.expect(await depository.isLockRefundable(lockNonce)).toEqual(true);

        const aliceBefore = await setup.wusdc.balanceOf(alice);

        // Refund.
        await depository.refundLock(lockNonce);

        // User got the FULL gross back.
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(aliceBefore + amount);
        // Inventory + accruedFees fully reversed.
        Assert.expect(await flowInventory(setup, flowId)).toEqual(0n);
        Assert.expect(await depository.accruedFees(flowId)).toEqual(0n);
        // Bridge balance drained back to 0 — invariant preserved.
        Assert.expect(await bridgeBalance(setup)).toEqual(0n);
        // Status is REFUNDED.
        const recAfter = await depository.lockRecord(lockNonce);
        Assert.expect(recAfter[0]!).toEqual(3n); // REFUNDED
        Assert.expect(await depository.isLockRefundable(lockNonce)).toEqual(false);
    });

    await vm.it('double-refundLock reverts', async () => {
        const { depository } = setup;
        const flowId = await registerFlow(setup, 1n);
        const lockNonce = await fundLock(setup, flowId, 2_000_000n);
        const rec = await depository.lockRecord(lockNonce);
        const { hash } = authFromRecord(setup.depositoryAddress, lockNonce, rec);
        setSender(alice);
        await depository.markLockRefundable(lockNonce, signAuth(setup.signerWallet, hash));
        await depository.refundLock(lockNonce);
        await Assert.expect(async () => {
            await depository.refundLock(lockNonce);
        }).toThrow();
    });

    await vm.it('refundLock before markLockRefundable reverts', async () => {
        const { depository } = setup;
        const flowId = await registerFlow(setup, 1n);
        const lockNonce = await fundLock(setup, flowId, 2_000_000n);
        setSender(alice);
        await Assert.expect(async () => {
            await depository.refundLock(lockNonce);
        }).toThrow();
    });

    await vm.it('markLockRefundable twice reverts (already refundable)', async () => {
        const { depository } = setup;
        const flowId = await registerFlow(setup, 1n);
        const lockNonce = await fundLock(setup, flowId, 2_000_000n);
        const rec = await depository.lockRecord(lockNonce);
        const { hash } = authFromRecord(setup.depositoryAddress, lockNonce, rec);
        const sig = signAuth(setup.signerWallet, hash);
        setSender(alice);
        await depository.markLockRefundable(lockNonce, sig);
        await Assert.expect(async () => {
            await depository.markLockRefundable(lockNonce, sig);
        }).toThrow();
    });
});

await opnet('BridgeDepository.stranded-lock-refund — mode-3 happy path', async (vm: OPNetUnit) => {
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

    await vm.it('mode-3 lock credits NO inventory; refund returns gross + reverses fee only', async () => {
        const { depository } = setup;
        const flowId = await registerFlow(setup, 3n);
        const amount = 2_000_000n;
        const fee = (amount * FEE_BPS) / 10_000n;

        const lockNonce = await fundLock(setup, flowId, amount);

        // Mode 3 credits NO OPNet inventory at lock time (release pool lives
        // on the EVM counterpart). Only the fee accrues.
        Assert.expect(await flowInventory(setup, flowId)).toEqual(0n);
        Assert.expect(await depository.accruedFees(flowId)).toEqual(fee);
        Assert.expect(await bridgeBalance(setup)).toEqual(amount);

        const rec = await depository.lockRecord(lockNonce);
        const { hash } = authFromRecord(setup.depositoryAddress, lockNonce, rec);
        setSender(alice);
        await depository.markLockRefundable(lockNonce, signAuth(setup.signerWallet, hash));

        const aliceBefore = await setup.wusdc.balanceOf(alice);
        await depository.refundLock(lockNonce);

        // Full gross back to user.
        Assert.expect(await setup.wusdc.balanceOf(alice)).toEqual(aliceBefore + amount);
        // Inventory stays 0 (nothing was credited); fee reversed to 0.
        Assert.expect(await flowInventory(setup, flowId)).toEqual(0n);
        Assert.expect(await depository.accruedFees(flowId)).toEqual(0n);
        Assert.expect(await bridgeBalance(setup)).toEqual(0n);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// Negative attestation cases
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository.stranded-lock-refund — bad attestations', async (vm: OPNetUnit) => {
    let setup: Setup;
    let flowId: bigint;
    let lockNonce: bigint;
    let rec: bigint[];

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        Blockchain.medianTimestamp = 1_000_000n;
        await Blockchain.init();
        setSender(deployer);
        setup = await setupContracts();
        flowId = await registerFlow(setup, 1n);
        lockNonce = await fundLock(setup, flowId, 2_000_000n);
        rec = await setup.depository.lockRecord(lockNonce);
        setSender(alice);
    });

    vm.afterEach(() => dispose(setup));

    await vm.it('wrong signerEpoch reverts', async () => {
        // Sig over the right identity but epoch 99 — contract rebuilds with the
        // current epoch (1), so the hashes differ and ML-DSA verify fails.
        const { hash } = authFromRecord(setup.depositoryAddress, lockNonce, rec, {
            signerEpoch: 99,
        });
        const sig = signAuth(setup.signerWallet, hash);
        await Assert.expect(async () => {
            await setup.depository.markLockRefundable(lockNonce, sig);
        }).toThrow();
    });

    await vm.it('wrong flowId (identity drift) reverts', async () => {
        const { hash } = authFromRecord(setup.depositoryAddress, lockNonce, rec, {
            flowId: 0xdeadbeefn,
        });
        const sig = signAuth(setup.signerWallet, hash);
        await Assert.expect(async () => {
            await setup.depository.markLockRefundable(lockNonce, sig);
        }).toThrow();
    });

    await vm.it('wrong user (identity drift) reverts', async () => {
        const { hash } = authFromRecord(setup.depositoryAddress, lockNonce, rec, {
            user: opnetAddrToBigInt(Blockchain.generateRandomAddress()),
        });
        const sig = signAuth(setup.signerWallet, hash);
        await Assert.expect(async () => {
            await setup.depository.markLockRefundable(lockNonce, sig);
        }).toThrow();
    });

    await vm.it('wrong amount (identity drift) reverts', async () => {
        const { hash } = authFromRecord(setup.depositoryAddress, lockNonce, rec, {
            amount: 999n,
        });
        const sig = signAuth(setup.signerWallet, hash);
        await Assert.expect(async () => {
            await setup.depository.markLockRefundable(lockNonce, sig);
        }).toThrow();
    });

    await vm.it('wrong lockBlock (reorg-guard drift) reverts', async () => {
        const { hash } = authFromRecord(setup.depositoryAddress, lockNonce, rec, {
            lockBlock: (rec[7]! ?? 0n) + 1n,
        });
        const sig = signAuth(setup.signerWallet, hash);
        await Assert.expect(async () => {
            await setup.depository.markLockRefundable(lockNonce, sig);
        }).toThrow();
    });

    await vm.it('wrong selector reverts', async () => {
        const { hash } = authFromRecord(setup.depositoryAddress, lockNonce, rec, {
            selector: 0xdeadbeef,
        });
        const sig = signAuth(setup.signerWallet, hash);
        await Assert.expect(async () => {
            await setup.depository.markLockRefundable(lockNonce, sig);
        }).toThrow();
    });

    // IDENTITY-MISMATCH / REPLAY GUARD: an attestation signed for lock A's
    // identity is rejected against lock B (a different record). This is the
    // exact reorg scenario — a lockNonce re-assigned to a different lock can
    // never reuse an old signature, because the rebuilt preimage binds the new
    // record's (user/token/amount/block).
    await vm.it('identity-mismatch: sig built for lock A rejected against lock B', async () => {
        // Lock A is `lockNonce` (alice, 2_000_000). Create lock B with a
        // DIFFERENT amount so its identity tuple differs.
        setSender(deployer);
        const lockNonceB = await fundLock(setup, flowId, 3_000_000n);
        const recB = await setup.depository.lockRecord(lockNonceB);
        // Sanity — different gross.
        Assert.expect(rec[4]!).toEqual(2_000_000n);
        Assert.expect(recB[4]!).toEqual(3_000_000n);

        // Build a VALID sig for lock A's record, but submit it against lock B's
        // nonce. The contract rebuilds B's identity-bound preimage → mismatch.
        const { hash: hashA } = authFromRecord(setup.depositoryAddress, lockNonceB, rec);
        const sigForA = signAuth(setup.signerWallet, hashA);
        setSender(alice);
        await Assert.expect(async () => {
            await setup.depository.markLockRefundable(lockNonceB, sigForA);
        }).toThrow();

        // And the genuine sig for B's own identity DOES authorize B.
        const { hash: hashB } = authFromRecord(setup.depositoryAddress, lockNonceB, recB);
        await setup.depository.markLockRefundable(lockNonceB, signAuth(setup.signerWallet, hashB));
        Assert.expect(await setup.depository.isLockRefundable(lockNonceB)).toEqual(true);
    });

    await vm.it('garbage (unsigned) sig reverts', async () => {
        // A structurally-plausible blob signed over a DIFFERENT hash — the
        // ML-DSA verify fails so validCount stays below threshold.
        const badSig = signAuth(setup.signerWallet, sha256(new Uint8Array([1, 2, 3])));
        await Assert.expect(async () => {
            await setup.depository.markLockRefundable(lockNonce, badSig);
        }).toThrow();
    });

    await vm.it('non-existent lockNonce reverts (mark + refund)', async () => {
        const bogus = 0xfffffn;
        // No record exists, so we can't read identity — sign over a plausible
        // preimage; the contract reverts on status NONE before verify anyway.
        const { hash } = buildRefundAuth({
            contractSelf: setup.depositoryAddress,
            lockNonce: bogus,
            flowId,
            user: 0n,
            token: 0n,
            amount: 0n,
            lockBlock: 0n,
        });
        const sig = signAuth(setup.signerWallet, hash);
        await Assert.expect(async () => {
            await setup.depository.markLockRefundable(bogus, sig);
        }).toThrow();
        await Assert.expect(async () => {
            await setup.depository.refundLock(bogus);
        }).toThrow();
    });
});
