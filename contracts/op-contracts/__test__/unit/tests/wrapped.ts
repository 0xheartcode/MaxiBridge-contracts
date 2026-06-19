/**
 * WrappedOP20 unit tests — mint gating, burnForRelease flow, governor rotation,
 * upgrade flow with populated v1 state.
 *
 * Run: cd contracts && npm run build && npx tsx __test__/unit/tests/wrapped.ts
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address } from '@btc-vision/transaction';
import { WrappedOP20 } from '../contracts/WrappedOP20.js';

const deployer: Address = Blockchain.generateRandomAddress();
const alice: Address = Blockchain.generateRandomAddress();
const bob: Address = Blockchain.generateRandomAddress();
const bridgeAddr: Address = Blockchain.generateRandomAddress();
const altBridgeAddr: Address = Blockchain.generateRandomAddress();

function setSender(addr: Address): void {
    Blockchain.msgSender = addr;
    Blockchain.txOrigin = addr;
}

function ethRecipient32(): Uint8Array {
    // 32-byte padded EVM recipient — 12 zero bytes + 20 bytes of address.
    // (bytes 12..31 = 0x01..0x14)
    const out = new Uint8Array(32);
    for (let i = 0; i < 20; i++) out[12 + i] = i + 1;
    return out;
}

function pad20to32(addr20: Uint8Array): Uint8Array {
    if (addr20.length !== 20) throw new Error('pad20to32: expected 20 bytes');
    const out = new Uint8Array(32);
    out.set(addr20, 12);
    return out;
}

async function makeWrapped(): Promise<WrappedOP20> {
    const addr: Address = Blockchain.generateRandomAddress();
    const t = new WrappedOP20({
        file: './build/WrappedOP20.wasm',
        address: addr,
        decimals: 6,
        deployer,
    });
    Blockchain.register(t);
    await t.init();
    return t;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Deployment + mint gate
// ─────────────────────────────────────────────────────────────────────────────

await opnet('WrappedOP20 — deployment + mint gate', async (vm: OPNetUnit) => {
    let token: WrappedOP20;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        token = await makeWrapped();
    });

    vm.afterEach(() => {
        token.dispose();
        Blockchain.dispose();
    });

    await vm.it('fresh deploy reports storageVersion=2 and governor=deployer', async () => {
        Assert.expect(await token.storageVersion()).toEqual(2n);
        Assert.expect((await token.governor()).equals(deployer)).toEqual(true);
    });

    await vm.it('fresh deploy initializes OP20S peg: rate=1e8, authority=deployer, not stale', async () => {
        Assert.expect(await token.pegRate()).toEqual(100_000_000n);
        Assert.expect((await token.pegAuthority()).equals(deployer)).toEqual(true);
        Assert.expect(await token.maxStaleness()).toEqual(1008n);
        Assert.expect(await token.isStale()).toEqual(false);
    });

    await vm.it('mintTo reverts when bridge not set', async () => {
        setSender(deployer);
        await Assert.expect(async () => {
            await token.mintTo(alice, 100n);
        }).toThrow();
    });

    await vm.it('only governor can setBridgeDepository', async () => {
        setSender(alice);
        await Assert.expect(async () => {
            await token.setBridgeDepository(bridgeAddr);
        }).toThrow();

        setSender(deployer);
        await token.setBridgeDepository(bridgeAddr);
        Assert.expect((await token.bridgeDepository()).equals(bridgeAddr)).toEqual(true);
    });

    await vm.it('mintTo works only from registered bridge', async () => {
        setSender(deployer);
        await token.setBridgeDepository(bridgeAddr);

        // deployer cannot mint after bridge is set
        setSender(deployer);
        await Assert.expect(async () => {
            await token.mintTo(alice, 100n);
        }).toThrow();

        // bob cannot mint
        setSender(bob);
        await Assert.expect(async () => {
            await token.mintTo(alice, 100n);
        }).toThrow();

        // bridge address can mint
        setSender(bridgeAddr);
        await token.mintTo(alice, 100n);
        Assert.expect(await token.balanceOf(alice)).toEqual(100n);
        Assert.expect(await token.totalSupply()).toEqual(100n);
    });

    await vm.it('setBridgeDepository is re-settable (pointer can be rotated)', async () => {
        setSender(deployer);
        await token.setBridgeDepository(bridgeAddr);
        await token.setBridgeDepository(altBridgeAddr);

        // old bridge can no longer mint
        setSender(bridgeAddr);
        await Assert.expect(async () => {
            await token.mintTo(alice, 100n);
        }).toThrow();

        // new bridge can mint
        setSender(altBridgeAddr);
        await token.mintTo(alice, 50n);
        Assert.expect(await token.balanceOf(alice)).toEqual(50n);
    });

    await vm.it('mintTo rejects zero amount and zero address', async () => {
        setSender(deployer);
        await token.setBridgeDepository(bridgeAddr);

        setSender(bridgeAddr);
        await Assert.expect(async () => {
            await token.mintTo(alice, 0n);
        }).toThrow();
        await Assert.expect(async () => {
            await token.mintTo(Address.zero(), 100n);
        }).toThrow();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. burnForRelease — real burn + monotonic nonce + event
// ─────────────────────────────────────────────────────────────────────────────

await opnet('WrappedOP20 — burnForRelease', async (vm: OPNetUnit) => {
    let token: WrappedOP20;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        token = await makeWrapped();
        await token.setBridgeDepository(bridgeAddr);

        // M-01 — burnForRelease now requires the destChainId to be enabled.
        // Enable the chains exercised by this suite (mainnet, Sepolia, and
        // the synthetic non-EVM chain 42).
        await token.setSupportedDestChain(1, true, true);
        await token.setSupportedDestChain(11155111, true, true);
        await token.setSupportedDestChain(42, true, false);

        // Pre-mint to alice and bob via the bridge so they have a balance to burn.
        setSender(bridgeAddr);
        await token.mintTo(alice, 1_000n);
        await token.mintTo(bob, 500n);
    });

    vm.afterEach(() => {
        token.dispose();
        Blockchain.dispose();
    });

    await vm.it('burn decreases sender balance and totalSupply, increments nonce', async () => {
        const supplyBefore = await token.totalSupply();
        Assert.expect(await token.burnNonce()).toEqual(0n);

        setSender(alice);
        const nonce = await token.burnForRelease(ethRecipient32(), 300n, 1);

        Assert.expect(nonce).toEqual(1n);
        Assert.expect(await token.balanceOf(alice)).toEqual(700n);
        Assert.expect(await token.totalSupply()).toEqual(supplyBefore - 300n);
        Assert.expect(await token.burnNonce()).toEqual(1n);
    });

    await vm.it('burnNonce is monotonic across senders', async () => {
        setSender(alice);
        Assert.expect(await token.burnForRelease(ethRecipient32(), 100n, 1)).toEqual(1n);

        setSender(bob);
        Assert.expect(await token.burnForRelease(ethRecipient32(), 100n, 1)).toEqual(2n);

        setSender(alice);
        Assert.expect(await token.burnForRelease(ethRecipient32(), 100n, 1)).toEqual(3n);

        Assert.expect(await token.burnNonce()).toEqual(3n);
    });

    await vm.it('harness rejects non-32-byte ethRecipient', async () => {
        setSender(alice);
        const short = new Uint8Array(20);
        await Assert.expect(async () => {
            await token.burnForRelease(short, 100n, 1);
        }).toThrow();
        const long = new Uint8Array(33);
        await Assert.expect(async () => {
            await token.burnForRelease(long, 100n, 1);
        }).toThrow();
    });

    await vm.it('reverts when EVM destChainId has non-zero upper 12 bytes', async () => {
        setSender(alice);
        // First byte nonzero → high 12 bytes are not all zero → must revert
        // for Ethereum mainnet (chainId=1) and Sepolia (11155111).
        const bad = new Uint8Array(32);
        bad[0] = 0x01;
        for (let i = 20; i < 32; i++) bad[i] = 0xaa;

        await Assert.expect(async () => {
            await token.burnForRelease(bad, 100n, 1);
        }).toThrow();

        await Assert.expect(async () => {
            await token.burnForRelease(bad, 100n, 11155111);
        }).toThrow();
    });

    await vm.it('accepts non-zero upper bytes for non-EVM destChainIds (future chains)', async () => {
        // destChainId 2 is reserved in this project for a hypothetical
        // future chain (e.g. Solana). Upper 12 bytes may be non-zero.
        setSender(alice);
        const nonEvm = new Uint8Array(32);
        for (let i = 0; i < 32; i++) nonEvm[i] = i + 1; // fully populated 32-byte recipient

        const nonce = await token.burnForRelease(nonEvm, 50n, 42);
        Assert.expect(nonce).toEqual(1n);
    });

    await vm.it('reverts on zero amount and zero destChainId', async () => {
        setSender(alice);
        await Assert.expect(async () => {
            await token.burnForRelease(ethRecipient32(), 0n, 1);
        }).toThrow();
        await Assert.expect(async () => {
            await token.burnForRelease(ethRecipient32(), 100n, 0);
        }).toThrow();
    });

    await vm.it('reverts when balance insufficient', async () => {
        setSender(alice);
        await Assert.expect(async () => {
            await token.burnForRelease(ethRecipient32(), 10_000n, 1);
        }).toThrow();
    });

    // #68 Tier C — the burn records the flowId it was given in the
    // BurnedForRelease event (appended last at offset 132 of the 164B data).
    await vm.it('records the flowId in the BurnedForRelease event', async () => {
        setSender(alice);
        const flowId = 0x9abcn;
        const events = await token.burnForReleaseEvents(ethRecipient32(), 100n, 1, flowId);
        const burned = events.find((e) => e.type === 'BurnedForRelease');
        Assert.expect(burned !== undefined).toEqual(true);
        const data = burned!.data;
        // Event layout (164B): user(32) | amount(32) | ethRecipient(32) |
        //   destChainId(4) | burnNonce(32) | flowId(32). flowId at offset 132.
        Assert.expect(data.length).toEqual(164);
        let parsedFlowId = 0n;
        for (let i = 132; i < 164; i++) {
            parsedFlowId = (parsedFlowId << 8n) | BigInt(data[i]);
        }
        Assert.expect(parsedFlowId).toEqual(flowId);
        // burnNonce (offset 100) still parses to 1 — pre-existing offsets stable.
        let parsedNonce = 0n;
        for (let i = 100; i < 132; i++) {
            parsedNonce = (parsedNonce << 8n) | BigInt(data[i]);
        }
        Assert.expect(parsedNonce).toEqual(1n);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Fix #6 — burnForRelease pause gate
// ─────────────────────────────────────────────────────────────────────────────

await opnet('WrappedOP20 — Fix #6: burnForRelease pause gate', async (vm: OPNetUnit) => {
    let token: WrappedOP20;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        token = await makeWrapped();
        await token.setBridgeDepository(bridgeAddr);

        // M-01 — enable destChainId 1 so the pause-gate test exercises the
        // burn path itself rather than tripping the allowlist.
        await token.setSupportedDestChain(1, true, true);

        setSender(bridgeAddr);
        await token.mintTo(alice, 1_000n);
    });

    vm.afterEach(() => {
        token.dispose();
        Blockchain.dispose();
    });

    await vm.it('default state is unpaused', async () => {
        Assert.expect(await token.paused()).toEqual(false);
    });

    await vm.it('only governor can call setPaused', async () => {
        setSender(alice);
        await Assert.expect(async () => {
            await token.setPaused(true);
        }).toThrow();
    });

    await vm.it('paused contract blocks burnForRelease; unpause restores it', async () => {
        setSender(deployer);
        await token.setPaused(true);
        Assert.expect(await token.paused()).toEqual(true);

        setSender(alice);
        await Assert.expect(async () => {
            await token.burnForRelease(ethRecipient32(), 100n, 1);
        }).toThrow();

        setSender(deployer);
        await token.setPaused(false);

        setSender(alice);
        const nonce = await token.burnForRelease(ethRecipient32(), 100n, 1);
        Assert.expect(nonce).toEqual(1n);
        Assert.expect(await token.balanceOf(alice)).toEqual(900n);
    });

    await vm.it('paused contract blocks mintTo; unpause restores it (PVE009)', async () => {
        // PVE009 — `_paused` is a full freeze: mint AND burn. `onlyMinter`
        // admits granted minters beyond the depository (grantMinter) and this
        // token is non-upgradeable, so the mint path needs its own circuit
        // breaker rather than relying on the depository pause.
        setSender(deployer);
        await token.setPaused(true);

        setSender(bridgeAddr);
        await Assert.expect(async () => {
            await token.mintTo(alice, 100n);
        }).toThrow();

        setSender(deployer);
        await token.setPaused(false);

        setSender(bridgeAddr);
        await token.mintTo(alice, 100n);
        Assert.expect(await token.balanceOf(alice)).toEqual(1_100n);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. OP20S peg oracle — rate updates, authority transfer, staleness
// ─────────────────────────────────────────────────────────────────────────────

await opnet('WrappedOP20 — OP20S peg oracle', async (vm: OPNetUnit) => {
    let token: WrappedOP20;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        token = await makeWrapped();
    });

    vm.afterEach(() => {
        token.dispose();
        Blockchain.dispose();
    });

    await vm.it('only peg authority can updatePegRate', async () => {
        setSender(alice);
        await Assert.expect(async () => {
            await token.updatePegRate(200_000_000n);
        }).toThrow();

        setSender(deployer);
        await token.updatePegRate(200_000_000n);
        Assert.expect(await token.pegRate()).toEqual(200_000_000n);
    });

    await vm.it('updatePegRate rejects zero rate', async () => {
        setSender(deployer);
        await Assert.expect(async () => {
            await token.updatePegRate(0n);
        }).toThrow();
    });

    await vm.it('updateMaxStaleness is authority-gated and zero-rejected', async () => {
        setSender(alice);
        await Assert.expect(async () => {
            await token.updateMaxStaleness(500n);
        }).toThrow();

        setSender(deployer);
        await Assert.expect(async () => {
            await token.updateMaxStaleness(0n);
        }).toThrow();

        setSender(deployer);
        await token.updateMaxStaleness(500n);
        Assert.expect(await token.maxStaleness()).toEqual(500n);
    });

    await vm.it('transferPegAuthority requires acceptance by the pending authority', async () => {
        setSender(deployer);
        await token.transferPegAuthority(alice);

        // Bob (not pending) cannot accept.
        setSender(bob);
        await Assert.expect(async () => {
            await token.acceptPegAuthority();
        }).toThrow();

        // Alice (pending) accepts — authority rotates.
        setSender(alice);
        await token.acceptPegAuthority();
        Assert.expect((await token.pegAuthority()).equals(alice)).toEqual(true);

        // Old authority (deployer) can no longer update the rate.
        setSender(deployer);
        await Assert.expect(async () => {
            await token.updatePegRate(300_000_000n);
        }).toThrow();

        // New authority (alice) can.
        setSender(alice);
        await token.updatePegRate(300_000_000n);
        Assert.expect(await token.pegRate()).toEqual(300_000_000n);
    });

    await vm.it('transferPegAuthority rejects zero address', async () => {
        setSender(deployer);
        await Assert.expect(async () => {
            await token.transferPegAuthority(Address.zero());
        }).toThrow();
    });

    await vm.it('renouncePegAuthority clears the authority permanently', async () => {
        setSender(deployer);
        await token.renouncePegAuthority();

        // Nobody can call authority-gated methods now.
        setSender(deployer);
        await Assert.expect(async () => {
            await token.updatePegRate(400_000_000n);
        }).toThrow();
    });
});

// ════════════════════════════════════════════════════════════════════════════
// Phase 1.2 — minter role separation
// ════════════════════════════════════════════════════════════════════════════

await opnet('WrappedOP20 — Phase 1.2 minter role', async (vm: OPNetUnit) => {
    let token: WrappedOP20;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        token = await makeWrapped();
        // Wire the legacy bridge — it should remain an implicit minter
        // for backward compat.
        await token.setBridgeDepository(bridgeAddr);
    });

    vm.afterEach(() => {
        token.dispose();
        Blockchain.dispose();
    });

    await vm.it('legacy bridge address is implicitly a minter (no grantMinter needed)', async () => {
        Assert.expect(await token.isMinter(bridgeAddr)).toEqual(true);
    });

    await vm.it('grantMinter: governor can grant; isMinter() reflects it', async () => {
        const newMinter = Blockchain.generateRandomAddress();
        Assert.expect(await token.isMinter(newMinter)).toEqual(false);

        setSender(deployer);
        await token.grantMinter(newMinter);
        Assert.expect(await token.isMinter(newMinter)).toEqual(true);
    });

    await vm.it('grantMinter: non-governor / non-authority reverts', async () => {
        setSender(alice);
        await Assert.expect(async () => {
            await token.grantMinter(bob);
        }).toThrow();
    });

    await vm.it('grantMinter: zero address reverts', async () => {
        setSender(deployer);
        await Assert.expect(async () => {
            await token.grantMinter(Address.zero());
        }).toThrow();
    });

    await vm.it('mintTo: granted minter can mint (parity with legacy bridge path)', async () => {
        const newMinter = Blockchain.generateRandomAddress();
        setSender(deployer);
        await token.grantMinter(newMinter);

        // The granted minter mints to alice — must succeed.
        setSender(newMinter);
        await token.mintTo(alice, 1_000_000n);
        Assert.expect(await token.balanceOf(alice)).toEqual(1_000_000n);
    });

    await vm.it('mintTo: legacy bridge still works after the v2 onlyMinter switch', async () => {
        setSender(bridgeAddr);
        await token.mintTo(alice, 500_000n);
        Assert.expect(await token.balanceOf(alice)).toEqual(500_000n);
    });

    await vm.it('mintTo: non-minter reverts', async () => {
        setSender(alice); // alice was never granted minter
        await Assert.expect(async () => {
            await token.mintTo(bob, 1_000_000n);
        }).toThrow();
    });

    await vm.it('revokeMinter: revoked address can no longer mint', async () => {
        const newMinter = Blockchain.generateRandomAddress();
        setSender(deployer);
        await token.grantMinter(newMinter);
        await token.revokeMinter(newMinter);
        Assert.expect(await token.isMinter(newMinter)).toEqual(false);

        setSender(newMinter);
        await Assert.expect(async () => {
            await token.mintTo(alice, 1n);
        }).toThrow();
    });

    await vm.it('setAuthorityAddress: registered authority can grant minters', async () => {
        // Pretend `bob` is the BridgeAuthority address.
        setSender(deployer);
        await token.setAuthorityAddress(bob);
        Assert.expect((await token.authorityAddress()).equals(bob)).toEqual(true);

        const newMinter = Blockchain.generateRandomAddress();
        setSender(bob);
        await token.grantMinter(newMinter);
        Assert.expect(await token.isMinter(newMinter)).toEqual(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// M-01 — burnForRelease destChainId allowlist
//
// Fix: WrappedOP20 now keeps a governor-managed `_supportedDestChains` set.
// `burnForRelease` reverts 'WrappedOP20: unsupported destChainId' for any
// destChainId not enabled. Fail-closed — a fresh deploy services no chain.
// A burn to an unsupported chain would otherwise destroy tokens with no
// release voucher and no refund path.
// ════════════════════════════════════════════════════════════════════════════

await opnet('WrappedOP20 — M-01: burnForRelease destChainId allowlist', async (vm: OPNetUnit) => {
    let token: WrappedOP20;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        token = await makeWrapped();
        await token.setBridgeDepository(bridgeAddr);

        setSender(bridgeAddr);
        await token.mintTo(alice, 10_000n);
    });

    vm.afterEach(() => {
        token.dispose();
        Blockchain.dispose();
    });

    await vm.it('fresh deploy: no destChainId is supported (fail-closed)', async () => {
        Assert.expect(await token.isSupportedDestChain(1)).toEqual(false);
        Assert.expect(await token.isSupportedDestChain(11155111)).toEqual(false);
        Assert.expect(await token.isSupportedDestChain(42)).toEqual(false);
    });

    await vm.it('burn to an un-enabled destChainId reverts', async () => {
        setSender(alice);
        await Assert.expect(async () => {
            await token.burnForRelease(ethRecipient32(), 100n, 1);
        }).toThrow();
        // Tokens were NOT destroyed — the revert rolled the burn back.
        Assert.expect(await token.balanceOf(alice)).toEqual(10_000n);
    });

    await vm.it('after setSupportedDestChain(id, true) the burn succeeds', async () => {
        setSender(deployer);
        await token.setSupportedDestChain(1, true, true);
        Assert.expect(await token.isSupportedDestChain(1)).toEqual(true);

        setSender(alice);
        const nonce = await token.burnForRelease(ethRecipient32(), 300n, 1);
        Assert.expect(nonce).toEqual(1n);
        Assert.expect(await token.balanceOf(alice)).toEqual(9_700n);
    });

    await vm.it('isSupportedDestChain reflects enable then disable state', async () => {
        setSender(deployer);
        await token.setSupportedDestChain(42, true, false);
        Assert.expect(await token.isSupportedDestChain(42)).toEqual(true);

        await token.setSupportedDestChain(42, false, false);
        Assert.expect(await token.isSupportedDestChain(42)).toEqual(false);

        // A burn to a now-disabled chain reverts again.
        setSender(alice);
        const nonEvm = new Uint8Array(32);
        for (let i = 0; i < 32; i++) nonEvm[i] = i + 1;
        await Assert.expect(async () => {
            await token.burnForRelease(nonEvm, 100n, 42);
        }).toThrow();
    });

    await vm.it('setSupportedDestChain by a non-governor reverts', async () => {
        setSender(alice);
        await Assert.expect(async () => {
            await token.setSupportedDestChain(1, true, true);
        }).toThrow();
        // State unchanged — alice's call had no effect.
        Assert.expect(await token.isSupportedDestChain(1)).toEqual(false);
    });

    await vm.it('enabling one chain does not enable others', async () => {
        setSender(deployer);
        await token.setSupportedDestChain(1, true, true);
        Assert.expect(await token.isSupportedDestChain(1)).toEqual(true);
        Assert.expect(await token.isSupportedDestChain(11155111)).toEqual(false);

        // Burn to the still-unsupported Sepolia chain reverts.
        setSender(alice);
        await Assert.expect(async () => {
            await token.burnForRelease(ethRecipient32(), 100n, 11155111);
        }).toThrow();
    });
});
