/**
 * BridgeAuthority — unit tests for the Phase 1.1 trust root.
 *
 * Covers:
 *   ✓ onDeployment seeds deployer as governor
 *   ✓ setManagedContracts / view chain
 *   ✓ pushGovernor is governor-gated (no bootstrap front-run window)
 *   ✓ pushGuardian is governor-gated (no bootstrap front-run window)
 *   ✓ pauseAll cascades pause to depository + wUSDC + wUSDT
 *   ✓ unpauseAll cascades unpause to all three
 *   ✓ unpauseAll is governor-only (guardian cannot unpause)
 *   ✓ pauseAll callable by guardian
 *   ✓ pushGovernor cascades the role to dependents (proves cross-contract push works)
 *
 * Cross-contract setup: dependents (BridgeDepository + 2× WrappedOP20) are
 * initially governed by `deployer`; deployer hands the governor role to the
 * BridgeAuthority contract address so subsequent BridgeAuthority pushes
 * pass `onlyGovernor` on the dependent side.
 *
 * Run: cd contracts/op-contracts && npm run build && npm run test:authority
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address } from '@btc-vision/transaction';

import { WrappedOP20 } from '../contracts/WrappedOP20.js';
import { BridgeDepository } from '../contracts/BridgeDepository.js';
import { BridgeAuthority } from '../contracts/BridgeAuthority.js';

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

const deployer: Address = Blockchain.generateRandomAddress();
const alice: Address = Blockchain.generateRandomAddress();
const bob: Address = Blockchain.generateRandomAddress();

function setSender(addr: Address): void {
    Blockchain.msgSender = addr;
    Blockchain.txOrigin = addr;
}

interface AuthSetup {
    authority: BridgeAuthority;
    authorityAddress: Address;
    depository: BridgeDepository;
    depositoryAddress: Address;
    wusdc: WrappedOP20;
    wusdcAddress: Address;
    wusdt: WrappedOP20;
    wusdtAddress: Address;
}

async function setupAll(): Promise<AuthSetup> {
    const authorityAddress = Blockchain.generateRandomAddress();
    const depositoryAddress = Blockchain.generateRandomAddress();
    const wusdcAddress = Blockchain.generateRandomAddress();
    const wusdtAddress = Blockchain.generateRandomAddress();

    const wusdc = new WrappedOP20({
        file: './build/WrappedOP20.wasm',
        address: wusdcAddress,
        decimals: 6,
        deployer,
    });
    Blockchain.register(wusdc);
    await wusdc.init();

    const wusdt = new WrappedOP20({
        file: './build/WrappedOP20.wasm',
        address: wusdtAddress,
        decimals: 6,
        deployer,
    });
    Blockchain.register(wusdt);
    await wusdt.init();

    const depository = new BridgeDepository({
        file: './build/BridgeDepository.wasm',
        address: depositoryAddress,
        deployer,
    });
    Blockchain.register(depository);
    await depository.init();

    const authority = new BridgeAuthority({
        file: './build/BridgeAuthority.wasm',
        address: authorityAddress,
        deployer,
    });
    Blockchain.register(authority);
    await authority.init();

    setSender(deployer);

    // Deployer transfers governor on each dependent to the authority address.
    // This is the post-deploy wire step — once done, the authority can push
    // role updates back down via Blockchain.call.
    // ALSO sets the depository's authorityAddress slot so M-of-N admin
    // pushes (addSignerToSet etc.) bypass the now-unreachable governor
    // path: after `setGovernor(authorityAddress)` the depository's
    // governor slot IS the authority address, so onlyGovernorOrAuthority
    // matches anyway. Belt + suspenders to allow tests to also call as
    // the registered authority directly without a governor handoff.
    await depository.setAuthorityAddress(authorityAddress);
    await wusdc.setGovernor(authorityAddress);
    await wusdt.setGovernor(authorityAddress);
    await depository.setGovernor(authorityAddress);

    // Authority registers the three contracts it manages.
    setSender(deployer);
    await authority.setManagedContracts(depositoryAddress, wusdcAddress, wusdtAddress);

    return {
        authority, authorityAddress,
        depository, depositoryAddress,
        wusdc, wusdcAddress,
        wusdt, wusdtAddress,
    };
}

function dispose(s: AuthSetup): void {
    s.authority.dispose();
    s.depository.dispose();
    s.wusdc.dispose();
    s.wusdt.dispose();
    Blockchain.dispose();
}

// ════════════════════════════════════════════════════════════════════════════
// 1. onDeployment seeds deployer as governor
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority — onDeployment seeds deployer as governor', async (vm: OPNetUnit) => {
    let setup: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupAll();
    });

    vm.afterEach(() => dispose(setup));

    await vm.it('governor() returns deployer right after deployment', async () => {
        const gov = await setup.authority.governor();
        Assert.expect(gov.equals(deployer)).toEqual(true);
    });

    await vm.it('storageVersion is 1', async () => {
        Assert.expect(await setup.authority.storageVersion()).toEqual(1n);
    });

    await vm.it('setManagedContracts wired the three contract slots', async () => {
        const depo = await setup.authority.depository();
        const wusdc = await setup.authority.wusdc();
        const wusdt = await setup.authority.wusdt();
        Assert.expect(depo.equals(setup.depositoryAddress)).toEqual(true);
        Assert.expect(wusdc.equals(setup.wusdcAddress)).toEqual(true);
        Assert.expect(wusdt.equals(setup.wusdtAddress)).toEqual(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 2. pushGovernor bootstrap-skip
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority — pushGovernor is governor-gated + cascade', async (vm: OPNetUnit) => {
    let setup: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupAll();
    });

    vm.afterEach(() => dispose(setup));

    await vm.it('first call pushes governor to dependents and updates local slot', async () => {
        // Deployer is current governor on authority. Push handoff to alice.
        setSender(deployer);
        await setup.authority.pushGovernor(alice);

        Assert.expect((await setup.authority.governor()).equals(alice)).toEqual(true);
        // Cascaded: depository now sees alice as its governor.
        Assert.expect((await setup.depository.governor()).equals(alice)).toEqual(true);
        // wUSDC / wUSDT are non-upgradeable and their setGovernor is strict
        // onlyGovernor, so the authority does NOT cascade governor handoff
        // into them. Wrapped admin ops are gated on `onlyGovernorOrAuthority`
        // via the registered _authorityAddress slot, so the wrapped's local
        // _governor slot stays at the authority address forever (set during
        // deploy wiring). See BridgeAuthority.pushGovernor for the rationale.
        Assert.expect((await setup.wusdc.governor()).equals(setup.authorityAddress)).toEqual(true);
        Assert.expect((await setup.wusdt.governor()).equals(setup.authorityAddress)).toEqual(true);
    });

    await vm.it('a non-governor cannot seize the role on the first call (no bootstrap front-run)', async () => {
        // HIGH-004 regression: onDeployment seeds the deployer as governor,
        // so there is NO open bootstrap window. bob is not the governor —
        // the very first pushGovernor he attempts must revert.
        setSender(bob);
        await Assert.expect(async () => {
            await setup.authority.pushGovernor(bob);
        }).toThrow();
        // Governor slot untouched — still the deployer.
        Assert.expect((await setup.authority.governor()).equals(deployer)).toEqual(true);
    });

    await vm.it('second call enforces onlyGovernor', async () => {
        setSender(deployer);
        await setup.authority.pushGovernor(alice);

        // Deployer is no longer governor — must revert.
        setSender(deployer);
        await Assert.expect(async () => {
            await setup.authority.pushGovernor(bob);
        }).toThrow();
    });

    await vm.it('alice (the new governor) can push again', async () => {
        setSender(deployer);
        await setup.authority.pushGovernor(alice);
        setSender(alice);
        await setup.authority.pushGovernor(bob);
        Assert.expect((await setup.authority.governor()).equals(bob)).toEqual(true);
        Assert.expect((await setup.depository.governor()).equals(bob)).toEqual(true);
    });

    await vm.it('rejects zero address governor', async () => {
        // Address.dead() is the all-zero address — exercises the
        // contract's `newGovernor.isZero()` guard for real. (The prior
        // Address.zero() is not a function; the test passed only because
        // toThrow() caught that TypeError, never the contract revert.)
        setSender(deployer);
        await Assert.expect(async () => {
            await setup.authority.pushGovernor(Address.dead());
        }).toThrow();
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 3. pushGuardian bootstrap-skip
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority — pushGuardian is governor-gated', async (vm: OPNetUnit) => {
    let setup: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupAll();
    });

    vm.afterEach(() => dispose(setup));

    await vm.it('governor sets the initial guardian', async () => {
        setSender(deployer);
        await setup.authority.pushGuardian(alice);
        Assert.expect((await setup.authority.guardian()).equals(alice)).toEqual(true);
    });

    await vm.it('a non-governor cannot set the first guardian (no bootstrap front-run)', async () => {
        // HIGH-004 regression: pushGuardian is always onlyGovernor. bob is
        // neither governor nor guardian — his first attempt must revert.
        setSender(bob);
        await Assert.expect(async () => {
            await setup.authority.pushGuardian(bob);
        }).toThrow();
        // bob did NOT seize the guardian slot.
        Assert.expect((await setup.authority.guardian()).equals(bob)).toEqual(false);
    });

    await vm.it('second call requires onlyGovernor (alice cannot self-promote)', async () => {
        setSender(deployer);
        await setup.authority.pushGuardian(alice);
        // Alice is guardian, NOT governor — must revert.
        setSender(alice);
        await Assert.expect(async () => {
            await setup.authority.pushGuardian(bob);
        }).toThrow();
    });

    await vm.it('governor can rotate guardian after initial set', async () => {
        setSender(deployer);
        await setup.authority.pushGuardian(alice);
        setSender(deployer);
        await setup.authority.pushGuardian(bob);
        Assert.expect((await setup.authority.guardian()).equals(bob)).toEqual(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 4. pauseAll / unpauseAll coordination
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority — pauseAll / unpauseAll cascades', async (vm: OPNetUnit) => {
    let setup: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupAll();
    });

    vm.afterEach(() => dispose(setup));

    await vm.it('governor can pause all dependents', async () => {
        // Sanity: nothing paused yet
        Assert.expect(await setup.depository.paused()).toEqual(false);
        Assert.expect(await setup.wusdc.paused()).toEqual(false);
        Assert.expect(await setup.wusdt.paused()).toEqual(false);

        setSender(deployer);
        await setup.authority.pauseAll();

        Assert.expect(await setup.depository.paused()).toEqual(true);
        Assert.expect(await setup.wusdc.paused()).toEqual(true);
        Assert.expect(await setup.wusdt.paused()).toEqual(true);
    });

    await vm.it('guardian can pause all dependents', async () => {
        setSender(deployer);
        await setup.authority.pushGuardian(alice);

        setSender(alice);
        await setup.authority.pauseAll();

        Assert.expect(await setup.depository.paused()).toEqual(true);
        Assert.expect(await setup.wusdc.paused()).toEqual(true);
        Assert.expect(await setup.wusdt.paused()).toEqual(true);
    });

    await vm.it('non-governor / non-guardian cannot pauseAll', async () => {
        setSender(bob);
        await Assert.expect(async () => {
            await setup.authority.pauseAll();
        }).toThrow();
    });

    await vm.it('governor can unpauseAll after pauseAll', async () => {
        setSender(deployer);
        await setup.authority.pauseAll();
        await setup.authority.unpauseAll();

        Assert.expect(await setup.depository.paused()).toEqual(false);
        Assert.expect(await setup.wusdc.paused()).toEqual(false);
        Assert.expect(await setup.wusdt.paused()).toEqual(false);
    });

    await vm.it('guardian CANNOT unpauseAll (governor only)', async () => {
        setSender(deployer);
        await setup.authority.pushGuardian(alice);
        await setup.authority.pauseAll();

        // Guardian can pause but not unpause — that's a positive action
        // requiring the higher trust tier.
        setSender(alice);
        await Assert.expect(async () => {
            await setup.authority.unpauseAll();
        }).toThrow();
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 5. M-of-N forwarding chain — BridgeAuthority → BridgeDepository
//
// Verifies that calls into BridgeAuthority's M-of-N admin selectors push
// down to the BridgeDepository correctly via Blockchain.call. This proves
// the cross-contract trust + role lattice works end-to-end.
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority — M-of-N forwarding to BridgeDepository', async (vm: OPNetUnit) => {
    let setup: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        setup = await setupAll();
    });

    vm.afterEach(() => dispose(setup));

    await vm.it('addBridgeSigner cascades to depository._signerKeyHashSet', async () => {
        setSender(deployer);
        await setup.authority.addBridgeSigner(0xaaaan);
        Assert.expect(await setup.depository.isSignerAuthorized(0xaaaan)).toEqual(true);
        Assert.expect(await setup.depository.signerCount()).toEqual(1n);
    });

    await vm.it('setBridgeThreshold cascades to depository._requiredSignatures', async () => {
        setSender(deployer);
        await setup.authority.addBridgeSigner(0xbbbbn);
        await setup.authority.addBridgeSigner(0xccccn);
        await setup.authority.setBridgeThreshold(2n);
        Assert.expect(await setup.depository.requiredSignatures()).toEqual(2n);
    });

    await vm.it('removeBridgeSigner cascades and bumps the signer epoch', async () => {
        setSender(deployer);
        await setup.authority.addBridgeSigner(0xddddn);
        await setup.authority.addBridgeSigner(0xeeeen);
        await setup.authority.setBridgeThreshold(1n);
        const epochBefore = await setup.depository.signerEpoch();
        await setup.authority.removeBridgeSigner(0xeeeen);
        Assert.expect(await setup.depository.isSignerAuthorized(0xeeeen)).toEqual(false);
        Assert.expect(await setup.depository.signerCount()).toEqual(1n);
        Assert.expect(await setup.depository.signerEpoch()).toEqual(epochBefore + 1n);
    });

    await vm.it('migrateBridgeSignerSet atomically adds + lifts threshold', async () => {
        // Seed depository with a single starting signer + threshold 1.
        setSender(deployer);
        await setup.authority.addBridgeSigner(0xf0f0n);
        Assert.expect(await setup.depository.signerCount()).toEqual(1n);
        await setup.authority.setBridgeThreshold(1n);

        // Atomic 1-of-1 → 2-of-2 transition: add a second signer AND
        // raise threshold to 2 in the same proposal so there is no
        // intermediate window where threshold=1 with two signers (which
        // would let either key sign alone).
        await setup.authority.migrateBridgeSignerSet(0xf1f1n, 2n);

        Assert.expect(await setup.depository.isSignerAuthorized(0xf0f0n)).toEqual(true);
        Assert.expect(await setup.depository.isSignerAuthorized(0xf1f1n)).toEqual(true);
        Assert.expect(await setup.depository.signerCount()).toEqual(2n);
        Assert.expect(await setup.depository.requiredSignatures()).toEqual(2n);
    });

    await vm.it('non-governor cannot push signer changes', async () => {
        setSender(alice);
        await Assert.expect(async () => {
            await setup.authority.addBridgeSigner(0x9999n);
        }).toThrow();
    });
});
