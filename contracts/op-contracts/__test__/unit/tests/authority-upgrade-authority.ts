/**
 * BridgeAuthority — governance-gated upgrade authority (O-4 / Option C).
 *
 * Ports the BridgeDepository upgrade-authority suite to BridgeAuthority so the
 * two governance contracts are covered identically. Background: the stock
 * `UpdatablePlugin.submitUpdate / applyUpdate / cancelUpdate` selectors gate on
 * `Blockchain.contractDeployer == tx.sender` (a welded, non-transferable EOA).
 * BridgeAuthority previously layered a `tx.sender == _governor` check inside
 * `onUpdate` ON TOP of that — so the two gates could only ever be satisfied by
 * the same sender, and handing `_governor` to a distinct multisig FROZE
 * upgrades. Option C replaces the governor-equality gate with the depository's
 * proven split: deployer EXECUTES `applyUpdate`, governance PRE-AUTHORIZES via
 * a one-shot `proposeUpgrade()` flag that `onUpdate` consumes.
 *
 * Mechanism (mirrors BridgeDepository):
 *   1. Governor calls `setUpgradeAuthority(addr)`.
 *   2. Each upgrade requires `proposeUpgrade()` first (governor OR the
 *      registered upgrade authority).
 *   3. The flag is one-shot — `onUpdate` consumes it. Veto: `cancelProposedUpgrade()`.
 *   4. Until `_upgradeAuthority` is wired, the legacy deployer-only path remains
 *      so the v1 deploy ceremony can bootstrap.
 *
 * These tests cover the authorization API surface — access control + flag
 * transitions + view consistency. The actual `onUpdate` gate is enforced inside
 * the contract on every apply (the underlying
 * `Blockchain.updateContractFromExisting` calls it before any new bytecode
 * takes effect). BridgeAuthority has NO parent-authority pointer (unlike the
 * depository's `_authorityAddress`), so the proposer set is {governor,
 * upgradeAuthority} — the registered-authority cases are intentionally absent.
 *
 * Run: cd contracts/op-contracts && npm run build && npm run test:authority-upgrade
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address } from '@btc-vision/transaction';

import { BridgeAuthority } from '../contracts/BridgeAuthority.js';

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

const deployer: Address = Blockchain.generateRandomAddress();
const governor: Address = deployer; // onDeployment seeds tx.sender as governor
const upgradeAuthorityAddr: Address = Blockchain.generateRandomAddress();
const newGovernor: Address = Blockchain.generateRandomAddress();
const rando: Address = Blockchain.generateRandomAddress();

function setSender(addr: Address): void {
    Blockchain.msgSender = addr;
    Blockchain.txOrigin = addr;
}

function isZeroAddr(a: Address): boolean {
    for (let i = 0; i < 32; i++) {
        if ((a as unknown as Uint8Array)[i] !== 0) return false;
    }
    return true;
}

interface AuthSetup {
    authority: BridgeAuthority;
    authorityAddress: Address;
}

async function setup(): Promise<AuthSetup> {
    const authorityAddress = Blockchain.generateRandomAddress();
    const authority = new BridgeAuthority({
        file: './build/BridgeAuthority.wasm',
        address: authorityAddress,
        deployer,
    });
    Blockchain.register(authority);
    await authority.init();
    return { authority, authorityAddress };
}

function dispose(s: AuthSetup): void {
    s.authority.dispose();
    Blockchain.dispose();
}

// ════════════════════════════════════════════════════════════════════════════
// 1. Default state — both slots zero / false on a fresh deploy.
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority upgrade-authority — default state', async (vm: OPNetUnit) => {
    let s: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        s = await setup();
    });

    vm.afterEach(() => dispose(s));

    await vm.it('upgradeAuthority and pendingUpgradeAuthorized start zero/false', async () => {
        Assert.expect(isZeroAddr(await s.authority.upgradeAuthority())).toEqual(true);
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(false);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 2. setUpgradeAuthority access control
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority upgrade-authority — setUpgradeAuthority access control', async (vm: OPNetUnit) => {
    let s: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        s = await setup();
    });

    vm.afterEach(() => dispose(s));

    await vm.it('governor can setUpgradeAuthority', async () => {
        setSender(governor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        const stored = await s.authority.upgradeAuthority();
        Assert.expect(stored.equals(upgradeAuthorityAddr)).toEqual(true);
    });

    await vm.it('rando cannot setUpgradeAuthority', async () => {
        setSender(rando);
        await Assert.expect(async () => {
            await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        }).toThrow();
    });

    await vm.it('governor can clear setUpgradeAuthority by passing zero', async () => {
        const zero = new Address(new Uint8Array(32));
        setSender(governor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.authority.setUpgradeAuthority(zero);
        Assert.expect(isZeroAddr(await s.authority.upgradeAuthority())).toEqual(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 3. proposeUpgrade access control + flag transitions
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority upgrade-authority — proposeUpgrade access control', async (vm: OPNetUnit) => {
    let s: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        s = await setup();
    });

    vm.afterEach(() => dispose(s));

    await vm.it('governor arms the flag', async () => {
        setSender(governor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.authority.proposeUpgrade();
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(true);
    });

    await vm.it('upgradeAuthority itself arms the flag', async () => {
        setSender(governor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);

        setSender(upgradeAuthorityAddr);
        await s.authority.proposeUpgrade();
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(true);
    });

    await vm.it('rando cannot proposeUpgrade', async () => {
        setSender(governor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);

        setSender(rando);
        await Assert.expect(async () => {
            await s.authority.proposeUpgrade();
        }).toThrow();
    });

    await vm.it('proposeUpgrade is idempotent (safe to call twice)', async () => {
        setSender(governor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.authority.proposeUpgrade();
        await s.authority.proposeUpgrade();
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 4. cancelProposedUpgrade access control + flag clear
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority upgrade-authority — cancelProposedUpgrade access control', async (vm: OPNetUnit) => {
    let s: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        s = await setup();
    });

    vm.afterEach(() => dispose(s));

    await vm.it('governor can veto', async () => {
        setSender(governor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.authority.proposeUpgrade();
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(true);

        await s.authority.cancelProposedUpgrade();
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(false);
    });

    await vm.it('upgradeAuthority can veto', async () => {
        setSender(governor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.authority.proposeUpgrade();

        setSender(upgradeAuthorityAddr);
        await s.authority.cancelProposedUpgrade();
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(false);
    });

    await vm.it('rando cannot veto', async () => {
        setSender(governor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.authority.proposeUpgrade();

        setSender(rando);
        await Assert.expect(async () => {
            await s.authority.cancelProposedUpgrade();
        }).toThrow();
    });

    await vm.it('cancel is idempotent (safe to call when no proposal armed)', async () => {
        setSender(governor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.authority.cancelProposedUpgrade();
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(false);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 5. proposeUpgrade with no upgradeAuthority set — governor still effective.
//    Belt-and-suspenders: even with the slot unset, governor can pre-arm the
//    flag (onUpdate's deployer-only legacy path only fires the gate when
//    _upgradeAuthority is non-zero).
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority upgrade-authority — proposeUpgrade pre-bootstrap', async (vm: OPNetUnit) => {
    let s: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        s = await setup();
    });

    vm.afterEach(() => dispose(s));

    await vm.it('governor can arm even before setUpgradeAuthority is wired', async () => {
        setSender(governor);
        await s.authority.proposeUpgrade();
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(true);

        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 6. O-4 regression — governor handoff no longer touches the upgrade EXECUTOR.
//    This is the whole point of Option C: after `pushGovernor` moves governance
//    to a distinct multisig, the NEW governor drives the authorization surface
//    (set/propose) while the OLD deployer key — which is no longer governor —
//    is correctly locked OUT of it. (The deployer's only remaining role is to
//    EXECUTE applyUpdate, gated by the plugin, which this harness does not
//    simulate.) Under the pre-fix `tx.sender == _governor` onUpdate gate this
//    handoff would have frozen upgrades entirely.
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeAuthority upgrade-authority — O-4 governor handoff', async (vm: OPNetUnit) => {
    let s: AuthSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        s = await setup();
    });

    vm.afterEach(() => dispose(s));

    await vm.it('after handoff: new governor controls the upgrade-auth surface; old deployer is locked out', async () => {
        // Hand governance off to a fresh multisig (depository unset → the
        // cascade push is a no-op, so this exercises the authority in isolation).
        setSender(governor);
        await s.authority.pushGovernor(newGovernor);

        // New governor can wire + arm.
        setSender(newGovernor);
        await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.authority.proposeUpgrade();
        Assert.expect(await s.authority.pendingUpgradeAuthorized()).toEqual(true);

        // Old deployer (no longer governor, not the upgrade authority) cannot
        // touch the authorization surface anymore.
        setSender(deployer);
        await Assert.expect(async () => {
            await s.authority.setUpgradeAuthority(upgradeAuthorityAddr);
        }).toThrow();
        await Assert.expect(async () => {
            await s.authority.cancelProposedUpgrade();
        }).toThrow();
    });
});
