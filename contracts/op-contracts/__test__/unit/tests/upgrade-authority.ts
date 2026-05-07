/**
 * BridgeDepository — governance-gated upgrade authority (Bug #16b).
 *
 * Closes the deployer-as-super-admin upgrade hole on the OPNet side. The
 * underlying `UpdatablePlugin.submitUpdate / applyUpdate / cancelUpdate`
 * selectors gate on `Blockchain.contractDeployer == tx.sender` — a hard-
 * coded EOA. We layer governance authorization on top via three new
 * methods + an `onUpdate` gate so a compromised deployer key alone cannot
 * push a malicious upgrade.
 *
 * Mechanism:
 *   1. Governor (or registered BridgeAuthority) calls `setUpgradeAuthority(addr)`.
 *   2. Each upgrade requires governance to call `proposeUpgrade()` first.
 *   3. The flag is one-shot — `onUpdate` consumes it before letting the
 *      apply land. Veto path: `cancelProposedUpgrade()`.
 *   4. Until `_upgradeAuthority` is wired, the legacy deployer-only path
 *      remains available so the v1 deploy ceremony can bootstrap.
 *
 * Tests in this file cover the authorization API surface — access control
 * on the new methods + flag transitions + view consistency. The actual
 * `onUpdate` gate is enforced inside the contract on every apply (the
 * underlying `Blockchain.updateContractFromExisting` calls it before any
 * new bytecode takes effect).
 *
 * Run: cd contracts/op-contracts && npm run build && npm run test:upgrade-authority
 */

import { Assert, Blockchain, opnet, OPNetUnit } from '@btc-vision/unit-test-framework';
import { Address } from '@btc-vision/transaction';

import { BridgeDepository } from '../contracts/BridgeDepository.js';

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

const deployer: Address = Blockchain.generateRandomAddress();
const governor: Address = deployer; // onDeployment seeds tx.sender as governor
const upgradeAuthorityAddr: Address = Blockchain.generateRandomAddress();
const bridgeAuthorityAddr: Address = Blockchain.generateRandomAddress();
const rando: Address = Blockchain.generateRandomAddress();

function setSender(addr: Address): void {
    Blockchain.msgSender = addr;
    Blockchain.txOrigin = addr;
}

function isZeroAddr(a: Address): boolean {
    // Address objects in @btc-vision/transaction are 32-byte buffers — compare
    // bytewise to avoid depending on a runtime helper that might not exist.
    for (let i = 0; i < 32; i++) {
        if ((a as unknown as Uint8Array)[i] !== 0) return false;
    }
    return true;
}

interface DepoSetup {
    depository: BridgeDepository;
    depositoryAddress: Address;
}

async function setup(): Promise<DepoSetup> {
    const depositoryAddress = Blockchain.generateRandomAddress();
    const depository = new BridgeDepository({
        file: './build/BridgeDepository.wasm',
        address: depositoryAddress,
        deployer,
    });
    Blockchain.register(depository);
    await depository.init();
    return { depository, depositoryAddress };
}

function dispose(s: DepoSetup): void {
    s.depository.dispose();
    Blockchain.dispose();
}

// ════════════════════════════════════════════════════════════════════════════
// 1. Default state — both slots zero / false on a fresh deploy.
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository upgrade-authority — default state', async (vm: OPNetUnit) => {
    let s: DepoSetup;

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();
        setSender(deployer);
        s = await setup();
    });

    vm.afterEach(() => dispose(s));

    await vm.it('upgradeAuthority and pendingUpgradeAuthorized start zero/false', async () => {
        Assert.expect(isZeroAddr(await s.depository.upgradeAuthority())).toEqual(true);
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(false);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 2. setUpgradeAuthority access control
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository upgrade-authority — setUpgradeAuthority access control', async (vm: OPNetUnit) => {
    let s: DepoSetup;

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
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        const stored = await s.depository.upgradeAuthority();
        Assert.expect(stored.equals(upgradeAuthorityAddr)).toEqual(true);
    });

    await vm.it('registered BridgeAuthority slot can setUpgradeAuthority', async () => {
        setSender(governor);
        await s.depository.setAuthorityAddress(bridgeAuthorityAddr);

        setSender(bridgeAuthorityAddr);
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        const stored = await s.depository.upgradeAuthority();
        Assert.expect(stored.equals(upgradeAuthorityAddr)).toEqual(true);
    });

    await vm.it('rando cannot setUpgradeAuthority', async () => {
        setSender(rando);
        await Assert.expect(async () => {
            await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        }).toThrow();
    });

    await vm.it('governor can clear setUpgradeAuthority by passing zero', async () => {
        const zero = new Address(new Uint8Array(32));
        setSender(governor);
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.depository.setUpgradeAuthority(zero);
        Assert.expect(isZeroAddr(await s.depository.upgradeAuthority())).toEqual(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 3. proposeUpgrade access control + flag transitions
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository upgrade-authority — proposeUpgrade access control', async (vm: OPNetUnit) => {
    let s: DepoSetup;

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
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.depository.proposeUpgrade();
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(true);
    });

    await vm.it('registered BridgeAuthority arms the flag', async () => {
        setSender(governor);
        await s.depository.setAuthorityAddress(bridgeAuthorityAddr);
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);

        setSender(bridgeAuthorityAddr);
        await s.depository.proposeUpgrade();
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(true);
    });

    await vm.it('upgradeAuthority itself arms the flag', async () => {
        setSender(governor);
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);

        setSender(upgradeAuthorityAddr);
        await s.depository.proposeUpgrade();
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(true);
    });

    await vm.it('rando cannot proposeUpgrade', async () => {
        setSender(governor);
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);

        setSender(rando);
        await Assert.expect(async () => {
            await s.depository.proposeUpgrade();
        }).toThrow();
    });

    await vm.it('proposeUpgrade is idempotent (safe to call twice)', async () => {
        setSender(governor);
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.depository.proposeUpgrade();
        await s.depository.proposeUpgrade();
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 4. cancelProposedUpgrade access control + flag clear
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository upgrade-authority — cancelProposedUpgrade access control', async (vm: OPNetUnit) => {
    let s: DepoSetup;

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
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.depository.proposeUpgrade();
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(true);

        await s.depository.cancelProposedUpgrade();
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(false);
    });

    await vm.it('registered BridgeAuthority can veto', async () => {
        setSender(governor);
        await s.depository.setAuthorityAddress(bridgeAuthorityAddr);
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.depository.proposeUpgrade();

        setSender(bridgeAuthorityAddr);
        await s.depository.cancelProposedUpgrade();
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(false);
    });

    await vm.it('upgradeAuthority can veto', async () => {
        setSender(governor);
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.depository.proposeUpgrade();

        setSender(upgradeAuthorityAddr);
        await s.depository.cancelProposedUpgrade();
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(false);
    });

    await vm.it('rando cannot veto', async () => {
        setSender(governor);
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.depository.proposeUpgrade();

        setSender(rando);
        await Assert.expect(async () => {
            await s.depository.cancelProposedUpgrade();
        }).toThrow();
    });

    await vm.it('cancel is idempotent (safe to call when no proposal armed)', async () => {
        setSender(governor);
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        await s.depository.cancelProposedUpgrade();
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(false);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 5. proposeUpgrade with no upgradeAuthority set — governor still effective.
//    Belt-and-suspenders: even with the slot unset, governor can pre-arm the
//    flag (no harm — onUpdate's deployer-only legacy path consumes the flag
//    when set, but the gate only fires when _upgradeAuthority is non-zero).
// ════════════════════════════════════════════════════════════════════════════

await opnet('BridgeDepository upgrade-authority — proposeUpgrade pre-bootstrap', async (vm: OPNetUnit) => {
    let s: DepoSetup;

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
        await s.depository.proposeUpgrade();
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(true);

        // Governor wires the authority; flag remains armed (no auto-clear on
        // setUpgradeAuthority — flag only clears via cancel or onUpdate).
        await s.depository.setUpgradeAuthority(upgradeAuthorityAddr);
        Assert.expect(await s.depository.pendingUpgradeAuthorized()).toEqual(true);
    });
});
