// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {VestingVault} from "../src/VestingVault.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";

/// @title  BridgeEscrowMode4Test
/// @notice Coverage for the POOLED_LOCK_VEST (mode 4) integration:
///
///           - addFlow accepts mode 4 (no vault yet); lock + claim
///             reject until governor wires setFlowVestingVault.
///           - setFlowVestingVault access control (onlyOwner) and mode
///             gating (refuses non-mode-4 flows).
///           - claim() routes funds to the VestingVault via depositFor
///             instead of safeTransfer-ing direct to recipient.
///           - relayer-tip path under mode 4: tip to msg.sender,
///             recipient-bound amount lands in the vault for the
///             beneficiary.
///           - vault re-pointing via setFlowVestingVault.
///
/// @dev    Self-contained fixture mirroring GuardianRole.t.sol /
///         BridgeEscrowAllModes.t.sol so parent test cases don't run
///         here.
contract BridgeEscrowMode4Test is Test {
    bytes32 internal constant RELEASE_INTENT_TYPEHASH = keccak256(
        "ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce,uint256 grossSrcAmount,uint128 relayerTip,bytes32 flowId)"
    );

    uint64  internal constant TEST_EVM_CHAIN_ID = 11155111;
    address internal constant TEST_EVM_BRIDGE = address(0xBEEF);
    bytes32 internal constant TEST_OPNET_BRIDGE = bytes32(uint256(0xAB12));
    bytes32 internal constant TEST_OPNET_MOTO = bytes32(uint256(0xC0DE));
    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;

    uint64 internal constant VESTING_BLOCKS = 50_400;

    BridgeEscrow internal impl;
    BridgeEscrow internal escrow;
    VestingVault internal vault;
    MockERC20 internal moto;

    bytes32 internal motoVestFlowId;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xB0B);
    address internal relayer = address(0xF000);

    function setUp() public {
        signerAddr = vm.addr(signerPk);

        moto = new MockERC20("MOTO", "MOTO", 6);
        impl = BridgeEscrow(address(new TestableBridgeEscrow()));

        address[] memory tokens = new address[](1);
        tokens[0] = address(moto);

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = BridgeEscrow(address(new ERC1967Proxy(address(impl), initData)));

        // Register the mode 4 flow. NOTE: vestingVault is NOT set here —
        // governor must call setFlowVestingVault before any user-facing path
        // becomes safe (this is the C-mode-4 two-step contract).
        vm.prank(owner);
        motoVestFlowId = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: uint8(BridgeEscrow.TokenMode.POOLED_LOCK_VEST),
                evmChainId: TEST_EVM_CHAIN_ID,
                evmBridge: TEST_EVM_BRIDGE,
                evmToken: address(moto),
                evmDecimals: 6,
                opnetBridge: TEST_OPNET_BRIDGE,
                opnetToken: TEST_OPNET_MOTO,
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 200
            })
        );

        vault = new VestingVault(IERC20(address(moto)), address(escrow), VESTING_BLOCKS);

        // Seed alice with MOTO + approval for the lock-side path.
        moto.mint(alice, 1_000_000e6);
        vm.prank(alice);
        moto.approve(address(escrow), type(uint256).max);
    }

    // ------------------------------------------------------------------
    // addFlow / mode bounds
    // ------------------------------------------------------------------

    function test_AddFlow_Mode4_NoVaultRequired() public view {
        BridgeEscrow.FlowRecord memory rec = escrow.getFlow(motoVestFlowId);
        assertEq(rec.mode, uint8(BridgeEscrow.TokenMode.POOLED_LOCK_VEST));
        assertEq(rec.vestingVault, address(0));
    }

    function test_AddFlow_RejectsModeAbovePooledLockVest() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowInvalidMode.selector);
        escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: 5, // beyond POOLED_LOCK_VEST
                evmChainId: TEST_EVM_CHAIN_ID,
                evmBridge: TEST_EVM_BRIDGE,
                evmToken: address(moto),
                evmDecimals: 6,
                opnetBridge: bytes32(uint256(0xFEFE)),
                opnetToken: bytes32(uint256(0xFAFA)),
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );
    }

    // ------------------------------------------------------------------
    // setFlowVestingVault
    // ------------------------------------------------------------------

    function test_SetFlowVestingVault_OnlyOwner() public {
        vm.prank(alice);
        vm.expectRevert();
        escrow.setFlowVestingVault(motoVestFlowId, address(vault));
    }

    function test_SetFlowVestingVault_RejectsZero() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.VestingVaultRequired.selector);
        escrow.setFlowVestingVault(motoVestFlowId, address(0));
    }

    function test_SetFlowVestingVault_RejectsNonMode4Flow() public {
        // Stand up a Mode 3 flow to attempt the (forbidden) vault wire.
        vm.prank(owner);
        bytes32 mode3Id = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: uint8(BridgeEscrow.TokenMode.POOLED_LOCK_RELEASE),
                evmChainId: TEST_EVM_CHAIN_ID,
                evmBridge: TEST_EVM_BRIDGE,
                evmToken: address(moto),
                evmDecimals: 6,
                opnetBridge: bytes32(uint256(0x1212)),
                opnetToken: bytes32(uint256(0x3434)),
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );

        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.VestingVaultNotPermitted.selector);
        escrow.setFlowVestingVault(mode3Id, address(vault));
    }

    function test_SetFlowVestingVault_RejectsTokenMismatch() public {
        // Stand up a vault whose underlying ERC20 is NOT the flow's evmToken.
        MockERC20 wrongToken = new MockERC20("WRONG", "WRONG", 6);
        VestingVault wrongVault = new VestingVault(
            IERC20(address(wrongToken)),
            address(escrow),
            VESTING_BLOCKS
        );

        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.VestingVaultTokenMismatch.selector);
        escrow.setFlowVestingVault(motoVestFlowId, address(wrongVault));
    }

    function test_SetFlowVestingVault_HappyPath_EmitsAndStores() public {
        vm.expectEmit(true, false, false, true, address(escrow));
        emit BridgeEscrow.FlowVestingVaultChanged(motoVestFlowId, address(0), address(vault));

        vm.prank(owner);
        escrow.setFlowVestingVault(motoVestFlowId, address(vault));

        assertEq(escrow.getFlow(motoVestFlowId).vestingVault, address(vault));
    }

    function test_SetFlowVestingVault_Repoint_NextClaimUsesNewVault() public {
        _wireVault();

        // Provision the pool and run one claim into the original vault.
        _seedInventory(500e6);
        _claim(alice, 100e6, "voucher-1");

        // Deploy a fresh vault and repoint.
        VestingVault freshVault = new VestingVault(
            IERC20(address(moto)),
            address(escrow),
            VESTING_BLOCKS
        );
        vm.prank(owner);
        escrow.setFlowVestingVault(motoVestFlowId, address(freshVault));

        uint256 freshBalBefore = moto.balanceOf(address(freshVault));
        _claim(bob, 50e6, "voucher-2");
        assertEq(
            moto.balanceOf(address(freshVault)),
            freshBalBefore + 50e6,
            "second claim routed to fresh vault"
        );
    }

    // ------------------------------------------------------------------
    // lock / claim guard for half-set-up flow
    // ------------------------------------------------------------------

    function test_Lock_Mode4_WithoutVault_Reverts() public {
        // No setFlowVestingVault call — vault stays address(0).
        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.VestingVaultNotSet.selector);
        escrow.lock(address(moto), 100e6, bytes32(uint256(0xCAFE)), motoVestFlowId);
    }

    function test_ProvisionInventory_Mode4_WithoutVault_Reverts() public {
        // The third path that could otherwise sit inventory on a half-set-
        // up mode 4 flow — provisionInventory. Symmetric guard to lock().
        // Provide the bridge with tokens it could pull, then attempt to
        // provision without a vault wired.
        moto.mint(owner, 100e6);
        vm.prank(owner);
        moto.approve(address(escrow), type(uint256).max);

        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.VestingVaultNotSet.selector);
        escrow.provisionInventory(motoVestFlowId, 100e6);
    }

    // ------------------------------------------------------------------
    // claim — happy path routes to vault
    // ------------------------------------------------------------------

    function test_Claim_Mode4_DepositsIntoVault() public {
        _wireVault();
        _seedInventory(500e6);

        bytes32 nonce = keccak256("voucher-claim-vault");
        BridgeEscrow.ReleaseIntent memory intent = _makeIntent(bob, 100e6, nonce);
        bytes memory sig = _signIntent(signerPk, intent);

        uint256 bobBefore = moto.balanceOf(bob);
        uint256 vaultBefore = moto.balanceOf(address(vault));

        escrow.claim(intent, sig);

        // Bob receives nothing directly — funds are in the vault.
        assertEq(moto.balanceOf(bob), bobBefore, "no direct transfer");
        assertEq(
            moto.balanceOf(address(vault)),
            vaultBefore + 100e6,
            "vault received deposit"
        );

        // Schedule opened.
        VestingVault.Schedule memory s = vault.getSchedule(bob, nonce);
        assertEq(s.total, 100e6);
        assertEq(s.claimed, 0);
        assertEq(s.startBlock, uint64(block.number));
        assertEq(s.endBlock, uint64(block.number) + VESTING_BLOCKS);
    }

    function test_Claim_Mode4_BeneficiaryClaimsFromVaultOverTime() public {
        _wireVault();
        _seedInventory(500e6);

        bytes32 nonce = keccak256("voucher-claim-then-vest");
        BridgeEscrow.ReleaseIntent memory intent = _makeIntent(bob, 100e6, nonce);
        escrow.claim(intent, _signIntent(signerPk, intent));

        // Halfway — bob can pull 50e6.
        vm.roll(block.number + VESTING_BLOCKS / 2);
        vm.prank(bob);
        uint128 c1 = vault.claim(nonce);
        assertEq(c1, 50e6);

        // Past end — pulls the rest.
        vm.roll(block.number + VESTING_BLOCKS);
        vm.prank(bob);
        uint128 c2 = vault.claim(nonce);
        assertEq(c2, 50e6);

        assertEq(moto.balanceOf(bob), 100e6, "bob fully received over 7d");
    }

    function test_Claim_Mode4_RelayerTip_PaysRelayer_DepositsNet() public {
        _wireVault();
        _seedInventory(500e6);

        // Tip cap 200 bps (set in setUp); voucher carries a 2% tip.
        bytes32 nonce = keccak256("voucher-tipped");
        BridgeEscrow.ReleaseIntent memory intent = _makeIntent(bob, 100e6, nonce);
        intent.relayerTip = 2e6; // 2% of 100e6 = 2 bps→ within cap
        bytes memory sig = _signIntent(signerPk, intent);

        uint256 relayerBefore = moto.balanceOf(relayer);
        uint256 vaultBefore = moto.balanceOf(address(vault));

        vm.prank(relayer);
        escrow.claim(intent, sig);

        assertEq(moto.balanceOf(relayer), relayerBefore + 2e6, "relayer got tip");
        assertEq(
            moto.balanceOf(address(vault)),
            vaultBefore + 98e6,
            "net (amount - tip) deposited into vault"
        );

        // Schedule opens with the net amount as the beneficiary's vest base.
        VestingVault.Schedule memory s = vault.getSchedule(bob, nonce);
        assertEq(s.total, 98e6, "vesting tracks net amount");
    }

    // ------------------------------------------------------------------
    // HIGH-001 — clawback forwarder (audit 2026-05-25)
    // ------------------------------------------------------------------

    /// Proves the bug existed pre-fix: VestingVault.clawback is `onlyBridge`,
    /// so calling it directly from owner / guardian / anyone reverts.
    /// Recovery is impossible without the BridgeEscrow forwarder.
    function test_Clawback_DirectVaultCall_ByOwner_Reverts_NotBridge() public {
        _wireVault();
        _seedInventory(500e6);
        bytes32 nonce = keccak256("voucher-direct-vault-clawback");
        escrow.claim(_makeIntent(bob, 100e6, nonce), _signIntent(signerPk, _makeIntent(bob, 100e6, nonce)));

        vm.prank(owner);
        vm.expectRevert(VestingVault.NotBridge.selector);
        vault.clawback(bob, nonce);
    }

    /// Happy path: cancelVoucher → clawbackVestedClaim succeeds, inventory
    /// is re-credited by the unvested amount, vault schedule terminates.
    function test_Clawback_Forwarder_HappyPath_BeforeAnyVest() public {
        _wireVault();
        _seedInventory(500e6);
        bytes32 nonce = keccak256("voucher-clawback-pre-vest");
        BridgeEscrow.ReleaseIntent memory intent = _makeIntent(bob, 100e6, nonce);
        escrow.claim(intent, _signIntent(signerPk, intent));

        // Inventory after claim: 500 - 100 = 400.
        assertEq(escrow.getFlow(motoVestFlowId).inventory, 400e6, "inventory decremented by claim");
        // Bridge balance after claim: 500 - 100 (went to vault) = 400.
        assertEq(moto.balanceOf(address(escrow)), 400e6, "bridge token balance after claim");

        // Cancel voucher (incident response — first step).
        vm.prank(owner);
        escrow.cancelVoucher(nonce);

        // Clawback at startBlock = no vest yet → full 100 returns.
        vm.prank(owner);
        escrow.clawbackVestedClaim(motoVestFlowId, bob, nonce);

        // Inventory restored to 500.
        assertEq(escrow.getFlow(motoVestFlowId).inventory, 500e6, "inventory recredited");
        // Bridge balance restored to 500.
        assertEq(moto.balanceOf(address(escrow)), 500e6, "bridge balance recredited");
        // Bob got nothing (no vest had accrued yet).
        assertEq(moto.balanceOf(bob), 0, "beneficiary received nothing pre-vest");
        // Vault is empty; schedule is terminal.
        assertEq(moto.balanceOf(address(vault)), 0, "vault drained");
        assertTrue(vault.getSchedule(bob, nonce).clawedBack, "schedule marked clawed-back");
    }

    /// Mid-vest: clawback at the halfway point splits funds — beneficiary
    /// keeps the vested portion, bridge recovers the unvested remainder.
    function test_Clawback_Forwarder_MidVest_SplitsCorrectly() public {
        _wireVault();
        _seedInventory(500e6);
        bytes32 nonce = keccak256("voucher-clawback-mid-vest");
        BridgeEscrow.ReleaseIntent memory intent = _makeIntent(bob, 100e6, nonce);
        escrow.claim(intent, _signIntent(signerPk, intent));

        // Advance to halfway through the vest window.
        vm.roll(block.number + VESTING_BLOCKS / 2);

        vm.prank(owner);
        escrow.cancelVoucher(nonce);
        vm.prank(owner);
        escrow.clawbackVestedClaim(motoVestFlowId, bob, nonce);

        // Inventory recredited by the unvested half (50e6); the vested half
        // (50e6) is genuinely paid out and never returns to the ledger.
        assertEq(escrow.getFlow(motoVestFlowId).inventory, 450e6, "inventory + unvested half");
        assertEq(moto.balanceOf(bob), 50e6, "beneficiary kept vested half");
        assertEq(moto.balanceOf(address(escrow)), 450e6, "bridge balance back to inventory");
        assertEq(moto.balanceOf(address(vault)), 0, "vault drained");
    }

    /// Voucher must be cancelled first — clawback without cancellation
    /// reverts so the operator can't accidentally terminate a live schedule.
    function test_Clawback_Forwarder_RevertsIfVoucherNotCancelled() public {
        _wireVault();
        _seedInventory(500e6);
        bytes32 nonce = keccak256("voucher-not-cancelled");
        BridgeEscrow.ReleaseIntent memory intent = _makeIntent(bob, 100e6, nonce);
        escrow.claim(intent, _signIntent(signerPk, intent));

        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.VoucherNotCancelled.selector);
        escrow.clawbackVestedClaim(motoVestFlowId, bob, nonce);
    }

    /// Mode dispatch: clawback only applies to Mode 4. Register a Mode 0
    /// (WRAPPED) flow and verify the forwarder rejects it as WrongMode.
    function test_Clawback_Forwarder_RevertsForNonMode4Flow() public {
        vm.prank(owner);
        bytes32 wrappedFlowId = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: uint8(BridgeEscrow.TokenMode.WRAPPED),
                evmChainId: TEST_EVM_CHAIN_ID,
                evmBridge: TEST_EVM_BRIDGE,
                evmToken: address(moto),
                evmDecimals: 6,
                opnetBridge: TEST_OPNET_BRIDGE,
                opnetToken: bytes32(uint256(0xC0DE2)),
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );

        // Pre-cancel a voucher so we get past that check and surface WrongMode.
        bytes32 nonce = keccak256("voucher-wrong-mode");
        vm.prank(owner);
        escrow.cancelVoucher(nonce);

        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.WrongMode.selector);
        escrow.clawbackVestedClaim(wrappedFlowId, bob, nonce);
    }

    /// Access control (HIGH-001 polish): clawbackVestedClaim is gated
    /// `onlyOwnerOrGuardian`. A caller that is neither must revert at the
    /// modifier — before any function-body check runs, so no wiring is
    /// needed to surface it. (Was uncovered: the happy/wrong-mode/not-
    /// cancelled tests all pranked `owner`, exercising only the owner branch.)
    function test_Clawback_Forwarder_RevertsForUnauthorizedCaller() public {
        bytes32 nonce = keccak256("voucher-unauthorized-clawback");
        vm.prank(alice); // alice is a plain user, not owner and not guardian
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.clawbackVestedClaim(motoVestFlowId, bob, nonce);
    }

    /// Access control (HIGH-001 polish): the guardian branch of
    /// `onlyOwnerOrGuardian` works end-to-end — guardian (not owner) can run
    /// the full incident-response ceremony (cancelVoucher → clawback). This
    /// is the path that matters once `owner` becomes the 7-day Timelock and
    /// the guardian is the only role able to respond immediately.
    function test_Clawback_Forwarder_GuardianCanClawback() public {
        address guardian = address(0x6A4D);
        vm.prank(owner);
        escrow.setGuardian(guardian);

        _wireVault();
        _seedInventory(500e6);
        bytes32 nonce = keccak256("voucher-guardian-clawback");
        BridgeEscrow.ReleaseIntent memory intent = _makeIntent(bob, 100e6, nonce);
        escrow.claim(intent, _signIntent(signerPk, intent));
        assertEq(escrow.getFlow(motoVestFlowId).inventory, 400e6, "inventory decremented by claim");

        // Guardian (NOT owner) runs both incident-response steps.
        vm.prank(guardian);
        escrow.cancelVoucher(nonce);
        vm.prank(guardian);
        escrow.clawbackVestedClaim(motoVestFlowId, bob, nonce);

        // No vest accrued → full 100 recovered; ledger + balance restored.
        assertEq(escrow.getFlow(motoVestFlowId).inventory, 500e6, "inventory recredited by guardian");
        assertEq(moto.balanceOf(address(escrow)), 500e6, "bridge balance recredited");
        assertEq(moto.balanceOf(bob), 0, "beneficiary received nothing pre-vest");
        assertTrue(vault.getSchedule(bob, nonce).clawedBack, "schedule marked clawed-back");
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    function _wireVault() internal {
        vm.prank(owner);
        escrow.setFlowVestingVault(motoVestFlowId, address(vault));
    }

    function _seedInventory(uint256 amount) internal {
        // Real path: alice locks → flow.inventory rises by `amount`.
        vm.prank(alice);
        escrow.lock(address(moto), amount, bytes32(uint256(0xCAFE)), motoVestFlowId);
    }

    function _claim(address recipient, uint256 amount, string memory nonceTag) internal {
        bytes32 nonce = keccak256(abi.encodePacked(nonceTag));
        BridgeEscrow.ReleaseIntent memory intent = _makeIntent(recipient, amount, nonce);
        escrow.claim(intent, _signIntent(signerPk, intent));
    }

    function _makeIntent(address recipient, uint256 amount, bytes32 nonce)
        internal
        view
        returns (BridgeEscrow.ReleaseIntent memory)
    {
        return BridgeEscrow.ReleaseIntent({
            token: address(moto),
            to: recipient,
            amount: amount,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: keccak256(abi.encodePacked("opnet-tx-", nonce)),
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: nonce,
            grossSrcAmount: amount,
            relayerTip: 0,
            flowId: motoVestFlowId
        });
    }

    function _makeIntentTag(address recipient, uint256 amount, string memory nonceTag)
        internal
        view
        returns (BridgeEscrow.ReleaseIntent memory)
    {
        return _makeIntent(recipient, amount, keccak256(abi.encodePacked(nonceTag)));
    }

    function _signIntent(uint256 pk, BridgeEscrow.ReleaseIntent memory intent)
        internal
        view
        returns (bytes memory sigBlob)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                RELEASE_INTENT_TYPEHASH,
                intent.token,
                intent.to,
                intent.amount,
                intent.srcChainId,
                intent.opnetTxHash,
                intent.opnetEventIndex,
                intent.burnNonce,
                intent.signerEpoch,
                intent.opnetNonce,
                intent.grossSrcAmount,
                intent.relayerTip,
                intent.flowId
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", escrow.domainSeparator(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        // M-of-N blob: [uint8 numSigs][r(32)|s(32)|v(1)].
        sigBlob = abi.encodePacked(uint8(1), r, s, v);
    }
}
