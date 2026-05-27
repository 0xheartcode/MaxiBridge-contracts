// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";

/// @title  GuardianRoleTest
/// @notice Regression tests for security fix H-01: the set-once `guardian`
///         gains authority over the protective subset of admin calls
///         (`pause`, `cancelVoucher`, `removeSigner`, `migrateSignerSet`)
///         via the new `onlyOwnerOrGuardian` modifier, while
///         owner-exclusive calls (`unpause`, `addSigner`, `setThreshold`)
///         remain `onlyOwner`.
///
/// @dev    Stands up its own minimal fixture (own proxy + initialize +
///         optional setGuardian) so the parent BridgeEscrow.t.sol cases
///         do not run under this contract — same convention as
///         BridgeEscrowAllModesTest.
contract GuardianRoleTest is Test {
    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;

    BridgeEscrow internal impl;
    BridgeEscrow internal escrow;

    MockERC20 internal usdc;
    MockUSDT internal usdt;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;

    address internal guardian = address(0x6CA6D1A4);
    address internal stranger = address(0xBADBAD);

    function setUp() public {
        signerAddr = vm.addr(signerPk);

        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdt = new MockUSDT();

        impl = BridgeEscrow(address(new TestableBridgeEscrow()));

        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(usdt);

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = BridgeEscrow(address(new ERC1967Proxy(address(impl), initData)));
        // Post-initialize state: owner set, one signer (signerAddr),
        // signerCount = 1, signerThreshold = 1, guardian = address(0).
    }

    /// @dev Wires the set-once guardian. Kept out of setUp() so the
    ///      "guardian unset" tests can observe the address(0) state.
    function _installGuardian() internal {
        vm.prank(owner);
        escrow.setGuardian(guardian);
        assertEq(escrow.guardian(), guardian, "guardian wired");
    }

    /// @dev Adds a spare signer (as owner) so removeSigner / migrateSignerSet
    ///      have a removable target without violating threshold <= count.
    function _addSpareSigner() internal returns (address spare) {
        spare = vm.addr(0x5A5A5A);
        vm.prank(owner);
        escrow.addSigner(spare);
        assertTrue(escrow.isSigner(spare), "spare signer added");
    }

    // -----------------------------------------------------------------
    // guardian CAN call the protective subset
    // -----------------------------------------------------------------

    function test_Guardian_CanPause() public {
        _installGuardian();
        vm.prank(guardian);
        escrow.pause();
        assertTrue(escrow.paused(), "guardian paused the escrow");
    }

    function test_Guardian_CanCancelVoucher() public {
        _installGuardian();
        bytes32 nonce = keccak256("guardian-cancel");
        vm.prank(guardian);
        escrow.cancelVoucher(nonce);
        assertTrue(escrow.cancelledVouchers(nonce), "voucher cancelled by guardian");
    }

    function test_Guardian_CanRemoveSigner() public {
        _installGuardian();
        address spare = _addSpareSigner();
        uint32 epochBefore = escrow.currentEpoch();

        vm.prank(guardian);
        escrow.removeSigner(spare);

        assertFalse(escrow.isSigner(spare), "signer removed by guardian");
        assertEq(escrow.signerCount(), 1, "signerCount decremented");
        assertEq(escrow.currentEpoch(), epochBefore + 1, "epoch bumped");
    }

    function test_Guardian_CanMigrateSignerSet() public {
        _installGuardian();
        address newSigner = vm.addr(0x7777);

        address[] memory addList = new address[](1);
        addList[0] = newSigner;
        address[] memory removeList = new address[](0);

        vm.prank(guardian);
        escrow.migrateSignerSet(addList, removeList, 1);

        assertTrue(escrow.isSigner(newSigner), "signer migrated in by guardian");
        assertEq(escrow.signerCount(), 2, "signerCount reflects migration");
    }

    // -----------------------------------------------------------------
    // owner CAN still call the protective subset
    // -----------------------------------------------------------------

    function test_Owner_CanPause() public {
        _installGuardian();
        vm.prank(owner);
        escrow.pause();
        assertTrue(escrow.paused(), "owner paused the escrow");
    }

    function test_Owner_CanCancelVoucher() public {
        _installGuardian();
        bytes32 nonce = keccak256("owner-cancel");
        vm.prank(owner);
        escrow.cancelVoucher(nonce);
        assertTrue(escrow.cancelledVouchers(nonce), "voucher cancelled by owner");
    }

    function test_Owner_CanRemoveSigner() public {
        _installGuardian();
        address spare = _addSpareSigner();
        vm.prank(owner);
        escrow.removeSigner(spare);
        assertFalse(escrow.isSigner(spare), "signer removed by owner");
    }

    function test_Owner_CanMigrateSignerSet() public {
        _installGuardian();
        address newSigner = vm.addr(0x8888);
        address[] memory addList = new address[](1);
        addList[0] = newSigner;
        address[] memory removeList = new address[](0);

        vm.prank(owner);
        escrow.migrateSignerSet(addList, removeList, 1);
        assertTrue(escrow.isSigner(newSigner), "signer migrated in by owner");
    }

    // -----------------------------------------------------------------
    // unauthorized stranger CANNOT — reverts NotGuardian
    // -----------------------------------------------------------------

    function test_Stranger_CannotPause() public {
        _installGuardian();
        vm.prank(stranger);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.pause();
    }

    function test_Stranger_CannotCancelVoucher() public {
        _installGuardian();
        vm.prank(stranger);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.cancelVoucher(keccak256("stranger-cancel"));
    }

    function test_Stranger_CannotRemoveSigner() public {
        _installGuardian();
        address spare = _addSpareSigner();
        vm.prank(stranger);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.removeSigner(spare);
    }

    function test_Stranger_CannotMigrateSignerSet() public {
        _installGuardian();
        address[] memory addList = new address[](1);
        addList[0] = vm.addr(0x9999);
        address[] memory removeList = new address[](0);

        vm.prank(stranger);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.migrateSignerSet(addList, removeList, 1);
    }

    // -----------------------------------------------------------------
    // guardian CANNOT call owner-exclusive calls — OZ Ownable revert
    // -----------------------------------------------------------------

    /// @dev Roles PR — `unpause` is now owner OR guardian (was owner-only).
    ///      The dedicated pauser role can freeze but never thaw; guardian can
    ///      do both as part of the incident-response surface.
    function test_Guardian_CanUnpause() public {
        _installGuardian();
        vm.prank(guardian);
        escrow.pause();
        assertTrue(escrow.paused());

        vm.prank(guardian);
        escrow.unpause();
        assertFalse(escrow.paused());
    }

    function test_Guardian_CannotAddSigner() public {
        _installGuardian();
        vm.prank(guardian);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, guardian)
        );
        escrow.addSigner(vm.addr(0xA1A1));
    }

    function test_Guardian_CannotSetThreshold() public {
        _installGuardian();
        // Add a second signer (as owner) so threshold=2 would otherwise
        // be valid — isolates the failure to the access modifier.
        _addSpareSigner();
        vm.prank(guardian);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, guardian)
        );
        escrow.setThreshold(2);
    }

    /// @dev Owner positive control on the owner-exclusive subset.
    function test_Owner_CanUnpause() public {
        vm.prank(owner);
        escrow.pause();
        vm.prank(owner);
        escrow.unpause();
        assertFalse(escrow.paused(), "owner unpaused the escrow");
    }

    // -----------------------------------------------------------------
    // guardian unset (address(0)) — only owner passes
    // -----------------------------------------------------------------

    function test_GuardianUnset_OwnerCanPause() public {
        assertEq(escrow.guardian(), address(0), "guardian unset");
        vm.prank(owner);
        escrow.pause();
        assertTrue(escrow.paused(), "owner still pauses when guardian unset");
    }

    function test_GuardianUnset_StrangerCannotPause() public {
        assertEq(escrow.guardian(), address(0), "guardian unset");
        vm.prank(stranger);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.pause();
    }

    function test_GuardianUnset_StrangerCannotCancelVoucher() public {
        assertEq(escrow.guardian(), address(0), "guardian unset");
        vm.prank(stranger);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.cancelVoucher(keccak256("unset-stranger-cancel"));
    }

    function test_GuardianUnset_OwnerCanCancelVoucher() public {
        bytes32 nonce = keccak256("unset-owner-cancel");
        vm.prank(owner);
        escrow.cancelVoucher(nonce);
        assertTrue(escrow.cancelledVouchers(nonce), "owner cancels when guardian unset");
    }
}
