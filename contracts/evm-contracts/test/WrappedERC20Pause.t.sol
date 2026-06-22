// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {WrappedERC20} from "../src/WrappedERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @notice PVE009 follow-through (EVM side). `mintFromBridge` gained a
///         `whenNotPaused` guard so an incident-response pause halts new mints
///         at the token layer — symmetric with OPNet `WrappedOP20.mintTo`.
///         This test owns the bridge role (`bridge_ = address(this)`) so it can
///         call `mintFromBridge` directly without standing up a BridgeEscrow.
contract WrappedERC20PauseTest is Test {
    WrappedERC20 internal tok;
    address internal constant ALICE = address(0xA11CE);
    bytes32 internal constant OPNET_COUNTERPART = bytes32(uint256(0xBEEF));

    function setUp() public {
        // owner_ = bridge_ = this — so the test can both pause and mint.
        tok = new WrappedERC20(
            "Wrapped MOTO",
            "wMOTO",
            18,
            address(this),
            address(this),
            2, // opnetChainId
            OPNET_COUNTERPART,
            type(uint256).max
        );
    }

    function test_MintFromBridge_WhenNotPaused_Succeeds() public {
        tok.mintFromBridge(ALICE, 1_000e18);
        assertEq(tok.balanceOf(ALICE), 1_000e18);
    }

    function test_MintFromBridge_WhenPaused_Reverts() public {
        tok.pause();
        vm.expectRevert(Pausable.EnforcedPause.selector);
        tok.mintFromBridge(ALICE, 1_000e18);
    }

    function test_MintFromBridge_AfterUnpause_Succeeds() public {
        tok.pause();
        tok.unpause();
        tok.mintFromBridge(ALICE, 5e18);
        assertEq(tok.balanceOf(ALICE), 5e18);
    }
}
