// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";
import {MockERC20Permit} from "./mocks/MockERC20Permit.sol";

/// @notice #3 — exercises `lockWithPermit`: a single-tx bridge that
///         consumes an EIP-2612 permit signature instead of a prior
///         `approve`. Also covers permit front-run tolerance and the
///         expired-deadline revert.
contract LockWithPermitTest is Test {
    TestableBridgeEscrow internal escrow;
    MockERC20Permit internal usdc;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    uint256 internal userPk = 0xBEEFCAFE;
    address internal user;

    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;
    bytes32 internal flowId;

    bytes32 private constant PERMIT_TYPEHASH =
        keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

    function setUp() public {
        user = vm.addr(userPk);
        usdc = new MockERC20Permit("USD Coin", "USDC", 6);

        TestableBridgeEscrow impl = new TestableBridgeEscrow();
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, vm.addr(signerPk), EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = TestableBridgeEscrow(address(new ERC1967Proxy(address(impl), initData)));

        vm.prank(owner);
        flowId = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: 0,
                evmChainId: 1,
                evmBridge: address(0xE5C0),
                evmToken: address(usdc),
                evmDecimals: 6,
                opnetBridge: bytes32(uint256(0xDEAD)),
                opnetToken: bytes32(uint256(0xC0FFEE)),
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );

        usdc.mint(user, 1_000_000e6);
    }

    function _signPermit(uint256 value, uint256 deadline)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH, user, address(escrow), value, usdc.nonces(user), deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", usdc.DOMAIN_SEPARATOR(), structHash)
        );
        (v, r, s) = vm.sign(userPk, digest);
    }

    function test_LockWithPermit_OneTx_NoPriorApproval() public {
        uint256 amount = 5_000e6;
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(amount, deadline);

        // No approve() beforehand — the permit grants the allowance.
        assertEq(usdc.allowance(user, address(escrow)), 0, "no prior allowance");

        vm.prank(user);
        (uint256 nonce, uint256 received) = escrow.lockWithPermit(
            address(usdc), amount, keccak256("rcp"), flowId, deadline, v, r, s
        );

        assertEq(nonce, 1);
        assertEq(received, amount);
        assertEq(usdc.balanceOf(address(escrow)), amount, "escrow received the lock");
        assertEq(escrow.getFlow(flowId).inventory, amount, "flow inventory bumped");
    }

    function test_LockWithPermit_FrontRunTolerated() public {
        // A griefer submits the signed permit first. lockWithPermit's
        // inner permit() then reverts on the consumed nonce — but the
        // catch path proceeds because the allowance is already in place.
        uint256 amount = 2_000e6;
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(amount, deadline);

        usdc.permit(user, address(escrow), amount, deadline, v, r, s); // front-run

        vm.prank(user);
        (uint256 nonce, ) = escrow.lockWithPermit(
            address(usdc), amount, keccak256("rcp"), flowId, deadline, v, r, s
        );
        assertEq(nonce, 1);
        assertEq(usdc.balanceOf(address(escrow)), amount);
    }

    function test_LockWithPermit_ExpiredDeadline_Reverts() public {
        uint256 amount = 1_000e6;
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(amount, deadline);
        vm.warp(block.timestamp + 2 hours); // permit deadline now passed

        // permit() reverts (expired); the catch finds no allowance → PermitFailed.
        vm.prank(user);
        vm.expectRevert(BridgeEscrow.PermitFailed.selector);
        escrow.lockWithPermit(address(usdc), amount, keccak256("rcp"), flowId, deadline, v, r, s);
    }
}
