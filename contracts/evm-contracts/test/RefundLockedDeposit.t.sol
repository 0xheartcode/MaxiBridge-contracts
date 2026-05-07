// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @notice PR γ.2c — exercises the permissionless `refundLockedDeposit`
///         escape hatch: timing gate, idempotency, inventory decrement,
///         token transfer, and event emission.
contract RefundLockedDepositTest is Test {
    TestableBridgeEscrow internal impl;
    TestableBridgeEscrow internal escrow;
    MockERC20 internal usdc;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xCAFE);
    address internal guardian = address(0xDEAD1234);

    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;
    uint64 internal constant ETH_CHAIN_ID = 1;
    bytes32 internal constant OPNET_BRIDGE = bytes32(uint256(0xDEAD));
    bytes32 internal constant OPNET_USDC = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant RECIPIENT = keccak256("rcp");

    bytes32 internal flowId;

    function setUp() public {
        signerAddr = vm.addr(signerPk);
        usdc = new MockERC20("USD Coin", "USDC", 6);

        impl = new TestableBridgeEscrow();
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = TestableBridgeEscrow(
            address(new ERC1967Proxy(address(impl), initData))
        );

        vm.startPrank(owner);
        escrow.setGuardian(guardian);
        flowId = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: 0,
                evmChainId: ETH_CHAIN_ID,
                evmBridge: address(0xE5C0),
                evmToken: address(usdc),
                evmDecimals: 6,
                opnetBridge: OPNET_BRIDGE,
                opnetToken: OPNET_USDC,
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 1_000,
                cap: 100_000e6,
                dailyLimit: 50_000e6,
                tipCapBps: 0
            })
        );
        vm.stopPrank();

        usdc.mint(alice, 10_000_000e6);
        vm.prank(alice);
        usdc.approve(address(escrow), type(uint256).max);
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    function _lock(uint256 amount) internal returns (uint256 nonce) {
        vm.prank(alice);
        (nonce, ) = escrow.lock(address(usdc), amount, RECIPIENT, flowId);
    }

    // -----------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------

    function test_RefundBeforeTimeout_Reverts() public {
        uint256 nonce = _lock(10_000e6);

        // Same block — well before the 7-day window.
        vm.expectRevert(BridgeEscrow.RefundTimeoutNotElapsed.selector);
        escrow.refundLockedDeposit(nonce);

        // Just one second before the timeout boundary.
        vm.warp(block.timestamp + 7 days - 1);
        vm.expectRevert(BridgeEscrow.RefundTimeoutNotElapsed.selector);
        escrow.refundLockedDeposit(nonce);
    }

    function test_RefundAfterTimeout_TransfersBackToUser() public {
        uint256 amount = 12_345e6;
        uint256 balBefore = usdc.balanceOf(alice);
        uint256 nonce = _lock(amount);
        uint256 balAfterLock = usdc.balanceOf(alice);
        assertEq(balBefore - balAfterLock, amount, "lock did not pull amount");

        vm.warp(block.timestamp + 7 days);

        // Permissionless — call from a totally unrelated address; funds
        // still go to alice.
        vm.prank(bob);
        escrow.refundLockedDeposit(nonce);

        assertEq(
            usdc.balanceOf(alice),
            balBefore,
            "alice should be made whole on refund"
        );
        assertEq(
            usdc.balanceOf(address(escrow)),
            0,
            "escrow should be empty after refund"
        );
    }

    function test_RefundDecrementsInventory() public {
        uint256 amount = 7_000e6;
        uint256 nonce = _lock(amount);
        assertEq(escrow.getFlow(flowId).inventory, amount);

        vm.warp(block.timestamp + 7 days + 1);
        escrow.refundLockedDeposit(nonce);

        assertEq(
            escrow.getFlow(flowId).inventory,
            0,
            "inventory should drop back to zero on refund"
        );
    }

    function test_RefundTwice_Reverts() public {
        uint256 nonce = _lock(5_000e6);
        vm.warp(block.timestamp + 7 days + 1);

        escrow.refundLockedDeposit(nonce);

        vm.expectRevert(BridgeEscrow.LockAlreadyRefunded.selector);
        escrow.refundLockedDeposit(nonce);
    }

    function test_RefundUnknownNonce_Reverts() public {
        vm.expectRevert(BridgeEscrow.LockNotFound.selector);
        escrow.refundLockedDeposit(9999);

        // Nonce 0 is never written by `lock` (++depositNonce starts at 1).
        vm.expectRevert(BridgeEscrow.LockNotFound.selector);
        escrow.refundLockedDeposit(0);
    }

    function test_RefundEmitsEvent() public {
        uint256 amount = 3_500e6;
        uint256 nonce = _lock(amount);
        vm.warp(block.timestamp + 7 days + 1);

        vm.recordLogs();
        vm.prank(bob);
        escrow.refundLockedDeposit(nonce);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        bytes32 sig = keccak256(
            "LockRefunded(uint256,address,address,uint256,bytes32,address)"
        );
        bool found;
        for (uint256 i; i < entries.length; i++) {
            if (entries[i].topics.length > 0 && entries[i].topics[0] == sig) {
                found = true;
                assertEq(uint256(entries[i].topics[1]), nonce, "nonce");
                assertEq(
                    address(uint160(uint256(entries[i].topics[2]))),
                    alice,
                    "user"
                );
                assertEq(
                    address(uint160(uint256(entries[i].topics[3]))),
                    address(usdc),
                    "token"
                );
                (uint256 amt, bytes32 fid, address caller) = abi.decode(
                    entries[i].data,
                    (uint256, bytes32, address)
                );
                assertEq(amt, amount);
                assertEq(fid, flowId);
                assertEq(caller, bob);
                break;
            }
        }
        assertTrue(found, "LockRefunded not emitted");
    }

    function test_RefundAtExactTimeoutBoundary_Succeeds() public {
        uint256 nonce = _lock(2_000e6);
        // `block.timestamp - lockedAt < REFUND_TIMEOUT` is the revert
        // condition; equality satisfies the gate.
        vm.warp(block.timestamp + 7 days);
        escrow.refundLockedDeposit(nonce);
    }

    function test_RefundIndependentOfPause() public {
        // Refunds must work even if the contract is paused — pause is for
        // freezing forward flow (lock/claim), not for blocking user
        // escape paths. This is intentional behavior. Documenting via
        // test.
        uint256 nonce = _lock(1_500e6);
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(owner);
        escrow.pause();

        escrow.refundLockedDeposit(nonce);
        ( , , bool refunded, , , ) = escrow.lockedDeposits(nonce);
        assertTrue(refunded, "record should be marked refunded");
    }
}
