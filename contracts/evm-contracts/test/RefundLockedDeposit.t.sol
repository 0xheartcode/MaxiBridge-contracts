// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @notice CRIT-001 — exercises the refund lifecycle. A locked deposit is
///         NOT refundable; it only becomes refundable via an M-of-N
///         `markDepositRefundable` attestation that the OPNet voucher was
///         cancelled. The previous timeout-only path let a user claim
///         wUSDC on OPNet AND refund the EVM lock (1:1 backing break) —
///         that path no longer exists.
contract RefundLockedDepositTest is Test {
    TestableBridgeEscrow internal impl;
    TestableBridgeEscrow internal escrow;
    MockERC20 internal usdc;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    uint256 internal roguePk = 0xBADBADBAD;
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
        vm.chainId(1);
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
                evmBridge: address(escrow),
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

    /// @dev Build the `[uint8 numSigs][r||s||v]` M-of-N blob for a 1-of-1
    ///      ECDSA signature over `digest`.
    function _mofnSig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(uint8(1), r, s, v);
    }

    /// @dev Sign a RefundAuthorization for `nonce` at the current epoch
    ///      with the authorized signer and submit `markDepositRefundable`.
    function _attest(uint256 nonce) internal {
        bytes32 digest = escrow.hashRefundAuthorization(
            nonce, flowId, escrow.currentEpoch()
        );
        escrow.markDepositRefundable(nonce, _mofnSig(signerPk, digest));
    }

    function _statusOf(uint256 nonce) internal view returns (BridgeEscrow.DepositStatus) {
        ( , , BridgeEscrow.DepositStatus status, , , , ) = escrow.lockedDeposits(nonce);
        return status;
    }

    // -----------------------------------------------------------------
    // CRIT-001 — a Locked deposit is NOT refundable
    // -----------------------------------------------------------------

    /// @notice The core regression. A successful lock — even one whose
    ///         OPNet voucher was already minted and claimed — must NOT be
    ///         refundable without a no-mint attestation. Time passing
    ///         changes nothing: there is no timeout path anymore.
    function test_CritRegression_LockedDepositIsNotRefundable() public {
        uint256 nonce = _lock(10_000e6);

        // Same block.
        vm.expectRevert(BridgeEscrow.RefundNotAuthorized.selector);
        escrow.refundLockedDeposit(nonce);

        // ...and still not refundable an arbitrarily long time later. The
        // old code refunded unconditionally after 7 days — the exact
        // double-spend window. Now elapsed time is irrelevant.
        vm.warp(block.timestamp + 3650 days);
        vm.expectRevert(BridgeEscrow.RefundNotAuthorized.selector);
        escrow.refundLockedDeposit(nonce);

        // The deposit is still Locked — no state was mutated.
        assertTrue(_statusOf(nonce) == BridgeEscrow.DepositStatus.Locked);
    }

    // -----------------------------------------------------------------
    // markDepositRefundable — the attestation gate
    // -----------------------------------------------------------------

    function test_MarkRefundable_ThenRefund_TransfersBackToUser() public {
        uint256 amount = 12_345e6;
        uint256 balBefore = usdc.balanceOf(alice);
        uint256 nonce = _lock(amount);
        assertEq(balBefore - usdc.balanceOf(alice), amount, "lock did not pull amount");

        _attest(nonce);
        assertTrue(_statusOf(nonce) == BridgeEscrow.DepositStatus.Refundable);

        // Permissionless to call — bob submits, funds still go to alice.
        vm.prank(bob);
        escrow.refundLockedDeposit(nonce);

        assertEq(usdc.balanceOf(alice), balBefore, "alice made whole");
        assertEq(usdc.balanceOf(address(escrow)), 0, "escrow empty after refund");
        assertTrue(_statusOf(nonce) == BridgeEscrow.DepositStatus.Refunded);
    }

    function test_MarkRefundable_BadSignature_Reverts() public {
        uint256 nonce = _lock(5_000e6);
        bytes32 digest = escrow.hashRefundAuthorization(
            nonce, flowId, escrow.currentEpoch()
        );
        // Signed by a key that is not in the signer set.
        vm.expectRevert(BridgeEscrow.InvalidSignature.selector);
        escrow.markDepositRefundable(nonce, _mofnSig(roguePk, digest));
    }

    function test_MarkRefundable_WrongEpoch_Reverts() public {
        uint256 nonce = _lock(5_000e6);
        // Authorized signer, but signs over the wrong epoch — the contract
        // hashes `currentEpoch`, so the digest mismatches and recovery
        // lands on a different address.
        bytes32 digest = escrow.hashRefundAuthorization(
            nonce, flowId, escrow.currentEpoch() + 1
        );
        vm.expectRevert(BridgeEscrow.InvalidSignature.selector);
        escrow.markDepositRefundable(nonce, _mofnSig(signerPk, digest));
    }

    function test_MarkRefundable_UnknownNonce_Reverts() public {
        bytes32 digest = escrow.hashRefundAuthorization(9999, flowId, 1);
        vm.expectRevert(BridgeEscrow.LockNotFound.selector);
        escrow.markDepositRefundable(9999, _mofnSig(signerPk, digest));
    }

    function test_MarkRefundable_Twice_Reverts() public {
        uint256 nonce = _lock(5_000e6);
        _attest(nonce);
        // Second attestation — deposit is no longer Locked.
        bytes32 digest = escrow.hashRefundAuthorization(
            nonce, flowId, escrow.currentEpoch()
        );
        vm.expectRevert(BridgeEscrow.DepositNotInLockedState.selector);
        escrow.markDepositRefundable(nonce, _mofnSig(signerPk, digest));
    }

    function test_MarkRefundable_EmitsEvent() public {
        uint256 nonce = _lock(3_500e6);
        bytes32 digest = escrow.hashRefundAuthorization(
            nonce, flowId, escrow.currentEpoch()
        );
        vm.recordLogs();
        vm.prank(bob);
        escrow.markDepositRefundable(nonce, _mofnSig(signerPk, digest));

        Vm.Log[] memory entries = vm.getRecordedLogs();
        bytes32 sig = keccak256("DepositMarkedRefundable(uint256,address,address)");
        bool found;
        for (uint256 i; i < entries.length; i++) {
            if (entries[i].topics.length > 0 && entries[i].topics[0] == sig) {
                found = true;
                assertEq(uint256(entries[i].topics[1]), nonce, "nonce");
                assertEq(address(uint160(uint256(entries[i].topics[2]))), alice, "user");
                assertEq(address(uint160(uint256(entries[i].topics[3]))), bob, "by");
                break;
            }
        }
        assertTrue(found, "DepositMarkedRefundable not emitted");
    }

    // -----------------------------------------------------------------
    // refundLockedDeposit
    // -----------------------------------------------------------------

    function test_RefundDecrementsInventory() public {
        uint256 amount = 7_000e6;
        uint256 nonce = _lock(amount);
        assertEq(escrow.getFlow(flowId).inventory, amount);

        _attest(nonce);
        escrow.refundLockedDeposit(nonce);

        assertEq(escrow.getFlow(flowId).inventory, 0, "inventory back to zero");
    }

    function test_RefundTwice_Reverts() public {
        uint256 nonce = _lock(5_000e6);
        _attest(nonce);
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
        _attest(nonce);

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
                assertEq(address(uint160(uint256(entries[i].topics[2]))), alice, "user");
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

    function test_RefundIndependentOfPause() public {
        // Refunds — both the attestation and the payout — must work even
        // while the contract is paused: pause freezes forward flow
        // (lock/claim), not user escape paths.
        uint256 nonce = _lock(1_500e6);

        vm.prank(owner);
        escrow.pause();

        _attest(nonce);
        escrow.refundLockedDeposit(nonce);
        assertTrue(_statusOf(nonce) == BridgeEscrow.DepositStatus.Refunded);
    }
}
