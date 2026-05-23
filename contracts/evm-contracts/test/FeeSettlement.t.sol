// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @notice #62-fix — Refund-safe fee accounting via time-based settlement.
///
///         The PR-62 lifecycle was: lock → accrue → withdrawFees (with the
///         deposit still refundable). That let a sweep make refund either
///         revert or drain another flow's reserves. New lifecycle:
///
///           lock      → Locked, fee captured on LockRecord, NOT accrued
///           settle    → Settled, fee promoted to accruedFees, inventory -= fee
///           OR
///           refund    → Refundable → Refunded, fee NEVER accrued
///
///         This suite covers the new invariants directly. Tests in the
///         original `FeeAccounting.t.sol` that assume lock-time accrual
///         (`test_Accrual_*`, `test_WithdrawFees_*` without first warping +
///         settling) need to be rewritten against the new spec — see
///         `docs/PR62_FIX_SKETCH.md` for the punch list.
contract FeeSettlementTest is Test {
    TestableBridgeEscrow internal impl;
    TestableBridgeEscrow internal escrow;
    MockERC20 internal usdc;
    MockERC20 internal usdt; // second same-token-class flow for cross-flow test

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xCAFE);
    address internal treasury = address(0x7EA5);
    address internal guardian = address(0x6A6D);

    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;
    uint64 internal constant ETH_CHAIN_ID = 1;
    bytes32 internal constant OPNET_BRIDGE = bytes32(uint256(0xDEAD));
    bytes32 internal constant OPNET_USDC = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant OPNET_USDC_B = bytes32(uint256(0xC0FFEF));
    bytes32 internal constant RECIPIENT = keccak256("rcp");

    uint16 internal constant FEE_BPS = 50;       // 0.5%
    uint128 internal constant MIN_FEE = 0;

    bytes32 internal flowA;
    bytes32 internal flowB;

    event DepositSettled(
        uint256 indexed depositNonce,
        bytes32 indexed flowId,
        uint128 fee,
        address indexed by
    );

    function setUp() public {
        signerAddr = vm.addr(signerPk);
        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdt = new MockERC20("Tether",   "USDT", 6);

        impl = new TestableBridgeEscrow();
        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(usdt);

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = TestableBridgeEscrow(
            address(new ERC1967Proxy(address(impl), initData))
        );

        vm.startPrank(owner);
        escrow.setGuardian(guardian);
        escrow.setTreasury(treasury);
        flowA = _addFlow(address(usdc), OPNET_USDC);
        flowB = _addFlow(address(usdc), OPNET_USDC_B);
        vm.stopPrank();

        usdc.mint(alice, 1_000_000_000e6);
        usdc.mint(bob,   1_000_000_000e6);
        vm.prank(alice); usdc.approve(address(escrow), type(uint256).max);
        vm.prank(bob);   usdc.approve(address(escrow), type(uint256).max);
    }

    function _addFlow(address tok, bytes32 opnetTok) internal returns (bytes32) {
        return escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: 0,
                evmChainId: ETH_CHAIN_ID,
                evmBridge: address(0xE5C0),
                evmToken: tok,
                evmDecimals: 6,
                opnetBridge: OPNET_BRIDGE,
                opnetToken: opnetTok,
                opnetDecimals: 6,
                feeBps: FEE_BPS,
                minFee: MIN_FEE,
                minAmount: 1_000,
                cap: 100_000_000e6,
                dailyLimit: 100_000_000e6,
                tipCapBps: 0
            })
        );
    }

    // ─── New-lifecycle invariants ───────────────────────────────────────

    /// Lock does NOT accrue. accruedFees stays zero; fee is captured per-deposit.
    function test_Lock_DoesNotAccrueAtLockTime() public {
        uint256 amount = 10_000e6;
        vm.prank(alice);
        (uint256 nonce, ) = escrow.lock(address(usdc), amount, RECIPIENT, flowA);

        assertEq(escrow.getFlow(flowA).accruedFees, 0, "should not accrue at lock");
        // LockRecord must carry the per-deposit fee.
        (, , , uint128 storedAmount, , , uint128 storedFee) = _readLockRecord(nonce);
        assertEq(uint256(storedAmount), amount, "amount mismatch");
        assertEq(uint256(storedFee), (amount * FEE_BPS) / 10_000, "fee not captured");
    }

    /// Settle after the window promotes the fee and drops inventory by the fee.
    function test_Settle_AfterWindow_PromotesFee() public {
        uint256 amount = 10_000e6;
        uint128 fee = uint128((amount * FEE_BPS) / 10_000);

        vm.prank(alice);
        (uint256 nonce, ) = escrow.lock(address(usdc), amount, RECIPIENT, flowA);

        uint128 invBefore = escrow.getFlow(flowA).inventory;

        vm.warp(block.timestamp + escrow.SETTLEMENT_WINDOW() + 1);

        vm.expectEmit(true, true, true, true);
        emit DepositSettled(nonce, flowA, fee, address(this));
        escrow.settleLockedDeposit(nonce);

        BridgeEscrow.FlowRecord memory f = escrow.getFlow(flowA);
        assertEq(uint256(f.accruedFees), uint256(fee), "fee not promoted");
        assertEq(uint256(invBefore) - uint256(f.inventory), uint256(fee), "inventory not reduced by fee");
    }

    /// Settle before the window reverts.
    function test_Settle_BeforeWindow_Reverts() public {
        vm.prank(alice);
        (uint256 nonce, ) = escrow.lock(address(usdc), 10_000e6, RECIPIENT, flowA);

        vm.expectRevert(BridgeEscrow.SettlementWindowNotMet.selector);
        escrow.settleLockedDeposit(nonce);
    }

    /// A deposit already moved to Refundable cannot be settled.
    function test_Settle_OnRefundable_Reverts() public {
        vm.prank(alice);
        (uint256 nonce, ) = escrow.lock(address(usdc), 10_000e6, RECIPIENT, flowA);

        // Move to Refundable via the M-of-N path. Helper omitted here for
        // brevity — see RefundFlow.t.sol for the sig-blob helper.
        // _markRefundable(nonce);

        // vm.warp(block.timestamp + escrow.SETTLEMENT_WINDOW() + 1);
        // vm.expectRevert(BridgeEscrow.LockNotSettleable.selector);
        // escrow.settleLockedDeposit(nonce);

        // TODO(maxime): port the _markRefundable helper from RefundFlow.t.sol.
        vm.skip(true);
    }

    /// Refund leaves accruedFees at zero — fee never promoted.
    function test_Refund_DoesNotLeakFee() public {
        // TODO(maxime): same _markRefundable helper needed. Once available:
        //   1. lock
        //   2. markRefundable
        //   3. refundLockedDeposit
        //   4. assert accruedFees == 0
        //   5. withdrawFees(any positive amount) reverts InsufficientAccruedFees
        vm.skip(true);
    }

    /// Lock with fee >= received reverts.
    function test_Lock_FeeGeqReceived_Reverts() public {
        // Create a flow where minFee is large enough that fee >= received.
        vm.startPrank(owner);
        bytes32 expensiveFlow = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: 0,
                evmChainId: ETH_CHAIN_ID,
                evmBridge: address(0xE5C0),
                evmToken: address(usdc),
                evmDecimals: 6,
                opnetBridge: OPNET_BRIDGE,
                opnetToken: bytes32(uint256(0xC0FFE1)),
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 10_000e6, // 10k minFee
                minAmount: 1,
                cap: 100_000_000e6,
                dailyLimit: 100_000_000e6,
                tipCapBps: 0
            })
        );
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.FeeExceedsAmount.selector);
        escrow.lock(address(usdc), 10_000e6, RECIPIENT, expensiveFlow); // amount == minFee
    }

    /// withdrawFees on a fresh-locked-but-not-settled deposit cannot drain
    /// anything: accruedFees is still 0.
    function test_WithdrawFees_CannotDrainUnsettled() public {
        vm.prank(alice);
        escrow.lock(address(usdc), 10_000e6, RECIPIENT, flowA);

        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.InsufficientAccruedFees.selector);
        escrow.withdrawFees(flowA, 1);
    }

    /// Cross-flow safety: settle A, sweep A — does NOT touch flow B's
    /// inventory (and physically backed because settle moved fee out of A's
    /// inventory and into accruedFees BEFORE the sweep transfer left escrow).
    function test_CrossFlow_SweepDoesNotDrainOtherFlow() public {
        // Flow A: lock then settle.
        vm.prank(alice);
        (uint256 nonceA, ) = escrow.lock(address(usdc), 10_000e6, RECIPIENT, flowA);
        // Flow B: lock to give the contract more balance + B inventory.
        vm.prank(bob);
        escrow.lock(address(usdc), 50_000e6, RECIPIENT, flowB);

        vm.warp(block.timestamp + escrow.SETTLEMENT_WINDOW() + 1);
        escrow.settleLockedDeposit(nonceA);

        uint128 invA_before = escrow.getFlow(flowA).inventory;
        uint128 invB_before = escrow.getFlow(flowB).inventory;
        uint128 accruedA   = escrow.getFlow(flowA).accruedFees;

        uint256 treasuryBefore = usdc.balanceOf(treasury);
        vm.prank(owner);
        escrow.withdrawFees(flowA, accruedA);

        assertEq(usdc.balanceOf(treasury) - treasuryBefore, uint256(accruedA), "treasury delta != fee");
        assertEq(escrow.getFlow(flowA).accruedFees, 0, "A accruedFees not cleared");
        // Critical: flow B's inventory must be untouched and physically backed.
        assertEq(escrow.getFlow(flowB).inventory, invB_before, "B inventory drift");
        assertEq(escrow.getFlow(flowA).inventory, invA_before, "A inventory should be unchanged by sweep itself");
    }

    /// Settlement must REVERT (not silently wrap inventory) when guardian
    /// `drainInventory` has lowered `flow.inventory` below the outstanding
    /// fee for this nonce. Regression test for the Codex-found `unchecked`
    /// underflow bug. The original tokens have already left escrow via the
    /// drain — promoting the fee would double-count.
    function test_Settle_RevertsIfInventoryDrainedBelowFee() public {
        uint256 amount = 10_000e6;
        uint128 fee = uint128((amount * FEE_BPS) / 10_000);

        vm.prank(alice);
        (uint256 nonce, ) = escrow.lock(address(usdc), amount, RECIPIENT, flowA);

        // Pause + drain ALL of flow A's inventory to treasury (simulates
        // guardian wind-down). After this, inventory < fee.
        vm.prank(guardian);
        escrow.pause();
        vm.prank(guardian);
        escrow.drainInventory(flowA, amount);
        vm.prank(owner);
        escrow.unpause();

        assertEq(escrow.getFlow(flowA).inventory, 0, "drain failed");

        vm.warp(block.timestamp + escrow.SETTLEMENT_WINDOW() + 1);
        // Solidity 0.8 checked subtraction reverts on underflow with the
        // panic code 0x11 (arithmetic over/underflow). The settle remains
        // callable later if governance re-provisions inventory.
        vm.expectRevert();
        escrow.settleLockedDeposit(nonce);

        // Status MUST stay Locked (the revert rolled back the status write).
        (, , BridgeEscrow.DepositStatus s, , , , uint128 storedFee) = escrow.lockedDeposits(nonce);
        assertEq(uint8(s), uint8(BridgeEscrow.DepositStatus.Locked), "status flipped despite revert");
        assertEq(uint256(storedFee), uint256(fee), "fee lost on revert");
    }

    // ─── Read helper ────────────────────────────────────────────────────

    /// `lockedDeposits` is `public` so Solidity generates a getter, but the
    /// tuple ordering follows the struct field order — keep in lockstep with
    /// `LockRecord` in BridgeEscrow.sol.
    function _readLockRecord(uint256 n) internal view returns (
        address user,
        uint64  lockedAt,
        BridgeEscrow.DepositStatus status,
        uint128 amount,
        address token,
        bytes32 flowId_,
        uint128 fee
    ) {
        return escrow.lockedDeposits(n);
    }
}
