// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @notice Explicit per-flow fee accounting + non-emergency `withdrawFees`.
///         Exercises:
///           - accrual: a `lock` on a fee-bearing flow bumps
///             `flow.accruedFees` by exactly the computed fee, while
///             net/inventory accounting is unchanged otherwise.
///           - `withdrawFees`: transfers exactly `amount` to `treasury`,
///             decrements `accruedFees`, emits `FeesWithdrawn`.
///           - reverts: amount > accruedFees, amount == 0, treasury unset,
///             caller is neither owner nor guardian.
///           - works while UNPAUSED and is NOT blocked by pause state.
contract FeeAccountingTest is Test {
    TestableBridgeEscrow internal impl;
    TestableBridgeEscrow internal escrow;
    MockERC20 internal usdc;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    address internal alice = address(0xBEEF);
    address internal treasury = address(0x7EA5);
    address internal guardian = address(0x6A6D);
    address internal stranger = address(0xBAD);

    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;
    uint64 internal constant ETH_CHAIN_ID = 1;
    bytes32 internal constant OPNET_BRIDGE = bytes32(uint256(0xDEAD));
    bytes32 internal constant OPNET_USDC = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant RECIPIENT = keccak256("rcp");

    // 50 bps = 0.5% (the canonical bridge fee).
    uint16 internal constant FEE_BPS = 50;
    uint128 internal constant MIN_FEE = 0;

    bytes32 internal flowId;

    event FeesWithdrawn(
        bytes32 indexed flowId,
        address indexed token,
        address indexed to,
        uint256 amount
    );

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
        escrow.setTreasury(treasury);
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
                feeBps: FEE_BPS,
                minFee: MIN_FEE,
                minAmount: 1_000,
                cap: 100_000_000e6,
                dailyLimit: 100_000_000e6,
                tipCapBps: 0
            })
        );
        vm.stopPrank();

        usdc.mint(alice, 1_000_000_000e6);
        vm.prank(alice);
        usdc.approve(address(escrow), type(uint256).max);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────
    //
    // Under the post-#62-fix lifecycle, lock-time fee accrual no longer
    // happens; the fee is captured per-deposit on the LockRecord and only
    // promoted to `flow.accruedFees` (with a matching inventory deduction)
    // via `settleLockedDeposit` after the settlement window. These helpers
    // collapse the lock → warp → settle dance into one call so the original
    // test assertions still read clearly.

    function _lockAs(address user, uint256 amount) internal returns (uint256 nonce) {
        vm.prank(user);
        (nonce, ) = escrow.lock(address(usdc), amount, RECIPIENT, flowId);
    }

    function _settle(uint256 nonce) internal {
        vm.warp(block.timestamp + escrow.SETTLEMENT_WINDOW() + 1);
        escrow.settleLockedDeposit(nonce);
    }

    function _lockAndSettle(address user, uint256 amount) internal returns (uint256 nonce) {
        nonce = _lockAs(user, amount);
        _settle(nonce);
    }

    // ─── Accrual (post-#62-fix: promotion happens at settle, not lock) ─────

    function test_Accrual_BumpsByExactFee() public {
        uint256 amount = 10_000e6;
        uint256 expectedFee = (amount * FEE_BPS) / 10_000; // 50e6

        assertEq(escrow.getFlow(flowId).accruedFees, 0);
        uint128 invBefore = escrow.getFlow(flowId).inventory;

        uint256 nonce = _lockAs(alice, amount);
        // Lock-time invariant under the new spec: accruedFees stays zero
        // and inventory is bumped by the gross amount. Fee is captured
        // per-deposit on the LockRecord, NOT promoted yet.
        BridgeEscrow.FlowRecord memory midF = escrow.getFlow(flowId);
        assertEq(uint256(midF.accruedFees), 0, "accruedFees should be 0 before settle");
        assertEq(uint256(midF.inventory) - uint256(invBefore), amount, "inventory should be gross at lock");

        _settle(nonce);

        BridgeEscrow.FlowRecord memory f = escrow.getFlow(flowId);
        assertEq(uint256(f.accruedFees), expectedFee, "accruedFees != fee after settle");
        // Post-settle inventory must drop back by exactly the fee — settlement
        // is a relabel from inventory-backing into withdrawable revenue.
        assertEq(uint256(f.inventory) - uint256(invBefore), amount - expectedFee, "inventory not reduced by fee");
    }

    function test_Accrual_Accumulates() public {
        uint256 n1 = _lockAs(alice, 10_000e6);
        uint256 n2 = _lockAs(alice, 20_000e6);

        // Warp once past the window then settle both deposits — accrual
        // must accumulate exactly as it did under the old (broken) spec.
        vm.warp(block.timestamp + escrow.SETTLEMENT_WINDOW() + 1);
        escrow.settleLockedDeposit(n1);
        escrow.settleLockedDeposit(n2);

        uint256 expected = ((10_000e6 + 20_000e6) * uint256(FEE_BPS)) / 10_000; // 150e6
        assertEq(uint256(escrow.getFlow(flowId).accruedFees), expected);
    }

    function test_Accrual_ZeroFeeFlow_AccruesNothing() public {
        // A flow with feeBps == 0 && minFee == 0 accrues nothing.
        MockERC20 dai = new MockERC20("Dai", "DAI", 18);
        vm.startPrank(owner);
        escrow.setSupportedToken(address(dai), true);
        bytes32 freeFlow = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: 0,
                evmChainId: ETH_CHAIN_ID,
                evmBridge: address(0xE5C0),
                evmToken: address(dai),
                evmDecimals: 18,
                opnetBridge: OPNET_BRIDGE,
                opnetToken: bytes32(uint256(0x9999)),
                opnetDecimals: 18,
                feeBps: 0,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );
        vm.stopPrank();
        dai.mint(alice, 1_000e18);
        vm.startPrank(alice);
        dai.approve(address(escrow), type(uint256).max);
        escrow.lock(address(dai), 1_000e18, RECIPIENT, freeFlow);
        vm.stopPrank();
        assertEq(escrow.getFlow(freeFlow).accruedFees, 0);
    }

    function test_Accrual_MinFeeFloorApplies() public {
        // minFee dominates when bps-derived fee is below it.
        MockERC20 tok = new MockERC20("Tok", "TOK", 6);
        vm.startPrank(owner);
        escrow.setSupportedToken(address(tok), true);
        bytes32 mf = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: 0,
                evmChainId: ETH_CHAIN_ID,
                evmBridge: address(0xE5C0),
                evmToken: address(tok),
                evmDecimals: 6,
                opnetBridge: OPNET_BRIDGE,
                opnetToken: bytes32(uint256(0x7777)),
                opnetDecimals: 6,
                feeBps: 1, // 0.01% — tiny
                minFee: 1e6, // 1 token floor
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );
        vm.stopPrank();
        tok.mint(alice, 1_000e6);
        vm.startPrank(alice);
        tok.approve(address(escrow), type(uint256).max);
        // gross 100e6 → bps fee = 100e6 * 1 / 10000 = 1e4 < minFee 1e6.
        (uint256 nonce, ) = escrow.lock(address(tok), 100e6, RECIPIENT, mf);
        vm.stopPrank();

        // Promote the captured fee via settlement.
        vm.warp(block.timestamp + escrow.SETTLEMENT_WINDOW() + 1);
        escrow.settleLockedDeposit(nonce);

        assertEq(uint256(escrow.getFlow(mf).accruedFees), 1e6);
    }

    // ─── withdrawFees ───────────────────────────────────────────────────────

    function test_WithdrawFees_TransfersAndDecrements() public {
        _lockAndSettle(alice, 10_000e6);
        uint256 fee = (10_000e6 * uint256(FEE_BPS)) / 10_000; // 50e6

        uint256 treBefore = usdc.balanceOf(treasury);
        uint256 escBefore = usdc.balanceOf(address(escrow));

        uint256 take = 20e6;
        vm.prank(owner);
        escrow.withdrawFees(flowId, take);

        assertEq(usdc.balanceOf(treasury) - treBefore, take, "treasury delta");
        assertEq(escBefore - usdc.balanceOf(address(escrow)), take, "escrow delta");
        assertEq(uint256(escrow.getFlow(flowId).accruedFees), fee - take, "accrued not decremented");
    }

    function test_WithdrawFees_FullDrain() public {
        _lockAndSettle(alice, 10_000e6);
        uint256 fee = (10_000e6 * uint256(FEE_BPS)) / 10_000;

        vm.prank(owner);
        escrow.withdrawFees(flowId, fee);
        assertEq(escrow.getFlow(flowId).accruedFees, 0);
        assertEq(usdc.balanceOf(treasury), fee);
    }

    function test_WithdrawFees_GuardianCanCall() public {
        _lockAndSettle(alice, 10_000e6);
        vm.prank(guardian);
        escrow.withdrawFees(flowId, 10e6);
        assertEq(usdc.balanceOf(treasury), 10e6);
    }

    function test_WithdrawFees_EmitsEvent() public {
        _lockAndSettle(alice, 10_000e6);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit FeesWithdrawn(flowId, address(usdc), treasury, 30e6);
        vm.prank(owner);
        escrow.withdrawFees(flowId, 30e6);
    }

    function test_WithdrawFees_WorksWhileUnpaused() public {
        // Sanity: contract is not paused, and withdrawFees succeeds. This is
        // the routine-revenue contract: unlike emergencyWithdraw it has no
        // whenPaused gate.
        assertEq(escrow.paused(), false);
        _lockAndSettle(alice, 10_000e6);
        vm.prank(owner);
        escrow.withdrawFees(flowId, 10e6);
        assertEq(usdc.balanceOf(treasury), 10e6);
        assertEq(escrow.paused(), false);
    }

    function test_WithdrawFees_NotBlockedByPause() public {
        // Even when paused, withdrawFees still works (no whenPaused, no
        // whenNotPaused gate — it is orthogonal to pause state).
        // NOTE: settle happens BEFORE pause because settle is permissionless;
        //       the post-fix lifecycle is lock → settle → (later) pause.
        _lockAndSettle(alice, 10_000e6);
        vm.prank(guardian);
        escrow.pause();
        assertEq(escrow.paused(), true);
        vm.prank(owner);
        escrow.withdrawFees(flowId, 10e6);
        assertEq(usdc.balanceOf(treasury), 10e6);
    }

    // ─── Reverts ────────────────────────────────────────────────────────────

    function test_WithdrawFees_AmountExceedsAccrued_Reverts() public {
        vm.prank(alice);
        escrow.lock(address(usdc), 10_000e6, RECIPIENT, flowId);
        uint256 fee = (10_000e6 * uint256(FEE_BPS)) / 10_000;
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.InsufficientAccruedFees.selector);
        escrow.withdrawFees(flowId, fee + 1);
    }

    function test_WithdrawFees_ZeroAmount_Reverts() public {
        vm.prank(alice);
        escrow.lock(address(usdc), 10_000e6, RECIPIENT, flowId);
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.AmountZero.selector);
        escrow.withdrawFees(flowId, 0);
    }

    function test_WithdrawFees_TreasuryUnset_Reverts() public {
        // Fresh escrow without a treasury set.
        TestableBridgeEscrow impl2 = new TestableBridgeEscrow();
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        TestableBridgeEscrow esc2 = TestableBridgeEscrow(
            address(new ERC1967Proxy(address(impl2), initData))
        );
        vm.startPrank(owner);
        bytes32 fId = esc2.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: 0,
                evmChainId: ETH_CHAIN_ID,
                evmBridge: address(0xE5C0),
                evmToken: address(usdc),
                evmDecimals: 6,
                opnetBridge: OPNET_BRIDGE,
                opnetToken: OPNET_USDC,
                opnetDecimals: 6,
                feeBps: FEE_BPS,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );
        vm.stopPrank();
        usdc.mint(alice, 100_000e6);
        vm.startPrank(alice);
        usdc.approve(address(esc2), type(uint256).max);
        esc2.lock(address(usdc), 10_000e6, RECIPIENT, fId);
        vm.stopPrank();

        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.TreasuryNotSet.selector);
        esc2.withdrawFees(fId, 1e6);
    }

    function test_WithdrawFees_UnknownFlow_Reverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowNotFound.selector);
        escrow.withdrawFees(keccak256("nope"), 1);
    }

    function test_WithdrawFees_NonOwnerNonGuardian_Reverts() public {
        vm.prank(alice);
        escrow.lock(address(usdc), 10_000e6, RECIPIENT, flowId);
        vm.prank(stranger);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.withdrawFees(flowId, 1e6);
    }
}
