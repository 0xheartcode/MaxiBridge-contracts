// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {AmountPolicy} from "../src/AmountPolicy.sol";

/// @notice External harness — `vm.expectRevert` only fires on lower-depth
///         reverts, but `internal` library calls are inlined. Wrap each
///         function in an external method on a separate contract so the
///         revert happens across a CALL boundary.
contract AmountPolicyHarness {
    function quote(
        uint256 grossSrc,
        uint8 srcDec,
        uint8 dstDec,
        uint16 feeBps,
        uint128 minFee,
        uint128 minAmount
    ) external pure returns (uint256, uint256, uint256) {
        return AmountPolicy.quote(grossSrc, srcDec, dstDec, feeBps, minFee, minAmount);
    }

    function scale(uint256 amountSrc, uint8 srcDec, uint8 dstDec)
        external
        pure
        returns (uint256)
    {
        return AmountPolicy.scale(amountSrc, srcDec, dstDec);
    }
}

/// @notice PR β.1 — AmountPolicy library tests.
///         Covers decimal scaling (same / grow / shrink + dust),
///         minAmount enforcement, fee math, and rejection paths.
contract AmountPolicyTest is Test {
    AmountPolicyHarness internal h;

    function setUp() public {
        h = new AmountPolicyHarness();
    }
    // ─── scale ─────────────────────────────────────────────────────────

    function test_Scale_SameDecimals_Identity() public view {
        assertEq(h.scale(123_456, 6, 6), 123_456);
    }

    function test_Scale_Grow_6to18() public view {
        // 1 USDC (1_000_000 base) → 1 ether (1e18) when going to 18 decimals.
        assertEq(h.scale(1_000_000, 6, 18), 1e18);
    }

    function test_Scale_Shrink_18to6_Clean() public view {
        // 1 ether at 18 dec → 1 USDC at 6 dec. Cleanly divisible.
        assertEq(h.scale(1e18, 18, 6), 1_000_000);
    }

    function test_Scale_Shrink_18to6_Dust_Reverts() public {
        // 1e12 + 1 wei is not divisible by 1e12 → revert.
        vm.expectRevert(AmountPolicy.AmountDustOnShrink.selector);
        h.scale(1e12 + 1, 18, 6);
    }

    function test_Scale_Shrink_18to6_BelowDelta_Reverts() public {
        // Anything < 1e12 wei = 0 USDC; reject (dust).
        vm.expectRevert(AmountPolicy.AmountDustOnShrink.selector);
        h.scale(999_999_999_999, 18, 6);
    }

    // ─── quote ─────────────────────────────────────────────────────────

    function test_Quote_SameDecimals_Happy() public view {
        // 100 USDC, 50 bps fee, no min — expect fee = 0.5 USDC.
        (uint256 grossDst, uint256 feeDst, uint256 netDst) =
            h.quote(100_000_000, 6, 6, 50, 0, 0);
        assertEq(grossDst, 100_000_000);
        assertEq(feeDst, 500_000);
        assertEq(netDst, 99_500_000);
    }

    function test_Quote_18to6_Happy() public view {
        // 1 ETH at 18 dec, going to a 6-dec wrapper. 50 bps fee.
        // grossDst = 1e18 / 1e12 = 1_000_000. fee = 5_000.
        (uint256 grossDst, uint256 feeDst, uint256 netDst) =
            h.quote(1e18, 18, 6, 50, 0, 0);
        assertEq(grossDst, 1_000_000);
        assertEq(feeDst, 5_000);
        assertEq(netDst, 995_000);
    }

    function test_Quote_6to18_Happy() public view {
        // 1 USDC at 6 dec → 1 ether at 18 dec; 50 bps fee → fee = 0.005 ether.
        (uint256 grossDst, uint256 feeDst, uint256 netDst) =
            h.quote(1_000_000, 6, 18, 50, 0, 0);
        assertEq(grossDst, 1e18);
        assertEq(feeDst, 5e15);
        assertEq(netDst, 995e15);
    }

    function test_Quote_BelowMin_Reverts() public {
        vm.expectRevert(AmountPolicy.AmountBelowMin.selector);
        h.quote(999_999, 6, 6, 50, 0, 1_000_000);
    }

    function test_Quote_FeeZero_Reverts() public {
        // 100 base units of USDC, 50 bps, no minFee.
        // raw fee = 100*50/10000 = 0 → reject.
        vm.expectRevert(AmountPolicy.FeeZero.selector);
        h.quote(100, 6, 6, 50, 0, 0);
    }

    function test_Quote_FeeExceedsGross_Reverts() public {
        // 200 base units, 50 bps, minFee = 200 → fee = max(1, 200) = 200,
        // grossDst = 200 → fee >= gross → reject.
        vm.expectRevert(AmountPolicy.FeeExceedsGross.selector);
        h.quote(200, 6, 6, 50, 200, 0);
    }

    function test_Quote_DecimalShrinkDust_Reverts() public {
        // 1e18 + 1 wei into a 6-dec wrapper → dust → reject.
        vm.expectRevert(AmountPolicy.AmountDustOnShrink.selector);
        h.quote(1e18 + 1, 18, 6, 50, 0, 0);
    }

    function test_Quote_DecimalZeroAmount_Reverts() public {
        // 999_999_999_999 wei into a 6-dec wrapper has grossDst < 1e12,
        // which scale() rejects as dust. (Edge case mirroring the
        // "amount-below-decimal-precision" branch.)
        vm.expectRevert(AmountPolicy.AmountDustOnShrink.selector);
        h.quote(999_999_999_999, 18, 6, 50, 0, 0);
    }

    function test_Quote_MinFeeWins_OverBpsRaw() public view {
        // 1 USDC, 50 bps → raw fee = 5_000. minFee = 100_000 → minFee wins.
        (, uint256 feeDst,) = h.quote(1_000_000, 6, 6, 50, 100_000, 0);
        assertEq(feeDst, 100_000);
    }

    function test_Quote_BadDecimals_Revert() public {
        vm.expectRevert(AmountPolicy.DecimalsTooLarge.selector);
        h.quote(1, 0, 6, 50, 0, 0);
        vm.expectRevert(AmountPolicy.DecimalsTooLarge.selector);
        h.quote(1, 6, 31, 50, 0, 0);
    }
}
