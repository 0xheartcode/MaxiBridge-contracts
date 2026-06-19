// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title AmountPolicy — pure math for decimal scaling + fee computation.
/// @notice Bridge-shared math layer. Used by `BridgeEscrow` and (via the
///         AssemblyScript port) by `BridgeDepository` so source and
///         destination amounts agree byte-for-byte across chains.
///
///         Strict semantics by design:
///           - Decimal scaling on shrink (`srcDec > dstDec`) requires the
///             source amount to be cleanly divisible — no silent rounding
///             that creates dust.
///           - Fee zero is rejected, matching the rest of the bridge.
///           - `grossDst <= feeDst` is rejected (no negative net).
///         Lenient mode is intentionally NOT supported. Integer-only
///         semantics, no accounting drift.
library AmountPolicy {
    error AmountBelowMin();
    error AmountBelowDecimalPrecision();
    error AmountDustOnShrink();
    error FeeZero();
    error FeeExceedsGross();
    error DecimalsTooLarge();

    /// @notice Hard cap on per-leg decimal width. EVM ERC20s typically max
    ///         out at 18; OPNet OP20s likewise. 30 leaves substantial
    ///         headroom for exotic tokens while keeping `10**delta` safely
    ///         within `uint256`.
    uint8 internal constant MAX_DECIMALS = 30;

    /// @notice Compute everything a voucher needs to commit to in one
    ///         deterministic call.
    /// @param  grossSrc      Source-side amount (base units of the source token).
    /// @param  srcDec        Source token decimals (1..MAX_DECIMALS).
    /// @param  dstDec        Destination token decimals (1..MAX_DECIMALS).
    /// @param  feeBps        Fee, basis points (0..10000). Caller must enforce
    ///                       its own cap (e.g. `MAX_FEE_BPS = 1000` on the
    ///                       bridge contracts) — this library does not.
    /// @param  minFee        Minimum fee, destination base units. The
    ///                       higher of `(grossDst * bps / 10000, minFee)`
    ///                       wins.
    /// @param  minAmount     Minimum source amount, source base units.
    ///                       `grossSrc < minAmount` reverts.
    /// @return grossDst      `grossSrc` scaled to destination decimals.
    /// @return feeDst        Destination-side fee.
    /// @return netDst        `grossDst - feeDst`.
    function quote(
        uint256 grossSrc,
        uint8 srcDec,
        uint8 dstDec,
        uint16 feeBps,
        uint128 minFee,
        uint128 minAmount
    ) internal pure returns (uint256 grossDst, uint256 feeDst, uint256 netDst) {
        if (srcDec == 0 || srcDec > MAX_DECIMALS) revert DecimalsTooLarge();
        if (dstDec == 0 || dstDec > MAX_DECIMALS) revert DecimalsTooLarge();
        if (grossSrc < uint256(minAmount)) revert AmountBelowMin();

        grossDst = scale(grossSrc, srcDec, dstDec);
        if (grossDst == 0) revert AmountBelowDecimalPrecision();

        uint256 raw = (grossDst * uint256(feeBps)) / 10_000;
        feeDst = raw > uint256(minFee) ? raw : uint256(minFee);
        if (feeDst == 0) revert FeeZero();
        if (grossDst <= feeDst) revert FeeExceedsGross();
        netDst = grossDst - feeDst;
    }

    /// @notice Scale `amountSrc` from `srcDec` to `dstDec` decimals.
    ///         Strict on shrink: `amountSrc` must be cleanly divisible by
    ///         `10 ** (srcDec - dstDec)`. Dust reverts; we never round.
    function scale(
        uint256 amountSrc,
        uint8 srcDec,
        uint8 dstDec
    ) internal pure returns (uint256 amountDst) {
        if (srcDec == dstDec) {
            return amountSrc;
        }
        // N3-2 (PeckShield) — parity with the OPNet `scale` guard. This leg is
        // `internal pure` (callers pre-bound decimals to 1..MAX_DECIMALS) and
        // a runaway `10 ** delta` would revert on checked overflow anyway, but
        // bound the delta explicitly so the invariant is self-evident.
        if (dstDec > srcDec) {
            if (dstDec - srcDec > MAX_DECIMALS) revert DecimalsTooLarge();
            uint256 mult = 10 ** uint256(dstDec - srcDec);
            return amountSrc * mult;
        }
        // srcDec > dstDec — strict floor with dust rejection.
        if (srcDec - dstDec > MAX_DECIMALS) revert DecimalsTooLarge();
        uint256 div = 10 ** uint256(srcDec - dstDec);
        if (amountSrc % div != 0) revert AmountDustOnShrink();
        return amountSrc / div;
    }
}
