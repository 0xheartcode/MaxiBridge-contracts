import { u256 } from '@btc-vision/as-bignum/assembly';
import { SafeMath } from '@btc-vision/btc-runtime/runtime';
import { Revert } from '@btc-vision/btc-runtime/runtime/types/Revert';

/**
 * AmountPolicy — pure math for decimal scaling + fee computation.
 *
 * AssemblyScript port of `contracts/evm-contracts/src/AmountPolicy.sol`.
 * Both sides MUST agree byte-for-byte; cross-chain voucher verification
 * relies on identical math here and on EVM.
 *
 * Strict semantics by design:
 *   - Decimal scaling on shrink (srcDec > dstDec) requires the source
 *     amount to be cleanly divisible — no silent rounding that creates
 *     dust.
 *   - Fee zero is rejected.
 *   - grossDst <= feeDst is rejected (no negative net).
 */

/** Hard cap on per-leg decimal width. Mirrors the Solidity constant. */
export const MAX_DECIMALS: u32 = 30;

/** Pre-computed 10^N up to 10^30, indexed by N. */
const POW10: u256[] = _buildPow10();

function _buildPow10(): u256[] {
    const out: u256[] = [];
    let v: u256 = u256.One;
    out.push(v); // 10^0
    const ten: u256 = u256.fromU32(10);
    for (let i: u32 = 1; i <= MAX_DECIMALS; i++) {
        v = SafeMath.mul(v, ten);
        out.push(v);
    }
    return out;
}

/**
 * Scale `amountSrc` from `srcDec` to `dstDec` decimals. Strict on shrink:
 * `amountSrc % 10^(srcDec-dstDec) != 0` reverts (no rounding).
 */
export function scale(amountSrc: u256, srcDec: u32, dstDec: u32): u256 {
    if (srcDec == dstDec) return amountSrc;

    if (dstDec > srcDec) {
        const mult: u256 = POW10[<i32>(dstDec - srcDec)];
        return SafeMath.mul(amountSrc, mult);
    }

    // srcDec > dstDec — strict floor with dust rejection.
    const div: u256 = POW10[<i32>(srcDec - dstDec)];
    const rem: u256 = _mod(amountSrc, div);
    if (!rem.isZero()) {
        throw new Revert('AmountPolicy: dust on shrink');
    }
    return SafeMath.div(amountSrc, div);
}

/**
 * Quote a voucher's full destination-side amounts in one call.
 *
 * Reverts on:
 *   - decimals out of range (1..MAX_DECIMALS)
 *   - grossSrc < minAmount
 *   - decimal-shrink dust (see scale)
 *   - grossDst == 0 after scaling (amount below decimal precision)
 *   - fee == 0
 *   - grossDst <= fee
 */
export class QuoteResult {
    grossDst: u256;
    feeDst: u256;
    netDst: u256;

    constructor(grossDst: u256, feeDst: u256, netDst: u256) {
        this.grossDst = grossDst;
        this.feeDst = feeDst;
        this.netDst = netDst;
    }
}

export function quote(
    grossSrc: u256,
    srcDec: u32,
    dstDec: u32,
    feeBps: u32,
    minFee: u256,
    minAmount: u256,
): QuoteResult {
    if (srcDec == 0 || srcDec > MAX_DECIMALS) {
        throw new Revert('AmountPolicy: bad srcDec');
    }
    if (dstDec == 0 || dstDec > MAX_DECIMALS) {
        throw new Revert('AmountPolicy: bad dstDec');
    }
    if (u256.lt(grossSrc, minAmount)) {
        throw new Revert('AmountPolicy: below minAmount');
    }

    const grossDst: u256 = scale(grossSrc, srcDec, dstDec);
    if (grossDst.isZero()) {
        throw new Revert('AmountPolicy: amount below decimal precision');
    }

    const raw: u256 = SafeMath.div(SafeMath.mul(grossDst, u256.fromU32(feeBps)), u256.fromU32(10000));
    const feeDst: u256 = u256.gt(raw, minFee) ? raw : minFee;
    if (feeDst.isZero()) {
        throw new Revert('AmountPolicy: fee zero');
    }
    if (u256.le(grossDst, feeDst)) {
        throw new Revert('AmountPolicy: fee >= gross');
    }
    const netDst: u256 = SafeMath.sub(grossDst, feeDst);
    return new QuoteResult(grossDst, feeDst, netDst);
}

/**
 * `a mod b` for u256 — `as-bignum` exposes div but not mod directly via
 * SafeMath. Use the identity `a - (a/b)*b`.
 */
function _mod(a: u256, b: u256): u256 {
    if (b.isZero()) {
        throw new Revert('AmountPolicy: mod by zero');
    }
    const q: u256 = SafeMath.div(a, b);
    const back: u256 = SafeMath.mul(q, b);
    return SafeMath.sub(a, back);
}
