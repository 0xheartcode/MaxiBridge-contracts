import { ABICoder, ABIDataTypes } from '@btc-vision/transaction';
import { AbiTypeToStr } from 'opnet';

/** Encodes a function signature string into a numeric SHA-256 selector. */
export function encodeNumericSelector(selector: string): number {
    return Number(`0x${new ABICoder().encodeSelector(selector)}`);
}

/** Encodes a function name + parameter types into a numeric SHA-256 selector. */
export function encodeSelectorWithParams(name: string, ...params: ABIDataTypes[]): number {
    return encodeNumericSelector(`${name}(${params.map((t) => AbiTypeToStr[t]).join(',')})`);
}
