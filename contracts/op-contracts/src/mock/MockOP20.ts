import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    Blockchain,
    BytesWriter,
    Calldata,
    OP20,
    OP20InitParameters,
} from '@btc-vision/btc-runtime/runtime';
import { StoredU256 } from '@btc-vision/btc-runtime/runtime/storage/StoredU256';
import { Revert } from '@btc-vision/btc-runtime/runtime/types/Revert';
import { EMPTY_POINTER } from '@btc-vision/btc-runtime/runtime/math/bytes';

/**
 * MockOP20 — TESTNET-ONLY faucet token.
 *
 * A plain OP20 with an OPEN, unguarded `mint` (and a one-click `drip`) so any
 * tester can self-fund the OPNet side of a flow. This is the OPNet analogue of
 * the EVM `MockERC20`/`MockUSDT` mocks (which also expose a public `mint`).
 *
 * Used as the OPNet-side token for flow modes where the OPNet token is a plain
 * pre-funded / mint-burn asset rather than a bridge-minted wrapper:
 *   - mode 1 INVERSE_WRAPPED  (OPNet lock → EVM wrapped mint)
 *   - mode 2 NATIVE_BURN_MINT
 *   - mode 3 POOLED_LOCK_RELEASE
 *   - mode 4 POOLED_LOCK_VEST
 *
 * NEVER deploy this on mainnet — an open mint has no backing and would let
 * anyone print the OPNet side of a route. The canonical wrapped tokens
 * (wUSDC/wUSDT, modes 0/1 wrapped side) stay `WrappedOP20`: mint is bridge-
 * gated precisely to preserve the 1:1 backing invariant.
 *
 * NON-UPGRADEABLE (no `UpdatablePlugin`) — it is a throwaway test fixture.
 */
@final
export class MockOP20 extends OP20 {
    // Append-only storage discipline kept even for the mock so the layout
    // stays auditable; this contract carries no upgrade hook.
    private _storageVersion: StoredU256 = new StoredU256(
        Blockchain.nextPointer,
        EMPTY_POINTER,
    );

    public override onDeployment(calldata: Calldata): void {
        super.onDeployment(calldata);

        // Same metadata layout as WrappedOP20 so the existing deploy tooling
        // can reuse its calldata encoder: (name, symbol, decimals, maxSupply).
        let maxSupply: u256 = u256.fromString('1000000000000000000000000000000000'); // 1e33 — effectively uncapped for a faucet
        let decimals: u8 = 6;
        let name: string = 'Mock Bridge Token';
        let symbol: string = 'mBRIDGE';

        if (calldata.byteLength >= 2) {
            name = calldata.readStringWithLength();
            symbol = calldata.readStringWithLength();
            decimals = calldata.readU8();
            maxSupply = calldata.readU256();
        }

        this.instantiate(new OP20InitParameters(maxSupply, decimals, name, symbol));

        this._storageVersion.value = u256.fromU32(1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Open faucet — TESTNET ONLY, no access control
    // ═══════════════════════════════════════════════════════════════════════

    /** Mint an arbitrary amount to any address. Unguarded by design. */
    @method(
        { name: 'to', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
    )
    @nonReentrant
    public mint(calldata: Calldata): BytesWriter {
        const to: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();
        if (to.isZero()) {
            throw new Revert('MockOP20: mint to zero');
        }
        if (amount.isZero()) {
            throw new Revert('MockOP20: zero amount');
        }
        this._mint(to, amount);
        return new BytesWriter(0);
    }

    /** One-click faucet: mint a fixed 10,000-token drip to the caller. */
    @method()
    @nonReentrant
    public drip(_calldata: Calldata): BytesWriter {
        // 10_000 tokens at 6 decimals.
        this._mint(Blockchain.tx.sender, u256.fromU64(10_000_000_000));
        return new BytesWriter(0);
    }

    @view
    @returns({ name: 'storageVersion', type: ABIDataTypes.UINT256 })
    public storageVersion(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(32);
        response.writeU256(this._storageVersion.value);
        return response;
    }
}
