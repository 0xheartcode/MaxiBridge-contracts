import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    Blockchain,
    BytesWriter,
    Calldata,
    OP20InitParameters,
    OP20S,
    SafeMath,
} from '@btc-vision/btc-runtime/runtime';
import { StoredAddress } from '@btc-vision/btc-runtime/runtime/storage/StoredAddress';
import { StoredU256 } from '@btc-vision/btc-runtime/runtime/storage/StoredU256';
import { StoredBoolean } from '@btc-vision/btc-runtime/runtime/storage/StoredBoolean';
import { Revert } from '@btc-vision/btc-runtime/runtime/types/Revert';
import { EMPTY_POINTER } from '@btc-vision/btc-runtime/runtime/math/bytes';
import { ADDRESS_BYTE_LENGTH } from '@btc-vision/btc-runtime/runtime/utils';
import { UpdatablePlugin } from '@btc-vision/btc-runtime/runtime/plugins/UpdatablePlugin';
import {
    BridgeDepositoryUpdated,
    GovernorUpdated,
    BurnedForRelease,
    Paused,
    Unpaused,
} from './events';

/**
 * WrappedOP20 — canonical wrapped representation of an EVM asset on OPNet.
 *
 * Deployed twice (wUSDC and wUSDT). 6 decimals to match USDC/USDT.
 *
 * Extends OP20S so MotoSwap's stablecoin pools can read a 1:1 USD peg rate
 * (`pegRate()` = 1e8). Peg authority = governor (same deployer) and must
 * heartbeat `updatePegRate` within `maxStaleness` blocks (default 1008 ≈ 7d).
 * Bridge redemptions are NOT gated on peg freshness — voucher correctness is
 * orthogonal to the oracle.
 *
 * Mint is gated: only `_bridgeDepository` can call `mintTo`. The depository
 * in turn only mints when a valid ML-DSA voucher was produced by the
 * current-epoch bridge signer.
 *
 * Burn is user-initiated: `burnForRelease(ethRecipient, amount, destChainId)`
 * performs a real OP20 burn and emits `BurnedForRelease` so the EVM indexer
 * can issue a release voucher against the EVM escrow.
 *
 * STORAGE IS APPEND-ONLY. `_storageVersion` is declared FIRST so its slot id
 * is pinned; every field below it may never be reordered, deleted, or retyped.
 * Only append new fields to the end of this class. See workspace CLAUDE.md
 * "Five Upgrade Commandments".
 */
@final
export class WrappedOP20 extends OP20S {
    // ─── STORAGE VERSION — MUST BE FIRST FIELD (append-only invariant) ──
    private _storageVersion: StoredU256 = new StoredU256(
        Blockchain.nextPointer,
        EMPTY_POINTER,
    );

    // ─── Core references ─────────────────────────────────────────────────
    private _bridgeDepository: StoredAddress = new StoredAddress(Blockchain.nextPointer);
    private _governor: StoredAddress = new StoredAddress(Blockchain.nextPointer);

    // ─── Monotonic burn nonce (per-burn unique id) ───────────────────────
    private _burnNonce: StoredU256 = new StoredU256(Blockchain.nextPointer, EMPTY_POINTER);

    // ─── Pause flag (Fix #6 — governor can halt burnForRelease so incident
    //     response can stop new EVM release liabilities from accruing while
    //     BridgeDepository is also paused) ───────────────────────────────
    // Declared last to preserve append-only storage discipline.
    private _paused: StoredBoolean = new StoredBoolean(Blockchain.nextPointer, false);

    public constructor() {
        super();

        // Phase 2.2 — 7-day upgrade timelock (1008 blocks ≈ 7 days at
        // 10 min/block). Matches BridgeDepository.ts; gives users a full
        // week to exit before any upgrade lands.
        // Registered last in the constructor body so its 2 storage pointers
        // append after every previously declared slot, preserving
        // append-only discipline for future upgrades.
        this.registerPlugin(new UpdatablePlugin(1008));
    }

    public override onDeployment(calldata: Calldata): void {
        super.onDeployment(calldata);

        // Accept token metadata + peg config from calldata so the same
        // bytecode deploys both wUSDC and wUSDT. Regtest may send empty
        // calldata on first deployment — in that case fall back to a generic
        // placeholder + 1:1 peg defaults.
        //
        // Layout:
        //   name           stringU32
        //   symbol         stringU32
        //   decimals       u8
        //   maxSupply      u256
        //   initialPegRate u256    (OP20S — 1:1 USD = 1e8)
        //   maxStaleness   u64     (OP20S — blocks before isStale())
        //
        // Peg authority is ALWAYS the deployer (also governor). Rotate later
        // via transferPegAuthority + acceptPegAuthority if needed.
        let maxSupply: u256 = u256.fromString('1000000000000000000000000'); // 1e24 (soft cap, per-asset)
        let decimals: u8 = 6;
        let name: string = 'Wrapped Bridge Token';
        let symbol: string = 'wBRIDGE';
        let initialPegRate: u256 = u256.fromU64(100_000_000); // 1:1 USD, 8 decimals
        let maxStaleness: u64 = 1008; // ~7 days of Bitcoin blocks

        if (calldata.byteLength >= 2) {
            name = calldata.readStringWithLength();
            symbol = calldata.readStringWithLength();
            decimals = calldata.readU8();
            maxSupply = calldata.readU256();
            // Peg params are optional in calldata for backward compat with
            // older deploy scripts — if the buffer is exhausted we keep the
            // defaults above.
            if (calldata.byteLength - calldata.getOffset() >= 32) {
                initialPegRate = calldata.readU256();
            }
            if (calldata.byteLength - calldata.getOffset() >= 8) {
                maxStaleness = calldata.readU64();
            }
        }

        this.instantiate(new OP20InitParameters(maxSupply, decimals, name, symbol));

        // Deployer is the initial governor AND the initial peg authority.
        // They can re-point the bridge depository, transfer governance, and
        // transfer/renounce peg authority later.
        this._governor.value = Blockchain.tx.sender;
        this.initializePeg(Blockchain.tx.sender, initialPegRate, maxStaleness);

        // Storage version 2 for fresh v2 (OP20S) deployments.
        this._storageVersion.value = u256.fromU32(2);
    }

    public override onUpdate(calldata: Calldata): void {
        super.onUpdate(calldata);

        this.onlyDeployer(Blockchain.tx.sender);

        // Append-only migrations gated by _storageVersion. Each branch bumps
        // the version so a contract upgraded across multiple hops doesn't
        // skip a migration, and each branch runs at most once.
        const version = this._storageVersion.value;
        if (u256.lt(version, u256.fromU32(2))) {
            // v1 → v2 reserved slot; no data backfill today.
            this._storageVersion.value = u256.fromU32(2);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Access control
    // ═══════════════════════════════════════════════════════════════════════

    private onlyGovernor(): void {
        const gov = this._governor.value;
        if (gov.isZero()) {
            throw new Revert('WrappedOP20: governor not set');
        }
        if (!Blockchain.tx.sender.equals(gov)) {
            throw new Revert('WrappedOP20: not governor');
        }
    }

    private onlyBridge(): void {
        const bridge = this._bridgeDepository.value;
        if (bridge.isZero()) {
            throw new Revert('WrappedOP20: bridge not set');
        }
        if (!Blockchain.tx.sender.equals(bridge)) {
            throw new Revert('WrappedOP20: not bridge');
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor methods
    // ═══════════════════════════════════════════════════════════════════════

    @method({ name: 'newBridge', type: ABIDataTypes.ADDRESS })
    @emit('BridgeDepositoryUpdated')
    public setBridgeDepository(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const newBridge: Address = calldata.readAddress();
        if (newBridge.isZero()) {
            throw new Revert('WrappedOP20: zero bridge');
        }
        const old = this._bridgeDepository.value;
        this._bridgeDepository.value = newBridge;
        this.emitEvent(new BridgeDepositoryUpdated(old, newBridge));
        return new BytesWriter(0);
    }

    @method({ name: 'newGovernor', type: ABIDataTypes.ADDRESS })
    @emit('GovernorUpdated')
    public setGovernor(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const newGovernor: Address = calldata.readAddress();
        if (newGovernor.isZero()) {
            throw new Revert('WrappedOP20: zero governor');
        }
        const old = this._governor.value;
        this._governor.value = newGovernor;
        this.emitEvent(new GovernorUpdated(old, newGovernor));
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Governor: pause (Fix #6 — gate burnForRelease)
    // ═══════════════════════════════════════════════════════════════════════

    @method({ name: 'paused', type: ABIDataTypes.BOOL })
    @emit('Paused', 'Unpaused')
    public setPaused(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const paused: boolean = calldata.readBoolean();
        this._paused.value = paused;
        if (paused) {
            this.emitEvent(new Paused());
        } else {
            this.emitEvent(new Unpaused());
        }
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Mint (bridge-only)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Mint wrapped tokens. Only the registered BridgeDepository may call.
     * The depository verifies an ML-DSA voucher before issuing this call.
     */
    @method(
        { name: 'to', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
    )
    @emit('Minted')
    public mintTo(calldata: Calldata): BytesWriter {
        this.onlyBridge();
        const to: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();
        if (to.isZero()) {
            throw new Revert('WrappedOP20: mint to zero');
        }
        if (amount.isZero()) {
            throw new Revert('WrappedOP20: zero amount');
        }
        this._mint(to, amount);
        return new BytesWriter(0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Burn for release (user-initiated OPNet → EVM)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Burn caller's wrapped tokens and emit BurnedForRelease. The EVM-side
     * indexer picks up the event, the server signs an EIP-712 release
     * message, and the user claims the underlying asset on the EVM escrow.
     *
     * `ethRecipient` is 32 bytes — future-proof for non-EVM destinations
     * (Solana/Cosmos/Polkadot recipients are 32 bytes). For EVM destinations
     * the caller left-pads the 20-byte address with 12 zero bytes; the
     * server extracts the low 20 bytes when building EIP-712. For the
     * EVM-family destChainIds (Ethereum mainnet and Sepolia) we enforce
     * that the high 12 bytes are zero so a malformed EVM recipient cannot
     * round-trip with non-zero padding.
     *
     * `burnNonce` is a monotonic counter on this contract so every burn is
     * uniquely identifiable even when the same user burns the same amount
     * to the same recipient repeatedly.
     */
    @method(
        { name: 'ethRecipient', type: ABIDataTypes.BYTES32 },
        { name: 'amount', type: ABIDataTypes.UINT256 },
        { name: 'destChainId', type: ABIDataTypes.UINT32 },
    )
    @emit('BurnedForRelease')
    public burnForRelease(calldata: Calldata): BytesWriter {
        // Fix #6 — honour the same pause switch as BridgeDepository so
        // incident response can halt new EVM release liabilities while the
        // mint side is also paused.
        if (this._paused.value) {
            throw new Revert('WrappedOP20: paused');
        }

        // BYTES32 is encoded as 32 raw bytes with no length prefix.
        const ethRecipient: Uint8Array = calldata.readBytes(32);
        const amount: u256 = calldata.readU256();
        const destChainId: u32 = calldata.readU32();

        if (ethRecipient.length != 32) {
            throw new Revert('WrappedOP20: ethRecipient must be 32 bytes');
        }
        if (amount.isZero()) {
            throw new Revert('WrappedOP20: zero amount');
        }
        if (destChainId == 0) {
            throw new Revert('WrappedOP20: zero destChainId');
        }

        // EVM-family padding check: for Ethereum mainnet (1) and Sepolia
        // (11155111), the high 12 bytes of the 32-byte recipient must be
        // zero so the low 20 bytes form a valid 20-byte address the server
        // can lift into EIP-712.
        if (destChainId == 1 || destChainId == 11155111) {
            for (let i: i32 = 0; i < 12; i++) {
                if (ethRecipient[i] != 0) {
                    throw new Revert('WrappedOP20: EVM recipient upper 12 bytes must be zero');
                }
            }
        }

        // CEI — update state (burn + nonce bump) before emitting.
        const user: Address = Blockchain.tx.sender;
        this._burn(user, amount);

        const nextNonce: u256 = SafeMath.add(this._burnNonce.value, u256.One);
        this._burnNonce.value = nextNonce;

        this.emitEvent(new BurnedForRelease(user, amount, ethRecipient, destChainId, nextNonce));

        // Return burnNonce so tooling can link the tx to the EVM-side lookup.
        const writer = new BytesWriter(32);
        writer.writeU256(nextNonce);
        return writer;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Views
    // ═══════════════════════════════════════════════════════════════════════

    @view
    @returns({ name: 'depository', type: ABIDataTypes.ADDRESS })
    public bridgeDepository(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(ADDRESS_BYTE_LENGTH);
        response.writeAddress(this._bridgeDepository.value);
        return response;
    }

    @view
    @returns({ name: 'governor', type: ABIDataTypes.ADDRESS })
    public governor(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(ADDRESS_BYTE_LENGTH);
        response.writeAddress(this._governor.value);
        return response;
    }

    @view
    @returns({ name: 'burnNonce', type: ABIDataTypes.UINT256 })
    public burnNonce(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(32);
        response.writeU256(this._burnNonce.value);
        return response;
    }

    @view
    @returns({ name: 'storageVersion', type: ABIDataTypes.UINT256 })
    public storageVersion(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(32);
        response.writeU256(this._storageVersion.value);
        return response;
    }

    @view
    @returns({ name: 'paused', type: ABIDataTypes.BOOL })
    public paused(_calldata: Calldata): BytesWriter {
        const response = new BytesWriter(1);
        response.writeBoolean(this._paused.value);
        return response;
    }
}
