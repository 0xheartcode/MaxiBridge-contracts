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
import { StoredMapU256 } from '@btc-vision/btc-runtime/runtime/storage/maps/StoredMapU256';
import { Revert } from '@btc-vision/btc-runtime/runtime/types/Revert';
import { EMPTY_POINTER } from '@btc-vision/btc-runtime/runtime/math/bytes';
import { ADDRESS_BYTE_LENGTH } from '@btc-vision/btc-runtime/runtime/utils';
import { sha256 } from '@btc-vision/btc-runtime/runtime/env/global';
import {
    AuthorityAddressSet,
    BridgeDepositoryUpdated,
    GovernorUpdated,
    MinterGranted,
    MinterRevoked,
    BurnedForRelease,
    Paused,
    Unpaused,
    SupportedDestChainSet,
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
 * Burn is user-initiated: `burnForRelease(flowId, ethRecipient, amount, destChainId)`
 * performs a real OP20 burn and emits `BurnedForRelease` so the EVM indexer
 * can issue a release voucher against the EVM escrow.
 *
 * NON-UPGRADEABLE. `UpdatablePlugin` is intentionally NOT registered. Wrapped
 * tokens are the canonical user-facing representation of every deposit — the
 * largest blast-radius surface in the bridge — so they ship as immutable code
 * rather than carrying an upgrade hook. Operational repointing flows through
 * `setBridgeDepository` and the explicit minter set; if a real flaw is ever
 * found, the response is a fresh wrapper deploy + governance pivot of the
 * depository's minter set, not an in-place upgrade. (`_storageVersion` and
 * the historical append-only discipline below remain so the storage layout
 * stays auditable, even though no upgrade can rewrite it.)
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
    private _paused: StoredBoolean = new StoredBoolean(Blockchain.nextPointer, false);

    // ─── Minter role separation ──────────────────────────────────────────
    // Phase 1.2 — replaces the single-bridge `onlyBridge()` gate with a
    // per-address minter set so BridgeAuthority can grant/revoke mint
    // authority without re-pointing `_bridgeDepository`. The legacy
    // `_bridgeDepository` slot is preserved as an IMPLICIT minter for
    // backward compat — anything wired via `setBridgeDepository` retains
    // mint authority without an explicit `grantMinter` call.
    //
    // _minters: sha256(addr) → u256.One when authorized.
    private _minters: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);
    // BridgeAuthority address allowed to grant/revoke minters in addition
    // to the governor. Set via `setAuthorityAddress`. Zero by default.
    private _authorityAddress: StoredAddress = new StoredAddress(Blockchain.nextPointer);

    // M-01 — supported burn destinations. `burnForRelease(destChainId)` is
    // permissionless; without this allowlist a user could burn to a chain
    // the bridge does not service, destroying tokens with no release voucher
    // and no refund path. Keyed by destChainId (u256), value u256.One when
    // enabled. Governor-set; fail-closed — empty until the deploy ceremony
    // calls `setSupportedDestChain` for each serviced chain.
    private _supportedDestChains: StoredMapU256 = new StoredMapU256(Blockchain.nextPointer);

    public constructor() {
        super();

        // wUSDC/wUSDT are intentionally NON-UPGRADEABLE. Wrapped tokens are
        // the largest blast-radius surface in the bridge — the canonical
        // representation of every user's deposit — so we trade upgrade
        // flexibility for verifiable immutability. Operational repointing
        // (e.g. swapping the BridgeDepository the wrapper trusts as minter)
        // is handled via `setBridgeDepository(address)` and the minter set,
        // both governance-gated. Industry precedent: Circle CCTP, tBTC
        // vending machines, and the canonical Optimism bridge wrapped
        // tokens are all non-upgradeable for the same reason.
        //
        // Do NOT register `UpdatablePlugin` here. If a flaw is ever found in
        // wUSDC/wUSDT, the response is a fresh wrapper deploy + governance
        // pivot of the depository's minter set, not an in-place upgrade.
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
        // Uncapped by default — u256 max. maxSupply is an OP20-mandated field
        // (a NON-binding sanity ceiling, NOT the supply control). The real,
        // governance-raisable per-token ceiling is the per-flow `cap` on the
        // bridge. The deploy script may override this via calldata if a hard
        // token-level cap is genuinely wanted for a fixed-supply asset.
        let maxSupply: u256 = u256.Max;
        let decimals: u8 = 18; // OP20 standard default; stablecoins pass 6 via calldata
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

    /**
     * Phase 1.2 — `mintTo` access gate. Accepts:
     *   - the legacy `_bridgeDepository` (backward compat — anything wired
     *     via `setBridgeDepository` retains mint authority without an
     *     explicit `grantMinter` call);
     *   - any address explicitly added to `_minters` via `grantMinter`.
     *
     * The governor is NOT a minter by default — minting is a privileged
     * operation that the governor delegates to the BridgeDepository (and
     * any future depository the BridgeAuthority hands a minter role to)
     * but does not perform itself.
     */
    private onlyMinter(): void {
        const sender = Blockchain.tx.sender;

        // Legacy bridge fallback.
        const bridge = this._bridgeDepository.value;
        if (!bridge.isZero() && sender.equals(bridge)) return;

        // Explicit minter set.
        if (!this._minters.get(_minterKey(sender)).isZero()) return;

        throw new Revert('WrappedOP20: not minter');
    }

    /**
     * Either the governor OR the registered BridgeAuthority may grant /
     * revoke minters. Helper centralises the check.
     */
    private onlyGovernorOrAuthority(): void {
        const sender = Blockchain.tx.sender;
        const gov = this._governor.value;
        if (!gov.isZero() && sender.equals(gov)) return;
        const auth = this._authorityAddress.value;
        if (!auth.isZero() && sender.equals(auth)) return;
        throw new Revert('WrappedOP20: not governor or authority');
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
    //  Phase 1.2 — minter role + authority address
    // ═══════════════════════════════════════════════════════════════════════

    @method({ name: 'authority', type: ABIDataTypes.ADDRESS })
    @emit('AuthorityAddressSet')
    public setAuthorityAddress(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const newAuth: Address = calldata.readAddress();
        this._authorityAddress.value = newAuth;
        this.emitEvent(new AuthorityAddressSet(newAuth));
        return new BytesWriter(0);
    }

    @method({ name: 'minter', type: ABIDataTypes.ADDRESS })
    @emit('MinterGranted')
    public grantMinter(calldata: Calldata): BytesWriter {
        this.onlyGovernorOrAuthority();
        const minter: Address = calldata.readAddress();
        if (minter.isZero()) {
            throw new Revert('WrappedOP20: zero minter');
        }
        this._minters.set(_minterKey(minter), u256.One);
        this.emitEvent(new MinterGranted(minter));
        return new BytesWriter(0);
    }

    @method({ name: 'minter', type: ABIDataTypes.ADDRESS })
    @emit('MinterRevoked')
    public revokeMinter(calldata: Calldata): BytesWriter {
        this.onlyGovernorOrAuthority();
        const minter: Address = calldata.readAddress();
        this._minters.set(_minterKey(minter), u256.Zero);
        this.emitEvent(new MinterRevoked(minter));
        return new BytesWriter(0);
    }

    @view
    @returns({ name: 'authorized', type: ABIDataTypes.BOOL })
    public isMinter(calldata: Calldata): BytesWriter {
        const addr: Address = calldata.readAddress();
        const r = new BytesWriter(1);
        // Legacy bridge OR explicit minter set membership.
        const bridge = this._bridgeDepository.value;
        const isLegacyBridge = !bridge.isZero() && addr.equals(bridge);
        const isExplicit = !this._minters.get(_minterKey(addr)).isZero();
        r.writeBoolean(isLegacyBridge || isExplicit);
        return r;
    }

    @view
    @returns({ name: 'authority', type: ABIDataTypes.ADDRESS })
    public authorityAddress(_calldata: Calldata): BytesWriter {
        const r = new BytesWriter(ADDRESS_BYTE_LENGTH);
        r.writeAddress(this._authorityAddress.value);
        return r;
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
    //  Governor: supported burn destinations (M-01)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Enable or disable a burn destination chain. `burnForRelease` rejects
     * any destChainId not enabled here. Fail-closed: a fresh deploy has no
     * enabled destinations until the governor adds them.
     */
    @method(
        { name: 'destChainId', type: ABIDataTypes.UINT32 },
        { name: 'enabled', type: ABIDataTypes.BOOL },
        { name: 'isEvmFamily', type: ABIDataTypes.BOOL },
    )
    @emit('SupportedDestChainSet')
    public setSupportedDestChain(calldata: Calldata): BytesWriter {
        this.onlyGovernor();
        const destChainId: u32 = calldata.readU32();
        if (destChainId == 0) {
            throw new Revert('WrappedOP20: zero destChainId');
        }
        const enabled: boolean = calldata.readBoolean();
        // LOW-2 — EVM-family is a per-chain GOVERNANCE flag, not a hardcoded
        // chainId list, so `burnForRelease`'s 20-byte-address padding check can
        // never drift when a new EVM chain is serviced. This is essential
        // because the token is NON-UPGRADEABLE: a hardcoded list could never be
        // extended to a new EVM chain without redeploying the whole wrapper.
        // Stored marker: 0 = disabled, 1 = enabled non-EVM (32-byte native
        // recipient), 2 = enabled EVM-family (recipient is a 20-byte address,
        // high 12 bytes must be zero). Forcing the flag at enable time is
        // fail-safe — a chain can't be enabled without deciding its encoding.
        const isEvmFamily: boolean = calldata.readBoolean();
        let stored: u256 = u256.Zero;
        if (enabled) {
            stored = isEvmFamily ? u256.fromU32(2) : u256.One;
        }
        this._supportedDestChains.set(u256.fromU32(destChainId), stored);
        this.emitEvent(new SupportedDestChainSet(destChainId, enabled));
        return new BytesWriter(0);
    }

    @view
    @returns({ name: 'supported', type: ABIDataTypes.BOOL })
    public isSupportedDestChain(calldata: Calldata): BytesWriter {
        const destChainId: u32 = calldata.readU32();
        const r = new BytesWriter(1);
        r.writeBoolean(!this._supportedDestChains.get(u256.fromU32(destChainId)).isZero());
        return r;
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
        this.onlyMinter();
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
    //
    // #68 Tier C — `flowId` is the FIRST param so a burn names which flow /
    // route it is for (the burn-initiated counterpart of the deposit-side
    // flowId). The token does NOT know the flow registry, so it only RECORDS
    // flowId in the event — flow validation happens at claim time on
    // BridgeDepository via the Tier B `_flowOpnetToken[flowId]` binding.
    //
    // ⚠️ IMMUTABILITY: WrappedOP20 is intentionally NON-UPGRADEABLE (no
    // UpdatablePlugin). Changing this signature changes the `burnForRelease`
    // selector (was 0x1d40b843) AND the `BurnedForRelease` event layout. On
    // MAINNET this is NOT an in-place upgrade — it requires a FRESH wrapped-
    // token DEPLOY + holder migration + re-audit. Only free to change on
    // testnet (redeploy). Do not change this signature lightly.
    @method(
        { name: 'flowId', type: ABIDataTypes.UINT256 },
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

        // #68 Tier C — flowId read FIRST (recorded, not validated here).
        const flowId: u256 = calldata.readU256();
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
        // M-01 — only allow burns to a destination the bridge services.
        // A burn to an unsupported chain would destroy tokens with no
        // release voucher ever signed and no on-chain refund path.
        const destEntry: u256 = this._supportedDestChains.get(u256.fromU32(destChainId));
        if (destEntry.isZero()) {
            throw new Revert('WrappedOP20: unsupported destChainId');
        }

        // LOW-2 — padding is gated on the per-chain EVM-family marker (== 2),
        // NOT a hardcoded chainId list, so it can never drift when a new EVM
        // chain is enabled. For an EVM-family destination the 32-byte recipient
        // is a 20-byte address: the high 12 bytes MUST be zero so the server can
        // lift the low 20 into EIP-712. Non-EVM destinations (marker == 1) carry
        // a full 32-byte native recipient and impose no padding constraint.
        if (destEntry == u256.fromU32(2)) {
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

        this.emitEvent(
            new BurnedForRelease(user, amount, ethRecipient, destChainId, nextNonce, flowId),
        );

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

/**
 * sha256 hash of a 32-byte address — used as the StoredMapU256 key for
 * `_minters[addr]`. Module-level so the @final class doesn't have to
 * carry it as an instance method.
 */
function _minterKey(addr: Address): u256 {
    const buf = new BytesWriter(32);
    buf.writeAddress(addr);
    return u256.fromUint8ArrayBE(sha256(buf.getBuffer()));
}
