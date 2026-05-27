// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IVestingVault} from "./IVestingVault.sol";

/// @notice Minimal interface for the bridge-issued WrappedERC20 (modes
///         INVERSE_WRAPPED + NATIVE_BURN_MINT). Defined here so the
///         escrow doesn't need to import the concrete contract.
interface IWrappedERC20 {
    function mintFromBridge(address to, uint256 amount) external;
}

/// @title BridgeEscrow (v2 — no legacy)
/// @notice UUPS upgradeable EVM side of the OPNet bridge.
///         Users `lock()` USDC/USDT to bridge to OPNet; the off-chain
///         M-of-N signer set issues an EIP-712 ReleaseIntent that anyone
///         can submit via `claim()`.
/// @dev The legacy single-sig storage slot was dropped before the first
///      production deploy — there is no `signer` field, no
///      `migrateToMofN()` shim, and no dual-sig acceptance path. Every
///      `claim()` requires the length-prefixed M-of-N blob format
///      `[uint8 numSigs][sig_0(65)][sig_1(65)]…`. A 1-of-1 deploy uses
///      `numSigs=1` (66-byte blob).
contract BridgeEscrow is
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    EIP712Upgradeable
{
    using SafeERC20 for IERC20;

    // ---------------------------------------------------------------------
    // EIP-712 type — LOCKED (typehash + struct field order both fixed)
    // ---------------------------------------------------------------------

    struct ReleaseIntent {
        address token;
        address to;
        uint256 amount;
        uint256 srcChainId;
        bytes32 opnetTxHash;
        uint32 opnetEventIndex;
        uint256 burnNonce;
        uint32 signerEpoch;
        bytes32 opnetNonce;
        // PR β.2.format — source-side gross input (pre fee, pre decimal scale).
        // Signed over but not yet enforced beyond the signature check.
        uint256 grossSrcAmount;
        // PR β.2.format — permissionless relayer tip in destination units.
        // uint128 caps the tip below 2^128 — way more than any token supply.
        // PR β.2.payout-evm: paid to msg.sender when > 0, capped per-flow.
        uint128 relayerTip;
        // PR β.2.payout-evm — flow binding. The voucher commits to a
        // specific flowId; claim looks it up to enforce status + per-flow
        // tipCapBps and emit a flow-tagged tip event.
        bytes32 flowId;
    }

    /// @dev keccak256("ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce,uint256 grossSrcAmount,uint128 relayerTip,bytes32 flowId)")
    bytes32 public constant RELEASE_INTENT_TYPEHASH =
        keccak256(
            "ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce,uint256 grossSrcAmount,uint128 relayerTip,bytes32 flowId)"
        );

    /// @notice EIP-712 type for mode-2/3 mints. Differs from ReleaseIntent
    ///         only by the `wrappedToken` field — binds the mint to a
    ///         specific WrappedERC20 contract so a sig signed for one
    ///         wrapped can't be replayed against a different wrapped.
    struct MintIntent {
        address wrappedToken;   // WrappedERC20 contract to mint into
        address to;             // recipient on EVM
        uint256 amount;         // net amount to mint
        uint256 srcChainId;     // OPNet network id (1=mainnet, 2=testnet)
        bytes32 opnetTxHash;
        uint32 opnetEventIndex;
        uint256 burnNonce;      // OPNet burn nonce (mode 3) or lock nonce (mode 2)
        uint32 signerEpoch;
        bytes32 opnetNonce;
        bytes32 flowId;         // PR β.2.payout-evm++ — flow binding for mode-dispatch
    }

    /// @dev keccak256("MintIntent(address wrappedToken,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce,bytes32 flowId)")
    bytes32 public constant MINT_INTENT_TYPEHASH =
        keccak256(
            "MintIntent(address wrappedToken,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce,bytes32 flowId)"
        );

    /// @notice EIP-712 type for the M-of-N refund attestation. Authorizes
    ///         `refundLockedDeposit` for ONE specific `depositNonce`. The
    ///         bridge authority signs this only after confirming the OPNet
    ///         voucher for that deposit was cancelled on `BridgeDepository`
    ///         and can never mint.
    /// @dev    CRIT-001 fix: a refund must be gated by a positive no-mint
    ///         attestation, never by the mere absence of a refunded flag.
    struct RefundAuthorization {
        uint256 depositNonce;
        bytes32 flowId;
        uint32 signerEpoch;
    }

    /// @dev keccak256("RefundAuthorization(uint256 depositNonce,bytes32 flowId,uint32 signerEpoch)")
    bytes32 public constant REFUND_AUTHORIZATION_TYPEHASH =
        keccak256(
            "RefundAuthorization(uint256 depositNonce,bytes32 flowId,uint32 signerEpoch)"
        );

    /// @notice EIP-712 type for the M-of-N burn-refund attestation (#55
    ///         EVM-side symmetric counterpart to OPNet `refundBurn`).
    ///         Authorizes `refundBurn` to RE-MINT a burned `WrappedERC20`
    ///         amount back to the original burner when that burn's OPNet
    ///         destination voucher was PERMANENTLY cancelled (reorg/fraud),
    ///         leaving the tokens destroyed with no release path.
    /// @dev    MINT-AUTHORITY PRIMITIVE. Trust model == vouchers: the SAME
    ///         M-of-N signer set attests off-chain that the burn is final
    ///         AND the OPNet destination is cancelled-and-final. Every
    ///         binding field lives inside the signed struct, so tampering
    ///         (amount / burner / token / flowId / epoch / nonce / txHash)
    ///         fails the EIP-712 digest recover → NO mint. `burnBlockHash`
    ///         is the reorg guard: opaque to the contract, but signed so a
    ///         stale-block attestation can't be reused after a reorg.
    struct BurnRefundAuthorization {
        address burner;          // original burner — the re-mint recipient
        address wrappedToken;    // WrappedERC20 to re-mint (bridge-mintable)
        uint256 amount;          // burned amount to re-mint (signer-attested)
        uint256 burnNonce;       // burn nonce from the BurnedForRelease event
        bytes32 burnTxHash;      // the EVM burn tx hash (binding + replay key)
        bytes32 burnBlockHash;   // reorg guard — opaque, but inside the struct
        bytes32 flowId;          // route binding; flow.evmToken must == wrappedToken
        uint32  signerEpoch;     // MUST equal currentEpoch
    }

    /// @dev keccak256("BurnRefundAuthorization(address burner,address wrappedToken,uint256 amount,uint256 burnNonce,bytes32 burnTxHash,bytes32 burnBlockHash,bytes32 flowId,uint32 signerEpoch)")
    bytes32 public constant BURN_REFUND_AUTHORIZATION_TYPEHASH =
        keccak256(
            "BurnRefundAuthorization(address burner,address wrappedToken,uint256 amount,uint256 burnNonce,bytes32 burnTxHash,bytes32 burnBlockHash,bytes32 flowId,uint32 signerEpoch)"
        );

    /// @notice Token bridging mode — set per token at registration time.
    ///         Once set, can never be changed for that token (set-once).
    ///
    ///         WRAPPED              — canonical token lives on EVM (USDC/USDT
    ///                                today). Lock on EVM, mint wrapped on
    ///                                OPNet. Default for legacy tokens.
    ///         INVERSE_WRAPPED      — canonical token lives on OPNet
    ///                                (project-issued OP20). Mint wrapped on
    ///                                EVM via this contract; lock canonical
    ///                                on OPNet via BridgeDepository.
    ///         NATIVE_BURN_MINT     — bridge is canonical issuer on BOTH
    ///                                chains. Burn on source, mint on
    ///                                destination. No reserves. Total
    ///                                supply across chains is conserved.
    ///         POOLED_LOCK_RELEASE  — neither side mints. Real assets exist on
    ///                                both chains; team provides initial
    ///                                inventory via `provisionInventory`,
    ///                                user-side flows top up / draw down
    ///                                that pool. Use case: project-issued
    ///                                tokens (e.g. MOTO) where the bridge
    ///                                does NOT have minter authority but
    ///                                the project pre-funds bidirectional
    ///                                inventory. Reuses the same `lock` +
    ///                                `claim` paths as WRAPPED — only the
    ///                                source of balance differs (user lock
    ///                                vs governor provisioning).
    enum TokenMode {
        WRAPPED,
        INVERSE_WRAPPED,
        NATIVE_BURN_MINT,
        POOLED_LOCK_RELEASE,
        // Mode 4 — same source/lock semantics as POOLED_LOCK_RELEASE, but on
        // the EVM `claim` path the release is deposited into a per-flow
        // VestingVault that linearly drips to the beneficiary over a fixed
        // block window (e.g. 7 days). The beneficiary then `claim`s accrued
        // portions from the vault at their own cadence. OPNet release leg
        // (for the EVM→OPNet direction) is unchanged from mode 3.
        POOLED_LOCK_VEST
    }

    /// @notice Hard cap on `unwrapFeeBps`. 1000 = 10%. A hostile or
    ///         compromised governor cannot set the bridge fee higher than
    ///         this — protects users from being effectively trapped.
    uint256 public constant MAX_FEE_BPS = 1000;

    /// @notice Hard cap on per-flow `tipCapBps`. 200 = 2%. Bounds the
    ///         permissionless relayer tip a flow can be configured to pay
    ///         out (PR β.2). Default per-flow tipCapBps is 0 — tipping
    ///         disabled until governance sets it.
    uint256 public constant MAX_TIP_BPS = 200;

    // ---------------------------------------------------------------------
    // Flow Registry (PR α — storage + governance only; consumed by PR γ)
    // ---------------------------------------------------------------------

    /// @notice Per-flow status. A flow is the smallest atom of bridge
    ///         routing — defined by (mode, evmChainId, evmBridge, evmToken,
    ///         opnetBridge, opnetToken). Vouchers are validated against
    ///         the flow's status before any inventory mutation in PR γ.
    ///
    ///         disabled  — flow does not exist OR has been retired
    ///         active    — vouchers and locks accepted normally
    ///         paused    — guardian-set protective freeze; can resume
    ///         draining  — governor-set; only release/burn (no new
    ///                     locks/mints) — used to wind a route down
    uint8 public constant FLOW_STATUS_DISABLED = 0;
    uint8 public constant FLOW_STATUS_ACTIVE = 1;
    uint8 public constant FLOW_STATUS_PAUSED = 2;
    uint8 public constant FLOW_STATUS_DRAINING = 3;

    /// @notice Rolling-window length for per-flow `dailyLimit`. 24 hours.
    ///         Hard-coded so a hostile governor cannot disable rate
    ///         limiting by setting it absurdly long.
    uint64 public constant FLOW_WINDOW_DURATION = 86400;

    /// @notice First-class object representing a single bridging route.
    ///         All fields except status / cap / dailyLimit / minAmount /
    ///         feeBps / minFee / mintedToday / lastWindowStart / inventory
    ///         are immutable once `addFlow` lands — set-once on add.
    ///
    ///         flowId = sha256(abi.encodePacked(
    ///             mode, evmChainId, evmBridge, evmToken,
    ///             opnetBridge, opnetToken
    ///         ))
    ///         The same flowId is computed identically on the OPNet side
    ///         (same sha256 over the same canonical byte order). EVM→OPNet
    ///         and OPNet→EVM legs of the same route share the same flowId.
    struct FlowRecord {
        // Set-once at addFlow:
        uint8   mode;             // 0=WRAPPED, 1=INVERSE_WRAPPED, 2=NATIVE_BURN_MINT, 3=POOLED_LOCK_RELEASE, 4=POOLED_LOCK_VEST
        uint8   status;           // see FLOW_STATUS_* above
        uint64  evmChainId;
        address evmBridge;        // BridgeEscrow proxy on the EVM source chain
        address evmToken;
        uint8   evmDecimals;
        uint8   opnetDecimals;
        bytes32 opnetBridge;      // 32-byte canonical OPNet address
        bytes32 opnetToken;
        // Mutable via timelocked governance:
        uint16  feeBps;           // 0..MAX_FEE_BPS
        uint128 minFee;           // dst-side base units
        uint128 minAmount;        // src-side base units
        uint128 cap;              // total inventory ceiling (mode 0/3/4) or mint ceiling (mode 2)
        uint128 dailyLimit;       // per-flow rolling window
        // Hot fields written by claim/release in PR γ:
        uint128 mintedToday;
        uint64  lastWindowStart;
        uint128 inventory;        // mode 0/3/4: locked tokens; mode 2: synthetic supply
        // PR β.2 — per-flow permissionless relayer tip cap.
        // 0 = tipping disabled (default); cap is per-flow,
        // ≤ MAX_TIP_BPS = 200 (2%); governor-set.
        uint16  tipCapBps;
        // Mode 4 (POOLED_LOCK_VEST) destination vault. Required iff
        // `mode == POOLED_LOCK_VEST`; address(0) for every other mode. On
        // claim, the bridge approves and calls `depositFor` on this vault
        // instead of `safeTransfer`ing directly to the recipient. Governor-
        // repointable via `setFlowVestingVault` (restricted to mode 4).
        address vestingVault;
        // Per-flow accumulated source-side bridge fees (EVM-lock direction).
        // Incremented on each `lock` by exactly the computed fee portion;
        // withdrawn (treasury-only) via `withdrawFees`. This is the entire
        // safety bound for routine fee collection — `withdrawFees` can NEVER
        // exceed this accumulator, so it can never touch user-locked
        // principal or another flow's reserves. Struct-field append (the
        // struct lives in a mapping) — does NOT consume a top-level storage
        // slot, so the `uint256[42] __gap` is unaffected.
        uint128 accruedFees;
    }

    // ---------------------------------------------------------------------
    // Storage layout (clean — append-only from here on)
    // ---------------------------------------------------------------------

    /// @notice Current signer-set epoch. Incremented on `removeSigner` and
    ///         `setThreshold`; vouchers signed under the old epoch stop
    ///         verifying immediately.
    uint32 public currentEpoch;

    /// @notice Monotonic deposit nonce; incremented per `lock`.
    uint256 public depositNonce;

    /// @notice Token allowlist.
    mapping(address => bool) public supportedToken;

    /// @notice opnetNonce → used. Per-voucher replay guard.
    mapping(bytes32 => bool) public signaturesUsed;

    /// @notice (opnetTxHash, opnetEventIndex) → used. Composite source-event replay guard.
    mapping(bytes32 => mapping(uint32 => bool)) public usedSourceEvent;

    /// @notice opnetNonce → cancelled. Tier-3 governance kill-switch.
    mapping(bytes32 => bool) public cancelledVouchers;

    /// @notice OPNet source-chain network id (1=mainnet, 2=testnet).
    ///         Enforced on every `claim()`.
    uint256 public expectedOpnetChainId;

    /// @notice M-of-N signer set. address → isAuthorized.
    mapping(address => bool) public isSigner;

    /// @notice Number of authorized signers in `isSigner`.
    uint256 public signerCount;

    /// @notice Required number of distinct valid signatures to claim.
    uint256 public signerThreshold;

    /// @notice Guardian — gates `emergencyWithdraw` (alongside `whenPaused`)
    ///         and shares the incident-response surface (`pause`,
    ///         `cancelVoucher`, `removeSigner`, `migrateSignerSet`).
    /// @dev    Owner-rotatable via `setGuardian` (was set-once pre-roles PR).
    ///         On mainnet `owner` is the 3-day TimelockController, so guardian
    ///         rotation is timelock-gated — an instant-EOA owner reintroduces
    ///         the hot-key risk this role exists to mitigate. H-3 (audit
    ///         2026-05-27): consider a 2-step accept (`startGuardianTransfer`
    ///         + `acceptGuardian`) as a follow-up if EOA owners are ever used
    ///         in production — the timelock IS the staging mechanism today.
    address public guardian;

    /// @notice Destination for `emergencyWithdraw` drains.
    /// @dev    Owner-rotatable via `setTreasury` (was set-once pre-roles PR).
    ///         On mainnet `owner` is the 3-day TimelockController, so treasury
    ///         rotation is timelock-gated. H-3 (audit 2026-05-27): same 2-step
    ///         consideration as `guardian` above — the timelock provides the
    ///         3-day staging window for today's mainnet topology.
    address public treasury;

    /// @notice Unwrap fee, bps (1 bp = 0.01%). Charged on the OPNet→EVM
    ///         release leg ("unwrapping" wrapped tokens back to the
    ///         canonical asset). Default 0 — set by the governor via
    ///         `setUnwrapFeeBps`. Hard-capped at `MAX_FEE_BPS = 1000` (10%)
    ///         so a hostile or compromised governor cannot make the
    ///         bridge effectively un-redeemable.
    ///
    ///         The actual fee math runs server-side at sign time
    ///         (`computeFee(gross, bps, minFee)`) and is recorded as
    ///         `feeAmount` / `netAmount` in the EIP-712 release intent;
    ///         the contract is the source of truth for the bps value
    ///         and the server reads it before signing.
    uint256 public unwrapFeeBps;

    /// @notice Per-token minimum unwrap fee (token base units, 6 dec for
    ///         USDC/USDT). Whichever is higher between bps-derived and
    ///         minFee is taken. Default 0.
    mapping(address => uint256) public unwrapMinFee;

    // ─── Flow Registry storage (PR α — additive) ───────────────────────

    /// @notice Source of truth for all bridging routes. Keyed by `flowId`.
    /// @dev    Internal — public access goes through `getFlow(flowId)`.
    ///         Skipping the auto-generated public getter keeps the
    ///         compiler under its stack-depth limit (the struct has too
    ///         many fields to return as a flat tuple).
    mapping(bytes32 => FlowRecord) internal flows;

    /// @notice Enumeration: every registered flowId, append-only. Removing
    ///         a flow sets its status to disabled but does NOT delete from
    ///         this list (deletes confuse front-ends and audit trails).
    bytes32[] public allFlowIds;

    /// @notice Enumeration: flows by EVM-side token. Useful for the dApp
    ///         to discover which routes exist for a given token.
    mapping(address => bytes32[]) public flowsByEvmToken;

    /// @notice Enumeration: flows by mode. Operational view.
    mapping(uint8 => bytes32[]) public flowsByMode;

    /// @notice Enumeration: flows by source EVM chainId. When this
    ///         contract is deployed via CREATE2 to multiple EVM chains
    ///         under the same proxy address, each instance still tracks
    ///         only its own flows; this index is just a per-flow chain
    ///         tag for cross-chain admin tooling.
    mapping(uint64 => bytes32[]) public flowsByEvmChain;

    // ─── PR γ.2c — refund lifecycle storage ──────────────────────────────

    /// @notice Lifecycle of a locked deposit. A refund is only possible
    ///         from `Refundable`, which is reached EXCLUSIVELY via
    ///         `markDepositRefundable` (an M-of-N no-mint attestation).
    ///         `Locked` deposits are never refundable — that is what closes
    ///         the CRIT-001 double-spend.
    ///
    ///         None       — slot never written (no such depositNonce)
    ///         Locked     — lock() succeeded; NOT refundable
    ///         Refundable — M-of-N attested the OPNet voucher was cancelled
    ///         Refunded   — terminal; tokens returned to the depositor
    ///         Settled    — terminal; OPNet-side mint is presumed final
    ///                      (time-based via `settleLockedDeposit`). Only
    ///                      this transition promotes the deposit's fee
    ///                      from inventory-backing into `accruedFees`.
    /// @dev    APPENDED ENUM VALUES — `Settled` MUST stay at the end so
    ///         existing on-chain status codes (0..3) remain stable across
    ///         the upgrade.
    enum DepositStatus {
        None,
        Locked,
        Refundable,
        Refunded,
        Settled
    }

    /// @notice On-chain record of every successful `lock` call. Indexed by
    ///         the per-deposit nonce returned by `lock`. A deposit becomes
    ///         refundable only when the M-of-N signer set attests, via
    ///         `markDepositRefundable`, that the OPNet voucher was cancelled
    ///         and can never mint (signer offline forever, voucher
    ///         invalidated, coordination permanently failed, etc.).
    /// @dev    Layout: `user (160) + lockedAt (64) + status (8) = 232 bits`
    ///         packs into one slot; `amount (uint128)` in the second slot,
    ///         `token (address)` in the third, `flowId (bytes32)` in the
    ///         fourth. Top-level layout cost: 1 slot (the mapping itself).
    struct LockRecord {
        address user;          // original depositor — refund destination
        uint64  lockedAt;      // block.timestamp at lock time
        DepositStatus status;  // lifecycle state (uint8 under the hood)
        uint128 amount;        // post-balance-delta received amount (refund value)
        address token;         // ERC-20 to send back
        bytes32 flowId;        // for inventory decrement on refund
        // #62-fix — per-deposit fee captured at lock. Stays in escrow as
        // part of `flow.inventory` until either (a) the deposit refunds —
        // fee is never promoted; or (b) `settleLockedDeposit` promotes it
        // into `flow.accruedFees` after the settlement window elapses.
        // Struct-field append (the struct lives in a `mapping`) — does NOT
        // consume a top-level storage slot.
        uint128 fee;
    }

    /// @notice depositNonce → LockRecord. Set in `lock`, consumed in
    ///         `refundLockedDeposit`. Permissionless refund path.
    mapping(uint256 => LockRecord) public lockedDeposits;

    /// @notice Dedicated pause role. May call `pause()` (alongside owner +
    ///         guardian) but NOT `unpause()` or any other privileged fn.
    ///         Owner-rotatable via `setPauser`; zero address = disabled.
    /// @dev    Roles PR — appended after `lockedDeposits` (append-only). The
    ///         trailing `__gap` shrinks by 1 (42 → 41) so the layout past this
    ///         slot is unchanged.
    address public pauser;

    /// @notice #55 — per-burn replay guard for `refundBurn`. Keyed by
    ///         `keccak256(abi.encode(burnTxHash, burnNonce))`. Set strictly
    ///         BEFORE the cross-contract re-mint (CEI) — it is the ONLY
    ///         protection against a double / infinite re-mint of the same
    ///         burn. An unset slot (false) means "not yet refunded";
    ///         append-only, no version bump needed.
    /// @dev    Appended after `pauser` (append-only). The trailing `__gap`
    ///         shrinks by 1 (41 → 40) so the layout past this slot is
    ///         unchanged.
    mapping(bytes32 => bool) public refundedBurns;

    /// @dev Reserved for future appends. New slots go BEFORE the gap and the
    ///      gap shrinks by the same count to preserve layout.
    ///      Slots past treasury: unwrapFeeBps + unwrapMinFee + flows +
    ///      allFlowIds + flowsByEvmToken + flowsByMode + flowsByEvmChain +
    ///      lockedDeposits + pauser + refundedBurns = 10. (Legacy tokenMode +
    ///      opnetCounterpartOf + _tokenModeFinalized were removed pre-mainnet;
    ///      flow registry is the source of truth for mode + OPNet counterpart
    ///      binding.)
    ///      50 - 10 = 40.
    uint256[40] private __gap;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event Locked(
        address indexed token,
        address indexed from,
        uint256 amountRequested,
        uint256 amountReceived,
        bytes32 opnetRecipient,
        uint256 indexed depositNonce
    );

    /// @notice PR γ.2a — flow-tagged lock event. Emitted alongside `Locked`
    ///         so existing indexers keep working while flow-aware tooling
    ///         can subscribe to the per-flow stream.
    /// @dev    FINDING-001 (audit 2026-05-26): `depositNonce` added so
    ///         indexers can persist `flow_id` per deposit without joining
    ///         against the legacy `Locked` event (which has no `flowId`).
    ///         Same tx, same log block, but `LockedToFlow` is now the
    ///         self-contained authoritative stream for flow-aware tooling.
    event LockedToFlow(
        bytes32 indexed flowId,
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 depositNonce
    );

    /// @notice PR γ.2c — emitted on a successful permissionless refund of a
    ///         stuck deposit. `depositNonce` matches the original `Locked`
    ///         event so indexers can pair them. `caller` is `msg.sender` —
    ///         anyone may submit (the original user, a relayer, etc.) but
    ///         the funds always go to the original `user`.
    event LockRefunded(
        uint256 indexed depositNonce,
        address indexed user,
        address indexed token,
        uint256 amount,
        bytes32 flowId,
        address caller
    );

    /// @notice CRIT-001 — emitted when the M-of-N signer set attests that a
    ///         locked deposit's OPNet voucher was cancelled, moving it to
    ///         `Refundable`. `by` is `msg.sender` (whoever submitted the
    ///         attestation blob).
    event DepositMarkedRefundable(
        uint256 indexed depositNonce,
        address indexed user,
        address indexed by
    );

    /// @notice #55 — emitted on a successful trustless burn-side recovery.
    ///         `burnId` is the replay key `keccak256(burnTxHash, burnNonce)`;
    ///         `burner` is the re-mint recipient; `amount` is the
    ///         signer-attested re-minted amount.
    event BurnRefunded(
        bytes32 indexed burnId,
        address indexed burner,
        address indexed wrappedToken,
        uint256 amount
    );

    event Claimed(
        address indexed token,
        address indexed to,
        uint256 amount,
        bytes32 indexed opnetNonce
    );

    event SignerEpochRotated(
        uint32 indexed oldEpoch,
        uint32 indexed newEpoch,
        address indexed reason
    );

    event SupportedTokenUpdated(address indexed token, bool enabled);

    event EmergencyWithdraw(
        address indexed token,
        address indexed to,
        uint256 amount,
        address indexed by
    );

    /// @dev H-3 (audit 2026-05-27): emits old + new for full audit-trail
    ///      readability. Pre-fix the event carried only the new value.
    event TreasurySet(address indexed oldTreasury, address indexed newTreasury);
    event GuardianSet(address indexed oldGuardian, address indexed newGuardian);
    /// @notice Emitted when the dedicated pause role is set/rotated/disabled.
    event PauserSet(address indexed pauser);

    /// @notice Emitted when accrued source-side fees for a flow are
    ///         withdrawn (always to the set-once `treasury`). Non-emergency
    ///         routine revenue collection — does NOT require pausing.
    event FeesWithdrawn(
        bytes32 indexed flowId,
        address indexed token,
        address indexed to,
        uint256 amount
    );
    event SignerAdded(address indexed signer, uint256 newCount);
    event SignerRemoved(address indexed signer, uint256 newCount);
    event ThresholdSet(uint256 indexed oldThreshold, uint256 indexed newThreshold);
    event VoucherCancelled(bytes32 indexed opnetNonce, address indexed by);

    // ─── Flow Registry events ──────────────────────────────────────────
    event FlowAdded(
        bytes32 indexed flowId,
        uint8 mode,
        uint64 evmChainId,
        address indexed evmToken,
        bytes32 indexed opnetToken
    );
    event FlowStatusChanged(bytes32 indexed flowId, uint8 oldStatus, uint8 newStatus);
    event FlowCapChanged(bytes32 indexed flowId, uint128 oldCap, uint128 newCap);
    event FlowDailyLimitChanged(bytes32 indexed flowId, uint128 oldLimit, uint128 newLimit);
    event FlowMinAmountChanged(bytes32 indexed flowId, uint128 oldMin, uint128 newMin);
    event FlowFeeChanged(bytes32 indexed flowId, uint16 oldBps, uint16 newBps, uint128 oldMinFee, uint128 newMinFee);
    event FlowTipCapUpdated(bytes32 indexed flowId, uint16 oldBps, uint16 newBps);
    event FlowVestingVaultChanged(bytes32 indexed flowId, address oldVault, address newVault);
    event VestedClaimClawedBack(
        bytes32 indexed flowId,
        address indexed beneficiary,
        bytes32 indexed opnetNonce,
        uint128 returnedAmount,
        address by
    );
    event SignerSetMigrated(
        uint32 indexed oldEpoch,
        uint32 indexed newEpoch,
        uint256 newCount,
        uint256 newThreshold
    );
    event UnwrapFeeBpsSet(uint256 indexed oldBps, uint256 indexed newBps);
    event UnwrapMinFeeSet(address indexed token, uint256 indexed amount);
    event WrappedMintedFromVoucher(
        address indexed wrappedToken,
        address indexed to,
        uint256 amount,
        bytes32 indexed opnetNonce
    );
    event InventoryProvisioned(bytes32 indexed flowId, address indexed token, address indexed by, uint256 amount);
    event InventoryDrained(bytes32 indexed flowId, address indexed token, address indexed to, uint256 amount, address by);

    /// @notice Emitted on a successful claim that paid a relayer tip
    ///         (PR β.2.payout-evm). `relayer` is `msg.sender` — anyone may
    ///         submit a tipped voucher and collect.
    event RelayerTipPaid(bytes32 indexed flowId, address indexed relayer, uint256 tip);

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    error ZeroAddress();
    error ZeroChainId();
    error TokenNotSupported();
    error AmountZero();
    error NothingReceived();
    error InvalidRecipient();
    error InvalidSrcChainId();
    error InvalidSignerEpoch();
    error AlreadyClaimed();
    error SourceEventAlreadyUsed();
    error InvalidSignature();
    error TreasuryNotSet();
    error NotGuardian();
    error NotASigner();
    error AlreadyASigner();
    error InvalidThreshold();
    error FeeBpsTooHigh();
    error TipCapTooHigh();
    error WrongMode();
    error InvalidSigBlob();
    error InsufficientSignatures();
    error DuplicateSigner();
    error VoucherCancelled_();
    error VestingVaultRequired();
    error VestingVaultNotPermitted();
    error VestingVaultNotSet();
    error VestingVaultTokenMismatch();
    error InsufficientAccruedFees();
    error VoucherNotCancelled();        // HIGH-001 — clawback requires prior cancelVoucher
    error BurnAlreadyRefunded();        // #55 — refundBurn replay guard already set
    // #62-fix — lifecycle errors for time-based settlement.
    error FeeExceedsAmount();           // lock with fee >= received (zero-net bridge)
    error LockNotSettleable();          // settleLockedDeposit on non-Locked status
    error SettlementWindowNotMet();     // settleLockedDeposit before lockedAt + WINDOW
    error FlowMinAmountBelowMinFee();   // addFlow / setFlowMinAmount / setFlowFee: minAmount > 0 && minAmount <= minFee

    // ─── Flow Registry errors ──────────────────────────────────────────
    error FlowAlreadyExists();
    error FlowNotFound();
    error FlowInvalidMode();
    error FlowInvalidDecimals();
    error FlowInvalidStatusTransition();
    error FlowCapBelowInventory();
    error FlowZeroChainId();

    // ─── Relayer-tip payout errors (PR β.2.payout-evm) ─────────────────
    error TipExceedsFlowCap();

    // ─── Flow consumption errors (PR γ.1) ──────────────────────────────
    error FlowNotActive();
    error AmountBelowFlowMin();
    error FlowCapExceeded();
    error DailyLimitExceeded();
    error InsufficientFlowInventory();
    error AmountExceedsGross();         // MED-001 — claim() intent.amount > grossSrcAmount
    error PermitFailed();               // lockWithPermit — permit reverted and allowance still short

    // ─── PR γ.2c — refund lifecycle errors ─────────────────────────────
    error LockNotFound();
    error LockAlreadyRefunded();
    error RefundNotAuthorized();        // refundLockedDeposit on a non-Refundable deposit
    error DepositNotInLockedState();    // markDepositRefundable on a non-Locked deposit

    // ---------------------------------------------------------------------
    // Init
    // ---------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize proxy state. Seeds 1-of-1 M-of-N with `initialSigner_`.
    /// @param owner_ Initial owner (Safe multisig in prod).
    /// @param initialSigner_ Seed signer; written into `isSigner` and used
    ///        as the only authorized signer until governance adds more.
    /// @param expectedOpnetChainId_ OPNet network id (1=mainnet, 2=testnet).
    /// @param supportedTokens_ Canonical token allowlist at deploy time.
    function initialize(
        address owner_,
        address initialSigner_,
        uint256 expectedOpnetChainId_,
        address[] calldata supportedTokens_
    ) external initializer {
        if (owner_ == address(0) || initialSigner_ == address(0)) revert ZeroAddress();
        if (expectedOpnetChainId_ == 0) revert ZeroChainId();

        __UUPSUpgradeable_init();
        __Ownable_init(owner_);
        __Pausable_init();
        __ReentrancyGuard_init();
        __EIP712_init("BridgeEscrow", "1");

        currentEpoch = 1;
        expectedOpnetChainId = expectedOpnetChainId_;

        // 1-of-1 by default. Governance can add more signers + raise threshold
        // via `migrateSignerSet` for atomic 1-of-1 → 2-of-2 transitions.
        isSigner[initialSigner_] = true;
        signerCount = 1;
        signerThreshold = 1;

        uint256 len = supportedTokens_.length;
        for (uint256 i; i < len; ) {
            address token = supportedTokens_[i];
            if (token == address(0)) revert ZeroAddress();
            supportedToken[token] = true;
            emit SupportedTokenUpdated(token, true);
            unchecked {
                ++i;
            }
        }
    }

    // ---------------------------------------------------------------------
    // Access control — incident response (H-01)
    // ---------------------------------------------------------------------

    /// @notice H-01 — incident-response actions (pause, voucher
    ///         cancellation, signer removal/rotation) must stay fast even
    ///         after `owner` is handed to the 3-day TimelockController.
    ///         The set-once `guardian` may invoke them alongside the owner.
    ///         Recovery actions (unpause, addSigner, setThreshold, upgrades,
    ///         flow/treasury config) remain owner-only — the timelock delay
    ///         IS the safeguard for those.
    modifier onlyOwnerOrGuardian() {
        if (msg.sender != owner() && msg.sender != guardian) revert NotGuardian();
        _;
    }

    // ---------------------------------------------------------------------
    // Core — lock
    // ---------------------------------------------------------------------

    function lock(
        address token,
        uint256 amount,
        bytes32 opnetRecipient,
        bytes32 flowId
    )
        public
        whenNotPaused
        nonReentrant
        returns (uint256 depositNonce_, uint256 amountReceived_)
    {
        if (!supportedToken[token]) revert TokenNotSupported();
        if (amount == 0) revert AmountZero();
        if (opnetRecipient == bytes32(0)) revert InvalidRecipient();

        // ─── PR γ.2a: flow binding + consumption (lock side) ──────────────
        // All status / minAmount / dailyLimit / cap enforcement happens in
        // a small helper to keep this function under the stack-depth limit.
        _consumeLockFlow(flowId, token, amount);

        IERC20 erc20 = IERC20(token);
        uint256 balBefore = erc20.balanceOf(address(this));
        erc20.safeTransferFrom(msg.sender, address(this), amount);
        uint256 balAfter = erc20.balanceOf(address(this));

        unchecked {
            amountReceived_ = balAfter - balBefore;
        }
        if (amountReceived_ == 0) revert NothingReceived();

        // 4. cap + inventory increment, on the ACTUAL received amount
        //    (post fee-on-transfer balance delta). `_bumpLockInventory`
        //    also computes the per-deposit fee that we'll capture on the
        //    LockRecord (NOT promoted to accruedFees yet — see
        //    `settleLockedDeposit`).
        uint128 lockFee = _bumpLockInventory(flowId, amountReceived_);

        unchecked {
            depositNonce_ = ++depositNonce;
        }

        // PR γ.2c — persist a refund-eligible record. `amountReceived_`
        // already passed the `_bumpLockInventory` uint128 cap check above,
        // so the cast is safe.
        lockedDeposits[depositNonce_] = LockRecord({
            user: msg.sender,
            lockedAt: uint64(block.timestamp),
            status: DepositStatus.Locked,
            amount: uint128(amountReceived_),
            token: token,
            flowId: flowId,
            fee: lockFee
        });

        emit Locked(token, msg.sender, amount, amountReceived_, opnetRecipient, depositNonce_);
        emit LockedToFlow(flowId, msg.sender, token, amountReceived_, depositNonce_);
    }

    /// @notice EIP-2612 one-transaction bridging: consume an off-chain
    ///         `permit` signature to grant the allowance, then `lock` in
    ///         the same tx. For permit-capable tokens (USDC) this collapses
    ///         the usual `approve` + `lock` into a single transaction.
    ///         USDT has no EIP-2612 — callers keep the plain `lock` path.
    /// @dev    Pause / reentrancy / flow gating are all delegated to
    ///         `lock` (now `public`, so this internal call preserves
    ///         `msg.sender` = the depositor for the balance-delta pull).
    ///         `permit` is wrapped in try/catch: the signature is public
    ///         calldata and can be front-run, which would consume the
    ///         nonce and revert a naive `permit`. If that happens we still
    ///         proceed as long as the allowance is already sufficient.
    function lockWithPermit(
        address token,
        uint256 amount,
        bytes32 opnetRecipient,
        bytes32 flowId,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 depositNonce_, uint256 amountReceived_) {
        try IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s) {
            // permit applied
        } catch {
            // Front-run or already-applied permit — tolerate it as long as
            // the resulting allowance covers the lock.
            if (IERC20(token).allowance(msg.sender, address(this)) < amount) {
                revert PermitFailed();
            }
        }
        return lock(token, amount, opnetRecipient, flowId);
    }

    // ---------------------------------------------------------------------
    // Core — refund (PR γ.2c, permissionless after REFUND_TIMEOUT)
    // ---------------------------------------------------------------------

    /// @notice Refund a stuck `lock` whose destination-side mint was
    ///         cancelled. Permissionless to *call* — the tokens always go
    ///         to the recorded depositor — but only proceeds once the
    ///         deposit has been moved to `Refundable` by
    ///         `markDepositRefundable`, i.e. the M-of-N signer set has
    ///         attested the OPNet voucher was cancelled and can never mint.
    ///
    /// @dev    CRIT-001 fix. The previous version was time-gated only:
    ///         after a 7-day timeout ANY lock was refundable, with no
    ///         on-chain dependency on whether the OPNet side had already
    ///         minted. A user could claim wUSDC on OPNet AND refund the EVM
    ///         lock, breaking 1:1 backing. Refund is now gated by a
    ///         positive no-mint attestation (`Refundable` state), never by
    ///         the mere absence of a refunded flag.
    ///
    ///         CEI: read → set Refunded → mutate inventory → transfer.
    ///         Reentrancy guarded; idempotent (a Refunded deposit reverts
    ///         with `LockAlreadyRefunded`).
    function refundLockedDeposit(uint256 depositNonce_) external nonReentrant {
        LockRecord storage rec = lockedDeposits[depositNonce_];

        // `status == None` means the slot was never written (no such
        // depositNonce). depositNonce starts at 1, so nonce 0 is also
        // unmapped — the None check covers it cleanly.
        if (rec.status == DepositStatus.None) revert LockNotFound();
        if (rec.status == DepositStatus.Refunded) revert LockAlreadyRefunded();
        if (rec.status != DepositStatus.Refundable) revert RefundNotAuthorized();

        // Snapshot the fields we need post-mark (storage-pointer stays
        // stable but reads are cheaper from memory).
        address user = rec.user;
        address token = rec.token;
        uint128 amount = rec.amount;
        bytes32 flowId = rec.flowId;

        // Effects.
        rec.status = DepositStatus.Refunded;

        // Decrement per-flow inventory. `lock` always bumped it so the
        // flow record is guaranteed to exist with at least `amount`
        // accounted. We still floor-clamp defensively against the unlikely
        // case where governance manually adjusted inventory downward via
        // a future ops path — under-flow would corrupt accounting.
        FlowRecord storage flow = flows[flowId];
        if (uint256(flow.inventory) >= uint256(amount)) {
            unchecked {
                flow.inventory = flow.inventory - amount;
            }
        } else {
            // Inventory was already reset/drained by ops — clamp to zero
            // rather than revert. The user's refund is the higher-priority
            // invariant; flow accounting is best-effort during emergency
            // recovery scenarios.
            flow.inventory = 0;
        }

        // Interactions — actual token return.
        IERC20(token).safeTransfer(user, uint256(amount));

        emit LockRefunded(
            depositNonce_,
            user,
            token,
            uint256(amount),
            flowId,
            msg.sender
        );
    }

    /// @notice #62-fix — Window after `lockedAt` during which the M-of-N can
    ///         still mark a Locked deposit `Refundable`. Past this window any
    ///         caller may settle the deposit, promoting its captured fee
    ///         from inventory-backing into withdrawable revenue. Long enough
    ///         that ops/M-of-N can comfortably issue a Refundable mark for
    ///         any OPNet voucher that needs cancelling; constant (not
    ///         governance-settable) to keep the surface flat.
    uint64 public constant SETTLEMENT_WINDOW = 14 days;

    /// @notice #62-fix — Emitted when a Locked deposit transitions to Settled
    ///         and its fee is promoted from inventory to `flow.accruedFees`.
    event DepositSettled(
        uint256 indexed depositNonce,
        bytes32 indexed flowId,
        uint128 fee,
        address indexed by
    );

    /// @notice #62-fix — Promote a Locked deposit to Settled after the
    ///         settlement window has elapsed without an M-of-N
    ///         `markDepositRefundable`. Permissionless: anyone may call it;
    ///         no external transfers occur — `rec.fee` is moved from
    ///         `flow.inventory` (where it sat as user-backing principal)
    ///         into `flow.accruedFees` (treasury-eligible revenue). Net
    ///         escrow ERC20 balance is unchanged; this is a relabel.
    ///
    /// @dev    Mutually exclusive with the refund path: a deposit already in
    ///         `Refundable` (or `Refunded`/`Settled`) reverts
    ///         `LockNotSettleable`. The M-of-N is expected to issue
    ///         `markDepositRefundable` well before SETTLEMENT_WINDOW for any
    ///         deposit whose OPNet voucher needs cancelling.
    ///
    ///         Pre-upgrade `Locked` deposits carry `rec.fee == 0` because
    ///         the field didn't exist before this upgrade; they settle as
    ///         zero-fee deposits (conservative — slight tail-window
    ///         under-report of revenue, accepted).
    ///
    ///         CEI: status read → status write → inventory/fee mutation.
    ///         No external calls; no reentrancy guard needed.
    function settleLockedDeposit(uint256 depositNonce_) external {
        LockRecord storage rec = lockedDeposits[depositNonce_];
        if (rec.status != DepositStatus.Locked) revert LockNotSettleable();
        // Window guard. `lockedAt` is uint64; addition with a `days` constant
        // is bounded well below uint64.max for any plausible block time.
        if (block.timestamp < uint256(rec.lockedAt) + SETTLEMENT_WINDOW) {
            revert SettlementWindowNotMet();
        }

        bytes32 flowId = rec.flowId;
        uint128 fee = rec.fee;

        // Effects.
        rec.status = DepositStatus.Settled;
        if (fee > 0) {
            FlowRecord storage flow = flows[flowId];
            // Inventory was incremented by `rec.amount` at lock time
            // (`rec.amount >= fee`), so subtracting `fee` from inventory is
            // normally safe. The exception: `drainInventory` (onlyGuardian +
            // whenPaused) could have lowered inventory below the
            // outstanding-fee total. In that abnormal state we MUST NOT
            // wrap — the underlying ERC20 has already been moved out, so
            // promoting the fee would double-count escrow obligations.
            // Solidity 0.8.x checked subtraction reverts on underflow;
            // settlement of this nonce stays callable once governance
            // re-provisions inventory (or never, by design, if the flow is
            // being permanently retired). NO `unchecked` here.
            flow.inventory = flow.inventory - fee;
            flow.accruedFees = uint128(uint256(flow.accruedFees) + fee);
        }

        emit DepositSettled(depositNonce_, flowId, fee, msg.sender);
    }

    /// @notice M-of-N attestation that a locked deposit's OPNet voucher was
    ///         cancelled and will never mint — the ONLY path that makes a
    ///         deposit refundable. The bridge authority collects the
    ///         threshold of signatures off-chain (after cancelling the
    ///         voucher on the OPNet `BridgeDepository`) and submits them
    ///         here. `sig` is the same `[uint8 numSigs][sig(65)]…` blob
    ///         format `claim()` consumes.
    ///
    /// @dev    Not pause-gated — refunds must stay possible during an
    ///         incident freeze. The signature is bound to `depositNonce`,
    ///         the deposit's `flowId`, and the current signer epoch, so a
    ///         rotation invalidates any un-submitted attestation. Makes no
    ///         external calls, so no reentrancy guard is needed.
    function markDepositRefundable(uint256 depositNonce_, bytes calldata sig)
        external
    {
        LockRecord storage rec = lockedDeposits[depositNonce_];
        if (rec.status == DepositStatus.None) revert LockNotFound();
        if (rec.status != DepositStatus.Locked) revert DepositNotInLockedState();

        bytes32 digest = _hashTypedDataV4(
            _hashRefundAuth(depositNonce_, rec.flowId, currentEpoch)
        );
        _verifySignatures(digest, sig);

        rec.status = DepositStatus.Refundable;
        emit DepositMarkedRefundable(depositNonce_, rec.user, msg.sender);
    }

    /// @dev PR γ.2a — flow binding + status / minAmount / dailyLimit
    ///      enforcement on the lock side. Extracted to keep `lock` under
    ///      the Solidity stack-depth limit. Uses `amount` (the caller's
    ///      requested source-side base units) for the enforcement keys —
    ///      identical semantics to the claim path's `grossSrcAmount`.
    function _consumeLockFlow(bytes32 flowId, address token, uint256 amount) internal {
        FlowRecord storage flow = flows[flowId];
        if (flow.evmChainId == 0) revert FlowNotFound();
        // Caller-supplied flowId must match the token being deposited —
        // a flow uniquely names the (mode, chains, both bridges, both
        // tokens) tuple, EVM token field is `flow.evmToken`.
        if (flow.evmToken != token) revert FlowNotFound();

        // Mode dispatch — `lock` is valid for WRAPPED (canonical USDC/USDT
        // accumulating) and POOLED_LOCK_RELEASE (project tokens like MOTO
        // where users top up the inventory pool). Modes 1/2 (mint-on-EVM)
        // use WrappedERC20.burnForRelease on the wrapped contract directly.
        if (
            flow.mode != uint8(TokenMode.WRAPPED)
            && flow.mode != uint8(TokenMode.POOLED_LOCK_RELEASE)
            && flow.mode != uint8(TokenMode.POOLED_LOCK_VEST)
        ) {
            revert WrongMode();
        }
        // Mode 4 — block locks on a flow whose VestingVault hasn't been
        // wired yet. Otherwise a user deposit would have no on-chain
        // destination for its later claim, stranding tokens.
        if (flow.mode == uint8(TokenMode.POOLED_LOCK_VEST) && flow.vestingVault == address(0)) {
            revert VestingVaultNotSet();
        }

        // 1. status: lock is a forward (inbound) path. Allowed only on
        //    ACTIVE. PAUSED = guardian quarantine; DRAINING = winding down,
        //    no new deposits; DISABLED = non-existent.
        if (flow.status != FLOW_STATUS_ACTIVE) revert FlowNotActive();

        // 2. minAmount — by spec always source-side base units.
        if (amount < uint256(flow.minAmount)) revert AmountBelowFlowMin();

        // 3. dailyLimit (rolling 24h window). Mirrors the claim path.
        if (amount > type(uint128).max) revert DailyLimitExceeded();
        if (block.timestamp - uint256(flow.lastWindowStart) > uint256(FLOW_WINDOW_DURATION)) {
            flow.mintedToday = 0;
            flow.lastWindowStart = uint64(block.timestamp);
        }
        uint256 newMinted = uint256(flow.mintedToday) + amount;
        if (newMinted > uint256(flow.dailyLimit)) revert DailyLimitExceeded();
        flow.mintedToday = uint128(newMinted);
    }

    /// @dev PR γ.2a — cap check + inventory increment, post-pull. Uses the
    ///      balance-delta `received` so the bookkeeping reflects what the
    ///      bridge actually holds, not what the caller asked to send.
    function _bumpLockInventory(bytes32 flowId, uint256 received)
        internal
        returns (uint128 lockFee)
    {
        if (received > type(uint128).max) revert FlowCapExceeded();
        FlowRecord storage flow = flows[flowId];
        uint256 newInventory = uint256(flow.inventory) + received;
        if (newInventory > uint256(flow.cap)) revert FlowCapExceeded();
        flow.inventory = uint128(newInventory);

        // ─── #62-fix — per-deposit fee CAPTURE (not promotion) ────────────
        // Compute the fee that WILL be earned by the bridge if this deposit
        // ultimately settles via successful OPNet mint. We do NOT promote it
        // into `flow.accruedFees` here — that would let `withdrawFees` drain
        // principal that may still be needed by a downstream `refundLockedDeposit`.
        //
        // Fee is stored on the LockRecord by the caller. It is promoted to
        // `flow.accruedFees` (and removed from `flow.inventory`) only via
        // `settleLockedDeposit`, which is gated on `SETTLEMENT_WINDOW`
        // having elapsed since `lockedAt`. A refund (`refundLockedDeposit`)
        // is mutually exclusive with settlement: the M-of-N moves the
        // deposit to `Refundable` BEFORE settlement, and the fee never
        // promotes — keeping the user's refund whole.
        //
        // Modes that retain an EVM-side fee on lock: WRAPPED (0),
        // POOLED_LOCK_RELEASE (3), POOLED_LOCK_VEST (4) — exactly the modes
        // `_consumeLockFlow` permits to reach this point.
        uint256 fee = (received * uint256(flow.feeBps)) / 10_000;
        uint256 minFee = uint256(flow.minFee);
        if (minFee > fee) fee = minFee;
        // Fail-closed on all-fee locks. If the fee would consume the entire
        // (or more than) received amount, there is no net to bridge — reject
        // the lock instead of silently producing a zero-net mint on OPNet.
        // (Replaces the previous defensive `if (fee > received) fee = received`
        // clamp, which papered over a misconfigured minFee.)
        if (fee >= received) revert FeeExceedsAmount();
        // fee < received <= uint128.max — cast is safe.
        lockFee = uint128(fee);
    }

    /// @dev MED-001 — minAmount + rolling-window dailyLimit enforcement for
    ///      the mint-on-EVM claim path (`claimMintWrapped`). Bounds how much
    ///      a compromised signer can authorize per 24h window. Keyed on the
    ///      minted amount — `MintIntent` has no separate gross field.
    ///      Mirrors the dailyLimit block in `claim()`.
    function _consumeMintFlowLimits(FlowRecord storage flow, uint256 amount) internal {
        if (amount < uint256(flow.minAmount)) revert AmountBelowFlowMin();
        if (amount > type(uint128).max) revert DailyLimitExceeded();
        if (block.timestamp - uint256(flow.lastWindowStart) > uint256(FLOW_WINDOW_DURATION)) {
            flow.mintedToday = 0;
            flow.lastWindowStart = uint64(block.timestamp);
        }
        uint256 newMinted = uint256(flow.mintedToday) + amount;
        if (newMinted > uint256(flow.dailyLimit)) revert DailyLimitExceeded();
        flow.mintedToday = uint128(newMinted);
    }

    // ---------------------------------------------------------------------
    // Core — claim (M-of-N only)
    // ---------------------------------------------------------------------

    /// @notice Claim a release authorized by the M-of-N signer set.
    /// @dev `sig` is the length-prefixed M-of-N blob:
    ///        `[uint8 numSigs][sig_0(65)][sig_1(65)]…[sig_{numSigs-1}(65)]`
    ///      Each sig is independently `ECDSA.recover`'d, must come from a
    ///      distinct authorized `isSigner`, and the count of valid recovers
    ///      must be `>= signerThreshold`.
    function claim(ReleaseIntent calldata intent, bytes calldata sig)
        external
        whenNotPaused
        nonReentrant
    {
        if (!supportedToken[intent.token]) revert TokenNotSupported();
        if (intent.to == address(0)) revert InvalidRecipient();
        if (intent.amount == 0) revert AmountZero();
        // MED-001 — bound the amount actually transferred out by the
        // cap-checked source gross. The flow's minAmount / dailyLimit /
        // inventory are all enforced against `grossSrcAmount`, but the
        // token movement is `intent.amount`; without this a compromised
        // signer could sign a small gross (under the daily cap) and a huge
        // amount. Honest vouchers always satisfy net <= gross. This holds
        // while gross and the EVM-side amount share a decimal basis (true
        // today — all flows are 6/6); decimal-aware AmountPolicy must
        // revisit every grossSrc-keyed check here, not just this one.
        if (intent.amount > intent.grossSrcAmount) revert AmountExceedsGross();
        if (intent.srcChainId != expectedOpnetChainId) revert InvalidSrcChainId();
        if (intent.signerEpoch != currentEpoch) revert InvalidSignerEpoch();
        // #49 — cancellation checked BEFORE replay, matching the OPNet
        // claimMintWithVoucher order. For a cancelled-then-claimed voucher
        // this surfaces VoucherCancelled_ instead of masking it as
        // AlreadyClaimed, which speeds incident triage.
        if (cancelledVouchers[intent.opnetNonce]) revert VoucherCancelled_();
        if (signaturesUsed[intent.opnetNonce]) revert AlreadyClaimed();
        if (usedSourceEvent[intent.opnetTxHash][intent.opnetEventIndex]) {
            revert SourceEventAlreadyUsed();
        }

        bytes32 structHash = _hashIntent(intent);
        bytes32 digest = _hashTypedDataV4(structHash);

        _verifySignatures(digest, sig);

        // ─── PR β.2.payout-evm: flow binding + relayer-tip payout ──────
        // The voucher commits to a flowId. Look it up after sig-verify
        // (so unauthenticated callers can't spam flow lookups) and
        // before any token movement. Existence flag matches the rest of
        // the registry: chainId == 0 means "not registered".
        FlowRecord storage flow = flows[intent.flowId];
        if (flow.evmChainId == 0) revert FlowNotFound();
        // Mode dispatch — `claim` releases real tokens from the bridge's
        // balance. Valid for WRAPPED and POOLED_LOCK_RELEASE only. Mint-on-
        // EVM modes (INVERSE_WRAPPED / NATIVE_BURN_MINT) go through
        // `claimMintWrapped`. Bind the intent's `token` to `flow.evmToken`
        // so a release sig can't be replayed against a different token's
        // pool.
        if (
            flow.mode != uint8(TokenMode.WRAPPED)
            && flow.mode != uint8(TokenMode.POOLED_LOCK_RELEASE)
            && flow.mode != uint8(TokenMode.POOLED_LOCK_VEST)
        ) {
            revert WrongMode();
        }
        if (flow.evmToken != intent.token) revert WrongMode();

        // ─── PR γ.1: flow consumption — minAmount / status / dailyLimit /
        //     inventory enforcement on the EVM claim (release) path. ──────
        // Order: status → minAmount → dailyLimit (window rotate + check) →
        // inventory decrement → tip cap → effects → external transfers.
        // Cap is NOT enforced here: EVM `claim` is a release path (modes
        // 0 / 3) — inventory only decreases, never grows past `cap`.

        // 1. status: claim allowed only on active or draining flows.
        //    PAUSED is a guardian quarantine; DISABLED means non-existent.
        if (flow.status != FLOW_STATUS_ACTIVE && flow.status != FLOW_STATUS_DRAINING) {
            revert FlowNotActive();
        }

        // 2. minAmount — uses source-side gross from the voucher (PR β.2).
        if (intent.grossSrcAmount < uint256(flow.minAmount)) revert AmountBelowFlowMin();

        // 3. dailyLimit (rolling 24h window keyed off `grossSrcAmount`).
        //    Window rotate: if more than 86400s since last window start,
        //    reset the bucket. Then assert and consume.
        uint128 grossDst128 = uint128(intent.grossSrcAmount);
        if (intent.grossSrcAmount > type(uint128).max) revert DailyLimitExceeded();
        if (block.timestamp - uint256(flow.lastWindowStart) > uint256(FLOW_WINDOW_DURATION)) {
            flow.mintedToday = 0;
            flow.lastWindowStart = uint64(block.timestamp);
        }
        // Check + consume. Use uint256 math to avoid uint128 overflow on
        // the addition itself. We can safely cast back because dailyLimit
        // is uint128.
        uint256 newMinted = uint256(flow.mintedToday) + uint256(grossDst128);
        if (newMinted > uint256(flow.dailyLimit)) revert DailyLimitExceeded();
        flow.mintedToday = uint128(newMinted);

        // 4. inventory: release direction. Decrement by grossDst. Revert
        //    if inventory < grossDst (insufficient).
        if (uint256(flow.inventory) < uint256(grossDst128)) revert InsufficientFlowInventory();
        unchecked {
            flow.inventory = flow.inventory - grossDst128;
        }

        // FINDING-004 (audit 2026-05-26): accrue the release-side fee.
        // The inventory was decremented by gross, but only
        // `intent.amount` (= net) leaves the bridge to the recipient and
        // `tip` to the relayer. The remainder `gross - net = fee`
        // stays in the bridge's balance. Pre-fix this delta was never
        // recorded anywhere, so `withdrawFees` couldn't sweep it and the
        // per-flow invariant `inventory + accruedFees == bridge.balance`
        // drifted upward on every release.
        // `intent.amount > intent.grossSrcAmount` is rejected earlier
        // (AmountExceedsGross), so the subtraction is safe.
        uint256 feePortion = uint256(intent.grossSrcAmount) - intent.amount;
        if (feePortion > 0) {
            // grossDst128 is uint128, feePortion <= grossDst128, so the
            // cast back to uint128 below is safe.
            flow.accruedFees = uint128(uint256(flow.accruedFees) + feePortion);
        }

        // 5. tip cap + carve.
        //
        // FINDING-006 (audit 2026-05-26): the pre-fix form was
        //   bps = tip * 10_000 / amount;  if (bps > tipCapBps) revert;
        // which floors the ratio. With `tipCapBps == 0` any positive tip
        // where `tip * 10_000 < amount` passed silently, so governance
        // could not fully disable tips through a zero cap. Cross-multiply
        // avoids the rounding entirely:
        //   tip * 10_000 > amount * tipCapBps  →  revert.
        // We also explicitly defend `tip <= amount` (the comment-only
        // invariant becomes a check) so the subtraction below cannot
        // underflow on a malformed signer-bound intent.
        uint256 recipientAmount = intent.amount;
        uint128 tip = intent.relayerTip;
        if (tip > 0) {
            if (uint256(tip) > intent.amount) revert TipExceedsFlowCap();
            if (uint256(tip) * 10_000 > intent.amount * uint256(flow.tipCapBps)) {
                revert TipExceedsFlowCap();
            }
            unchecked {
                // Safe: tip <= amount asserted directly above.
                recipientAmount = intent.amount - tip;
            }
        }

        // Effects BEFORE interaction (CEI).
        signaturesUsed[intent.opnetNonce] = true;
        usedSourceEvent[intent.opnetTxHash][intent.opnetEventIndex] = true;

        emit Claimed(intent.token, intent.to, recipientAmount, intent.opnetNonce);
        if (tip > 0) {
            // msg.sender — NOT tx.origin — so smart-contract relayers can
            // sweep into their own balance in the same transaction.
            emit RelayerTipPaid(intent.flowId, msg.sender, tip);
            IERC20(intent.token).safeTransfer(msg.sender, tip);
        }

        // Destination dispatch:
        //   Mode 4 (POOLED_LOCK_VEST) — deposit into the per-flow VestingVault
        //     for linear release to `intent.to`. Schedule key is the voucher
        //     opnetNonce (already replay-guarded above), so each claim opens
        //     an independent vest. Tip carve happened above; only the
        //     recipient-bound `recipientAmount` enters the vault.
        //   Default (modes 0 / 3) — direct release to `intent.to`.
        if (flow.mode == uint8(TokenMode.POOLED_LOCK_VEST)) {
            address vault = flow.vestingVault;
            // addFlow + setFlowVestingVault both enforce non-zero for mode 4;
            // defensive recheck before granting allowance.
            if (vault == address(0)) revert VestingVaultNotSet();
            IERC20(intent.token).safeIncreaseAllowance(vault, recipientAmount);
            IVestingVault(vault).depositFor(intent.to, recipientAmount, intent.opnetNonce);
        } else {
            IERC20(intent.token).safeTransfer(intent.to, recipientAmount);
        }
    }

    /// @dev Reverts on any verification failure. Sig format:
    ///      `[uint8 numSigs][sig_0(65)][sig_1(65)]…`. Signers must be
    ///      distinct, all in `isSigner`, count >= `signerThreshold`.
    function _verifySignatures(bytes32 digest, bytes calldata sig) internal view {
        uint256 threshold = signerThreshold;
        if (sig.length < 1) revert InvalidSigBlob();

        uint256 numSigs = uint256(uint8(sig[0]));
        if (numSigs == 0) revert InvalidSigBlob();
        if (sig.length != 1 + numSigs * 65) revert InvalidSigBlob();

        address[] memory seen = new address[](numSigs);
        uint256 validCount = 0;

        for (uint256 i = 0; i < numSigs; ) {
            uint256 off = 1 + i * 65;
            bytes memory single = new bytes(65);
            for (uint256 j = 0; j < 65; ) {
                single[j] = sig[off + j];
                unchecked {
                    ++j;
                }
            }
            address recovered = ECDSA.recover(digest, single);
            if (recovered == address(0)) revert InvalidSignature();
            // Unauthorized recovered signer (or wrong-digest case where the
            // recover lands on a random address) surfaces as InvalidSignature
            // — keeps the error surface stable across "wrong key" and
            // "valid key but wrong digest" cases.
            if (!isSigner[recovered]) revert InvalidSignature();

            for (uint256 k = 0; k < i; ) {
                if (seen[k] == recovered) revert DuplicateSigner();
                unchecked {
                    ++k;
                }
            }
            seen[i] = recovered;
            unchecked {
                ++validCount;
                ++i;
            }
        }

        if (validCount < threshold) revert InsufficientSignatures();
    }

    // ---------------------------------------------------------------------
    // Admin — signer set management (M-of-N)
    // ---------------------------------------------------------------------

    function addSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ZeroAddress();
        if (isSigner[newSigner]) revert AlreadyASigner();
        isSigner[newSigner] = true;
        unchecked {
            ++signerCount;
        }
        emit SignerAdded(newSigner, signerCount);
    }

    function removeSigner(address oldSigner) external onlyOwnerOrGuardian {
        if (!isSigner[oldSigner]) revert NotASigner();
        unchecked {
            uint256 newCount = signerCount - 1;
            if (newCount < signerThreshold) revert InvalidThreshold();
            signerCount = newCount;
        }
        isSigner[oldSigner] = false;

        uint32 oldEpoch = currentEpoch;
        uint32 newEpoch;
        unchecked {
            newEpoch = oldEpoch + 1;
        }
        currentEpoch = newEpoch;
        emit SignerRemoved(oldSigner, signerCount);
        emit SignerEpochRotated(oldEpoch, newEpoch, oldSigner);
    }

    function setThreshold(uint256 newThreshold) external onlyOwner {
        if (newThreshold == 0 || newThreshold > signerCount) revert InvalidThreshold();
        uint256 oldThreshold = signerThreshold;
        signerThreshold = newThreshold;

        uint32 oldEpoch = currentEpoch;
        uint32 newEpoch;
        unchecked {
            newEpoch = oldEpoch + 1;
        }
        currentEpoch = newEpoch;
        emit ThresholdSet(oldThreshold, newThreshold);
        emit SignerEpochRotated(oldEpoch, newEpoch, address(0));
    }

    /// @notice Atomic add+remove+threshold update — required for safe
    ///         transitions like 1-of-1 → 2-of-2 (no intermediate weakening).
    function migrateSignerSet(
        address[] calldata addList,
        address[] calldata removeList,
        uint256 newThreshold
    ) external onlyOwnerOrGuardian {
        uint256 rLen = removeList.length;
        for (uint256 i = 0; i < rLen; ) {
            address s = removeList[i];
            if (!isSigner[s]) revert NotASigner();
            isSigner[s] = false;
            unchecked {
                --signerCount;
                ++i;
            }
        }
        uint256 aLen = addList.length;
        for (uint256 i = 0; i < aLen; ) {
            address s = addList[i];
            if (s == address(0)) revert ZeroAddress();
            if (isSigner[s]) revert AlreadyASigner();
            isSigner[s] = true;
            unchecked {
                ++signerCount;
                ++i;
            }
        }
        if (newThreshold == 0 || newThreshold > signerCount) revert InvalidThreshold();
        signerThreshold = newThreshold;

        uint32 oldEpoch = currentEpoch;
        uint32 newEpoch;
        unchecked {
            newEpoch = oldEpoch + 1;
        }
        currentEpoch = newEpoch;
        emit SignerSetMigrated(oldEpoch, newEpoch, signerCount, newThreshold);
    }

    function cancelVoucher(bytes32 opnetNonce) external onlyOwnerOrGuardian {
        if (cancelledVouchers[opnetNonce]) return;
        cancelledVouchers[opnetNonce] = true;
        emit VoucherCancelled(opnetNonce, msg.sender);
    }

    /// @notice Recover the unvested portion of a Mode 4 claim whose source
    ///         voucher has been cancelled. Forwards to the flow's
    ///         `VestingVault.clawback`: the vault pays vested-so-far to the
    ///         beneficiary and returns the unvested remainder to this
    ///         contract. Re-credits `flow.inventory` so the release ledger
    ///         tracks the actual balance held.
    /// @dev    HIGH-001 follow-through for Mode 4 reorg handling. The
    ///         documented incident flow assumed callers could invoke the
    ///         vault directly, but `VestingVault.clawback` is `onlyBridge`
    ///         — without this forwarder no role can recover the tokens.
    ///         Voucher MUST be cancelled first: clawback is an incident-
    ///         response action, not a casual revoke. The cap check is
    ///         deliberately skipped — this restores funds that came out of
    ///         the flow's pool at claim time, not a new deposit. Gated
    ///         `onlyOwnerOrGuardian` (same lattice as `cancelVoucher` /
    ///         `pause`), `nonReentrant`. The vault is a trusted,
    ///         reentrancy-guarded custodian deployed by us — calling it
    ///         before the inventory write is safe and required to know
    ///         the returned amount.
    function clawbackVestedClaim(
        bytes32 flowId,
        address beneficiary,
        bytes32 opnetNonce
    )
        external
        onlyOwnerOrGuardian
        nonReentrant
    {
        FlowRecord storage flow = flows[flowId];
        if (flow.evmChainId == 0) revert FlowNotFound();
        if (flow.mode != uint8(TokenMode.POOLED_LOCK_VEST)) revert WrongMode();
        address vault = flow.vestingVault;
        if (vault == address(0)) revert VestingVaultNotSet();
        if (!cancelledVouchers[opnetNonce]) revert VoucherNotCancelled();

        // Interaction — vault transfers vested-so-far to beneficiary and
        // returns unvested remainder to msg.sender (this contract).
        uint128 returned = IVestingVault(vault).clawback(beneficiary, opnetNonce);

        // Effect — restore the flow ledger. Cap is intentionally not
        // re-enforced: a governor lowering cap between claim and clawback
        // must not be able to brick recovery.
        if (returned > 0) {
            flow.inventory = flow.inventory + returned;
        }

        emit VestedClaimClawedBack(flowId, beneficiary, opnetNonce, returned, msg.sender);
    }

    // ---------------------------------------------------------------------
    // Admin — token allowlist + pause + treasury/guardian
    // ---------------------------------------------------------------------

    function setSupportedToken(address token, bool enabled) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        supportedToken[token] = enabled;
        emit SupportedTokenUpdated(token, enabled);
    }

    /// @notice Protective freeze. Callable by owner, guardian, OR the
    ///         dedicated `pauser` role — the widest incident-response surface.
    ///         `unpause` deliberately stays narrower (owner/guardian only).
    function pause() external {
        if (msg.sender != owner() && msg.sender != guardian && msg.sender != pauser) {
            revert NotGuardian();
        }
        _pause();
    }

    /// @notice Resume. OWNER-ONLY (audit H-01). The guardian and `pauser`
    ///         roles can freeze for incident response but must never re-open
    ///         the bridge — resumption is a deliberate governance decision
    ///         (timelock-gated on mainnet), so a compromised incident-response
    ///         key cannot thaw a legitimate freeze.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Set/rotate/disable the dedicated pause role.
    /// @dev    Owner-only (timelock-gated on mainnet). Zero address disables.
    function setPauser(address newPauser) external onlyOwner {
        pauser = newPauser;
        emit PauserSet(newPauser);
    }

    /// @notice Set or rotate the emergency-drain destination.
    /// @dev    Owner-rotatable (was set-once pre-roles PR). On mainnet `owner`
    ///         is the 3-day TimelockController, so rotation is timelock-gated
    ///         (the timelock IS the staging step). H-3 (audit 2026-05-27):
    ///         emits the OLD treasury alongside the new for full audit-trail
    ///         readability — a forgotten or accidental rotation now shows up
    ///         with both values in the indexer. If EOA owners are ever used,
    ///         consider adding an explicit `startTreasuryTransfer` /
    ///         `acceptTreasury` 2-step on top (see `treasury` storage doc).
    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert ZeroAddress();
        address old = treasury;
        treasury = newTreasury;
        emit TreasurySet(old, newTreasury);
    }

    /// @notice Set or rotate the guardian (incident-response co-signer).
    /// @dev    Owner-rotatable (was set-once pre-roles PR). Timelock-gated on
    ///         mainnet (3 days). H-3 — emits old + new for audit-trail parity
    ///         with `setTreasury`. Same 2-step follow-up consideration applies.
    function setGuardian(address newGuardian) external onlyOwner {
        if (newGuardian == address(0)) revert ZeroAddress();
        address old = guardian;
        guardian = newGuardian;
        emit GuardianSet(old, newGuardian);
    }

    /// @notice Update the unwrap fee bps. Capped at `MAX_FEE_BPS = 1000`
    ///         (10%) so a compromised governor cannot trap user funds
    ///         via fee inflation.
    /// @param bps Fee in basis points (1 bp = 0.01%). Pass 0 to disable.
    function setUnwrapFeeBps(uint256 bps) external onlyOwner {
        if (bps > MAX_FEE_BPS) revert FeeBpsTooHigh();
        uint256 old = unwrapFeeBps;
        unwrapFeeBps = bps;
        emit UnwrapFeeBpsSet(old, bps);
    }

    /// @notice Set the per-token minimum unwrap fee. Whichever is higher
    ///         between bps-derived and minFee is the actual fee charged.
    ///         No cap on minFee — keep it well below typical user amounts.
    function setUnwrapMinFee(address token, uint256 amount) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        unwrapMinFee[token] = amount;
        emit UnwrapMinFeeSet(token, amount);
    }

    // ---------------------------------------------------------------------
    // Modal extensions — modes 2 + 3 (INVERSE_WRAPPED + NATIVE_BURN_MINT)
    // ---------------------------------------------------------------------

    /// @notice Claim a mode-2/3 mint authorised by the M-of-N signer set.
    ///         Mints `intent.amount` WrappedERC20 tokens (the
    ///         `intent.wrappedToken` contract) to `intent.to`.
    /// @dev    EIP-712 typehash is `MINT_INTENT_TYPEHASH` (different from
    ///         the mode-1 `RELEASE_INTENT_TYPEHASH`); a sig signed for one
    ///         cannot be replayed against the other. Replay protection
    ///         shares the existing `signaturesUsed` and `usedSourceEvent`
    ///         maps with `claim()` — opnetNonce + (opnetTxHash,
    ///         opnetEventIndex) are globally unique on OPNet so no
    ///         collision risk between flows.
    function claimMintWrapped(MintIntent calldata intent, bytes calldata sig)
        external
        whenNotPaused
        nonReentrant
    {
        if (!supportedToken[intent.wrappedToken]) revert TokenNotSupported();
        if (intent.to == address(0)) revert InvalidRecipient();
        if (intent.amount == 0) revert AmountZero();
        if (intent.srcChainId != expectedOpnetChainId) revert InvalidSrcChainId();
        if (intent.signerEpoch != currentEpoch) revert InvalidSignerEpoch();
        // #49 — cancellation checked BEFORE replay, matching the OPNet
        // claimMintWithVoucher order. For a cancelled-then-claimed voucher
        // this surfaces VoucherCancelled_ instead of masking it as
        // AlreadyClaimed, which speeds incident triage.
        if (cancelledVouchers[intent.opnetNonce]) revert VoucherCancelled_();
        if (signaturesUsed[intent.opnetNonce]) revert AlreadyClaimed();
        if (usedSourceEvent[intent.opnetTxHash][intent.opnetEventIndex]) {
            revert SourceEventAlreadyUsed();
        }

        bytes32 structHash = _hashMintIntent(intent);
        bytes32 digest = _hashTypedDataV4(structHash);

        _verifySignatures(digest, sig);

        // PR β.2.payout-evm++ — flow binding. The voucher commits to a
        // specific flowId via MINT_INTENT_TYPEHASH. Look it up after
        // sig-verify (so unauthenticated callers can't spam flow
        // lookups) and assert: (1) the flow exists, (2) its mode is one
        // of the mint-on-EVM modes, (3) the wrappedToken in the voucher
        // matches the flow's evmToken — prevents a sig signed for one
        // wrapped from being replayed against a different wrapped.
        FlowRecord storage flow = flows[intent.flowId];
        if (flow.evmChainId == 0) revert FlowNotFound();
        if (flow.mode != uint8(TokenMode.INVERSE_WRAPPED) && flow.mode != uint8(TokenMode.NATIVE_BURN_MINT)) {
            revert WrongMode();
        }
        if (flow.evmToken != intent.wrappedToken) revert WrongMode();
        if (flow.status != FLOW_STATUS_ACTIVE && flow.status != FLOW_STATUS_DRAINING) {
            revert FlowNotActive();
        }

        // MED-001 — the mint-on-EVM path previously enforced NO flow
        // limits, so a compromised signer faced no per-window bound.
        // Apply minAmount + rolling-window dailyLimit, keyed on the minted
        // amount. (Per-mode `cap`/`inventory` accounting for mint-on-EVM
        // flows is deliberately not added here — it is entangled with the
        // mode-1/2 inventory-semantics question in #44 and is tracked
        // there; dailyLimit is the substantive bad-signer bound.)
        _consumeMintFlowLimits(flow, intent.amount);

        // Effects BEFORE interaction (CEI).
        signaturesUsed[intent.opnetNonce] = true;
        usedSourceEvent[intent.opnetTxHash][intent.opnetEventIndex] = true;

        emit WrappedMintedFromVoucher(
            intent.wrappedToken,
            intent.to,
            intent.amount,
            intent.opnetNonce
        );

        IWrappedERC20(intent.wrappedToken).mintFromBridge(intent.to, intent.amount);
    }

    /// @notice #55 — trustless burn-side recovery (MINT-AUTHORITY PRIMITIVE).
    ///         Symmetric EVM counterpart to OPNet `BridgeDepository.refundBurn`.
    ///         When a `WrappedERC20` burn's OPNet destination voucher is
    ///         PERMANENTLY cancelled (reorg/fraud) the burned tokens are gone
    ///         AND the destination never pays. This RE-MINTS the burned
    ///         `amount` back to the original `burner`, gated by an M-of-N
    ///         EIP-712 attestation from the SAME signer set that signs
    ///         vouchers — they attest off-chain that the burn is final AND the
    ///         destination voucher is cancelled-and-final.
    ///
    /// @dev    Permissionless to *call* — the tokens always go to the
    ///         signer-attested `intent.burner`, so anyone may submit the blob.
    ///         M-5 — IS pause-gated (`whenNotPaused`). Unlike
    ///         `markDepositRefundable` / `refundLockedDeposit` which return
    ///         user PRINCIPAL during a freeze (no new asset created),
    ///         `refundBurn` is a MINT primitive and pause halts mint authority
    ///         system-wide (mirrors OPNet `requireNotPaused`).
    ///
    ///         Replay guard: `keccak256(abi.encode(burnTxHash, burnNonce))` is
    ///         set BEFORE the cross-contract mint (CEI) — the ONLY protection
    ///         against a double / infinite re-mint. `nonReentrant` backstops
    ///         the external `mintFromBridge` call.
    ///
    ///         `sig` is the same `[uint8 numSigs][sig(65)]…` M-of-N blob that
    ///         `claim`/`claimMintWrapped` consume, verified over the EIP-712
    ///         digest of the BurnRefundAuthorization. Binding mirrors the
    ///         claimMintWrapped flow checks: wrappedToken allowlisted +
    ///         bridge-mintable; flow exists + ACTIVE/DRAINING + its evmToken
    ///         binds the wrapped (so a sig for one wrapped can't be replayed
    ///         against another).
    function refundBurn(BurnRefundAuthorization calldata intent, bytes calldata sig)
        external
        nonReentrant
        whenNotPaused
    {
        if (intent.burner == address(0)) revert InvalidRecipient();
        if (intent.amount == 0) revert AmountZero();
        if (intent.signerEpoch != currentEpoch) revert InvalidSignerEpoch();
        if (!supportedToken[intent.wrappedToken]) revert TokenNotSupported();

        // Per-burn replay key. Computed before any sig work so the revert
        // surface is stable and cheap for an already-refunded burn.
        // M-4 — bind wrappedToken + burner into the replay key. burnNonce is
        // per-`WrappedERC20` (see WrappedERC20.burnNonce), so two different
        // wrappeds can produce overlapping (txHash, nonce) pairs and one
        // legitimate refund would otherwise permanently block the other.
        bytes32 burnId = keccak256(
            abi.encode(intent.wrappedToken, intent.burner, intent.burnTxHash, intent.burnNonce)
        );
        if (refundedBurns[burnId]) revert BurnAlreadyRefunded();

        // Verify the M-of-N attestation over the EIP-712 digest. Done before
        // the flow lookup so unauthenticated callers can't spam flow reads.
        bytes32 digest = _hashTypedDataV4(_hashBurnRefundAuth(intent));
        _verifySignatures(digest, sig);

        // Flow binding — mirrors claimMintWrapped. The attestation commits to
        // a flowId; assert (1) it exists, (2) it is a mint-on-EVM mode (the
        // bridge can only re-mint where it is the minter), (3) the wrapped in
        // the attestation matches the flow's evmToken, (4) the flow is live.
        FlowRecord storage flow = flows[intent.flowId];
        if (flow.evmChainId == 0) revert FlowNotFound();
        if (flow.mode != uint8(TokenMode.INVERSE_WRAPPED) && flow.mode != uint8(TokenMode.NATIVE_BURN_MINT)) {
            revert WrongMode();
        }
        if (flow.evmToken != intent.wrappedToken) revert WrongMode();
        // M-3 (audit 2026-05-27) — tighten to ACTIVE-only. A DRAINING flow is
        // intentionally winding down (no new locks/mints, see L214); allowing
        // `refundBurn` against a DRAINING flow lets a (potentially compromised)
        // signer set continue minting into a route that was deliberately
        // marked for shutdown. Recovery for a burn whose flow has gone DRAINING
        // is an operator decision — resume the flow briefly, refund, then
        // re-drain.
        if (flow.status != FLOW_STATUS_ACTIVE) {
            revert FlowNotActive();
        }

        // H-1 — the mint-on-EVM `claimMintWrapped` path enforces minAmount +
        // rolling-window dailyLimit via `_consumeMintFlowLimits` (MED-001)
        // precisely to bound how much a compromised signer can mint per 24h.
        // `refundBurn` is the OTHER signer-attested mint primitive on this
        // contract and must share the same bound, or it becomes an unbounded
        // mint hole. Keyed on the minted `amount` (matches the helper's
        // contract). `whenNotPaused` is a global freeze, not a rolling bound.
        _consumeMintFlowLimits(flow, intent.amount);

        // Effects BEFORE interaction (CEI): set the replay flag, then mint.
        refundedBurns[burnId] = true;

        emit BurnRefunded(burnId, intent.burner, intent.wrappedToken, intent.amount);

        IWrappedERC20(intent.wrappedToken).mintFromBridge(intent.burner, intent.amount);
    }

    // ---------------------------------------------------------------------
    // Mode-4 inventory provisioning (POOLED_LOCK_RELEASE)
    // ---------------------------------------------------------------------

    /// @notice Add inventory to a specific flow's EVM-side pool. Used for
    ///         POOLED_LOCK_RELEASE tokens (e.g. MOTO) where the project
    ///         pre-funds the pool so users can claim against OPNet locks
    ///         before any reverse flow has happened, and for topping up a
    ///         WRAPPED flow's release pool.
    /// @dev    #44 — provisioning is now FLOW-SCOPED and atomic: the
    ///         transferred tokens AND `flow.inventory` move together, so
    ///         the balance the bridge holds and the accounting that
    ///         `claim()` checks can never drift. The previous
    ///         `provisionInventory(token, amount)` moved tokens but never
    ///         touched `flow.inventory`, so pooled-flow claims reverted
    ///         `InsufficientFlowInventory` even though the funds existed.
    ///         Caller must `approve(bridge, amount)` first; balance-delta
    ///         survives fee-on-transfer / non-canonical ERC20s. Only
    ///         release-pool modes (WRAPPED / POOLED_LOCK_RELEASE) have an
    ///         EVM-side inventory — mint-on-EVM modes are rejected.
    function provisionInventory(bytes32 flowId, uint256 amount) external onlyOwner nonReentrant {
        if (amount == 0) revert AmountZero();
        FlowRecord storage flow = flows[flowId];
        if (flow.evmChainId == 0) revert FlowNotFound();
        if (
            flow.mode != uint8(TokenMode.WRAPPED)
            && flow.mode != uint8(TokenMode.POOLED_LOCK_RELEASE)
            && flow.mode != uint8(TokenMode.POOLED_LOCK_VEST)
        ) {
            revert WrongMode();
        }
        // Mode 4 — prevent provisioning a flow whose VestingVault hasn't
        // been wired yet. Symmetric to the lock-side guard; closes the
        // last path that could otherwise sit inventory on a half-set-up
        // flow.
        if (flow.mode == uint8(TokenMode.POOLED_LOCK_VEST) && flow.vestingVault == address(0)) {
            revert VestingVaultNotSet();
        }

        address token = flow.evmToken;
        IERC20 erc20 = IERC20(token);
        uint256 balBefore = erc20.balanceOf(address(this));
        erc20.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received;
        unchecked {
            received = erc20.balanceOf(address(this)) - balBefore;
        }
        if (received == 0) revert NothingReceived();
        if (received > type(uint128).max) revert FlowCapExceeded();

        // Atomic: tokens in AND accounting up, in the same call.
        uint256 newInventory = uint256(flow.inventory) + received;
        if (newInventory > uint256(flow.cap)) revert FlowCapExceeded();
        flow.inventory = uint128(newInventory);

        emit InventoryProvisioned(flowId, token, msg.sender, received);
    }

    /// @notice Drain a flow's inventory back to the set-once `treasury`.
    ///         For orderly wind-down of a flow's pool (de-listing, bridge
    ///         migration) — not incident response (`emergencyWithdraw`).
    /// @dev    #44 — flow-scoped: decrements `flow.inventory` by the drained
    ///         amount so accounting tracks the balance. onlyGuardian +
    ///         whenPaused — same trust model as `emergencyWithdraw`.
    ///         CEI: checks → inventory effect → token transfer.
    function drainInventory(bytes32 flowId, uint256 amount)
        external
        nonReentrant
        whenPaused
    {
        if (msg.sender != guardian) revert NotGuardian();
        if (treasury == address(0)) revert TreasuryNotSet();
        if (amount == 0) revert AmountZero();
        FlowRecord storage flow = flows[flowId];
        if (flow.evmChainId == 0) revert FlowNotFound();
        if (uint256(flow.inventory) < amount) revert InsufficientFlowInventory();

        address token = flow.evmToken;
        unchecked {
            flow.inventory = flow.inventory - uint128(amount);
        }
        emit InventoryDrained(flowId, token, treasury, amount, msg.sender);
        IERC20(token).safeTransfer(treasury, amount);
    }

    function emergencyWithdraw(address token, uint256 amount)
        external
        nonReentrant
        whenPaused
    {
        if (msg.sender != guardian) revert NotGuardian();
        if (token == address(0)) revert ZeroAddress();
        if (treasury == address(0)) revert TreasuryNotSet();
        if (amount == 0) revert AmountZero();
        emit EmergencyWithdraw(token, treasury, amount, msg.sender);
        IERC20(token).safeTransfer(treasury, amount);
    }

    /// @notice Withdraw accrued source-side bridge fees for a flow to the
    ///         set-once `treasury`. This is the ROUTINE revenue-collection
    ///         path — unlike `emergencyWithdraw` it does NOT require the
    ///         bridge to be paused, so fees can be swept during normal
    ///         operation.
    /// @dev    The recipient is ALWAYS `treasury` — never an arbitrary
    ///         address. The withdrawable amount is bounded by the per-flow
    ///         `accruedFees` accumulator (incremented in `_bumpLockInventory`
    ///         by exactly the fee portion of each lock); this bound is the
    ///         entire safety property. There is NO "withdraw excess balance"
    ///         fallback — a withdrawal can never reach into user-locked
    ///         principal or another flow's reserves.
    ///         Gated `onlyOwnerOrGuardian` (same role lattice as `pause` /
    ///         `cancelVoucher`), `nonReentrant`, strict CEI.
    function withdrawFees(bytes32 flowId, uint256 amount)
        external
        onlyOwnerOrGuardian
        nonReentrant
    {
        if (treasury == address(0)) revert TreasuryNotSet();
        FlowRecord storage flow = flows[flowId];
        if (flow.evmChainId == 0) revert FlowNotFound();
        if (amount == 0) revert AmountZero();
        if (amount > uint256(flow.accruedFees)) revert InsufficientAccruedFees();

        // Effects (CEI): decrement the accumulator before the transfer.
        unchecked {
            flow.accruedFees = flow.accruedFees - uint128(amount);
        }

        address token = flow.evmToken;
        emit FeesWithdrawn(flowId, token, treasury, amount);

        // Interaction.
        IERC20(token).safeTransfer(treasury, amount);
    }

    // ---------------------------------------------------------------------
    // Flow Registry — governance (PR α)
    // ---------------------------------------------------------------------

    /// @notice Compute the canonical flowId for a route. Anyone can call;
    ///         used by tooling + tests. The exact same hash is computed on
    ///         the OPNet side over the same byte order so a single 32-byte
    ///         identifier names a route end-to-end.
    function computeFlowId(
        uint8 mode,
        uint64 evmChainId,
        address evmBridge,
        address evmToken,
        bytes32 opnetBridge,
        bytes32 opnetToken
    ) public pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                mode,
                evmChainId,
                evmBridge,
                evmToken,
                opnetBridge,
                opnetToken
            )
        );
    }

    /// @notice Inputs to `addFlow`. Bundled in a struct to keep the call
    ///         under the Solidity stack-depth limit. Output / hot fields
    ///         (`mintedToday`, `lastWindowStart`, `inventory`, plus `status`
    ///         which always starts active) are not caller-supplied.
    struct FlowAddParams {
        uint8   mode;
        uint64  evmChainId;
        address evmBridge;
        address evmToken;
        uint8   evmDecimals;
        bytes32 opnetBridge;
        bytes32 opnetToken;
        uint8   opnetDecimals;
        uint16  feeBps;
        uint128 minFee;
        uint128 minAmount;
        uint128 cap;
        uint128 dailyLimit;
        uint16  tipCapBps;
    }

    /// @notice Register a new flow. Governor-only — production deploys
    ///         route this through the Safe + 48h TimelockController.
    ///         Set-once for all immutable fields. Initial status is active.
    /// @dev    `mintedToday`, `lastWindowStart`, `inventory` start at 0.
    ///         Caller is responsible for picking sane initial cap /
    ///         dailyLimit / minAmount / fee values; bps is hard-capped at
    ///         MAX_FEE_BPS (10%).
    function addFlow(FlowAddParams calldata p) external onlyOwner returns (bytes32 flowId) {
        if (p.mode > uint8(TokenMode.POOLED_LOCK_VEST)) revert FlowInvalidMode();
        if (p.evmChainId == 0) revert FlowZeroChainId();
        if (p.evmBridge == address(0) || p.evmToken == address(0)) revert ZeroAddress();
        if (p.opnetBridge == bytes32(0) || p.opnetToken == bytes32(0)) revert ZeroAddress();
        if (p.evmDecimals == 0 || p.evmDecimals > 30) revert FlowInvalidDecimals();
        if (p.opnetDecimals == 0 || p.opnetDecimals > 30) revert FlowInvalidDecimals();
        if (p.feeBps > MAX_FEE_BPS) revert FeeBpsTooHigh();
        if (p.tipCapBps > MAX_TIP_BPS) revert TipCapTooHigh();
        // #62-fix — if `minAmount` is set, it MUST exceed `minFee`. Otherwise
        // the public-facing minimum advertises a usable amount that `lock`
        // would reject with `FeeExceedsAmount` (because `fee >= received`).
        // `minAmount == 0` is the explicit "no-floor" config and is allowed.
        if (p.minAmount > 0 && p.minAmount <= p.minFee) revert FlowMinAmountBelowMinFee();
        // Mode 4 (POOLED_LOCK_VEST) is two-step: addFlow registers the route,
        // `setFlowVestingVault` then wires the destination VestingVault before
        // any user-facing path becomes safe. The lock and claim paths both
        // defensively check `vestingVault != 0` for mode 4, so a half-set-up
        // flow rejects locks/claims rather than silently stranding tokens.

        flowId = computeFlowId(
            p.mode, p.evmChainId, p.evmBridge, p.evmToken, p.opnetBridge, p.opnetToken
        );

        // Set-once: an existing record with non-zero chainId means the
        // flowId is already taken. Use chainId as the existence flag
        // because addFlow rejects chainId==0.
        if (flows[flowId].evmChainId != 0) revert FlowAlreadyExists();

        FlowRecord storage f = flows[flowId];
        f.mode = p.mode;
        f.status = FLOW_STATUS_ACTIVE;
        f.evmChainId = p.evmChainId;
        f.evmBridge = p.evmBridge;
        f.evmToken = p.evmToken;
        f.evmDecimals = p.evmDecimals;
        f.opnetDecimals = p.opnetDecimals;
        f.opnetBridge = p.opnetBridge;
        f.opnetToken = p.opnetToken;
        f.feeBps = p.feeBps;
        f.minFee = p.minFee;
        f.minAmount = p.minAmount;
        f.cap = p.cap;
        f.dailyLimit = p.dailyLimit;
        f.tipCapBps = p.tipCapBps;
        // f.vestingVault remains address(0); mode 4 flows must call
        // setFlowVestingVault before users can lock/claim against them.
        // mintedToday, lastWindowStart, inventory remain 0.

        allFlowIds.push(flowId);
        flowsByEvmToken[p.evmToken].push(flowId);
        flowsByMode[p.mode].push(flowId);
        flowsByEvmChain[p.evmChainId].push(flowId);

        // Auto-whitelist the EVM token. Pre-storage-cleanup this was
        // `setTokenMode`'s job; with flow registry as source of truth,
        // a registered flow IS the registration. Subsequent flows for
        // the same evmToken (different modes / opnetTokens) are
        // idempotent here.
        if (!supportedToken[p.evmToken]) {
            supportedToken[p.evmToken] = true;
            emit SupportedTokenUpdated(p.evmToken, true);
        }

        emit FlowAdded(flowId, p.mode, p.evmChainId, p.evmToken, p.opnetToken);
    }

    /// @notice Guardian-only protective freeze. Immediate (no timelock)
    ///         so a compromise can be quarantined fast. Only valid from
    ///         the active state.
    function pauseFlow(bytes32 flowId) external {
        if (msg.sender != guardian) revert NotGuardian();
        FlowRecord storage f = flows[flowId];
        if (f.evmChainId == 0) revert FlowNotFound();
        if (f.status != FLOW_STATUS_ACTIVE) revert FlowInvalidStatusTransition();
        emit FlowStatusChanged(flowId, f.status, FLOW_STATUS_PAUSED);
        f.status = FLOW_STATUS_PAUSED;
    }

    /// @notice Governor-only resume — flips paused → active.
    function resumeFlow(bytes32 flowId) external onlyOwner {
        FlowRecord storage f = flows[flowId];
        if (f.evmChainId == 0) revert FlowNotFound();
        if (f.status != FLOW_STATUS_PAUSED) revert FlowInvalidStatusTransition();
        emit FlowStatusChanged(flowId, f.status, FLOW_STATUS_ACTIVE);
        f.status = FLOW_STATUS_ACTIVE;
    }

    /// @notice Governor-only — start winding a route down. Permitted from
    ///         active or paused. Once draining, the only forward path is
    ///         disabled (after inventory hits zero) — no resume back to
    ///         active. Consumed by PR γ: claim/release allowed; lock/mint
    ///         rejected.
    function drainFlow(bytes32 flowId) external onlyOwner {
        FlowRecord storage f = flows[flowId];
        if (f.evmChainId == 0) revert FlowNotFound();
        if (f.status != FLOW_STATUS_ACTIVE && f.status != FLOW_STATUS_PAUSED) {
            revert FlowInvalidStatusTransition();
        }
        emit FlowStatusChanged(flowId, f.status, FLOW_STATUS_DRAINING);
        f.status = FLOW_STATUS_DRAINING;
    }

    /// @notice Governor-only — adjust the per-flow inventory ceiling.
    ///         Cannot drop the cap below current inventory (would brick
    ///         existing locks).
    function setFlowCap(bytes32 flowId, uint128 newCap) external onlyOwner {
        FlowRecord storage f = flows[flowId];
        if (f.evmChainId == 0) revert FlowNotFound();
        if (newCap < f.inventory) revert FlowCapBelowInventory();
        emit FlowCapChanged(flowId, f.cap, newCap);
        f.cap = newCap;
    }

    /// @notice Governor-only — adjust the per-flow rolling 24h limit.
    ///         No floor: setting to zero disables new mints (paired with
    ///         pause/drain for soft-shutdown UX).
    function setFlowDailyLimit(bytes32 flowId, uint128 newLimit) external onlyOwner {
        FlowRecord storage f = flows[flowId];
        if (f.evmChainId == 0) revert FlowNotFound();
        emit FlowDailyLimitChanged(flowId, f.dailyLimit, newLimit);
        f.dailyLimit = newLimit;
    }

    /// @notice Governor-only — adjust the per-flow minimum source-side
    ///         amount. Helps reject dust deposits that wouldn't pay their
    ///         own gas back out.
    function setFlowMinAmount(bytes32 flowId, uint128 newMin) external onlyOwner {
        FlowRecord storage f = flows[flowId];
        if (f.evmChainId == 0) revert FlowNotFound();
        // #62-fix — preserve the addFlow invariant: a non-zero minAmount
        // must exceed minFee, otherwise the smallest lock at the advertised
        // floor reverts with FeeExceedsAmount.
        if (newMin > 0 && newMin <= f.minFee) revert FlowMinAmountBelowMinFee();
        emit FlowMinAmountChanged(flowId, f.minAmount, newMin);
        f.minAmount = newMin;
    }

    /// @notice Governor-only — adjust per-flow fee parameters. Hard-capped
    ///         at MAX_FEE_BPS (10%).
    function setFlowFee(bytes32 flowId, uint16 newBps, uint128 newMinFee) external onlyOwner {
        if (newBps > MAX_FEE_BPS) revert FeeBpsTooHigh();
        FlowRecord storage f = flows[flowId];
        if (f.evmChainId == 0) revert FlowNotFound();
        // #62-fix — preserve the addFlow invariant: if a positive minAmount
        // is configured, it must still strictly exceed the (possibly new)
        // minFee. Raising minFee at or above an existing minAmount would
        // brick every lock at the floor.
        if (f.minAmount > 0 && f.minAmount <= newMinFee) revert FlowMinAmountBelowMinFee();
        emit FlowFeeChanged(flowId, f.feeBps, newBps, f.minFee, newMinFee);
        f.feeBps = newBps;
        f.minFee = newMinFee;
    }

    /// @notice Governor-only — adjust the per-flow permissionless relayer
    ///         tip cap. 0 = tipping disabled. Hard-capped at MAX_TIP_BPS
    ///         (2%). PR β.2.scaffold lays storage + governance only —
    ///         actual tip payout wiring lands in a follow-up PR.
    function setFlowTipCap(bytes32 flowId, uint16 newBps) external onlyOwner {
        if (newBps > MAX_TIP_BPS) revert TipCapTooHigh();
        FlowRecord storage f = flows[flowId];
        if (f.evmChainId == 0) revert FlowNotFound();
        emit FlowTipCapUpdated(flowId, f.tipCapBps, newBps);
        f.tipCapBps = newBps;
    }

    /// @notice Governor-only — repoint the destination VestingVault for a
    ///         POOLED_LOCK_VEST flow. Restricted to mode 4 flows so a
    ///         non-vest flow can't accidentally acquire a vault. The new
    ///         vault must be non-zero — to disable a mode 4 flow entirely
    ///         the governor uses pause/drain, not a zero-vault setter.
    /// @dev    Live re-pointing affects only NEW claims; schedules already
    ///         opened in the previous vault continue to vest there and the
    ///         beneficiary keeps claiming from that one. Operational
    ///         guidance: pause → wait for in-flight vouchers to drain →
    ///         repoint → unpause.
    function setFlowVestingVault(bytes32 flowId, address newVault) external onlyOwner {
        if (newVault == address(0)) revert VestingVaultRequired();
        FlowRecord storage f = flows[flowId];
        if (f.evmChainId == 0) revert FlowNotFound();
        if (f.mode != uint8(TokenMode.POOLED_LOCK_VEST)) revert VestingVaultNotPermitted();
        // Defense-in-depth — the vault's immutable underlying asset MUST be
        // this flow's `evmToken`. Without this check, a governor that wires
        // a vault holding a *different* token would silently let the claim
        // path approve token-A, while the vault's `depositFor` then pulls
        // token-B from the bridge — draining a different flow's pool into
        // the wrong vault. Cheap to enforce, closes the misconfiguration.
        if (address(IVestingVault(newVault).token()) != f.evmToken) revert VestingVaultTokenMismatch();
        emit FlowVestingVaultChanged(flowId, f.vestingVault, newVault);
        f.vestingVault = newVault;
    }

    /// @notice Read-only accessor — returns the full FlowRecord. Easier
    ///         to consume from off-chain than the auto-generated public
    ///         mapping getter (which only returns the tuple).
    function getFlow(bytes32 flowId) external view returns (FlowRecord memory) {
        return flows[flowId];
    }

    /// @notice Read-only existence check.
    function flowExists(bytes32 flowId) external view returns (bool) {
        return flows[flowId].evmChainId != 0;
    }

    /// @notice Total registered flows (lifetime — includes disabled).
    function flowCount() external view returns (uint256) {
        return allFlowIds.length;
    }

    // ---------------------------------------------------------------------
    // UUPS
    // ---------------------------------------------------------------------

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    function _hashIntent(ReleaseIntent calldata intent) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    RELEASE_INTENT_TYPEHASH,
                    intent.token,
                    intent.to,
                    intent.amount,
                    intent.srcChainId,
                    intent.opnetTxHash,
                    intent.opnetEventIndex,
                    intent.burnNonce,
                    intent.signerEpoch,
                    intent.opnetNonce,
                    intent.grossSrcAmount,
                    intent.relayerTip,
                    intent.flowId
                )
            );
    }

    function _hashMintIntent(MintIntent calldata intent) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    MINT_INTENT_TYPEHASH,
                    intent.wrappedToken,
                    intent.to,
                    intent.amount,
                    intent.srcChainId,
                    intent.opnetTxHash,
                    intent.opnetEventIndex,
                    intent.burnNonce,
                    intent.signerEpoch,
                    intent.opnetNonce,
                    intent.flowId
                )
            );
    }

    function _hashRefundAuth(uint256 depositNonce_, bytes32 flowId, uint32 signerEpoch)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    REFUND_AUTHORIZATION_TYPEHASH,
                    depositNonce_,
                    flowId,
                    signerEpoch
                )
            );
    }

    function _hashBurnRefundAuth(BurnRefundAuthorization calldata intent)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    BURN_REFUND_AUTHORIZATION_TYPEHASH,
                    intent.burner,
                    intent.wrappedToken,
                    intent.amount,
                    intent.burnNonce,
                    intent.burnTxHash,
                    intent.burnBlockHash,
                    intent.flowId,
                    intent.signerEpoch
                )
            );
    }

    /// @notice EIP-712 digest for a RefundAuthorization — the server signs
    ///         this to build the M-of-N attestation, and tests verify it.
    function hashRefundAuthorization(
        uint256 depositNonce_,
        bytes32 flowId,
        uint32 signerEpoch
    ) external view returns (bytes32) {
        return _hashTypedDataV4(_hashRefundAuth(depositNonce_, flowId, signerEpoch));
    }
}
