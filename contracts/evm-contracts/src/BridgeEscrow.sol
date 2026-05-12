// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

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
        POOLED_LOCK_RELEASE
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

    /// @notice PR γ.2c — minimum elapsed time between a `lock` and the
    ///         permissionless `refundLockedDeposit` escape hatch. 7 days.
    ///         Hard-coded (not governor-settable) so a hostile governor
    ///         cannot extend the window indefinitely and brick user
    ///         refunds, and cannot shrink it to enable a refund + claim
    ///         double-spend race against an in-flight voucher.
    uint64 public constant REFUND_TIMEOUT = 7 days;

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
        uint8   mode;             // 0=WRAPPED, 1=INVERSE_WRAPPED, 2=NATIVE_BURN_MINT, 3=POOLED_LOCK_RELEASE
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
        uint128 cap;              // total inventory ceiling (mode 0/3) or mint ceiling (mode 2)
        uint128 dailyLimit;       // per-flow rolling window
        // Hot fields written by claim/release in PR γ:
        uint128 mintedToday;
        uint64  lastWindowStart;
        uint128 inventory;        // mode 0/3: locked tokens; mode 2: synthetic supply
        // PR β.2 — per-flow permissionless relayer tip cap.
        // 0 = tipping disabled (default); cap is per-flow,
        // ≤ MAX_TIP_BPS = 200 (2%); governor-set.
        uint16  tipCapBps;
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

    /// @notice Guardian — gates `emergencyWithdraw` (alongside `whenPaused`).
    ///         Set-once via `setGuardian`.
    address public guardian;

    /// @notice Set-once destination for `emergencyWithdraw`. Once non-zero,
    ///         cannot be changed — prevents redirection by a compromised owner.
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

    // ─── PR γ.2c — permissionless refund storage ────────────────────────

    /// @notice On-chain record of every successful `lock` call. Indexed by
    ///         the per-deposit nonce returned by `lock`. Allows the
    ///         original depositor to call `refundLockedDeposit` after
    ///         `REFUND_TIMEOUT` has elapsed if the OPNet side never
    ///         minted (signer offline, voucher invalidated by signer
    ///         rotation, M-of-N never reached, etc.).
    /// @dev    Layout: `user (160) + lockedAt (64) + refunded (8) = 232 bits`
    ///         packs into one slot; `amount (uint128)` in the second slot
    ///         alongside `flowId (bytes32)` in the third slot. Slot count
    ///         in the top-level layout: 1 (the mapping itself).
    struct LockRecord {
        address user;       // original depositor — refund destination
        uint64  lockedAt;   // block.timestamp at lock time
        bool    refunded;   // idempotency guard
        uint128 amount;     // post-balance-delta received amount (refund value)
        address token;      // ERC-20 to send back
        bytes32 flowId;     // for inventory decrement on refund
    }

    /// @notice depositNonce → LockRecord. Set in `lock`, consumed in
    ///         `refundLockedDeposit`. Permissionless refund path.
    mapping(uint256 => LockRecord) public lockedDeposits;

    /// @dev Reserved for future appends. New slots go BEFORE the gap and the
    ///      gap shrinks by the same count to preserve layout.
    ///      Slots past treasury: unwrapFeeBps + unwrapMinFee + flows +
    ///      allFlowIds + flowsByEvmToken + flowsByMode + flowsByEvmChain +
    ///      lockedDeposits = 8. (Legacy tokenMode + opnetCounterpartOf +
    ///      _tokenModeFinalized were removed pre-mainnet; flow registry is
    ///      the source of truth for mode + OPNet counterpart binding.)
    ///      50 - 8 = 42.
    uint256[42] private __gap;

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
    event LockedToFlow(
        bytes32 indexed flowId,
        address indexed user,
        address indexed token,
        uint256 amount
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

    event TreasurySet(address indexed treasury);
    event GuardianSet(address indexed guardian);
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
    event InventoryProvisioned(address indexed token, address indexed by, uint256 amount);
    event InventoryDrained(address indexed token, address indexed to, uint256 amount, address indexed by);

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
    error TreasuryAlreadySet();
    error TreasuryNotSet();
    error GuardianAlreadySet();
    error NotGuardian();
    error NotASigner();
    error AlreadyASigner();
    error InvalidThreshold();
    error FeeBpsTooHigh();
    error TipCapTooHigh();
    error WrongMode();
    error InsufficientInventory();
    error NotProvisioner();
    error InvalidSigBlob();
    error InsufficientSignatures();
    error DuplicateSigner();
    error VoucherCancelled_();

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
    error TipPaidOnInactiveFlow();

    // ─── Flow consumption errors (PR γ.1) ──────────────────────────────
    error FlowNotActive();
    error AmountBelowFlowMin();
    error FlowCapExceeded();
    error DailyLimitExceeded();
    error InsufficientFlowInventory();

    // ─── PR γ.2c — permissionless refund errors ────────────────────────
    error LockNotFound();
    error RefundTimeoutNotElapsed();
    error LockAlreadyRefunded();

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
    // Core — lock
    // ---------------------------------------------------------------------

    function lock(
        address token,
        uint256 amount,
        bytes32 opnetRecipient,
        bytes32 flowId
    )
        external
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
        //    (post fee-on-transfer balance delta).
        _bumpLockInventory(flowId, amountReceived_);

        unchecked {
            depositNonce_ = ++depositNonce;
        }

        // PR γ.2c — persist a refund-eligible record. `amountReceived_`
        // already passed the `_bumpLockInventory` uint128 cap check above,
        // so the cast is safe.
        lockedDeposits[depositNonce_] = LockRecord({
            user: msg.sender,
            lockedAt: uint64(block.timestamp),
            refunded: false,
            amount: uint128(amountReceived_),
            token: token,
            flowId: flowId
        });

        emit Locked(token, msg.sender, amount, amountReceived_, opnetRecipient, depositNonce_);
        emit LockedToFlow(flowId, msg.sender, token, amountReceived_);
    }

    // ---------------------------------------------------------------------
    // Core — refund (PR γ.2c, permissionless after REFUND_TIMEOUT)
    // ---------------------------------------------------------------------

    /// @notice Permissionless escape hatch for a stuck `lock`. After
    ///         `REFUND_TIMEOUT` elapsed since the deposit was locked, anyone
    ///         (typically the original user, but a relayer is fine — the
    ///         tokens always go to the recorded depositor) can call this
    ///         to refund the lock and decrement per-flow inventory.
    ///
    /// @dev    Time-based, NOT coordinated with the OPNet side. If the
    ///         OPNet voucher was already minted and claimed, the EVM
    ///         contract does not know — it cannot, by design, since the
    ///         two chains are independent. Governance is responsible for
    ///         calling `cancelVoucher(opnetNonce)` BEFORE the timeout
    ///         elapses on any voucher it does not want refundable. After
    ///         REFUND_TIMEOUT the refund proceeds unconditionally; the
    ///         simultaneous-claim race is bounded by the 7-day window
    ///         which is far longer than any realistic voucher
    ///         coordination window.
    ///
    ///         CEI: read → mark refunded → mutate inventory → transfer.
    ///         Reentrancy guarded; refund is idempotent (second call
    ///         reverts with `LockAlreadyRefunded`).
    function refundLockedDeposit(uint256 depositNonce_) external nonReentrant {
        LockRecord storage rec = lockedDeposits[depositNonce_];

        // `user == address(0)` means the slot was never written (no such
        // depositNonce). depositNonce starts at 1, so nonce 0 is also
        // unmapped — the user check covers it cleanly.
        if (rec.user == address(0)) revert LockNotFound();
        if (rec.refunded) revert LockAlreadyRefunded();
        if (block.timestamp - uint256(rec.lockedAt) < uint256(REFUND_TIMEOUT)) {
            revert RefundTimeoutNotElapsed();
        }

        // Snapshot the fields we need post-mark (storage-pointer stays
        // stable but reads are cheaper from memory).
        address user = rec.user;
        address token = rec.token;
        uint128 amount = rec.amount;
        bytes32 flowId = rec.flowId;

        // Effects.
        rec.refunded = true;

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
        if (flow.mode != uint8(TokenMode.WRAPPED) && flow.mode != uint8(TokenMode.POOLED_LOCK_RELEASE)) {
            revert WrongMode();
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
    function _bumpLockInventory(bytes32 flowId, uint256 received) internal {
        if (received > type(uint128).max) revert FlowCapExceeded();
        FlowRecord storage flow = flows[flowId];
        uint256 newInventory = uint256(flow.inventory) + received;
        if (newInventory > uint256(flow.cap)) revert FlowCapExceeded();
        flow.inventory = uint128(newInventory);
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
        if (intent.srcChainId != expectedOpnetChainId) revert InvalidSrcChainId();
        if (intent.signerEpoch != currentEpoch) revert InvalidSignerEpoch();
        if (signaturesUsed[intent.opnetNonce]) revert AlreadyClaimed();
        if (cancelledVouchers[intent.opnetNonce]) revert VoucherCancelled_();
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
        if (flow.mode != uint8(TokenMode.WRAPPED) && flow.mode != uint8(TokenMode.POOLED_LOCK_RELEASE)) {
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

        // 5. tip cap + carve. Status was already enforced above so we drop
        //    the redundant TipPaidOnInactiveFlow gate; tipped paths still
        //    surface FlowNotActive on inactive flows. Bps math identical to
        //    pre-PR γ.1 — uses `amount` (= netDst) as the denominator.
        uint256 recipientAmount = intent.amount;
        uint128 tip = intent.relayerTip;
        if (tip > 0) {
            uint256 bps = (uint256(tip) * 10_000) / intent.amount;
            if (bps > uint256(flow.tipCapBps)) revert TipExceedsFlowCap();
            unchecked {
                // tip <= amount enforced indirectly: bps <= MAX_TIP_BPS = 200
                // (governor-capped at addFlow / setFlowTipCap). 200 bps = 2%
                // of amount, so tip < amount always. Safe to subtract.
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

        IERC20(intent.token).safeTransfer(intent.to, recipientAmount);
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

    function removeSigner(address oldSigner) external onlyOwner {
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
    ) external onlyOwner {
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

    function cancelVoucher(bytes32 opnetNonce) external onlyOwner {
        if (cancelledVouchers[opnetNonce]) return;
        cancelledVouchers[opnetNonce] = true;
        emit VoucherCancelled(opnetNonce, msg.sender);
    }

    // ---------------------------------------------------------------------
    // Admin — token allowlist + pause + treasury/guardian
    // ---------------------------------------------------------------------

    function setSupportedToken(address token, bool enabled) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        supportedToken[token] = enabled;
        emit SupportedTokenUpdated(token, enabled);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function setTreasury(address newTreasury) external onlyOwner {
        if (treasury != address(0)) revert TreasuryAlreadySet();
        if (newTreasury == address(0)) revert ZeroAddress();
        treasury = newTreasury;
        emit TreasurySet(newTreasury);
    }

    function setGuardian(address newGuardian) external onlyOwner {
        if (guardian != address(0)) revert GuardianAlreadySet();
        if (newGuardian == address(0)) revert ZeroAddress();
        guardian = newGuardian;
        emit GuardianSet(newGuardian);
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
        if (signaturesUsed[intent.opnetNonce]) revert AlreadyClaimed();
        if (cancelledVouchers[intent.opnetNonce]) revert VoucherCancelled_();
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

    // ---------------------------------------------------------------------
    // Mode-4 inventory provisioning (POOLED_LOCK_RELEASE)
    // ---------------------------------------------------------------------

    /// @notice Add `amount` of `token` to the bridge's inventory pool.
    ///         Used for POOLED_LOCK_RELEASE tokens (e.g. MOTO) where the
    ///         project pre-funds the EVM-side pool so users can claim
    ///         against OPNet locks before any reverse flow has happened.
    /// @dev    Caller transfers tokens INTO the bridge — they must
    ///         `approve(bridge, amount)` first. Uses balance-delta to
    ///         survive fee-on-transfer / non-canonical ERC20s.
    ///         Works for any registered token regardless of mode (a
    ///         WRAPPED token's pool is just the locked-deposit balance,
    ///         provisioning is harmless additive). The flag is
    ///         intentional: top-ups for capacity planning, not just
    ///         mode-4-only.
    function provisionInventory(address token, uint256 amount) external onlyOwner nonReentrant {
        if (token == address(0)) revert ZeroAddress();
        if (!supportedToken[token]) revert TokenNotSupported();
        if (amount == 0) revert AmountZero();

        IERC20 erc20 = IERC20(token);
        uint256 balBefore = erc20.balanceOf(address(this));
        erc20.safeTransferFrom(msg.sender, address(this), amount);
        uint256 balAfter = erc20.balanceOf(address(this));
        unchecked {
            uint256 received = balAfter - balBefore;
            if (received == 0) revert NothingReceived();
            emit InventoryProvisioned(token, msg.sender, received);
        }
    }

    /// @notice Drain inventory back to the set-once `treasury`. Same
    ///         destination and pause-gate as `emergencyWithdraw`, but
    ///         with separate semantics: `drainInventory` is for orderly
    ///         wind-down of a token's pool (e.g. de-listing a token,
    ///         migrating to a new bridge), not for incident response.
    /// @dev    onlyGuardian + whenPaused — same trust model as
    ///         emergencyWithdraw. Owner alone cannot drain; pause must
    ///         be exercised first.
    function drainInventory(address token, uint256 amount)
        external
        nonReentrant
        whenPaused
    {
        if (msg.sender != guardian) revert NotGuardian();
        if (token == address(0)) revert ZeroAddress();
        if (treasury == address(0)) revert TreasuryNotSet();
        if (amount == 0) revert AmountZero();
        emit InventoryDrained(token, treasury, amount, msg.sender);
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
        if (p.mode > uint8(TokenMode.POOLED_LOCK_RELEASE)) revert FlowInvalidMode();
        if (p.evmChainId == 0) revert FlowZeroChainId();
        if (p.evmBridge == address(0) || p.evmToken == address(0)) revert ZeroAddress();
        if (p.opnetBridge == bytes32(0) || p.opnetToken == bytes32(0)) revert ZeroAddress();
        if (p.evmDecimals == 0 || p.evmDecimals > 30) revert FlowInvalidDecimals();
        if (p.opnetDecimals == 0 || p.opnetDecimals > 30) revert FlowInvalidDecimals();
        if (p.feeBps > MAX_FEE_BPS) revert FeeBpsTooHigh();
        if (p.tipCapBps > MAX_TIP_BPS) revert TipCapTooHigh();

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
        emit FlowMinAmountChanged(flowId, f.minAmount, newMin);
        f.minAmount = newMin;
    }

    /// @notice Governor-only — adjust per-flow fee parameters. Hard-capped
    ///         at MAX_FEE_BPS (10%).
    function setFlowFee(bytes32 flowId, uint16 newBps, uint128 newMinFee) external onlyOwner {
        if (newBps > MAX_FEE_BPS) revert FeeBpsTooHigh();
        FlowRecord storage f = flows[flowId];
        if (f.evmChainId == 0) revert FlowNotFound();
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

    function hashIntent(ReleaseIntent calldata intent) external view returns (bytes32) {
        return _hashTypedDataV4(_hashIntent(intent));
    }

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

    /// @notice EIP-712 digest for a MintIntent — useful off-chain and for tests.
    function hashMintIntent(MintIntent calldata intent) external view returns (bytes32) {
        return _hashTypedDataV4(_hashMintIntent(intent));
    }
}
