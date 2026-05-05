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

/// @title BridgeEscrow
/// @notice UUPS upgradeable EVM side of the OPNet bridge.
///         Users `lock()` USDC/USDT to bridge to OPNet; the off-chain signer
///         set issues an EIP-712 ReleaseIntent that anyone can submit via `claim()`.
/// @dev Phase 1 hardening:
///        - M-of-N ECDSA signer set (single-signer mode = 1-of-1, default after migration)
///        - Treasury (set-once) + Guardian roles
///        - emergencyWithdraw is `onlyGuardian` + `whenPaused`, sends to fixed treasury
///        - cancelVoucher per-voucher invalidation
///        - Backward-compat: legacy 65-byte single ECDSA sig still accepted while
///          `signerThreshold == 0` (pre-migration). Once `migrateToMofN` runs, only
///          length-prefixed M-of-N blobs verify.
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
    // EIP-712 type — UNCHANGED (typehash + struct order are LOCKED)
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
    }

    /// @dev keccak256("ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce)")
    bytes32 public constant RELEASE_INTENT_TYPEHASH =
        keccak256(
            "ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce)"
        );

    // ---------------------------------------------------------------------
    // Storage  (append-only — NEVER reorder/delete/retype)
    // ---------------------------------------------------------------------

    /// @notice Legacy signer slot — kept for backward compat. After migration
    ///         to M-of-N (`migrateToMofN`) this is *deprecated in place*: the
    ///         `claim()` path no longer reads it for verification.
    address public signer;

    /// @notice Current signer epoch; incremented on rotation/threshold change.
    uint32 public currentEpoch;

    /// @notice Monotonic deposit nonce; incremented per lock.
    uint256 public depositNonce;

    /// @notice Token address => supported flag.
    mapping(address => bool) public supportedToken;

    /// @notice opnetNonce => used. Per-voucher replay guard.
    mapping(bytes32 => bool) public signaturesUsed;

    /// @notice opnetTxHash => opnetEventIndex => used. Composite source-event replay guard.
    mapping(bytes32 => mapping(uint32 => bool)) public usedSourceEvent;

    /// @notice Expected OPNet source-chain network id. Set once at init.
    ///         Mainnet = 1, testnet = 2. Enforced in `claim()`.
    uint256 public expectedOpnetChainId;

    // ─── Phase 1 additions (append-only) ─────────────────────────────────

    /// @notice Guardian — can pause via owner pipeline AND call emergencyWithdraw
    ///         (which is `whenPaused`). Set-once via `setGuardian`.
    address public guardian;

    /// @notice Set-once destination for emergencyWithdraw. After it is non-zero
    ///         it can never be changed. Prevents a compromised owner from
    ///         redirecting emergency drains.
    address public treasury;

    /// @notice M-of-N signer set. address => isAuthorized.
    mapping(address => bool) public isSigner;

    /// @notice Number of authorized signers in `isSigner`.
    uint256 public signerCount;

    /// @notice Required number of valid signatures to claim. Once non-zero,
    ///         the contract is in M-of-N mode and `claim()` only accepts
    ///         length-prefixed blobs.
    uint256 public signerThreshold;

    /// @notice opnetNonce => cancelled. Per-voucher governance kill-switch.
    ///         Cancellation is checked alongside the standard replay guard.
    mapping(bytes32 => bool) public cancelledVouchers;

    // 49-slot gap reduced by 6 (guardian, treasury, isSigner mapping slot,
    // signerCount, signerThreshold, cancelledVouchers mapping slot) = 43.
    uint256[43] private __gap;

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

    event Claimed(
        address indexed token,
        address indexed to,
        uint256 amount,
        bytes32 indexed opnetNonce
    );

    event SignerEpochRotated(
        uint32 indexed oldEpoch,
        uint32 indexed newEpoch,
        address indexed newSigner
    );

    event SupportedTokenUpdated(address indexed token, bool enabled);

    event EmergencyWithdraw(
        address indexed token,
        address indexed to,
        uint256 amount,
        address indexed by
    );

    // ─── Phase 1 events ───────────────────────────────────────────────────

    event TreasurySet(address indexed treasury);
    event GuardianSet(address indexed guardian);
    event SignerAdded(address indexed signer, uint256 newCount);
    event SignerRemoved(address indexed signer, uint256 newCount);
    event ThresholdSet(uint256 indexed oldThreshold, uint256 indexed newThreshold);
    event MigratedToMofN(uint256 epoch, uint256 threshold);
    event VoucherCancelled(bytes32 indexed opnetNonce, address indexed by);
    event SignerSetMigrated(
        uint32 indexed oldEpoch,
        uint32 indexed newEpoch,
        uint256 newCount,
        uint256 newThreshold
    );

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

    // ─── Phase 1 errors ───────────────────────────────────────────────────

    error TreasuryAlreadySet();
    error TreasuryNotSet();
    error GuardianAlreadySet();
    error NotGuardian();
    error NotASigner();
    error AlreadyASigner();
    error InvalidThreshold();
    error InvalidSigBlob();
    error InsufficientSignatures();
    error DuplicateSigner();
    error VoucherCancelled_();
    error AlreadyMigrated();
    error MofNNotInitialized();

    // ---------------------------------------------------------------------
    // Init
    // ---------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize proxy state.
    /// @param owner_ Initial owner (Safe multisig in prod).
    /// @param signer_ Initial EIP-712 signer EOA. Also seeded into `isSigner`
    ///        so a fresh deploy is implicitly 1-of-1 M-of-N from day one.
    /// @param expectedOpnetChainId_ OPNet source-chain network id (mainnet=1, testnet=2).
    ///        Every `claim()` enforces `intent.srcChainId == this value`.
    /// @param supportedTokens_ Canonical token allowlist at deploy time.
    function initialize(
        address owner_,
        address signer_,
        uint256 expectedOpnetChainId_,
        address[] calldata supportedTokens_
    ) external initializer {
        if (owner_ == address(0) || signer_ == address(0)) revert ZeroAddress();
        if (expectedOpnetChainId_ == 0) revert ZeroChainId();

        __UUPSUpgradeable_init();
        __Ownable_init(owner_);
        __Pausable_init();
        __ReentrancyGuard_init();
        __EIP712_init("BridgeEscrow", "1");

        signer = signer_;
        currentEpoch = 1;
        expectedOpnetChainId = expectedOpnetChainId_;

        // Phase 1: fresh deploys come up in M-of-N mode at 1-of-1 with the
        // initial signer. UUPS upgrades from a pre-Phase-1 impl land with
        // signerThreshold == 0 and need a one-time `migrateToMofN` call.
        isSigner[signer_] = true;
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

    /// @notice One-time post-upgrade migration: seed M-of-N state from the
    ///         legacy single `signer` slot. Idempotent — reverts after first
    ///         success. Required after UUPS-upgrading a pre-Phase-1 impl.
    function migrateToMofN() external onlyOwner {
        if (signerThreshold != 0) revert AlreadyMigrated();
        address legacy = signer;
        if (legacy == address(0)) revert ZeroAddress();
        isSigner[legacy] = true;
        signerCount = 1;
        signerThreshold = 1;
        emit MigratedToMofN(currentEpoch, 1);
    }

    // ---------------------------------------------------------------------
    // Core — lock (UNCHANGED)
    // ---------------------------------------------------------------------

    function lock(
        address token,
        uint256 amount,
        bytes32 opnetRecipient
    )
        external
        whenNotPaused
        nonReentrant
        returns (uint256 depositNonce_, uint256 amountReceived_)
    {
        if (!supportedToken[token]) revert TokenNotSupported();
        if (amount == 0) revert AmountZero();
        if (opnetRecipient == bytes32(0)) revert InvalidRecipient();

        IERC20 erc20 = IERC20(token);
        uint256 balBefore = erc20.balanceOf(address(this));
        erc20.safeTransferFrom(msg.sender, address(this), amount);
        uint256 balAfter = erc20.balanceOf(address(this));

        unchecked {
            amountReceived_ = balAfter - balBefore;
        }
        if (amountReceived_ == 0) revert NothingReceived();

        unchecked {
            depositNonce_ = ++depositNonce;
        }

        emit Locked(
            token,
            msg.sender,
            amount,
            amountReceived_,
            opnetRecipient,
            depositNonce_
        );
    }

    // ---------------------------------------------------------------------
    // Core — claim (M-of-N + legacy single-sig fallback)
    // ---------------------------------------------------------------------

    /// @notice Claim a release authorized by the current signer set.
    /// @dev Strict EIP-712 typehash unchanged. The `sig` arg is now one of:
    ///        (a) Legacy single-sig: `bytes` of length 65 — recovered against
    ///            the legacy `signer` slot. Only accepted when
    ///            `signerThreshold == 0` (pre-migration).
    ///        (b) M-of-N blob: `[uint8 numSigs][sig_0 (65B)][sig_1 (65B)]...`
    ///            Each sig is independently recovered, must come from a
    ///            distinct authorized `isSigner`, and the count of valid
    ///            recovers must be `>= signerThreshold`.
    function claim(
        ReleaseIntent calldata intent,
        bytes calldata sig
    ) external whenNotPaused nonReentrant {
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

        // Effects BEFORE interaction (CEI).
        signaturesUsed[intent.opnetNonce] = true;
        usedSourceEvent[intent.opnetTxHash][intent.opnetEventIndex] = true;

        emit Claimed(intent.token, intent.to, intent.amount, intent.opnetNonce);

        IERC20(intent.token).safeTransfer(intent.to, intent.amount);
    }

    /// @dev Reverts on any verification failure. Sig formats:
    ///        - Legacy (sig.length == 65): one ECDSA recover, must equal
    ///          `signer`. Only accepted while `signerThreshold == 0`.
    ///        - M-of-N (sig.length == 1 + 65*numSigs): parse `numSigs`,
    ///          recover each, require all signers in `isSigner`, no
    ///          duplicates, and `validCount >= signerThreshold`.
    function _verifySignatures(bytes32 digest, bytes calldata sig) internal view {
        uint256 threshold = signerThreshold;

        // ── Single-sig path (65 raw bytes, no length prefix) ──
        // Accepted in two scenarios:
        //   (a) Pre-migration (`threshold == 0`): recovered signer must equal
        //       the legacy `signer` slot.
        //   (b) Post-migration with `threshold == 1`: recovered signer must be
        //       a member of the M-of-N set. This preserves backward compat for
        //       clients submitting 65-byte sigs while in 1-of-N mode.
        // Threshold > 1 with a single 65-byte sig is rejected — the caller
        // must use the length-prefixed M-of-N blob format.
        if (sig.length == 65) {
            address recovered = ECDSA.recover(digest, sig);
            if (recovered == address(0)) revert InvalidSignature();
            if (threshold == 0) {
                if (recovered != signer) revert InvalidSignature();
                return;
            }
            if (threshold > 1) revert InsufficientSignatures();
            // For backward compat with the legacy single-sig error surface,
            // an unauthorized recovered signer surfaces as InvalidSignature.
            if (!isSigner[recovered]) revert InvalidSignature();
            return;
        }

        // ── M-of-N length-prefixed blob path ──
        if (threshold == 0) revert MofNNotInitialized();
        if (sig.length < 1) revert InvalidSigBlob();

        uint256 numSigs = uint256(uint8(sig[0]));
        if (numSigs == 0) revert InvalidSigBlob();
        if (sig.length != 1 + numSigs * 65) revert InvalidSigBlob();

        // Collect distinct, authorized signers. With max 255 sigs the
        // bounded O(n²) duplicate check remains cheap.
        address[] memory seen = new address[](numSigs);
        uint256 validCount = 0;

        for (uint256 i = 0; i < numSigs; ) {
            uint256 off = 1 + i * 65;
            bytes memory single = new bytes(65);
            // copy 65 bytes [off .. off+65) from calldata into memory
            for (uint256 j = 0; j < 65; ) {
                single[j] = sig[off + j];
                unchecked {
                    ++j;
                }
            }
            address recovered = ECDSA.recover(digest, single);
            if (recovered == address(0)) revert InvalidSignature();
            if (!isSigner[recovered]) revert NotASigner();

            // Duplicate-signer check
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

    /// @notice Legacy single-rotation flow. Replaces the entire signer set
    ///         with `newSigner` AND keeps backward compat by writing the
    ///         legacy `signer` slot. Bumps epoch; old-epoch sigs invalidated.
    function rotateSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ZeroAddress();
        // Atomically swap the entire set: clear current, set new, keep threshold.
        address oldLegacy = signer;
        if (oldLegacy != address(0) && isSigner[oldLegacy]) {
            isSigner[oldLegacy] = false;
            unchecked {
                --signerCount;
            }
        }
        signer = newSigner;
        if (!isSigner[newSigner]) {
            isSigner[newSigner] = true;
            unchecked {
                ++signerCount;
            }
        }
        if (signerThreshold == 0) {
            signerThreshold = 1;
        }

        uint32 oldEpoch = currentEpoch;
        uint32 newEpoch;
        unchecked {
            newEpoch = oldEpoch + 1;
        }
        currentEpoch = newEpoch;
        emit SignerEpochRotated(oldEpoch, newEpoch, newSigner);
    }

    /// @notice Add an authorized signer. Threshold unchanged. Does NOT bump
    ///         the epoch — vouchers signed by the prior set remain valid (any
    ///         single sig still resolves to a member of the new superset).
    function addSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ZeroAddress();
        if (isSigner[newSigner]) revert AlreadyASigner();
        isSigner[newSigner] = true;
        unchecked {
            ++signerCount;
        }
        emit SignerAdded(newSigner, signerCount);
    }

    /// @notice Remove an authorized signer. Bumps the epoch — any voucher
    ///         signed exclusively by the removed signer immediately stops
    ///         verifying. Reverts if the removal would push count below
    ///         threshold.
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
        emit SignerEpochRotated(oldEpoch, newEpoch, address(0));
    }

    /// @notice Update the M-of-N threshold. Bumps the epoch. Threshold must
    ///         be 1 ≤ m ≤ signerCount.
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

    /// @notice Atomic add+remove+threshold update. Required for safe
    ///         transitions like 1-of-1 → 2-of-2 (no intermediate weakening).
    function migrateSignerSet(
        address[] calldata addList,
        address[] calldata removeList,
        uint256 newThreshold
    ) external onlyOwner {
        // Removes first so adds aren't undone if a name collides.
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

    /// @notice Cancel a specific voucher (by opnetNonce) so it can never be
    ///         claimed. Used by Tier-3 incident response in concert with the
    ///         server's refund flow.
    function cancelVoucher(bytes32 opnetNonce) external onlyOwner {
        if (cancelledVouchers[opnetNonce]) return; // idempotent
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

    /// @notice Set the treasury (set-once). Called immediately after
    ///         deployment / upgrade. Cannot be re-pointed by a compromised
    ///         owner — the slot becomes immutable after first write.
    function setTreasury(address newTreasury) external onlyOwner {
        if (treasury != address(0)) revert TreasuryAlreadySet();
        if (newTreasury == address(0)) revert ZeroAddress();
        treasury = newTreasury;
        emit TreasurySet(newTreasury);
    }

    /// @notice Set the guardian (set-once). Single EOA on an independent
    ///         device, paged via PagerDuty. Authorized to call
    ///         `emergencyWithdraw` while the contract is paused.
    function setGuardian(address newGuardian) external onlyOwner {
        if (guardian != address(0)) revert GuardianAlreadySet();
        if (newGuardian == address(0)) revert ZeroAddress();
        guardian = newGuardian;
        emit GuardianSet(newGuardian);
    }

    /// @notice Emergency drain to the pre-set treasury. Gated on
    ///         `onlyGuardian` AND `whenPaused` — owner cannot drain
    ///         unilaterally; pauser path must be exercised first.
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
                    intent.opnetNonce
                )
            );
    }
}
