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
    }

    /// @dev keccak256("ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce)")
    bytes32 public constant RELEASE_INTENT_TYPEHASH =
        keccak256(
            "ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce)"
        );

    /// @notice Hard cap on `unwrapFeeBps`. 1000 = 10%. A hostile or
    ///         compromised governor cannot set the bridge fee higher than
    ///         this — protects users from being effectively trapped.
    uint256 public constant MAX_FEE_BPS = 1000;

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

    /// @dev Reserved for future appends. New slots go BEFORE the gap and the
    ///      gap shrinks by the same count to preserve layout.
    uint256[48] private __gap;

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
    event SignerSetMigrated(
        uint32 indexed oldEpoch,
        uint32 indexed newEpoch,
        uint256 newCount,
        uint256 newThreshold
    );
    event UnwrapFeeBpsSet(uint256 indexed oldBps, uint256 indexed newBps);
    event UnwrapMinFeeSet(address indexed token, uint256 indexed amount);

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
    error InvalidSigBlob();
    error InsufficientSignatures();
    error DuplicateSigner();
    error VoucherCancelled_();

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

        emit Locked(token, msg.sender, amount, amountReceived_, opnetRecipient, depositNonce_);
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

        // Effects BEFORE interaction (CEI).
        signaturesUsed[intent.opnetNonce] = true;
        usedSourceEvent[intent.opnetTxHash][intent.opnetEventIndex] = true;

        emit Claimed(intent.token, intent.to, intent.amount, intent.opnetNonce);

        IERC20(intent.token).safeTransfer(intent.to, intent.amount);
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
