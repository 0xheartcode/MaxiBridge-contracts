// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IVestingVault} from "./IVestingVault.sol";

/// @title  VestingVault
/// @author Bridge team — Mode 4 (POOLED_LOCK_VEST) destination-side vault.
/// @notice Holds bridged funds and releases them to the beneficiary linearly
///         over a fixed block window. Each bridge claim opens an independent
///         schedule keyed by the voucher's opnetNonce. The beneficiary
///         claims accrued portions at their own cadence.
///
/// Design notes (security-relevant):
///
/// * Block-based release (NOT timestamp). `block.number` is monotonic and
///   not miner-manipulable, giving a deterministic drip. 7 days ≈ 50_400
///   blocks at 12s/block — the deployer picks `vestingBlocks_` per vault.
///
/// * No owner role. The vault is a pure custodian: tokens in via the bridge,
///   tokens out via the beneficiary's `claim` or the bridge's `clawback`.
///   There is no admin path that can divert beneficiary funds — the bridge
///   only ever recovers the *unvested* portion via `clawback`, and the
///   vested-but-unclaimed portion is force-paid to the beneficiary in the
///   same transaction.
///
/// * SafeERC20 throughout. Survives USDT-style non-bool-returning tokens.
///
/// * Balance-delta check on deposit. If the token is fee-on-transfer or
///   somehow yields less than `amount`, `depositFor` reverts rather than
///   silently opening a schedule the vault can't honour.
///
/// * Schedule replay protection. The (`beneficiary`, `scheduleKey`) tuple
///   is single-use — a duplicate `depositFor` reverts `ScheduleAlreadyExists`.
///   In honest operation this can never trigger because the bridge dedupes
///   on `opnetNonce` first; defense in depth.
///
/// * ReentrancyGuard on every state-mutator that calls into ERC20s.
contract VestingVault is IVestingVault, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ---------------------------------------------------------------------
    // Immutables
    // ---------------------------------------------------------------------

    /// @notice The single ERC20 this vault vests. Locked at deploy.
    IERC20 public immutable token;

    /// @notice The only address allowed to `depositFor` and `clawback`.
    ///         Set to the BridgeEscrow proxy at deploy.
    address public immutable bridge;

    /// @notice Linear-vest window in blocks. 50_400 ≈ 7 days at 12s/block.
    uint64 public immutable vestingBlocks;

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    /// @notice Per-schedule state. Two slots: (total + claimed) and
    ///         (startBlock + endBlock + clawback marker).
    ///
    ///         A schedule is "terminal" when `claimed == total`. After
    ///         clawback the vault force-flips the schedule to terminal,
    ///         so `claim` can no longer find anything to pay out.
    struct Schedule {
        uint128 total;          // tokens deposited for the beneficiary
        uint128 claimed;        // tokens already paid out (incl. clawback drain)
        uint64  startBlock;     // block.number at depositFor
        uint64  endBlock;       // startBlock + vestingBlocks
        bool    clawedBack;     // audit-trail marker; doesn't change math
    }

    /// @notice beneficiary → scheduleKey → Schedule.
    mapping(address => mapping(bytes32 => Schedule)) public schedules;

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    error NotBridge();
    error ZeroAddress();
    error ZeroAmount();
    error ZeroVestingDuration();
    error AmountOverflow();
    error ScheduleAlreadyExists();
    error ScheduleNotFound();
    error NothingToClaim();
    error TokenTransferIncomplete();

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event Deposited(
        address indexed beneficiary,
        bytes32 indexed scheduleKey,
        uint128 amount,
        uint64  startBlock,
        uint64  endBlock
    );
    event Claimed(
        address indexed beneficiary,
        bytes32 indexed scheduleKey,
        uint128 amount
    );
    event ClawedBack(
        address indexed beneficiary,
        bytes32 indexed scheduleKey,
        uint128 returnedToBridge,
        uint128 paidToBeneficiary
    );

    // ---------------------------------------------------------------------
    // Modifiers
    // ---------------------------------------------------------------------

    modifier onlyBridge() {
        if (msg.sender != bridge) revert NotBridge();
        _;
    }

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------

    constructor(IERC20 token_, address bridge_, uint64 vestingBlocks_) {
        if (address(token_) == address(0) || bridge_ == address(0)) revert ZeroAddress();
        if (vestingBlocks_ == 0) revert ZeroVestingDuration();
        token = token_;
        bridge = bridge_;
        vestingBlocks = vestingBlocks_;
    }

    // ---------------------------------------------------------------------
    // Bridge-only mutators
    // ---------------------------------------------------------------------

    /// @inheritdoc IVestingVault
    function depositFor(address beneficiary, uint256 amount, bytes32 scheduleKey)
        external
        nonReentrant
        onlyBridge
    {
        if (beneficiary == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (amount > type(uint128).max) revert AmountOverflow();

        Schedule storage s = schedules[beneficiary][scheduleKey];
        // total != 0 means an active schedule already exists for this key.
        // We do NOT permit top-ups — each bridge claim is its own schedule.
        if (s.total != 0) revert ScheduleAlreadyExists();

        // Pull the tokens. Balance-delta verifies the bridge actually paid
        // in full (no fee-on-transfer leakage). Reverts loudly on shortfall
        // rather than opening an under-funded schedule.
        uint256 balBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received;
        unchecked {
            received = token.balanceOf(address(this)) - balBefore;
        }
        if (received != amount) revert TokenTransferIncomplete();

        uint64 startBlock = uint64(block.number);
        uint64 endBlock;
        unchecked {
            // vestingBlocks ≤ 2^64-1 by type; block.number realistically <<
            // 2^63, so the sum cannot overflow uint64.
            endBlock = startBlock + vestingBlocks;
        }

        s.total = uint128(amount);
        s.startBlock = startBlock;
        s.endBlock = endBlock;

        emit Deposited(beneficiary, scheduleKey, uint128(amount), startBlock, endBlock);
    }

    /// @inheritdoc IVestingVault
    function clawback(address beneficiary, bytes32 scheduleKey)
        external
        nonReentrant
        onlyBridge
        returns (uint128 returnedToBridge)
    {
        Schedule storage s = schedules[beneficiary][scheduleKey];
        if (s.total == 0) revert ScheduleNotFound();
        // Already terminal (claimed == total) means either fully claimed or
        // already clawed-back. Either way, nothing left to recover.
        if (s.claimed >= s.total) revert ScheduleNotFound();

        uint128 vested = _computeVested(s);
        // Beneficiary keeps everything vested up to "now". The bridge gets
        // back the unvested remainder.
        uint128 owedToBeneficiary = vested > s.claimed ? vested - s.claimed : 0;
        uint128 unvested;
        unchecked {
            unvested = s.total - vested;
        }
        returnedToBridge = unvested;

        // Effects: flip schedule terminal AND set the clawback flag for the
        // audit trail. After this the schedule is permanently closed.
        s.claimed = s.total;
        s.clawedBack = true;

        // Interactions.
        if (unvested > 0) {
            token.safeTransfer(msg.sender, unvested);
        }
        if (owedToBeneficiary > 0) {
            token.safeTransfer(beneficiary, owedToBeneficiary);
            emit Claimed(beneficiary, scheduleKey, owedToBeneficiary);
        }
        emit ClawedBack(beneficiary, scheduleKey, unvested, owedToBeneficiary);
    }

    // ---------------------------------------------------------------------
    // Beneficiary path
    // ---------------------------------------------------------------------

    /// @notice Beneficiary draws their accrued vested portion. Reverts
    ///         `NothingToClaim` if nothing has vested since the last claim.
    ///         Block-based math is deterministic — front-end can simulate
    ///         exactly what will return.
    function claim(bytes32 scheduleKey)
        external
        nonReentrant
        returns (uint128 claimedAmount)
    {
        Schedule storage s = schedules[msg.sender][scheduleKey];
        if (s.total == 0) revert ScheduleNotFound();

        uint128 vested = _computeVested(s);
        if (vested <= s.claimed) revert NothingToClaim();

        unchecked {
            claimedAmount = vested - s.claimed;
        }
        s.claimed = vested;

        emit Claimed(msg.sender, scheduleKey, claimedAmount);
        token.safeTransfer(msg.sender, claimedAmount);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    /// @inheritdoc IVestingVault
    function previewClaimable(address beneficiary, bytes32 scheduleKey)
        external
        view
        returns (uint128)
    {
        Schedule storage s = schedules[beneficiary][scheduleKey];
        if (s.total == 0) return 0;
        uint128 vested = _computeVested(s);
        if (vested <= s.claimed) return 0;
        unchecked {
            return vested - s.claimed;
        }
    }

    /// @notice Full schedule view for off-chain consumers.
    function getSchedule(address beneficiary, bytes32 scheduleKey)
        external
        view
        returns (Schedule memory)
    {
        return schedules[beneficiary][scheduleKey];
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    /// @dev Linear release math, block-based.
    ///        vested = total * elapsed / duration
    ///      Clamped: before start → 0; at-or-after end → total.
    function _computeVested(Schedule storage s) internal view returns (uint128) {
        uint256 blockNum = block.number;
        if (blockNum >= uint256(s.endBlock)) return s.total;
        if (blockNum <= uint256(s.startBlock)) return 0;
        uint256 elapsed;
        uint256 duration;
        unchecked {
            elapsed = blockNum - uint256(s.startBlock);
            duration = uint256(s.endBlock) - uint256(s.startBlock);
        }
        // total is uint128, elapsed < duration ≤ uint64.max, so product fits
        // in uint256 with margin; division yields a uint128.
        uint256 vested = (uint256(s.total) * elapsed) / duration;
        return uint128(vested);
    }
}
