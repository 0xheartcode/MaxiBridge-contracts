// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title  IVestingVault
/// @notice Minimal interface BridgeEscrow uses to integrate Mode 4
///         (POOLED_LOCK_VEST). The vault holds bridged funds and releases
///         them linearly (block-based) to the beneficiary over a fixed
///         duration. Each bridge claim opens an independent schedule keyed
///         by the voucher's opnetNonce — globally unique on OPNet, so
///         duplicates indicate replay attempts and the vault rejects them.
interface IVestingVault {
    /// @notice The single ERC20 asset this vault is configured to hold.
    ///         BridgeEscrow asserts `TOKEN() == flow.evmToken` in
    ///         `setFlowVestingVault` so a vault wired by a misconfigured
    ///         governor can never drain a different flow's inventory.
    function TOKEN() external view returns (IERC20);

    /// @notice Open a new linear-vest schedule on behalf of `beneficiary`.
    ///         Caller (the bridge) must have approved `amount` to the vault.
    ///         `scheduleKey` is the voucher's opnetNonce — must be unique
    ///         for this beneficiary (the vault rejects duplicates).
    function depositFor(address beneficiary, uint256 amount, bytes32 scheduleKey) external;

    /// @notice Return the unvested portion of `(beneficiary, scheduleKey)`
    ///         to the calling bridge and force-pay the vested-but-unclaimed
    ///         portion to `beneficiary`. Terminal — no further claims.
    ///         Used by the bridge when the source voucher is invalidated
    ///         by an OPNet reorg (C-01 follow-through for Mode 4).
    /// @return returnedToBridge  Tokens transferred back to msg.sender.
    function clawback(address beneficiary, bytes32 scheduleKey)
        external
        returns (uint128 returnedToBridge);

    /// @notice View — how many tokens beneficiary can claim right now.
    function previewClaimable(address beneficiary, bytes32 scheduleKey)
        external
        view
        returns (uint128);
}
