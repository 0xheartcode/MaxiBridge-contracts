// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @notice Minimal BridgeEscrow surface the vault forwards into.
interface IBridgeEscrowLock {
    function lock(address token, uint256 amount, bytes32 opnetRecipient, bytes32 flowId)
        external
        returns (uint256 depositNonce, uint256 amountReceived);
}

/// @title  DepositVault
/// @notice #4 — single-use, CREATE2-deployed deposit vault. The
///         `DepositAddressFactory` computes this contract's address
///         deterministically *before* it exists; a user (or a CEX
///         withdrawal, cold wallet, aggregator) sends tokens to that
///         address with no dApp interaction. Anyone then calls
///         `factory.sweep(...)`, which deploys this vault — the entire
///         job happens in the constructor: pull the received balance,
///         approve the escrow, `lock` it for the bridge, then
///         self-destruct so the deterministic address is freed.
/// @dev    `selfdestruct` runs in the SAME transaction as creation, so
///         EIP-6780 still clears the account. This is a throwaway
///         forwarder — the "no selfdestruct" rule applies to the
///         upgradeable bridge core, not to a single-use vault.
contract DepositVault {
    using SafeERC20 for IERC20;

    constructor(address token, address escrow, bytes32 opnetRecipient, bytes32 flowId) {
        uint256 bal = IERC20(token).balanceOf(address(this));
        if (bal > 0) {
            // forceApprove handles USDT's approve-from-nonzero quirk.
            IERC20(token).forceApprove(escrow, bal);
            IBridgeEscrowLock(escrow).lock(token, bal, opnetRecipient, flowId);
        }
        // Free the address for a future deposit (EIP-6780: same-tx
        // create+destruct still clears code). Any stray ETH → escrow.
        selfdestruct(payable(escrow));
    }
}
