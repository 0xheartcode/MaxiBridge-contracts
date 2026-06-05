// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {DepositVault} from "./DepositVault.sol";

/// @title  DepositAddressFactory
/// @notice #4 — FixedFloat-style "send to an address" bridging. Produces
///         deterministic CREATE2 deposit addresses: a user sends tokens
///         to `predict(...)` from any wallet / CEX / cold storage with no
///         dApp interaction, then anyone calls `sweep(...)` to deploy the
///         single-use `DepositVault` whose constructor forwards the whole
///         received balance into `BridgeEscrow.lock`.
/// @dev    Isolated from the bridge core — it never touches BridgeEscrow
///         storage; it only calls the permissionless `lock`. Each deposit
///         uses a fresh `salt`, so addresses are single-use.
contract DepositAddressFactory {
    /// @notice The BridgeEscrow every vault locks into.
    address public immutable BRIDGE_ESCROW;

    /// @notice Emitted when a deposit address is swept into the bridge.
    event Swept(
        bytes32 indexed salt,
        address indexed vault,
        address indexed token,
        bytes32 opnetRecipient,
        bytes32 flowId,
        // E-2 — the user-controlled refund destination committed into the
        // vault's CREATE2 initcode (where a cancelled-mint refund returns to).
        address refundTo
    );

    error ZeroAddress();

    constructor(address bridgeEscrow_) {
        if (bridgeEscrow_ == address(0)) revert ZeroAddress();
        BRIDGE_ESCROW = bridgeEscrow_;
    }

    /// @notice Deterministic address a deposit for these exact params
    ///         will land on. Show this to the user as "send funds here".
    /// @dev    The vault's constructor args are part of its initcode, so
    ///         the address commits to (token, escrow, recipient, flow,
    ///         refundTo) — a sweep cannot redirect a deposit to a different
    ///         flow OR a different refund destination (E-2).
    /// @param  refundTo — the user-controlled EVM address a cancelled-mint
    ///         refund returns to. MUST be set by the user up front (the vault
    ///         self-destructs, so it can't be the deposit destination). Bound
    ///         into the CREATE2 address, so it cannot be changed at sweep time.
    function predict(
        bytes32 salt,
        address token,
        bytes32 opnetRecipient,
        bytes32 flowId,
        address refundTo
    ) public view returns (address) {
        // forge-lint: disable-next-line(asm-keccak256)
        bytes32 initcodeHash = keccak256(
            abi.encodePacked(
                type(DepositVault).creationCode,
                abi.encode(token, BRIDGE_ESCROW, opnetRecipient, flowId, refundTo)
            )
        );
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xff), address(this), salt, initcodeHash)
                    )
                )
            )
        );
    }

    /// @notice Deploy the vault for `salt` — its constructor sweeps the
    ///         balance held at the predicted address into
    ///         `BridgeEscrow.lock`. Permissionless: anyone (the user, a
    ///         relayer, a sweeper bot) may call it; the bridged funds are
    ///         bound to `opnetRecipient` regardless of who sweeps.
    function sweep(
        bytes32 salt,
        address token,
        bytes32 opnetRecipient,
        bytes32 flowId,
        address refundTo
    ) external returns (address vault) {
        // E-2 — `refundTo` is part of the vault's CREATE2 initcode, so a sweep
        // can only deploy a vault at the address the user funded if it passes
        // the SAME refundTo they committed to. A zero refundTo would revert in
        // `lockFor`; reject early for a clearer error.
        if (refundTo == address(0)) revert ZeroAddress();
        vault = predict(salt, token, opnetRecipient, flowId, refundTo);
        // Nothing to sweep — return without deploying the vault so the salt is
        // preserved and no misleading Swept event is emitted.
        if (IERC20(token).balanceOf(vault) == 0) return vault;
        new DepositVault{salt: salt}(token, BRIDGE_ESCROW, opnetRecipient, flowId, refundTo);
        emit Swept(salt, vault, token, opnetRecipient, flowId, refundTo);
    }
}
