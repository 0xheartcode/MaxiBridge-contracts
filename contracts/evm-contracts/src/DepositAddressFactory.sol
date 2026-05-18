// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

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
    address public immutable bridgeEscrow;

    /// @notice Emitted when a deposit address is swept into the bridge.
    event Swept(
        bytes32 indexed salt,
        address indexed vault,
        address indexed token,
        bytes32 opnetRecipient,
        bytes32 flowId
    );

    error ZeroAddress();

    constructor(address bridgeEscrow_) {
        if (bridgeEscrow_ == address(0)) revert ZeroAddress();
        bridgeEscrow = bridgeEscrow_;
    }

    /// @notice Deterministic address a deposit for these exact params
    ///         will land on. Show this to the user as "send funds here".
    /// @dev    The vault's constructor args are part of its initcode, so
    ///         the address commits to (token, escrow, recipient, flow) —
    ///         a sweep cannot redirect a deposit to a different flow.
    function predict(
        bytes32 salt,
        address token,
        bytes32 opnetRecipient,
        bytes32 flowId
    ) public view returns (address) {
        bytes32 initcodeHash = keccak256(
            abi.encodePacked(
                type(DepositVault).creationCode,
                abi.encode(token, bridgeEscrow, opnetRecipient, flowId)
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
        bytes32 flowId
    ) external returns (address vault) {
        vault = address(
            new DepositVault{salt: salt}(token, bridgeEscrow, opnetRecipient, flowId)
        );
        emit Swept(salt, vault, token, opnetRecipient, flowId);
    }
}
