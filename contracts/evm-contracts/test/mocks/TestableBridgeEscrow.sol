// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BridgeEscrow} from "../../src/BridgeEscrow.sol";

/// @notice Test-only escrow exposing internal hooks needed to bootstrap
///         per-flow `inventory` and reset window counters without an
///         admin setter on the production contract. PR γ.1 — flow
///         consumption tests use these to seed scenarios that depend on
///         non-zero starting inventory or a stale rolling-window bucket.
///
///         Production `BridgeEscrow` exposes only governance-validated
///         setters (`setFlowCap`, `setFlowDailyLimit`, `setFlowMinAmount`)
///         that intentionally do NOT let the governor write inventory or
///         the window counters directly — those are claim/lock-side
///         hot fields. Tests need to write them; this child contract
///         supplies the hook used only from tests.
contract TestableBridgeEscrow is BridgeEscrow {
    /// @notice Seed a flow's hot fields directly. One combined hook (instead
    ///         of separate inventory/window setters) keeps this child under
    ///         the EIP-170 runtime size limit — it inherits the full prod
    ///         contract, so every extra external selector costs scarce bytes.
    ///         Pass `0` for any field a test doesn't care about.
    function _testSeed(
        bytes32 flowId,
        uint128 inventory,
        uint128 minted,
        uint64 windowStart
    ) external {
        flows[flowId].inventory = inventory;
        flows[flowId].mintedToday = minted;
        flows[flowId].lastWindowStart = windowStart;
    }
}
