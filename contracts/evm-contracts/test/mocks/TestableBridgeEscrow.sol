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
    function _testSetInventory(bytes32 flowId, uint128 amount) external {
        flows[flowId].inventory = amount;
    }

    function _testSetWindow(bytes32 flowId, uint128 minted, uint64 windowStart)
        external
    {
        flows[flowId].mintedToday = minted;
        flows[flowId].lastWindowStart = windowStart;
    }
}
