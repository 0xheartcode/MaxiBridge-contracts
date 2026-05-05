// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BridgeEscrow} from "../../src/BridgeEscrow.sol";

/// @notice Dummy V2 to exercise UUPS upgrade paths.
contract BridgeEscrowV2 is BridgeEscrow {
    function version() external pure returns (string memory) {
        return "v2";
    }
}
