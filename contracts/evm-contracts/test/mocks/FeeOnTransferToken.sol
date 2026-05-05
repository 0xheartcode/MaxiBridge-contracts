// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {MockERC20} from "./MockERC20.sol";

/// @notice Malicious fee-on-transfer token: returns true but delivers
///         fewer tokens than `value`. Exercises balance-delta check.
contract FeeOnTransferToken is MockERC20 {
    uint256 public feeBps;

    constructor(uint256 feeBps_) MockERC20("FeeOnTransfer", "FEE", 18) {
        feeBps = feeBps_;
    }

    function setFeeBps(uint256 feeBps_) external {
        feeBps = feeBps_;
    }

    function _transfer(address from, address to, uint256 value) internal override {
        require(balanceOf[from] >= value, "FEE: balance");
        uint256 fee = (value * feeBps) / 10_000;
        uint256 received = value - fee;
        balanceOf[from] -= value;
        balanceOf[to] += received;
        // fee is silently burned
        totalSupply -= fee;
        emit Transfer(from, to, received);
        if (fee > 0) {
            emit Transfer(from, address(0), fee);
        }
    }
}
