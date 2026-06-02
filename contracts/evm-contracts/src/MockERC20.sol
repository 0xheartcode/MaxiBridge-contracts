// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title MockERC20
/// @notice Testnet-only freely-mintable ERC20.
///         Used as the EVM-side pooled token for modes 3 (POOLED_LOCK_RELEASE)
///         and 4 (POOLED_LOCK_VEST) where users lock tokens on the EVM side
///         and the bridge releases from a pre-funded pool on OPNet.
///
///         Anyone can call `mint` — this is intentional for testnet faucet
///         usage. NEVER deploy on mainnet.
contract MockERC20 is ERC20, Ownable {
    uint8 private immutable _decimals;

    /// @dev Emitted on every open mint so the faucet is auditable.
    event Minted(address indexed to, uint256 amount);

    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_
    ) ERC20(name_, symbol_) Ownable(msg.sender) {
        _decimals = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    /// @notice Open faucet — anyone can mint for testnet testing.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
        emit Minted(to, amount);
    }
}
