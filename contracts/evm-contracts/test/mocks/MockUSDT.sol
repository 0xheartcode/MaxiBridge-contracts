// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Minimal non-ERC20-compliant token mimicking mainnet USDT
///         (transfer/transferFrom return no bool). Used to verify SafeERC20.
contract MockUSDT {
    string public constant name = "Mock USDT";
    string public constant symbol = "mUSDT";
    uint8 public constant decimals = 6;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    /// @dev No return value — matches USDT on mainnet.
    function transfer(address to, uint256 value) external {
        _transfer(msg.sender, to, value);
    }

    function transferFrom(address from, address to, uint256 value) external {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= value, "USDT: insufficient allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
    }

    function approve(address spender, uint256 value) external {
        // USDT's quirk: approve from non-zero to non-zero reverts; we skip it for test cleanliness.
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(balanceOf[from] >= value, "USDT: balance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
