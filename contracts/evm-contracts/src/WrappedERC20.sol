// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title WrappedERC20
/// @notice EVM-side wrapped representation of either:
///         (a) an OPNet canonical OP20 token (mode INVERSE_WRAPPED), or
///         (b) a bridge-native asset where the bridge is the canonical
///             minter on both chains (mode NATIVE_BURN_MINT).
///
///         This contract is NOT upgradeable. It's intentionally thin —
///         the trust surface is just "the bridge can mint, anyone can
///         burn for release". For complex tokens (rebasing, fees, etc.)
///         use a different wrapped pattern.
///
/// @dev    `bridge` is set at construction and is the BridgeEscrow proxy.
///         Mint authority is bridge-only. Burn is user-callable: it
///         destroys the caller's tokens and emits BurnedForRelease so
///         the indexer can produce a release/mint voucher on OPNet.
contract WrappedERC20 is ERC20, Ownable, Pausable {
    /// @notice The BridgeEscrow proxy authorized to mint. Set once at
    ///         construction; rotation requires a redeploy.
    address public immutable bridge;

    /// @notice OPNet network id this wrapped maps to (mainnet=1, testnet=2).
    uint256 public immutable opnetChainId;

    /// @notice 32-byte OPNet identity of the source asset:
    ///         - INVERSE_WRAPPED: the canonical OP20 address on OPNet
    ///         - NATIVE_BURN_MINT: the wrapped OP20 address on OPNet (no
    ///           canonical exists; this is the OPNet-side "twin")
    bytes32 public immutable opnetCounterpart;

    error NotBridge();
    error AmountZero();
    error ZeroRecipient();

    event BurnedForRelease(
        address indexed from,
        uint256 amount,
        bytes32 opnetRecipient,
        uint256 indexed burnNonce
    );

    /// @dev Monotonic burn nonce — gives each burn a unique id even when
    ///      the same user burns the same amount to the same recipient
    ///      repeatedly.
    uint256 public burnNonce;

    constructor(
        string memory name_,
        string memory symbol_,
        address owner_,
        address bridge_,
        uint256 opnetChainId_,
        bytes32 opnetCounterpart_
    ) ERC20(name_, symbol_) Ownable(owner_) {
        require(bridge_ != address(0), "WrappedERC20: zero bridge");
        bridge = bridge_;
        opnetChainId = opnetChainId_;
        opnetCounterpart = opnetCounterpart_;
    }

    function decimals() public pure override returns (uint8) {
        // 6 decimals to match wUSDC/wUSDT and OPNet OP20 stable conventions.
        // Concrete deployments that need a different precision should
        // subclass + override.
        return 6;
    }

    modifier onlyBridge() {
        if (msg.sender != bridge) revert NotBridge();
        _;
    }

    /// @notice Mint wrapped tokens. Only the bridge may call.
    function mintFromBridge(address to, uint256 amount) external onlyBridge {
        if (to == address(0)) revert ZeroRecipient();
        if (amount == 0) revert AmountZero();
        _mint(to, amount);
    }

    /// @notice Burn caller's tokens and emit BurnedForRelease so the
    ///         indexer can issue a release/mint voucher on OPNet.
    /// @dev    `whenNotPaused` so an incident-response pause halts new
    ///         OPNet release/mint liabilities from accruing.
    /// @param  opnetRecipient — 32-byte OPNet identity that receives on the
    ///         other side. Caller is responsible for picking the right
    ///         encoding for their target (canonical OP20 receive vs
    ///         wrapped OP20 receive).
    /// @param  amount — token base units (6 decimals).
    function burnForRelease(bytes32 opnetRecipient, uint256 amount) external whenNotPaused {
        if (opnetRecipient == bytes32(0)) revert ZeroRecipient();
        if (amount == 0) revert AmountZero();
        _burn(msg.sender, amount);
        unchecked {
            ++burnNonce;
        }
        emit BurnedForRelease(msg.sender, amount, opnetRecipient, burnNonce);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
