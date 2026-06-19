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
/// @dev    `BRIDGE` is set at construction and is the BridgeEscrow proxy.
///         Mint authority is bridge-only. Burn is user-callable: it
///         destroys the caller's tokens and emits BurnedForRelease so
///         the indexer can produce a release/mint voucher on OPNet.
contract WrappedERC20 is ERC20, Ownable, Pausable {
    /// @notice The BridgeEscrow proxy authorized to mint. Set once at
    ///         construction; rotation requires a redeploy.
    address public immutable BRIDGE;

    /// @notice OPNet network id this wrapped maps to (mainnet=1, testnet=2).
    uint256 public immutable OPNET_CHAIN_ID;

    /// @notice 32-byte OPNet identity of the source asset:
    ///         - INVERSE_WRAPPED: the canonical OP20 address on OPNet
    ///         - NATIVE_BURN_MINT: the wrapped OP20 address on OPNet (no
    ///           canonical exists; this is the OPNet-side "twin")
    bytes32 public immutable OPNET_COUNTERPART;

    /// @notice Decimal precision of this token on the EVM side. Set once at
    ///         construction to match the EVM-ecosystem convention for the
    ///         bridged asset (e.g. 6 for USDT-on-Ethereum, 18 for
    ///         USDT-bridged-from-BSC). AmountPolicy handles cross-chain
    ///         decimal scaling; this field simply tells wallets and DEXes
    ///         how to display the balance.
    uint8 private immutable _decimals;

    /// @notice E-1 — hard supply ceiling enforced on EVERY mint path
    ///         (`mintFromBridge`, reached by `BridgeEscrow.claim`
    ///         AND `refundBurn`). Mirrors the OPNet `WrappedOP20`'s
    ///         OP20-mandated `maxSupply` so a compromised signer set cannot
    ///         mint without bound across successive windows. Set once at
    ///         construction (non-upgradeable → raising it = fresh wrapper
    ///         deploy + governance minter pivot, same as OPNet). Pass
    ///         `type(uint256).max` for an explicitly-uncapped wrapper; a zero
    ///         cap is rejected (it would brick all mints). Burns reduce
    ///         `totalSupply`, so a burn frees headroom — the ceiling is on
    ///         OUTSTANDING supply, not cumulative-minted-ever.
    uint256 public immutable MAX_SUPPLY;

    error NotBridge();
    error AmountZero();
    error ZeroRecipient();
    error MaxSupplyExceeded();

    event BurnedForRelease(
        address indexed from,
        uint256 amount,
        bytes32 opnetRecipient,
        uint256 indexed burnNonce,
        // #68 Tier C — flowId APPENDED last (non-indexed) so all pre-existing
        // log offsets stay stable. Names which flow/route this burn is for.
        bytes32 flowId
    );

    /// @dev Monotonic burn nonce — gives each burn a unique id even when
    ///      the same user burns the same amount to the same recipient
    ///      repeatedly.
    uint256 public burnNonce;

    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address owner_,
        address bridge_,
        uint256 opnetChainId_,
        bytes32 opnetCounterpart_,
        uint256 maxSupply_
    ) ERC20(name_, symbol_) Ownable(owner_) {
        require(bridge_ != address(0), "WrappedERC20: zero bridge");
        // E-1 — a zero cap would make `MAX_SUPPLY - totalSupply() == 0` and
        // revert EVERY mint, bricking the wrapper. Force a deliberate ceiling
        // (use type(uint256).max for an uncapped wrapper).
        require(maxSupply_ > 0, "WrappedERC20: zero maxSupply");
        _decimals = decimals_;
        BRIDGE = bridge_;
        OPNET_CHAIN_ID = opnetChainId_;
        OPNET_COUNTERPART = opnetCounterpart_;
        MAX_SUPPLY = maxSupply_;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    modifier onlyBridge() {
        _onlyBridge();
        _;
    }

    function _onlyBridge() internal view {
        if (msg.sender != BRIDGE) revert NotBridge();
    }

    /// @notice Mint wrapped tokens. Only the bridge may call.
    function mintFromBridge(address to, uint256 amount) external onlyBridge {
        if (to == address(0)) revert ZeroRecipient();
        if (amount == 0) revert AmountZero();
        // E-1 — hard supply ceiling. `MAX_SUPPLY >= totalSupply()` is an
        // invariant (we never mint past it), so the subtraction is safe and
        // the check is overflow-free. Caps BOTH the mint-on-EVM `claim` and
        // refundBurn (both funnel through here).
        if (amount > MAX_SUPPLY - totalSupply()) revert MaxSupplyExceeded();
        _mint(to, amount);
    }

    /// @notice Burn caller's tokens and emit BurnedForRelease so the
    ///         indexer can issue a release/mint voucher on OPNet.
    /// @dev    `whenNotPaused` so an incident-response pause halts new
    ///         OPNet release/mint liabilities from accruing.
    /// @param  flowId — #68 Tier C: which flow/route this burn is for. Only
    ///         recorded in the event; the signed release voucher binds it to
    ///         the destination flow on the OPNet side.
    /// @param  opnetRecipient — 32-byte OPNet identity that receives on the
    ///         other side. Caller is responsible for picking the right
    ///         encoding for their target (canonical OP20 receive vs
    ///         wrapped OP20 receive).
    /// @param  amount — token base units (see \`decimals()\` for this wrapper's precision).
    function burnForRelease(bytes32 flowId, bytes32 opnetRecipient, uint256 amount)
        external
        whenNotPaused
    {
        if (opnetRecipient == bytes32(0)) revert ZeroRecipient();
        if (amount == 0) revert AmountZero();
        _burn(msg.sender, amount);
        unchecked {
            ++burnNonce;
        }
        // Outstanding-supply accounting needs no callback: the bridge enforces
        // the per-flow mode-2 `cap` against THIS token's `totalSupply()`, which
        // this `_burn` has already reduced — so the burn frees cap headroom
        // automatically (see BridgeEscrow.claim / refundBurn, PVE003).
        emit BurnedForRelease(msg.sender, amount, opnetRecipient, burnNonce, flowId);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
