// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {MockERC20} from "./MockERC20.sol";

/// @notice EIP-2612 permit-capable test ERC-20 (USDC-style). Adds the
///         `permit` / `nonces` / `DOMAIN_SEPARATOR` surface so tests can
///         exercise `BridgeEscrow.lockWithPermit`.
contract MockERC20Permit is MockERC20 {
    bytes32 public immutable DOMAIN_SEPARATOR;

    bytes32 private constant PERMIT_TYPEHASH =
        keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

    mapping(address => uint256) public nonces;

    constructor(string memory n, string memory s, uint8 d) MockERC20(n, s, d) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(n)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "ERC20Permit: expired deadline");
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "ERC20Permit: invalid signature");
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }
}
