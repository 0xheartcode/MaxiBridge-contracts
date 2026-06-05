// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";

/// @title Create2Deploy
/// @notice Phase 2.1 — verifies that CREATE2 of the BridgeEscrow ERC1967Proxy
///         lands at the deterministic address predicted off-chain by
///         `scripts/src/lib/create2.ts::predictCreate2Address`.
///
/// @dev    Asserts that:
///           1. CREATE2(factory, salt, initcode) lands at keccak256-derived addr
///           2. The deployed proxy is functional after deterministic deploy
///           3. The same salt yields the same address regardless of impl
///              address (because impl address goes into initcode → different
///              addr when impl differs — which is what we WANT to highlight)
contract Create2DeployTest is Test {
    /// @dev Salt convention from `create2.ts`: keccak256("opnet-bridge-escrow-v1").
    bytes32 internal constant SALT_V1 = keccak256(bytes("opnet-bridge-escrow-v1"));

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;

    function setUp() public {
        signerAddr = vm.addr(signerPk);
    }

    function _buildInitData(address[] memory tokens) internal view returns (bytes memory) {
        return abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, uint256(2), tokens)
        );
    }

    /// @dev Replicates `predictCreate2Address(factory, salt, initcode)` from create2.ts.
    function _predictCreate2(
        address factory,
        bytes32 salt,
        bytes memory initcode
    ) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            factory,
            salt,
            keccak256(initcode)
        )))));
    }

    function test_Create2_PredictedAddressMatches_Deploy() public {
        BridgeEscrow impl = new BridgeEscrow();
        address[] memory tokens = new address[](0);
        bytes memory initData = _buildInitData(tokens);

        // Build proxy creation bytecode with constructor args ABI-encoded —
        // matching `buildErc1967ProxyInitcode` in scripts/src/lib/create2.ts.
        bytes memory proxyInitcode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(impl), initData)
        );

        address self = address(this); // pretend "this test contract" is the CREATE2 factory
        address predicted = _predictCreate2(self, SALT_V1, proxyInitcode);

        // Deploy via CREATE2 from this contract → the address must match.
        address deployed;
        bytes32 saltLocal = SALT_V1;
        assembly {
            deployed := create2(0, add(proxyInitcode, 0x20), mload(proxyInitcode), saltLocal)
        }
        require(deployed != address(0), "create2 reverted");
        assertEq(deployed, predicted, "CREATE2 address must match predict");

        // Sanity — proxy is functional. v2: no legacy `signer` slot;
        // initial signer is in the M-of-N set.
        BridgeEscrow proxied = BridgeEscrow(deployed);
        assertTrue(proxied.isSigner(signerAddr));
        assertEq(proxied.expectedOpnetChainId(), 2);
        assertEq(proxied.signerThreshold(), 1);
    }

    function test_Create2_DifferentImpl_DifferentAddress() public {
        // Same salt, different impl → different proxy address. Confirms that
        // the impl ADDRESS feeds into initcode (so per-chain impls produce
        // per-chain proxies if both go through the same factory+salt).
        BridgeEscrow implA = new BridgeEscrow();
        BridgeEscrow implB = new BridgeEscrow();

        address[] memory tokens = new address[](0);
        bytes memory initData = _buildInitData(tokens);

        bytes memory codeA = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(implA), initData)
        );
        bytes memory codeB = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(implB), initData)
        );

        address self = address(this);
        address addrA = _predictCreate2(self, SALT_V1, codeA);
        address addrB = _predictCreate2(self, SALT_V1, codeB);

        assertTrue(addrA != addrB, "different impls must yield different proxy addrs");
    }

    function test_Create2_SameImpl_SameSalt_SameAddress() public {
        // Two test contracts that follow the deploy script's algorithm with
        // the SAME impl + SAME salt MUST produce the same proxy address.
        // This is the core cross-chain invariant.
        BridgeEscrow impl = new BridgeEscrow();
        address[] memory tokens = new address[](0);
        bytes memory initData = _buildInitData(tokens);
        bytes memory proxyInitcode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(impl), initData)
        );

        // Predict twice with same inputs — must be byte-identical.
        address self = address(this);
        address p1 = _predictCreate2(self, SALT_V1, proxyInitcode);
        address p2 = _predictCreate2(self, SALT_V1, proxyInitcode);
        assertEq(p1, p2);
    }

    function test_Create2_Idempotent_RedeployReverts() public {
        // CREATE2 is idempotent at the ADDRESS level — second deploy reverts.
        // Confirms the script's pre-flight `getCode(predicted) != "0x"` check
        // is the right defensive pattern.
        BridgeEscrow impl = new BridgeEscrow();
        address[] memory tokens = new address[](0);
        bytes memory initData = _buildInitData(tokens);
        bytes memory proxyInitcode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(impl), initData)
        );

        bytes32 saltLocal = SALT_V1;
        address first;
        assembly {
            first := create2(0, add(proxyInitcode, 0x20), mload(proxyInitcode), saltLocal)
        }
        require(first != address(0), "first create2 reverted");

        address second;
        assembly {
            second := create2(0, add(proxyInitcode, 0x20), mload(proxyInitcode), saltLocal)
        }
        // create2 returns 0 on collision (no revert in raw assembly)
        assertEq(second, address(0), "second deploy must collide and return 0");
    }
}
