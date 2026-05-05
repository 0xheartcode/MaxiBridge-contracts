// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";

/// @notice Deploys BridgeEscrow implementation + ERC1967 proxy.
/// @dev Reads env: DEPLOYER_PRIVATE_KEY, BRIDGE_OWNER, BRIDGE_SIGNER,
///      EXPECTED_OPNET_CHAIN_ID (1=mainnet, 2=testnet), EVM_USDC, EVM_USDT.
///      Owner defaults to the deployer address if unset. Both USDC + USDT are added to
///      the supported-token whitelist at init time.
contract Deploy is Script {
    function run() external returns (address proxy, address implementation) {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);

        address ownerAddr = vm.envOr("BRIDGE_OWNER", deployer);
        address signerAddr = vm.envAddress("BRIDGE_SIGNER");
        uint256 expectedOpnetChainId = vm.envUint("EXPECTED_OPNET_CHAIN_ID");
        address usdc = vm.envAddress("EVM_USDC");
        address usdt = vm.envAddress("EVM_USDT");

        require(ownerAddr != address(0), "owner zero");
        require(signerAddr != address(0), "signer zero");
        require(expectedOpnetChainId != 0, "opnet chain id zero");
        require(usdc != address(0) && usdt != address(0), "token zero");

        vm.startBroadcast(deployerPk);

        BridgeEscrow impl = new BridgeEscrow();

        address[] memory tokens = new address[](2);
        tokens[0] = usdc;
        tokens[1] = usdt;

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (ownerAddr, signerAddr, expectedOpnetChainId, tokens)
        );
        ERC1967Proxy p = new ERC1967Proxy(address(impl), initData);

        vm.stopBroadcast();

        console2.log("BridgeEscrow implementation:", address(impl));
        console2.log("BridgeEscrow proxy:", address(p));
        console2.log("Owner:", ownerAddr);
        console2.log("Signer:", signerAddr);
        console2.log("Expected OPNet chainId:", expectedOpnetChainId);

        return (address(p), address(impl));
    }
}
