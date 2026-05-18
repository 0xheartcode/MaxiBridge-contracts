// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {DepositAddressFactory} from "../src/DepositAddressFactory.sol";

/// @notice #4 — exercises the CREATE2 deposit-address flow: predict an
///         address, fund it with a bare transfer (no approve, no dApp),
///         sweep it, and confirm the funds land in BridgeEscrow.lock.
contract DepositAddressFactoryTest is Test {
    TestableBridgeEscrow internal escrow;
    MockERC20 internal usdc;
    DepositAddressFactory internal factory;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    bytes32 internal flowId;
    bytes32 internal constant RECIPIENT = keccak256("opnet-rcp");

    function setUp() public {
        usdc = new MockERC20("USD Coin", "USDC", 6);

        TestableBridgeEscrow impl = new TestableBridgeEscrow();
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize, (owner, vm.addr(signerPk), 2, tokens)
        );
        escrow = TestableBridgeEscrow(address(new ERC1967Proxy(address(impl), initData)));

        vm.prank(owner);
        flowId = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: 0,
                evmChainId: 1,
                evmBridge: address(0xE5C0),
                evmToken: address(usdc),
                evmDecimals: 6,
                opnetBridge: bytes32(uint256(0xDEAD)),
                opnetToken: bytes32(uint256(0xC0FFEE)),
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );

        factory = new DepositAddressFactory(address(escrow));
    }

    function test_PredictMatchesSweptVault_AndForwardsToLock() public {
        bytes32 salt = keccak256("deposit-1");
        uint256 amount = 7_500e6;

        address depositAddr = factory.predict(salt, address(usdc), RECIPIENT, flowId);

        // User sends tokens to the predicted address — no dApp, no approve.
        usdc.mint(depositAddr, amount);
        assertEq(usdc.balanceOf(depositAddr), amount);

        // Anyone sweeps.
        address vault = factory.sweep(salt, address(usdc), RECIPIENT, flowId);

        assertEq(vault, depositAddr, "predict must match the deployed vault");
        assertEq(usdc.balanceOf(address(escrow)), amount, "escrow received the deposit");
        assertEq(usdc.balanceOf(depositAddr), 0, "vault drained");
        assertEq(escrow.depositNonce(), 1, "a lock was recorded");
        assertEq(escrow.getFlow(flowId).inventory, amount, "flow inventory bumped");
        assertEq(depositAddr.code.length, 0, "vault self-destructed");
    }

    function test_PredictIsParamBound() public view {
        bytes32 salt = keccak256("deposit-x");
        address a = factory.predict(salt, address(usdc), RECIPIENT, flowId);
        // A different opnetRecipient → a different deposit address: the
        // address commits to where the bridged funds will go.
        address b = factory.predict(salt, address(usdc), keccak256("other"), flowId);
        assertTrue(a != b, "deposit address commits to opnetRecipient");
    }

    function test_Sweep_EmptyAddress_RecordsNoLock() public {
        // Sweeping an unfunded address still deploys+destructs the vault,
        // but the constructor's bal==0 branch records no lock.
        bytes32 salt = keccak256("empty");
        factory.sweep(salt, address(usdc), RECIPIENT, flowId);
        assertEq(escrow.depositNonce(), 0, "no lock for an empty deposit address");
    }
}
