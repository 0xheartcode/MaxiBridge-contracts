// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @notice PR γ.2a — exercises lock-side flow consumption: status /
///         minAmount / cap / dailyLimit gates and the per-flow inventory
///         increment. Mirrors the FlowConsumption suite but on the inbound
///         (lock) direction.
contract LockInventoryTest is Test {
    bytes32 internal constant RELEASE_INTENT_TYPEHASH =
        keccak256(
            "ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce,uint256 grossSrcAmount,uint128 relayerTip,bytes32 flowId)"
        );

    TestableBridgeEscrow internal impl;
    TestableBridgeEscrow internal escrow;
    MockERC20 internal usdc;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xB0B);
    address internal guardian = address(0x6A6D);

    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;
    uint64 internal constant ETH_CHAIN_ID = 1;
    bytes32 internal constant OPNET_BRIDGE = bytes32(uint256(0xDEAD));
    bytes32 internal constant OPNET_USDC = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant RECIPIENT = keccak256("rcp");

    bytes32 internal flowId;

    function setUp() public {
        signerAddr = vm.addr(signerPk);
        usdc = new MockERC20("USD Coin", "USDC", 6);

        impl = new TestableBridgeEscrow();
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = TestableBridgeEscrow(
            address(new ERC1967Proxy(address(impl), initData))
        );

        vm.startPrank(owner);
        escrow.setGuardian(guardian);
        flowId = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: 0,
                evmChainId: ETH_CHAIN_ID,
                evmBridge: address(0xE5C0),
                evmToken: address(usdc),
                evmDecimals: 6,
                opnetBridge: OPNET_BRIDGE,
                opnetToken: OPNET_USDC,
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 1_000, // 0.001 USDC dust floor
                cap: 100_000e6,
                dailyLimit: 50_000e6,
                tipCapBps: 0
            })
        );
        vm.stopPrank();

        usdc.mint(alice, 10_000_000e6);
        vm.prank(alice);
        usdc.approve(address(escrow), type(uint256).max);
    }

    // ─── status ─────────────────────────────────────────────────────────

    function test_Lock_StatusInactive_Reverts() public {
        vm.prank(guardian);
        escrow.pauseFlow(flowId);
        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.FlowNotActive.selector);
        escrow.lock(address(usdc), 10_000e6, RECIPIENT, flowId);
    }

    function test_Lock_StatusDraining_Reverts() public {
        // DRAINING means winding down — only release/burn allowed, no new
        // forward deposits. Verify lock is rejected on a draining flow.
        vm.prank(owner);
        escrow.drainFlow(flowId);
        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.FlowNotActive.selector);
        escrow.lock(address(usdc), 10_000e6, RECIPIENT, flowId);
    }

    // ─── minAmount ──────────────────────────────────────────────────────

    function test_Lock_BelowMinAmount_Reverts() public {
        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.AmountBelowFlowMin.selector);
        escrow.lock(address(usdc), 999, RECIPIENT, flowId);
    }

    function test_Lock_AtMinAmount_Succeeds() public {
        vm.prank(alice);
        escrow.lock(address(usdc), 1_000, RECIPIENT, flowId);
        assertEq(escrow.getFlow(flowId).inventory, 1_000);
    }

    // ─── cap ────────────────────────────────────────────────────────────

    function test_Lock_CapExceeded_Reverts() public {
        // Pre-fill inventory to one wei below the cap; next 1_000 lock bumps over.
        escrow._testSetInventory(flowId, uint128(100_000e6) - 1);
        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.FlowCapExceeded.selector);
        escrow.lock(address(usdc), 1_000, RECIPIENT, flowId);
    }

    function test_Lock_AtCapBoundary_Succeeds() public {
        // Pre-fill to (cap - 1_000); locking exactly 1_000 lands on the cap.
        escrow._testSetInventory(flowId, uint128(100_000e6) - 1_000);
        vm.prank(alice);
        escrow.lock(address(usdc), 1_000, RECIPIENT, flowId);
        assertEq(escrow.getFlow(flowId).inventory, 100_000e6);
    }

    // ─── dailyLimit ─────────────────────────────────────────────────────

    function test_Lock_DailyLimit_Exceeded_Reverts() public {
        // dailyLimit = 50_000e6 — first lock at the cap consumes the
        // bucket; the next 1_000 dust lock should revert.
        vm.prank(alice);
        escrow.lock(address(usdc), 50_000e6, RECIPIENT, flowId);
        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.DailyLimitExceeded.selector);
        escrow.lock(address(usdc), 1_000, RECIPIENT, flowId);
    }

    function test_Lock_DailyLimit_WindowRotates() public {
        // Window rotation after FLOW_WINDOW_DURATION lets the next lock
        // proceed even though we already hit the limit.
        vm.prank(alice);
        escrow.lock(address(usdc), 50_000e6, RECIPIENT, flowId);
        vm.warp(block.timestamp + 86_401);
        vm.prank(alice);
        escrow.lock(address(usdc), 1_000, RECIPIENT, flowId);
    }

    // ─── inventory ──────────────────────────────────────────────────────

    function test_Lock_InventoryIncrements() public {
        uint128 before = escrow.getFlow(flowId).inventory;
        vm.prank(alice);
        escrow.lock(address(usdc), 12_345e6, RECIPIENT, flowId);
        uint128 afterAmt = escrow.getFlow(flowId).inventory;
        assertEq(uint256(afterAmt) - uint256(before), 12_345e6);
    }

    // ─── flowId binding ─────────────────────────────────────────────────

    function test_Lock_UnknownFlowId_Reverts() public {
        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.FlowNotFound.selector);
        escrow.lock(address(usdc), 1_000, RECIPIENT, keccak256("nope"));
    }

    function test_Lock_FlowTokenMismatch_Reverts() public {
        // Register a second flow against a different token; passing its
        // flowId for a usdc lock must revert.
        MockERC20 other = new MockERC20("Other", "OTH", 18);
        vm.startPrank(owner);
        escrow.setSupportedToken(address(other), true);
        bytes32 otherFlowId = escrow.addFlow(BridgeEscrow.FlowAddParams({
            mode: 0,
            evmChainId: ETH_CHAIN_ID,
            evmBridge: address(0xE5C0),
            evmToken: address(other),
            evmDecimals: 18,
            opnetBridge: OPNET_BRIDGE,
            opnetToken: bytes32(uint256(0x9999)),
            opnetDecimals: 18,
            feeBps: 0,
            minFee: 0,
            minAmount: 0,
            cap: type(uint128).max,
            dailyLimit: type(uint128).max,
            tipCapBps: 0
        }));
        vm.stopPrank();
        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.FlowNotFound.selector);
        escrow.lock(address(usdc), 1_000, RECIPIENT, otherFlowId);
    }

    function test_Lock_EmitsLockedToFlowEvent() public {
        vm.recordLogs();
        vm.prank(alice);
        escrow.lock(address(usdc), 5_000e6, RECIPIENT, flowId);
        Vm.Log[] memory entries = vm.getRecordedLogs();
        bytes32 sig = keccak256("LockedToFlow(bytes32,address,address,uint256)");
        bool found;
        for (uint256 i; i < entries.length; i++) {
            if (entries[i].topics.length > 0 && entries[i].topics[0] == sig) {
                found = true;
                assertEq(entries[i].topics[1], flowId);
                assertEq(address(uint160(uint256(entries[i].topics[2]))), alice);
                assertEq(address(uint160(uint256(entries[i].topics[3]))), address(usdc));
                assertEq(abi.decode(entries[i].data, (uint256)), 5_000e6);
                break;
            }
        }
        assertTrue(found, "LockedToFlow not emitted");
    }

    // ─── Round-trip: lock then claim ────────────────────────────────────

    function test_LockThenClaim_InventoryNetZero() public {
        // Lock 100 USDC → claim 100 USDC out — inventory should be back
        // to its starting value (0).
        uint128 before = escrow.getFlow(flowId).inventory;
        assertEq(before, 0);

        vm.prank(alice);
        escrow.lock(address(usdc), 100e6, RECIPIENT, flowId);
        assertEq(escrow.getFlow(flowId).inventory, 100e6);

        // Build + sign a release intent for the same 100 USDC.
        BridgeEscrow.ReleaseIntent memory intent = BridgeEscrow.ReleaseIntent({
            token: address(usdc),
            to: bob,
            amount: 100e6,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: keccak256("rt-tx"),
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: keccak256("rt-n"),
            grossSrcAmount: 100e6,
            relayerTip: 0,
            flowId: flowId
        });

        bytes32 structHash = keccak256(
            abi.encode(
                RELEASE_INTENT_TYPEHASH,
                intent.token,
                intent.to,
                intent.amount,
                intent.srcChainId,
                intent.opnetTxHash,
                intent.opnetEventIndex,
                intent.burnNonce,
                intent.signerEpoch,
                intent.opnetNonce,
                intent.grossSrcAmount,
                intent.relayerTip,
                intent.flowId
            )
        );
        bytes32 domain = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("BridgeEscrow")),
                keccak256(bytes("1")),
                block.chainid,
                address(escrow)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domain, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        bytes memory raw = abi.encodePacked(r, s, v);
        bytes memory sig = abi.encodePacked(uint8(1), raw);

        escrow.claim(intent, sig);

        // Inventory net-zero on round-trip.
        assertEq(escrow.getFlow(flowId).inventory, 0);
        assertEq(usdc.balanceOf(bob), 100e6);
    }
}

