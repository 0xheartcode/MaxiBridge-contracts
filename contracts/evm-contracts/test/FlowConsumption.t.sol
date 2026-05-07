// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @notice PR γ.1 — flow consumption (cap / dailyLimit / minAmount /
///         status active / inventory) on the EVM `claim` (release) path.
///
///         EVM `claim` is the release direction (modes 0 / 3). Inventory
///         decreases by `grossSrcAmount` on every successful claim; the
///         per-flow `cap` is only meaningful on the lock side (which
///         doesn't bump `inventory` yet — γ.2 territory). Cap-overflow
///         protection on this side reduces to `inventory >= grossDst`.
contract FlowConsumptionTest is Test {
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
                cap: 10_000_000e6,
                dailyLimit: 100_000e6,
                tipCapBps: 100
            })
        );
        vm.stopPrank();

        // Seed escrow's USDC balance + flow inventory.
        usdc.mint(alice, 10_000_000e6);
        vm.startPrank(alice);
        usdc.approve(address(escrow), type(uint256).max);
        escrow.lock(address(usdc), 1_000_000e6, keccak256("seed"));
        vm.stopPrank();

        // Seed inventory directly — `lock` doesn't bump inventory yet
        // (γ.2 territory). Tests in this file rely on a non-zero starting
        // inventory so the release path can decrement it.
        escrow._testSetInventory(flowId, 1_000_000e6);
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    function _hashIntent(BridgeEscrow.ReleaseIntent memory intent)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
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
    }

    function _domainSeparator() internal view returns (bytes32) {
        return
            keccak256(
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
    }

    function _sign(uint256 pk, BridgeEscrow.ReleaseIntent memory intent)
        internal
        view
        returns (bytes memory)
    {
        bytes32 d = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), _hashIntent(intent))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        bytes memory raw = abi.encodePacked(r, s, v);
        return abi.encodePacked(uint8(1), raw);
    }

    function _intent(
        uint256 amount,
        uint256 grossSrc,
        uint128 tip,
        bytes32 fId,
        bytes32 nonceSalt
    ) internal view returns (BridgeEscrow.ReleaseIntent memory intent) {
        intent = BridgeEscrow.ReleaseIntent({
            token: address(usdc),
            to: bob,
            amount: amount,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: nonceSalt,
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: keccak256(abi.encodePacked("nonce", nonceSalt)),
            grossSrcAmount: grossSrc,
            relayerTip: tip,
            flowId: fId
        });
    }

    // ─── minAmount ──────────────────────────────────────────────────────

    function test_Claim_GrossBelowMinAmount_Reverts() public {
        // minAmount = 1_000; grossSrc = 999 → reject.
        BridgeEscrow.ReleaseIntent memory intent = _intent(
            999,
            999,
            0,
            flowId,
            keccak256("under-min")
        );
        bytes memory sig = _sign(signerPk, intent);
        vm.expectRevert(BridgeEscrow.AmountBelowFlowMin.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_AtMinAmount_Succeeds() public {
        // grossSrc == minAmount (1_000) — boundary accept.
        BridgeEscrow.ReleaseIntent memory intent = _intent(
            1_000,
            1_000,
            0,
            flowId,
            keccak256("at-min")
        );
        bytes memory sig = _sign(signerPk, intent);
        uint256 bobBefore = usdc.balanceOf(bob);
        escrow.claim(intent, sig);
        assertEq(usdc.balanceOf(bob) - bobBefore, 1_000, "recipient credited");
    }

    // ─── cap (overflow proxy via inventory) ─────────────────────────────

    function test_Claim_CapWouldOverflow_Reverts() public {
        // EVM claim is the release path — the relevant overflow guard is
        // `inventory >= grossDst`. Set inventory to a tiny value and submit
        // a claim larger than that. Surfaces as InsufficientFlowInventory.
        escrow._testSetInventory(flowId, 500);
        BridgeEscrow.ReleaseIntent memory intent = _intent(
            10_000,
            10_000,
            0,
            flowId,
            keccak256("cap-overflow")
        );
        bytes memory sig = _sign(signerPk, intent);
        vm.expectRevert(BridgeEscrow.InsufficientFlowInventory.selector);
        escrow.claim(intent, sig);
    }

    // ─── dailyLimit (rolling 24h window) ────────────────────────────────

    function test_Claim_DailyLimit_FirstClaimResetsWindow() public {
        // Initial state: lastWindowStart = 0, mintedToday = 0. First claim
        // rotates the window (block.timestamp - 0 > 86400) and consumes
        // grossDst. Verify the post-state via getFlow.
        vm.warp(1_000_000); // pin a known timestamp.
        BridgeEscrow.ReleaseIntent memory intent = _intent(
            10_000,
            10_000,
            0,
            flowId,
            keccak256("first")
        );
        bytes memory sig = _sign(signerPk, intent);
        escrow.claim(intent, sig);
        BridgeEscrow.FlowRecord memory f = escrow.getFlow(flowId);
        assertEq(f.mintedToday, 10_000, "minted bucket reset and consumed");
        assertEq(f.lastWindowStart, 1_000_000, "window pinned to current ts");
    }

    function test_Claim_DailyLimit_AccumulatesWithinWindow() public {
        vm.warp(1_000_000);
        // Two claims back-to-back stay inside the 24h window.
        BridgeEscrow.ReleaseIntent memory intent1 = _intent(
            10_000,
            10_000,
            0,
            flowId,
            keccak256("acc-1")
        );
        escrow.claim(intent1, _sign(signerPk, intent1));

        // 1 hour later — still inside window.
        vm.warp(1_000_000 + 3_600);
        BridgeEscrow.ReleaseIntent memory intent2 = _intent(
            10_000,
            10_000,
            0,
            flowId,
            keccak256("acc-2")
        );
        escrow.claim(intent2, _sign(signerPk, intent2));

        BridgeEscrow.FlowRecord memory f = escrow.getFlow(flowId);
        assertEq(f.mintedToday, 20_000, "bucket accumulates");
        assertEq(f.lastWindowStart, 1_000_000, "window unchanged");
    }

    function test_Claim_DailyLimit_Exceeded_Reverts() public {
        // dailyLimit = 100_000e6. Pre-fill the bucket to exactly the cap;
        // any further claim of any size must revert.
        escrow._testSetWindow(flowId, 100_000e6, uint64(block.timestamp));
        BridgeEscrow.ReleaseIntent memory intent = _intent(
            1_000,
            1_000,
            0,
            flowId,
            keccak256("over-limit")
        );
        bytes memory sig = _sign(signerPk, intent);
        vm.expectRevert(BridgeEscrow.DailyLimitExceeded.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_DailyLimit_RollsOverAfter24h() public {
        // Pre-fill bucket at the cap; advance time > 24h; new claim
        // succeeds and the bucket is reset to (just) `grossDst`.
        vm.warp(1_000_000);
        escrow._testSetWindow(flowId, 100_000e6, uint64(block.timestamp));
        vm.warp(1_000_000 + 86_400 + 1); // strictly past the window edge.
        BridgeEscrow.ReleaseIntent memory intent = _intent(
            10_000,
            10_000,
            0,
            flowId,
            keccak256("rollover")
        );
        escrow.claim(intent, _sign(signerPk, intent));
        BridgeEscrow.FlowRecord memory f = escrow.getFlow(flowId);
        assertEq(f.mintedToday, 10_000, "bucket reset to fresh consumption");
        assertEq(f.lastWindowStart, 1_000_000 + 86_400 + 1, "window pinned to now");
    }

    // ─── status active ──────────────────────────────────────────────────

    function test_Claim_StatusInactive_Reverts() public {
        // PR β.2 already covered the tipped-claim path on a paused flow.
        // PR γ.1 widens the gate to ALL claims regardless of tip.
        vm.prank(guardian);
        escrow.pauseFlow(flowId);
        BridgeEscrow.ReleaseIntent memory intent = _intent(
            10_000,
            10_000,
            0, // tip = 0 — still must revert.
            flowId,
            keccak256("paused-no-tip")
        );
        bytes memory sig = _sign(signerPk, intent);
        vm.expectRevert(BridgeEscrow.FlowNotActive.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_StatusDraining_Allows() public {
        // DRAINING is intentionally claim-allowed (winding the route down
        // means letting in-flight withdrawals settle). Sanity-check the
        // status gate doesn't reject DRAINING.
        vm.prank(owner);
        escrow.drainFlow(flowId);
        BridgeEscrow.ReleaseIntent memory intent = _intent(
            10_000,
            10_000,
            0,
            flowId,
            keccak256("draining-ok")
        );
        escrow.claim(intent, _sign(signerPk, intent));
    }

    // ─── inventory ──────────────────────────────────────────────────────

    function test_Claim_InsufficientInventory_Reverts() public {
        escrow._testSetInventory(flowId, 5_000);
        BridgeEscrow.ReleaseIntent memory intent = _intent(
            10_000,
            10_000,
            0,
            flowId,
            keccak256("low-inv")
        );
        bytes memory sig = _sign(signerPk, intent);
        vm.expectRevert(BridgeEscrow.InsufficientFlowInventory.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_InventoryDecrementsOnRelease() public {
        uint128 before = escrow.getFlow(flowId).inventory;
        BridgeEscrow.ReleaseIntent memory intent = _intent(
            10_000,
            10_000,
            0,
            flowId,
            keccak256("inv-dec")
        );
        escrow.claim(intent, _sign(signerPk, intent));
        uint128 afterAmt = escrow.getFlow(flowId).inventory;
        assertEq(uint256(before) - uint256(afterAmt), 10_000, "inventory -= grossDst");
    }
}
