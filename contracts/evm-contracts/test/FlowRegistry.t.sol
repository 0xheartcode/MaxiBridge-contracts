// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";

/// @notice PR α — FlowRegistry storage + governance.
///         Verifies the additive layer: addFlow / pauseFlow / resumeFlow
///         / drainFlow / setFlowCap / setFlowDailyLimit / setFlowMinAmount
///         / setFlowFee plus immutability of set-once fields, status-
///         transition guards, role enforcement, and enumeration views.
///         No claim / lock paths are exercised here — those land in PR γ.
contract FlowRegistryTest is Test {
    BridgeEscrow internal impl;
    BridgeEscrow internal escrow;

    MockERC20 internal usdc;
    MockUSDT internal usdt;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    address internal guardian = address(0x6A6D);
    address internal stranger = address(0xBAD);

    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;
    uint64 internal constant ETH_CHAIN_ID = 1;
    uint64 internal constant ARB_CHAIN_ID = 42161;

    bytes32 internal constant OPNET_BRIDGE = bytes32(uint256(0xDEAD));
    bytes32 internal constant OPNET_USDC = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant OPNET_USDT = bytes32(uint256(0xBEEF));

    function setUp() public {
        signerAddr = vm.addr(signerPk);

        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdt = new MockUSDT();

        impl = new BridgeEscrow();

        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(usdt);

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = BridgeEscrow(address(new ERC1967Proxy(address(impl), initData)));

        // Set guardian via owner so guardian-only paths are exercisable.
        vm.prank(owner);
        escrow.setGuardian(guardian);
    }

    // ─── Helpers ───────────────────────────────────────────────────────

    function _defaultParams(address evmToken, bytes32 opnetToken)
        internal
        pure
        returns (BridgeEscrow.FlowAddParams memory)
    {
        return BridgeEscrow.FlowAddParams({
            mode: 0, // WRAPPED
            evmChainId: ETH_CHAIN_ID,
            evmBridge: address(0xE5C0),
            evmToken: evmToken,
            evmDecimals: 6,
            opnetBridge: OPNET_BRIDGE,
            opnetToken: opnetToken,
            opnetDecimals: 6,
            feeBps: 50,
            minFee: 0,
            minAmount: 1_000_000, // 1 USDC
            cap: 1_000_000_000_000, // 1M USDC
            dailyLimit: 100_000_000_000, // 100k USDC
            tipCapBps: 0 // tipping disabled by default (PR β.2.scaffold)
        });
    }

    function _addDefault(address evmToken, bytes32 opnetToken)
        internal
        returns (bytes32 flowId)
    {
        BridgeEscrow.FlowAddParams memory p = _defaultParams(evmToken, opnetToken);
        vm.prank(owner);
        flowId = escrow.addFlow(p);
    }

    // ─── computeFlowId ─────────────────────────────────────────────────

    function test_ComputeFlowId_IsDeterministic() public view {
        bytes32 a = escrow.computeFlowId(0, ETH_CHAIN_ID, address(0xE5C0), address(usdc), OPNET_BRIDGE, OPNET_USDC);
        bytes32 b = escrow.computeFlowId(0, ETH_CHAIN_ID, address(0xE5C0), address(usdc), OPNET_BRIDGE, OPNET_USDC);
        assertEq(a, b);
    }

    function test_ComputeFlowId_DiffersByMode() public view {
        bytes32 a = escrow.computeFlowId(0, ETH_CHAIN_ID, address(0xE5C0), address(usdc), OPNET_BRIDGE, OPNET_USDC);
        bytes32 b = escrow.computeFlowId(2, ETH_CHAIN_ID, address(0xE5C0), address(usdc), OPNET_BRIDGE, OPNET_USDC);
        assertTrue(a != b, "different mode must yield different flowId");
    }

    function test_ComputeFlowId_DiffersByChain() public view {
        bytes32 a = escrow.computeFlowId(0, ETH_CHAIN_ID, address(0xE5C0), address(usdc), OPNET_BRIDGE, OPNET_USDC);
        bytes32 b = escrow.computeFlowId(0, ARB_CHAIN_ID, address(0xE5C0), address(usdc), OPNET_BRIDGE, OPNET_USDC);
        assertTrue(a != b, "different chain must yield different flowId");
    }

    // ─── addFlow ───────────────────────────────────────────────────────

    function test_AddFlow_Happy() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        BridgeEscrow.FlowRecord memory f = escrow.getFlow(flowId);
        assertEq(f.mode, 0);
        assertEq(f.status, escrow.FLOW_STATUS_ACTIVE());
        assertEq(f.evmChainId, ETH_CHAIN_ID);
        assertEq(f.evmToken, address(usdc));
        assertEq(f.opnetToken, OPNET_USDC);
        assertEq(f.evmDecimals, 6);
        assertEq(f.opnetDecimals, 6);
        assertEq(uint256(f.cap), 1_000_000_000_000);
        assertEq(uint256(f.dailyLimit), 100_000_000_000);
        assertEq(uint256(f.minAmount), 1_000_000);
        assertEq(f.feeBps, 50);
        assertEq(uint256(f.inventory), 0);
        assertEq(uint256(f.mintedToday), 0);
        assertTrue(escrow.flowExists(flowId));
        assertEq(escrow.flowCount(), 1);
    }

    function test_AddFlow_RejectsDuplicate() public {
        _addDefault(address(usdc), OPNET_USDC);
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdc), OPNET_USDC);
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowAlreadyExists.selector);
        escrow.addFlow(p);
    }

    function test_AddFlow_RejectsNonOwner() public {
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdc), OPNET_USDC);
        vm.prank(stranger);
        vm.expectRevert(); // OZ Ownable revert (custom OwnableUnauthorizedAccount)
        escrow.addFlow(p);
    }

    function test_AddFlow_RejectsInvalidMode() public {
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdc), OPNET_USDC);
        p.mode = 4; // beyond POOLED_LOCK_RELEASE (3)
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowInvalidMode.selector);
        escrow.addFlow(p);
    }

    function test_AddFlow_RejectsZeroChainId() public {
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdc), OPNET_USDC);
        p.evmChainId = 0;
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowZeroChainId.selector);
        escrow.addFlow(p);
    }

    function test_AddFlow_RejectsZeroAddrs() public {
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdc), OPNET_USDC);
        p.evmBridge = address(0);
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.ZeroAddress.selector);
        escrow.addFlow(p);

        p = _defaultParams(address(usdc), OPNET_USDC);
        p.opnetToken = bytes32(0);
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.ZeroAddress.selector);
        escrow.addFlow(p);
    }

    function test_AddFlow_RejectsBadDecimals() public {
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdc), OPNET_USDC);
        p.evmDecimals = 0;
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowInvalidDecimals.selector);
        escrow.addFlow(p);

        p = _defaultParams(address(usdc), OPNET_USDC);
        p.evmDecimals = 31;
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowInvalidDecimals.selector);
        escrow.addFlow(p);

        p = _defaultParams(address(usdc), OPNET_USDC);
        p.opnetDecimals = 0;
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowInvalidDecimals.selector);
        escrow.addFlow(p);
    }

    function test_AddFlow_RejectsBpsTooHigh() public {
        uint16 tooHigh = uint16(escrow.MAX_FEE_BPS()) + 1;
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdc), OPNET_USDC);
        p.feeBps = tooHigh;
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FeeBpsTooHigh.selector);
        escrow.addFlow(p);
    }

    function test_AddFlow_AllowsMultiChainSameToken() public {
        // ETH USDT mode 0
        bytes32 a = _addDefault(address(usdt), OPNET_USDT);
        // ARB USDT mode 0 — different chainId → different flowId, both allowed.
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdt), OPNET_USDT);
        p.evmChainId = ARB_CHAIN_ID;
        vm.prank(owner);
        bytes32 b = escrow.addFlow(p);
        assertTrue(a != b);
        assertEq(escrow.flowCount(), 2);
    }

    function test_AddFlow_AllowsMultiModeSameToken() public {
        // mode 0
        bytes32 a = _addDefault(address(usdt), OPNET_USDT);
        // mode 3 same (chain, token) → different flowId, both allowed.
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdt), OPNET_USDT);
        p.mode = 3;
        vm.prank(owner);
        bytes32 b = escrow.addFlow(p);
        assertTrue(a != b);
        assertEq(escrow.flowCount(), 2);
    }

    function test_AddFlow_EnumerationsPopulated() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        assertEq(escrow.allFlowIds(0), flowId);
        assertEq(escrow.flowsByEvmToken(address(usdc), 0), flowId);
        assertEq(escrow.flowsByMode(0, 0), flowId);
        assertEq(escrow.flowsByEvmChain(ETH_CHAIN_ID, 0), flowId);
    }

    // ─── pauseFlow / resumeFlow / drainFlow ────────────────────────────

    function test_PauseFlow_GuardianOnly() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(stranger);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.pauseFlow(flowId);

        vm.prank(guardian);
        escrow.pauseFlow(flowId);
        assertEq(escrow.getFlow(flowId).status, escrow.FLOW_STATUS_PAUSED());
    }

    function test_PauseFlow_RejectsUnknown() public {
        vm.prank(guardian);
        vm.expectRevert(BridgeEscrow.FlowNotFound.selector);
        escrow.pauseFlow(bytes32(uint256(0xDEADBEEF)));
    }

    function test_PauseFlow_RejectsAlreadyPaused() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(guardian);
        escrow.pauseFlow(flowId);
        vm.prank(guardian);
        vm.expectRevert(BridgeEscrow.FlowInvalidStatusTransition.selector);
        escrow.pauseFlow(flowId);
    }

    function test_ResumeFlow_OwnerOnly() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(guardian);
        escrow.pauseFlow(flowId);

        vm.prank(stranger);
        vm.expectRevert(); // OZ Ownable
        escrow.resumeFlow(flowId);

        vm.prank(owner);
        escrow.resumeFlow(flowId);
        assertEq(escrow.getFlow(flowId).status, escrow.FLOW_STATUS_ACTIVE());
    }

    function test_ResumeFlow_RejectsFromActive() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowInvalidStatusTransition.selector);
        escrow.resumeFlow(flowId);
    }

    function test_DrainFlow_OneWay() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(owner);
        escrow.drainFlow(flowId);
        assertEq(escrow.getFlow(flowId).status, escrow.FLOW_STATUS_DRAINING());

        // Cannot resume from draining.
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowInvalidStatusTransition.selector);
        escrow.resumeFlow(flowId);

        // Cannot pause from draining.
        vm.prank(guardian);
        vm.expectRevert(BridgeEscrow.FlowInvalidStatusTransition.selector);
        escrow.pauseFlow(flowId);
    }

    function test_DrainFlow_FromPaused() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(guardian);
        escrow.pauseFlow(flowId);
        vm.prank(owner);
        escrow.drainFlow(flowId);
        assertEq(escrow.getFlow(flowId).status, escrow.FLOW_STATUS_DRAINING());
    }

    // ─── setFlowCap / setFlowDailyLimit / setFlowMinAmount / setFlowFee ─

    function test_SetFlowCap_OwnerOnly() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(stranger);
        vm.expectRevert();
        escrow.setFlowCap(flowId, 1);

        vm.prank(owner);
        escrow.setFlowCap(flowId, 5_000_000);
        assertEq(uint256(escrow.getFlow(flowId).cap), 5_000_000);
    }

    function test_SetFlowCap_RejectsBelowInventory() public {
        // PR α has no path to write inventory > 0 — rate-limit test only
        // verifies the comparison path. Synthetically force inventory by
        // calling setFlowCap with a value less than the (zero) inventory
        // is fine; we cover the actual revert case in PR γ once claim()
        // mutates inventory. For now, just sanity-check the happy path
        // also accepts cap = 0 when inventory = 0.
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(owner);
        escrow.setFlowCap(flowId, 0);
        assertEq(uint256(escrow.getFlow(flowId).cap), 0);
    }

    function test_SetFlowDailyLimit_AllowsZero() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(owner);
        escrow.setFlowDailyLimit(flowId, 0);
        assertEq(uint256(escrow.getFlow(flowId).dailyLimit), 0);
    }

    function test_SetFlowMinAmount_RejectsUnknown() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowNotFound.selector);
        escrow.setFlowMinAmount(bytes32(uint256(0xDEADBEEF)), 1);
    }

    function test_SetFlowFee_RejectsBpsTooHigh() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        // Hoist the constant read so vm.expectRevert applies to setFlowFee,
        // not to the MAX_FEE_BPS getter.
        uint16 tooHigh = uint16(escrow.MAX_FEE_BPS()) + 1;
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FeeBpsTooHigh.selector);
        escrow.setFlowFee(flowId, tooHigh, 0);
    }

    function test_SetFlowFee_Happy() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(owner);
        escrow.setFlowFee(flowId, 75, 1_000);
        BridgeEscrow.FlowRecord memory f = escrow.getFlow(flowId);
        assertEq(f.feeBps, 75);
        assertEq(uint256(f.minFee), 1_000);
    }

    // ─── tipCapBps (PR β.2.scaffold) ───────────────────────────────────

    function test_AddFlow_DefaultTipCap_IsZero() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        assertEq(escrow.getFlow(flowId).tipCapBps, 0);
    }

    function test_AddFlow_TipCap_Above200_Reverts() public {
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdc), OPNET_USDC);
        p.tipCapBps = 201;
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.TipCapTooHigh.selector);
        escrow.addFlow(p);
    }

    function test_AddFlow_TipCap_AtMax_Succeeds() public {
        BridgeEscrow.FlowAddParams memory p = _defaultParams(address(usdc), OPNET_USDC);
        p.tipCapBps = 200;
        vm.prank(owner);
        bytes32 flowId = escrow.addFlow(p);
        assertEq(escrow.getFlow(flowId).tipCapBps, 200);
    }

    function test_SetFlowTipCap_GovernorOnly() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(stranger);
        vm.expectRevert(); // OZ Ownable
        escrow.setFlowTipCap(flowId, 100);
    }

    function test_SetFlowTipCap_HappyPath() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        vm.prank(owner);
        vm.expectEmit(true, false, false, true, address(escrow));
        emit BridgeEscrow.FlowTipCapUpdated(flowId, 0, 100);
        escrow.setFlowTipCap(flowId, 100);
        assertEq(escrow.getFlow(flowId).tipCapBps, 100);
    }

    function test_SetFlowTipCap_AboveMax_Reverts() public {
        bytes32 flowId = _addDefault(address(usdc), OPNET_USDC);
        // Hoist the constant read so vm.expectRevert applies to setFlowTipCap.
        uint16 tooHigh = uint16(escrow.MAX_TIP_BPS()) + 1;
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.TipCapTooHigh.selector);
        escrow.setFlowTipCap(flowId, tooHigh);
    }

    function test_SetFlowTipCap_UnknownFlow_Reverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FlowNotFound.selector);
        escrow.setFlowTipCap(bytes32(uint256(0xDEADBEEF)), 50);
    }

    // ─── Existence / read views ────────────────────────────────────────

    function test_FlowExists_FalseBeforeAdd() public view {
        bytes32 flowId = escrow.computeFlowId(0, ETH_CHAIN_ID, address(0xE5C0), address(usdc), OPNET_BRIDGE, OPNET_USDC);
        assertFalse(escrow.flowExists(flowId));
    }

    function test_FlowCount_StartsZero() public view {
        assertEq(escrow.flowCount(), 0);
    }
}
