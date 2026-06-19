// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {AmountPolicy} from "../src/AmountPolicy.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @notice E-3 — decimal-aware `claim()` (OPNet→EVM release). The signed
///         voucher carries `grossSrcAmount` in OPNet-SOURCE units and
///         `amount` in EVM-DESTINATION units; `claim` scales grossSrc to dest
///         units via AmountPolicy.scale and keys every dest-side check
///         (amount bound, dailyLimit, inventory, fee) off the scaled gross.
///         Covers shrink (18→6), grow (6→18), strict dust rejection on
///         shrink, and destination-unit fee accrual.
contract DecimalScalingTest is Test {
    TestableBridgeEscrow internal escrow;
    MockERC20 internal tok6;   // dest token for the 18→6 (shrink) flow
    MockERC20 internal tok18;  // dest token for the 6→18 (grow) flow

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    address internal bob = address(0xB0B);

    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;
    uint64 internal constant ETH_CHAIN_ID = 1;
    bytes32 internal constant OPNET_BRIDGE = bytes32(uint256(0xDEAD));

    bytes32 internal constant RELEASE_INTENT_TYPEHASH = keccak256(
        "ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce,uint256 grossSrcAmount,uint128 relayerTip,bytes32 flowId)"
    );

    bytes32 internal shrinkFlow; // opnet 18 → evm 6
    bytes32 internal growFlow;   // opnet 6  → evm 18

    function setUp() public {
        vm.chainId(1);
        signerAddr = vm.addr(signerPk);
        tok6 = new MockERC20("Six", "SIX", 6);
        tok18 = new MockERC20("Eighteen", "EIG", 18);

        TestableBridgeEscrow impl = new TestableBridgeEscrow();
        address[] memory tokens = new address[](2);
        tokens[0] = address(tok6);
        tokens[1] = address(tok18);

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = TestableBridgeEscrow(address(new ERC1967Proxy(address(impl), initData)));

        vm.startPrank(owner);
        // Shrink flow: source (OPNet) 18 dec, destination (EVM) 6 dec.
        shrinkFlow = escrow.addFlow(BridgeEscrow.FlowAddParams({
            mode: 0,
            evmChainId: ETH_CHAIN_ID,
            evmBridge: address(escrow),
            evmToken: address(tok6),
            evmDecimals: 6,
            opnetBridge: OPNET_BRIDGE,
            opnetToken: bytes32(uint256(0xC0FFEE)),
            opnetDecimals: 18,
            feeBps: 0,
            minFee: 0,
            minAmount: 0,
            cap: type(uint128).max,
            dailyLimit: type(uint128).max,
            tipCapBps: 0
        }));
        // Grow flow: source (OPNet) 6 dec, destination (EVM) 18 dec.
        growFlow = escrow.addFlow(BridgeEscrow.FlowAddParams({
            mode: 0,
            evmChainId: ETH_CHAIN_ID,
            evmBridge: address(escrow),
            evmToken: address(tok18),
            evmDecimals: 18,
            opnetBridge: OPNET_BRIDGE,
            opnetToken: bytes32(uint256(0xBEEF)),
            opnetDecimals: 6,
            feeBps: 0,
            minFee: 0,
            minAmount: 0,
            cap: type(uint128).max,
            dailyLimit: type(uint128).max,
            tipCapBps: 0
        }));
        vm.stopPrank();

        // Seed inventory (DEST units) + escrow balance to cover releases.
        escrow._testSeed(shrinkFlow, type(uint128).max, 0, 0);
        escrow._testSeed(growFlow, type(uint128).max, 0, 0);
        tok6.mint(address(escrow), 1_000_000_000e6);
        tok18.mint(address(escrow), 1_000_000_000e18);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    function _hashIntent(BridgeEscrow.ReleaseIntent memory i) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            RELEASE_INTENT_TYPEHASH, i.token, i.to, i.amount, i.srcChainId,
            i.opnetTxHash, i.opnetEventIndex, i.burnNonce, i.signerEpoch,
            i.opnetNonce, i.grossSrcAmount, i.relayerTip, i.flowId
        ));
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("BridgeEscrow")), keccak256(bytes("1")),
            block.chainid, address(escrow)
        ));
    }

    function _sign(BridgeEscrow.ReleaseIntent memory i) internal view returns (bytes memory) {
        bytes32 d = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), _hashIntent(i)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, d);
        return abi.encodePacked(uint8(1), abi.encodePacked(r, s, v));
    }

    function _intent(address token, bytes32 fId, uint256 grossSrc, uint256 amount, bytes32 salt)
        internal view returns (BridgeEscrow.ReleaseIntent memory)
    {
        return BridgeEscrow.ReleaseIntent({
            token: token,
            to: bob,
            amount: amount,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: salt,
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: keccak256(abi.encodePacked("n", salt)),
            grossSrcAmount: grossSrc,
            relayerTip: 0,
            flowId: fId
        });
    }

    // ─── Tests ────────────────────────────────────────────────────────────

    /// @notice 18→6 shrink: grossSrc = 5e18 (5 tokens, 18 dec) releases
    ///         scale(5e18,18,6) = 5e6 on the 6-dec destination.
    function test_Claim_Shrink_18to6_ReleasesScaledAmount() public {
        uint256 grossSrc = 5e18;
        uint256 amount = 5e6; // net == gross (fee 0), in DEST units
        BridgeEscrow.ReleaseIntent memory i = _intent(address(tok6), shrinkFlow, grossSrc, amount, "shrink");
        uint256 before = tok6.balanceOf(bob);
        escrow.claim(i, _sign(i));
        assertEq(tok6.balanceOf(bob) - before, 5e6, "recipient gets scaled dest amount");
    }

    /// @notice 6→18 grow: grossSrc = 5e6 releases scale(5e6,6,18) = 5e18.
    function test_Claim_Grow_6to18_ReleasesScaledAmount() public {
        uint256 grossSrc = 5e6;
        uint256 amount = 5e18; // net == gross, DEST units
        BridgeEscrow.ReleaseIntent memory i = _intent(address(tok18), growFlow, grossSrc, amount, "grow");
        uint256 before = tok18.balanceOf(bob);
        escrow.claim(i, _sign(i));
        assertEq(tok18.balanceOf(bob) - before, 5e18, "recipient gets scaled dest amount");
    }

    /// @notice Shrink with indivisible dust reverts (no silent rounding).
    ///         grossSrc = 5e18 + 1 is not a clean multiple of 10**12.
    function test_Claim_Shrink_Dust_Reverts() public {
        uint256 grossSrc = 5e18 + 1;
        uint256 amount = 5e6;
        BridgeEscrow.ReleaseIntent memory i = _intent(address(tok6), shrinkFlow, grossSrc, amount, "dust");
        vm.expectRevert(AmountPolicy.AmountDustOnShrink.selector);
        escrow.claim(i, _sign(i));
    }

    /// @notice amount (dest units) > scaled grossDst reverts AmountExceedsGross.
    ///         grossSrc=5e18 → grossDst=5e6; amount=5e6+1 exceeds it.
    function test_Claim_AmountExceedsScaledGross_Reverts() public {
        BridgeEscrow.ReleaseIntent memory i = _intent(address(tok6), shrinkFlow, 5e18, 5e6 + 1, "exceed");
        vm.expectRevert(BridgeEscrow.AmountExceedsGross.selector);
        escrow.claim(i, _sign(i));
    }

    /// @notice Fee accrues in DESTINATION units: a 50-bps shrink flow with
    ///         grossSrc=1e18 → grossDst=1e6, net=995000 → feePortion=5000.
    function test_Claim_FeeAccruesInDestUnits() public {
        // Re-register a fee-bearing shrink flow on a fresh dest token.
        MockERC20 tok6b = new MockERC20("SixB", "SIXB", 6);
        vm.prank(owner);
        bytes32 feeFlow = escrow.addFlow(BridgeEscrow.FlowAddParams({
            mode: 0,
            evmChainId: ETH_CHAIN_ID,
            evmBridge: address(escrow),
            evmToken: address(tok6b),
            evmDecimals: 6,
            opnetBridge: OPNET_BRIDGE,
            opnetToken: bytes32(uint256(0xFEE5)),
            opnetDecimals: 18,
            feeBps: 50,
            minFee: 0,
            minAmount: 0,
            cap: type(uint128).max,
            dailyLimit: type(uint128).max,
            tipCapBps: 0
        }));
        escrow._testSeed(feeFlow, type(uint128).max, 0, 0);
        tok6b.mint(address(escrow), 1_000e6);

        uint256 grossSrc = 1e18;     // 1 token, 18 dec source
        uint256 amount = 995_000;    // net in 6-dec dest = grossDst(1e6) - fee(5000)
        BridgeEscrow.ReleaseIntent memory i = _intent(address(tok6b), feeFlow, grossSrc, amount, "fee");

        uint256 before = tok6b.balanceOf(bob);
        escrow.claim(i, _sign(i));
        assertEq(tok6b.balanceOf(bob) - before, 995_000, "recipient gets dest net");
        assertEq(escrow.getFlow(feeFlow).accruedFees, 5_000, "fee accrued in dest units");
    }
}
