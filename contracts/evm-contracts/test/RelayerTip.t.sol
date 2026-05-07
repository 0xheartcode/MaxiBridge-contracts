// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";

/// @notice Smart-contract relayer used in
///         `test_Claim_TipPaidToMsgSender_NotTxOrigin`. The tip MUST land
///         on `msg.sender` (this contract), NOT `tx.origin` (the EOA).
contract RelayerProxy {
    BridgeEscrow public immutable escrow;

    constructor(BridgeEscrow _escrow) {
        escrow = _escrow;
    }

    function relay(BridgeEscrow.ReleaseIntent calldata intent, bytes calldata sig) external {
        escrow.claim(intent, sig);
    }
}

/// @notice PR β.2.payout-evm — exercises the new flowId binding +
///         permissionless relayer tip payout in `BridgeEscrow.claim`.
///         Companion to FlowRegistry.t.sol — uses the same proxy bring-up
///         pattern and the same USDC fixture.
contract RelayerTipTest is Test {
    bytes32 internal constant RELEASE_INTENT_TYPEHASH =
        keccak256(
            "ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce,uint256 grossSrcAmount,uint128 relayerTip,bytes32 flowId)"
        );

    BridgeEscrow internal impl;
    BridgeEscrow internal escrow;
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

        impl = BridgeEscrow(address(new TestableBridgeEscrow()));
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = BridgeEscrow(address(new ERC1967Proxy(address(impl), initData)));

        // Guardian is needed for pauseFlow (test_Claim_TipOnPausedFlow_Reverts).
        vm.startPrank(owner);
        escrow.setGuardian(guardian);
        flowId = escrow.addFlow(BridgeEscrow.FlowAddParams({
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
            minAmount: 0,
            cap: type(uint128).max,
            dailyLimit: type(uint128).max,
            // 100 bps = 1% — bounds the per-flow tip.
            tipCapBps: 100
        }));
        vm.stopPrank();

        // PR γ.1: bootstrap inventory; lock-side bump is γ.2.
        TestableBridgeEscrow(address(escrow))._testSetInventory(
            flowId,
            type(uint128).max
        );

        // Seed alice + give the escrow balance to cover claims.
        // Direct-mint (not `lock`) because PR γ.2a's lock-side cap check
        // would reject the seed: inventory above is already at uint128.max,
        // so any further increment overflows the cap. This test isolates
        // claim-side tip behaviour; lock-side coverage lives in
        // LockInventory.t.sol.
        usdc.mint(address(escrow), 100_000e6);
        usdc.mint(alice, 1_000_000e6);
        vm.prank(alice);
        usdc.approve(address(escrow), type(uint256).max);
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    function _hashIntent(BridgeEscrow.ReleaseIntent memory intent) internal pure returns (bytes32) {
        return keccak256(
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
        return keccak256(
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

    function _sign(uint256 pk, BridgeEscrow.ReleaseIntent memory intent) internal view returns (bytes memory) {
        bytes32 d = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), _hashIntent(intent))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        bytes memory raw = abi.encodePacked(r, s, v);
        // M-of-N envelope: numSigs = 1.
        return abi.encodePacked(uint8(1), raw);
    }

    function _intent(uint256 amount, uint128 tip, bytes32 fId, bytes32 nonceSalt)
        internal
        view
        returns (BridgeEscrow.ReleaseIntent memory intent)
    {
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
            grossSrcAmount: amount,
            relayerTip: tip,
            flowId: fId
        });
    }

    // ─── Tests ──────────────────────────────────────────────────────────

    /// @notice Tip = 0 → recipient gets full `amount`, msg.sender gets 0.
    function test_Claim_TipZero_PaysFullToRecipient() public {
        BridgeEscrow.ReleaseIntent memory intent = _intent(10_000e6, 0, flowId, keccak256("zero"));
        bytes memory sig = _sign(signerPk, intent);

        address relayer = address(0xCAFE);
        uint256 bobBefore = usdc.balanceOf(bob);
        uint256 relayerBefore = usdc.balanceOf(relayer);

        vm.prank(relayer);
        escrow.claim(intent, sig);

        assertEq(usdc.balanceOf(bob) - bobBefore, 10_000e6, "recipient gets full amount");
        assertEq(usdc.balanceOf(relayer) - relayerBefore, 0, "relayer gets nothing");
    }

    /// @notice Tip > 0 within cap: relayer gets tip, recipient gets
    ///         amount-tip, RelayerTipPaid event emitted.
    /// @dev    amount = 1e6 (1 USDC); tip = 50 → bps = 50*10000/1e6 = 0.
    ///         To exercise a non-trivial bps we use amount = 1e4, tip = 50
    ///         → bps = 50 (right at half the cap of 100). The user-spec
    ///         example "tip = 50 (50 bps of amount = 5e3 / 1e6 numerically)"
    ///         — we verify the relayer credit + recipient debit + emit.
    function test_Claim_TipNonZero_HappyPath() public {
        // amount = 1e4, tip = 50 → bps = (50 * 10_000) / 10_000 = 50 ≤ 100 cap.
        uint256 amount = 10_000;
        uint128 tip = 50;

        BridgeEscrow.ReleaseIntent memory intent = _intent(amount, tip, flowId, keccak256("happy"));
        bytes memory sig = _sign(signerPk, intent);

        address relayer = address(0xCAFE);
        uint256 bobBefore = usdc.balanceOf(bob);
        uint256 relayerBefore = usdc.balanceOf(relayer);

        vm.expectEmit(true, true, false, true, address(escrow));
        emit BridgeEscrow.RelayerTipPaid(flowId, relayer, tip);

        vm.prank(relayer);
        escrow.claim(intent, sig);

        assertEq(usdc.balanceOf(relayer) - relayerBefore, tip, "relayer credited tip");
        assertEq(usdc.balanceOf(bob) - bobBefore, amount - tip, "recipient gets net");
    }

    /// @notice tip bps > flow cap reverts TipExceedsFlowCap.
    function test_Claim_TipExceedsFlowCap_Reverts() public {
        // amount = 10_000, tip = 200 → bps = (200 * 10_000) / 10_000 = 200 > cap (100).
        uint256 amount = 10_000;
        uint128 tip = 200;

        BridgeEscrow.ReleaseIntent memory intent = _intent(amount, tip, flowId, keccak256("over"));
        bytes memory sig = _sign(signerPk, intent);

        vm.expectRevert(BridgeEscrow.TipExceedsFlowCap.selector);
        escrow.claim(intent, sig);
    }

    /// @notice Pausing the flow blocks tipped vouchers.
    function test_Claim_TipOnPausedFlow_Reverts() public {
        vm.prank(guardian);
        escrow.pauseFlow(flowId);

        BridgeEscrow.ReleaseIntent memory intent = _intent(10_000, 50, flowId, keccak256("paused"));
        bytes memory sig = _sign(signerPk, intent);

        // PR γ.1: status enforcement moved ahead of tip carve and now
        // applies regardless of tip presence. The original PR β.2.payout
        // behaviour (TipPaidOnInactiveFlow) is subsumed by FlowNotActive.
        vm.expectRevert(BridgeEscrow.FlowNotActive.selector);
        escrow.claim(intent, sig);
    }

    /// @notice The tip MUST land on `msg.sender` (the contract that called
    ///         `claim`), not `tx.origin`. SC relayers — including
    ///         atomic-arbitrage bundlers — must be able to sweep their own
    ///         balance in the same tx.
    function test_Claim_TipPaidToMsgSender_NotTxOrigin() public {
        RelayerProxy relay = new RelayerProxy(escrow);
        address eoa = address(0xE0A);

        uint256 amount = 10_000;
        uint128 tip = 50;
        BridgeEscrow.ReleaseIntent memory intent = _intent(amount, tip, flowId, keccak256("origin"));
        bytes memory sig = _sign(signerPk, intent);

        uint256 relayBefore = usdc.balanceOf(address(relay));
        uint256 eoaBefore = usdc.balanceOf(eoa);

        // tx.origin = eoa, msg.sender at claim() = address(relay)
        vm.prank(eoa, eoa);
        relay.relay(intent, sig);

        assertEq(usdc.balanceOf(address(relay)) - relayBefore, tip, "tip went to msg.sender (relay contract)");
        assertEq(usdc.balanceOf(eoa) - eoaBefore, 0, "tx.origin (EOA) got nothing");
    }

    /// @notice Voucher with a flowId that doesn't exist reverts FlowNotFound.
    function test_Claim_FlowIdMismatch_Reverts() public {
        bytes32 ghost = bytes32(uint256(0xDEADBEEF));
        BridgeEscrow.ReleaseIntent memory intent = _intent(10_000, 0, ghost, keccak256("ghost"));
        bytes memory sig = _sign(signerPk, intent);

        vm.expectRevert(BridgeEscrow.FlowNotFound.selector);
        escrow.claim(intent, sig);
    }
}
