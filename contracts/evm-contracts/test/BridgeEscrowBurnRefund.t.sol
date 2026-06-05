// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {WrappedERC20} from "../src/WrappedERC20.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";

/// @title  BridgeEscrowBurnRefundTest
/// @notice #55 — coverage for the EVM-side trustless burn recovery
///         (`refundBurn`), the symmetric counterpart to OPNet
///         `BridgeDepository.refundBurn`. A WrappedERC20 burn whose OPNet
///         destination voucher was PERMANENTLY cancelled is re-minted to the
///         original burner, gated by an M-of-N EIP-712 attestation + a
///         per-burn replay guard set strictly before the mint (CEI).
///
/// @dev    Mirrors the EIP-712 helper + 1-of-1 M-of-N sig-blob layout used by
///         BridgeEscrowAllModes.t.sol. MINT-AUTHORITY PRIMITIVE — every
///         negative path MUST assert NO mint occurred.
contract BridgeEscrowBurnRefundTest is Test {
    bytes32 internal constant BURN_REFUND_AUTHORIZATION_TYPEHASH = keccak256(
        "BurnRefundAuthorization(address burner,address wrappedToken,uint256 amount,uint256 burnNonce,bytes32 burnTxHash,bytes32 burnBlockHash,bytes32 flowId,uint32 signerEpoch)"
    );

    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;
    uint64 internal constant TEST_EVM_CHAIN_ID = 1;
    address internal constant TEST_EVM_BRIDGE = address(0xE5C0);
    bytes32 internal constant TEST_OPNET_BRIDGE = bytes32(uint256(0xDEAD));
    bytes32 internal constant TEST_OPNET_WMOTO = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant TEST_OPNET_MOTO = bytes32(uint256(0x4070));

    BridgeEscrow internal impl;
    BridgeEscrow internal escrow;

    MockERC20 internal moto;       // mode-3 POOLED token — NOT bridge-mintable
    WrappedERC20 internal wmoto;   // mode-2 NATIVE_BURN_MINT — bridge-mintable

    bytes32 internal wmotoFlowId;  // NATIVE_BURN_MINT flow (mint-on-EVM)
    bytes32 internal motoFlowId;   // POOLED_LOCK_RELEASE flow (NOT mint-on-EVM)

    address internal owner = address(0xA11CE);
    address internal guardian = address(0x6471D);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    uint256 internal roguePk = 0xBADBADBAD;
    address internal burner = address(0xB0B);

    function setUp() public virtual {
        signerAddr = vm.addr(signerPk);

        moto = new MockERC20("MOTO", "MOTO", 6);
        impl = BridgeEscrow(address(new TestableBridgeEscrow()));

        address[] memory tokens = new address[](1);
        tokens[0] = address(moto);

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = BridgeEscrow(address(new ERC1967Proxy(address(impl), initData)));

        wmoto = new WrappedERC20(
            "Wrapped MOTO",
            "wMOTO",
            18,
            owner,
            address(escrow),
            EXPECTED_OPNET_CHAIN_ID,
            TEST_OPNET_WMOTO,
            type(uint256).max // E-1 maxSupply — uncapped in tests
        );

        vm.startPrank(owner);

        // mode-2 NATIVE_BURN_MINT — the bridge is the minter, so refundBurn
        // can re-mint here.
        wmotoFlowId = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: uint8(BridgeEscrow.TokenMode.NATIVE_BURN_MINT),
                evmChainId: TEST_EVM_CHAIN_ID,
                evmBridge: TEST_EVM_BRIDGE,
                evmToken: address(wmoto),
                evmDecimals: 6,
                opnetBridge: TEST_OPNET_BRIDGE,
                opnetToken: TEST_OPNET_WMOTO,
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );

        // mode-3 POOLED — NOT a mint-on-EVM flow; refundBurn must reject it.
        motoFlowId = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: uint8(BridgeEscrow.TokenMode.POOLED_LOCK_RELEASE),
                evmChainId: TEST_EVM_CHAIN_ID,
                evmBridge: TEST_EVM_BRIDGE,
                evmToken: address(moto),
                evmDecimals: 6,
                opnetBridge: TEST_OPNET_BRIDGE,
                opnetToken: TEST_OPNET_MOTO,
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );
        escrow.setGuardian(guardian);
        vm.stopPrank();
    }

    // =====================================================================
    // Happy path
    // =====================================================================

    function test_refundBurn_happyPath() public {
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        bytes memory sig = _signAuth(signerPk, a);

        bytes32 burnId = keccak256(abi.encode(a.wrappedToken, a.burner, a.burnTxHash, a.burnNonce));
        assertFalse(escrow.refundedBurns(burnId), "not refunded pre-call");

        vm.expectEmit(true, true, true, true);
        emit BridgeEscrow.BurnRefunded(burnId, a.burner, a.wrappedToken, a.amount);
        escrow.refundBurn(a, sig);

        assertEq(wmoto.balanceOf(burner), 100e6, "exact amount re-minted to burner");
        assertTrue(escrow.refundedBurns(burnId), "replay flag set");
    }

    // =====================================================================
    // Negatives — each reverts, NO mint
    // =====================================================================

    function test_refundBurn_whenPaused_reverts() public {
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        bytes memory sig = _signAuth(signerPk, a);

        // A mint primitive MUST be frozen by pause (mirrors OPNet refundBurn
        // requireNotPaused) — a compromised-signer attestation cannot mint while
        // the bridge is paused for incident response.
        vm.prank(owner);
        escrow.pause();

        vm.expectRevert(); // OZ PausableUpgradeable EnforcedPause()
        escrow.refundBurn(a, sig);
        _assertNoMint(a);
    }

    function test_refundBurn_replay_reverts() public {
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        bytes memory sig = _signAuth(signerPk, a);
        escrow.refundBurn(a, sig); // first consumes it

        // Same burnTxHash + burnNonce — even with a fresh valid sig, replay.
        bytes memory sig2 = _signAuth(signerPk, a);
        vm.expectRevert(BridgeEscrow.BurnAlreadyRefunded.selector);
        escrow.refundBurn(a, sig2);

        // Only ONE mint ever happened.
        assertEq(wmoto.balanceOf(burner), 100e6, "no double mint");
    }

    function test_refundBurn_badSigner_reverts() public {
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        bytes memory sig = _signAuth(roguePk, a); // not an authorized signer

        vm.expectRevert(BridgeEscrow.InvalidSignature.selector);
        escrow.refundBurn(a, sig);
        _assertNoMint(a);
    }

    function test_refundBurn_emptySigBlob_reverts() public {
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);

        vm.expectRevert(BridgeEscrow.InvalidSigBlob.selector);
        escrow.refundBurn(a, hex"00"); // numSigs == 0
        _assertNoMint(a);
    }

    function test_refundBurn_wrongSignerEpoch_reverts() public {
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        a.signerEpoch = escrow.currentEpoch() + 1;
        bytes memory sig = _signAuth(signerPk, a);

        vm.expectRevert(BridgeEscrow.InvalidSignerEpoch.selector);
        escrow.refundBurn(a, sig);
        _assertNoMint(a);
    }

    function test_refundBurn_tamperedAmount_reverts() public {
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        bytes memory sig = _signAuth(signerPk, a);
        // Tamper after signing — digest no longer matches → recover lands
        // off the signer set.
        a.amount = 999e6;

        vm.expectRevert(BridgeEscrow.InvalidSignature.selector);
        escrow.refundBurn(a, sig);
        _assertNoMint(a);
    }

    function test_refundBurn_tamperedBurner_reverts() public {
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        bytes memory sig = _signAuth(signerPk, a);
        a.burner = address(0xDEADBEEF); // identity tamper

        vm.expectRevert(BridgeEscrow.InvalidSignature.selector);
        escrow.refundBurn(a, sig);
        assertEq(wmoto.balanceOf(address(0xDEADBEEF)), 0, "no mint to tampered burner");
        assertEq(wmoto.balanceOf(burner), 0, "no mint to original burner");
    }

    function test_refundBurn_unregisteredWrappedToken_reverts() public {
        // A wrapped token never added to supportedToken.
        WrappedERC20 stray = new WrappedERC20(
            "Stray", "STRAY", 18, owner, address(escrow), EXPECTED_OPNET_CHAIN_ID, bytes32(uint256(0x1)), type(uint256).max
        );
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        a.wrappedToken = address(stray);
        bytes memory sig = _signAuth(signerPk, a);

        vm.expectRevert(BridgeEscrow.TokenNotSupported.selector);
        escrow.refundBurn(a, sig);
        assertEq(stray.balanceOf(burner), 0, "no mint");
    }

    function test_refundBurn_wrongFlowMode_reverts() public {
        // moto is registered (supportedToken via addFlow) but its flow is
        // POOLED_LOCK_RELEASE — not a mint-on-EVM mode.
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        a.wrappedToken = address(moto);
        a.flowId = motoFlowId;
        bytes memory sig = _signAuth(signerPk, a);

        vm.expectRevert(BridgeEscrow.WrongMode.selector);
        escrow.refundBurn(a, sig);
        assertEq(moto.balanceOf(burner), 0, "no mint");
    }

    function test_refundBurn_flowTokenMismatch_reverts() public {
        // wmoto wrapped but flowId points at the moto flow → evmToken
        // binding mismatch (WrongMode). moto is supported so it clears the
        // allowlist gate first.
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        a.flowId = motoFlowId; // flow.evmToken == moto != wmoto
        bytes memory sig = _signAuth(signerPk, a);

        vm.expectRevert(BridgeEscrow.WrongMode.selector);
        escrow.refundBurn(a, sig);
        _assertNoMint(a);
    }

    function test_refundBurn_flowInactive_reverts() public {
        vm.prank(guardian);
        escrow.pauseFlow(wmotoFlowId); // FLOW_STATUS_PAUSED

        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        bytes memory sig = _signAuth(signerPk, a);

        vm.expectRevert(BridgeEscrow.FlowNotActive.selector);
        escrow.refundBurn(a, sig);
        _assertNoMint(a);
    }

    /// M-3 (audit 2026-05-27) — refundBurn now rejects DRAINING flows. A
    /// DRAINING flow is intentionally winding down (no new locks/mints); a
    /// compromised signer set must NOT be able to keep minting into a route
    /// the operator already marked for shutdown.
    function test_refundBurn_flowDraining_reverts() public {
        vm.prank(owner);
        escrow.drainFlow(wmotoFlowId); // FLOW_STATUS_DRAINING

        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        bytes memory sig = _signAuth(signerPk, a);

        vm.expectRevert(BridgeEscrow.FlowNotActive.selector);
        escrow.refundBurn(a, sig);
        _assertNoMint(a);
    }

    function test_refundBurn_zeroAmount_reverts() public {
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(0);
        bytes memory sig = _signAuth(signerPk, a);

        vm.expectRevert(BridgeEscrow.AmountZero.selector);
        escrow.refundBurn(a, sig);
        _assertNoMint(a);
    }

    function test_refundBurn_zeroBurner_reverts() public {
        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        a.burner = address(0);
        bytes memory sig = _signAuth(signerPk, a);

        vm.expectRevert(BridgeEscrow.InvalidRecipient.selector);
        escrow.refundBurn(a, sig);
    }

    // =====================================================================
    // H-1 — refundBurn shares the rolling-window dailyLimit (MED-001)
    // =====================================================================

    /// H-1 — without `_consumeMintFlowLimits` here, refundBurn is an unbounded
    /// mint primitive: a compromised signer set re-mints arbitrarily across
    /// fabricated (burnTxHash, burnNonce) tuples, bounded only by pause.
    function test_refundBurn_dailyLimitExceeded_reverts() public {
        vm.prank(owner);
        escrow.setFlowDailyLimit(wmotoFlowId, 50e6);

        BridgeEscrow.BurnRefundAuthorization memory a = _auth(100e6);
        bytes memory sig = _signAuth(signerPk, a);

        vm.expectRevert(BridgeEscrow.DailyLimitExceeded.selector);
        escrow.refundBurn(a, sig);
        _assertNoMint(a);
    }

    // =====================================================================
    // M-4 — burnId binds wrappedToken + burner (per-token nonce collisions)
    // =====================================================================

    /// M-4 — `WrappedERC20.burnNonce` is per-token, so two different wrappeds
    /// can legitimately produce the same (burnTxHash, burnNonce) pair. The
    /// pre-fix burnId did not bind the token, so one legitimate refund would
    /// permanently block the other. Asserts both refunds proceed independently.
    function test_refundBurn_burnIdScopedToWrappedToken() public {
        address burner2 = address(0xB0B2);
        WrappedERC20 wmoto2 = new WrappedERC20(
            "Wrapped MOTO 2",
            "wMOTO2",
            18,
            owner,
            address(escrow),
            EXPECTED_OPNET_CHAIN_ID,
            bytes32(uint256(0xC0FFEE2)),
            type(uint256).max // E-1 maxSupply — uncapped in tests
        );
        vm.prank(owner);
        bytes32 wmoto2FlowId = escrow.addFlow(
            BridgeEscrow.FlowAddParams({
                mode: uint8(BridgeEscrow.TokenMode.NATIVE_BURN_MINT),
                evmChainId: TEST_EVM_CHAIN_ID,
                evmBridge: TEST_EVM_BRIDGE,
                evmToken: address(wmoto2),
                evmDecimals: 6,
                opnetBridge: TEST_OPNET_BRIDGE,
                opnetToken: bytes32(uint256(0xC0FFEE2)),
                opnetDecimals: 6,
                feeBps: 0,
                minFee: 0,
                minAmount: 0,
                cap: type(uint128).max,
                dailyLimit: type(uint128).max,
                tipCapBps: 0
            })
        );

        // Refund #1 — wmoto + original burner.
        BridgeEscrow.BurnRefundAuthorization memory a1 = _auth(100e6);
        bytes memory sig1 = _signAuth(signerPk, a1);
        escrow.refundBurn(a1, sig1);
        assertEq(wmoto.balanceOf(burner), 100e6, "first refund minted wmoto");

        // Refund #2 — same (burnTxHash, burnNonce) but a different wrapped +
        // burner. Pre-fix this collided and reverted BurnAlreadyRefunded;
        // post-fix the replay key is scoped, so both refunds succeed.
        BridgeEscrow.BurnRefundAuthorization memory a2 = a1;
        a2.wrappedToken = address(wmoto2);
        a2.flowId = wmoto2FlowId;
        a2.burner = burner2;
        bytes memory sig2 = _signAuth(signerPk, a2);
        escrow.refundBurn(a2, sig2);
        assertEq(wmoto2.balanceOf(burner2), 100e6, "second refund minted wmoto2");
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    function _auth(uint256 amount)
        internal
        view
        returns (BridgeEscrow.BurnRefundAuthorization memory)
    {
        return BridgeEscrow.BurnRefundAuthorization({
            burner: burner,
            wrappedToken: address(wmoto),
            amount: amount,
            burnNonce: 7,
            burnTxHash: keccak256("evm-burn-tx"),
            burnBlockHash: keccak256("evm-burn-block"),
            flowId: wmotoFlowId,
            signerEpoch: escrow.currentEpoch()
        });
    }

    function _signAuth(uint256 pk, BridgeEscrow.BurnRefundAuthorization memory a)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                BURN_REFUND_AUTHORIZATION_TYPEHASH,
                a.burner,
                a.wrappedToken,
                a.amount,
                a.burnNonce,
                a.burnTxHash,
                a.burnBlockHash,
                a.flowId,
                a.signerEpoch
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", escrow.domainSeparator(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        // 1-of-1 M-of-N blob: [uint8 numSigs][r||s||v].
        return abi.encodePacked(uint8(1), r, s, v);
    }

    function _assertNoMint(BridgeEscrow.BurnRefundAuthorization memory a) internal view {
        assertEq(wmoto.balanceOf(a.burner), 0, "no mint on revert");
        bytes32 burnId = keccak256(abi.encode(a.wrappedToken, a.burner, a.burnTxHash, a.burnNonce));
        assertFalse(escrow.refundedBurns(burnId), "replay flag not set on revert");
    }
}
