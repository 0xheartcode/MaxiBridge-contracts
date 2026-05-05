// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {WrappedERC20} from "../src/WrappedERC20.sol";
import {BridgeEscrowV2} from "./mocks/BridgeEscrowV2.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {FeeOnTransferToken} from "./mocks/FeeOnTransferToken.sol";

interface IOwnable {
    function owner() external view returns (address);
}

contract BridgeEscrowTest is Test {
    bytes32 internal constant RELEASE_INTENT_TYPEHASH =
        keccak256(
            "ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce)"
        );

    BridgeEscrow internal impl;
    BridgeEscrow internal escrow;

    MockERC20 internal usdc;
    MockUSDT internal usdt;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xB0B);

    /// @dev OPNet testnet network id (matches bridge CLAUDE.md domain separation).
    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;

    function setUp() public virtual {
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

        // Seed Alice with plenty of tokens and infinite approvals.
        usdc.mint(alice, 1_000_000e6);
        usdt.mint(alice, 1_000_000e6);

        vm.startPrank(alice);
        usdc.approve(address(escrow), type(uint256).max);
        usdt.approve(address(escrow), type(uint256).max);
        vm.stopPrank();
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

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
                    intent.opnetNonce
                )
            );
    }

    function _domainSeparator(address verifyingContract)
        internal
        view
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    keccak256(
                        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                    ),
                    keccak256(bytes("BridgeEscrow")),
                    keccak256(bytes("1")),
                    block.chainid,
                    verifyingContract
                )
            );
    }

    function _digest(BridgeEscrow.ReleaseIntent memory intent, address verifyingContract)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = _hashIntent(intent);
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(verifyingContract), structHash));
    }

    /// @dev v2 — claim() only accepts the M-of-N blob format
    /// `[uint8 numSigs][sig_0(65)]…`. `_sign` returns a numSigs=1 envelope
    /// (66 bytes) so every existing test still works without per-call rewrites.
    function _sign(
        uint256 pk,
        BridgeEscrow.ReleaseIntent memory intent,
        address verifyingContract
    ) internal view returns (bytes memory) {
        bytes32 d = _digest(intent, verifyingContract);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        bytes memory raw = abi.encodePacked(r, s, v);
        return abi.encodePacked(uint8(1), raw);
    }

    /// @dev Raw 65-byte sig (no envelope) — fed into `_packMofN` for M-of-N
    /// tests that assemble the blob themselves, and used to assert the
    /// bare-sig path is rejected by the v2 contract.
    function _signRaw65(
        uint256 pk,
        BridgeEscrow.ReleaseIntent memory intent,
        address verifyingContract
    ) internal view returns (bytes memory) {
        bytes32 d = _digest(intent, verifyingContract);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function _signRaw65(uint256 pk, BridgeEscrow.ReleaseIntent memory intent)
        internal
        view
        returns (bytes memory)
    {
        return _signRaw65(pk, intent, address(escrow));
    }

    function _sign(uint256 pk, BridgeEscrow.ReleaseIntent memory intent)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, intent, address(escrow));
    }

    function _defaultIntent(address token, address to, uint256 amount)
        internal
        view
        returns (BridgeEscrow.ReleaseIntent memory intent)
    {
        intent = BridgeEscrow.ReleaseIntent({
            token: token,
            to: to,
            amount: amount,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: keccak256("opnet-tx-1"),
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: keccak256("opnet-nonce-1")
        });
    }

    // =====================================================================
    // Init
    // =====================================================================

    function test_Init_Twice_Reverts() public {
        address[] memory tokens = new address[](0);
        vm.expectRevert();
        escrow.initialize(owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens);
    }

    function test_Init_ImplementationDisabled() public {
        address[] memory tokens = new address[](0);
        vm.expectRevert();
        impl.initialize(owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens);
    }

    function test_Init_ZeroOwnerReverts() public {
        BridgeEscrow freshImpl = new BridgeEscrow();
        address[] memory tokens = new address[](0);
        bytes memory data = abi.encodeCall(
            BridgeEscrow.initialize,
            (address(0), signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        vm.expectRevert(BridgeEscrow.ZeroAddress.selector);
        new ERC1967Proxy(address(freshImpl), data);
    }

    function test_Init_ZeroSignerReverts() public {
        BridgeEscrow freshImpl = new BridgeEscrow();
        address[] memory tokens = new address[](0);
        bytes memory data = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, address(0), EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        vm.expectRevert(BridgeEscrow.ZeroAddress.selector);
        new ERC1967Proxy(address(freshImpl), data);
    }

    function test_Init_ZeroChainIdReverts() public {
        BridgeEscrow freshImpl = new BridgeEscrow();
        address[] memory tokens = new address[](0);
        bytes memory data = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, uint256(0), tokens)
        );
        vm.expectRevert(BridgeEscrow.ZeroChainId.selector);
        new ERC1967Proxy(address(freshImpl), data);
    }

    function test_Init_StoresExpectedOpnetChainId() public view {
        assertEq(escrow.expectedOpnetChainId(), EXPECTED_OPNET_CHAIN_ID);
    }

    // =====================================================================
    // lock()
    // =====================================================================

    function test_Lock_USDC_Succeeds() public {
        uint256 amount = 100e6;
        vm.prank(alice);
        (uint256 nonce_, uint256 received_) = escrow.lock(address(usdc), amount, keccak256("recipient-1"));
        assertEq(nonce_, 1);
        assertEq(received_, amount);
        assertEq(usdc.balanceOf(address(escrow)), amount);
    }

    function test_Lock_USDT_NoBoolReturn_Succeeds() public {
        uint256 amount = 100e6;
        vm.prank(alice);
        (uint256 nonce_, uint256 received_) = escrow.lock(address(usdt), amount, keccak256("recipient-usdt"));
        assertEq(nonce_, 1);
        assertEq(received_, amount);
        assertEq(usdt.balanceOf(address(escrow)), amount);
    }

    function test_Lock_BalanceDelta_FeeOnTransfer() public {
        FeeOnTransferToken fee = new FeeOnTransferToken(100); // 1% fee
        vm.prank(owner);
        escrow.setSupportedToken(address(fee), true);

        fee.mint(alice, 1_000e18);
        vm.startPrank(alice);
        fee.approve(address(escrow), type(uint256).max);
        (, uint256 received_) = escrow.lock(address(fee), 1_000e18, keccak256("fee-rec"));
        vm.stopPrank();

        // 1% fee → received is 99%
        assertEq(received_, 990e18);
        assertEq(fee.balanceOf(address(escrow)), 990e18);
    }

    function test_Lock_ZeroAmountReverts() public {
        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.AmountZero.selector);
        escrow.lock(address(usdc), 0, keccak256("x"));
    }

    function test_Lock_ZeroRecipientReverts() public {
        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.InvalidRecipient.selector);
        escrow.lock(address(usdc), 1, bytes32(0));
    }

    function test_Lock_UnsupportedTokenReverts() public {
        MockERC20 rando = new MockERC20("R", "R", 18);
        rando.mint(alice, 1e18);
        vm.startPrank(alice);
        rando.approve(address(escrow), type(uint256).max);
        vm.expectRevert(BridgeEscrow.TokenNotSupported.selector);
        escrow.lock(address(rando), 1e18, keccak256("y"));
        vm.stopPrank();
    }

    function test_Lock_WhenPausedReverts() public {
        vm.prank(owner);
        escrow.pause();
        vm.prank(alice);
        vm.expectRevert();
        escrow.lock(address(usdc), 1e6, keccak256("z"));
    }

    function test_Lock_EmitsLockedEvent() public {
        vm.recordLogs();
        vm.prank(alice);
        escrow.lock(address(usdc), 50e6, keccak256("evt"));
        Vm.Log[] memory entries = vm.getRecordedLogs();
        // Find our Locked event (topic0 = keccak of signature)
        bytes32 topic = keccak256(
            "Locked(address,address,uint256,uint256,bytes32,uint256)"
        );
        bool found;
        for (uint256 i; i < entries.length; i++) {
            if (entries[i].topics.length > 0 && entries[i].topics[0] == topic) {
                found = true;
                // token indexed
                assertEq(address(uint160(uint256(entries[i].topics[1]))), address(usdc));
                // from indexed
                assertEq(address(uint160(uint256(entries[i].topics[2]))), alice);
                // depositNonce indexed
                assertEq(uint256(entries[i].topics[3]), 1);
                break;
            }
        }
        assertTrue(found, "Locked event not emitted");
    }

    // =====================================================================
    // claim()
    // =====================================================================

    function test_Claim_Succeeds() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes memory sig = _sign(signerPk, intent);

        uint256 bobBefore = usdc.balanceOf(bob);
        escrow.claim(intent, sig);
        assertEq(usdc.balanceOf(bob), bobBefore + 100e6);
        assertTrue(escrow.signaturesUsed(intent.opnetNonce));
        assertTrue(escrow.usedSourceEvent(intent.opnetTxHash, intent.opnetEventIndex));
    }

    function test_Claim_SubmittedByNonRecipient_StillGoesToRecipient() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes memory sig = _sign(signerPk, intent);

        address relayer = address(0xCAFE);
        vm.prank(relayer);
        escrow.claim(intent, sig);
        assertEq(usdc.balanceOf(bob), 100e6);
        assertEq(usdc.balanceOf(relayer), 0);
    }

    function test_Claim_USDT_SafeTransfer() public {
        _fundEscrow(address(usdt), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdt), bob, 100e6);
        bytes memory sig = _sign(signerPk, intent);
        escrow.claim(intent, sig);
        assertEq(usdt.balanceOf(bob), 100e6);
    }

    function test_Claim_ReplayByOpnetNonceReverts() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes memory sig = _sign(signerPk, intent);
        escrow.claim(intent, sig);

        vm.expectRevert(BridgeEscrow.AlreadyClaimed.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_ReplayByCompositeSourceEventReverts() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory a = _defaultIntent(address(usdc), bob, 100e6);
        bytes memory sigA = _sign(signerPk, a);
        escrow.claim(a, sigA);

        // Same (opnetTxHash, opnetEventIndex) but fresh opnetNonce — must revert
        // on the composite source-event guard.
        BridgeEscrow.ReleaseIntent memory b = a;
        b.opnetNonce = keccak256("different-nonce");
        bytes memory sigB = _sign(signerPk, b);
        vm.expectRevert(BridgeEscrow.SourceEventAlreadyUsed.selector);
        escrow.claim(b, sigB);
    }

    function test_Claim_WrongSignerEpochReverts() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        intent.signerEpoch = 99;
        bytes memory sig = _sign(signerPk, intent);

        vm.expectRevert(BridgeEscrow.InvalidSignerEpoch.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_AfterRotate_OldSigFails() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes memory sig = _sign(signerPk, intent);

        // v2 rotation — atomic add+remove via migrateSignerSet (1-of-1 → 1-of-1
        // with a different key, no intermediate weakening).
        uint256 newPk = 0xDEAFBEEF;
        address newSigner = vm.addr(newPk);
        address[] memory addList = new address[](1);
        addList[0] = newSigner;
        address[] memory removeList = new address[](1);
        removeList[0] = signerAddr;
        vm.prank(owner);
        escrow.migrateSignerSet(addList, removeList, 1);

        vm.expectRevert(BridgeEscrow.InvalidSignerEpoch.selector);
        escrow.claim(intent, sig);

        // Re-sign at new epoch should work.
        intent.signerEpoch = escrow.currentEpoch();
        bytes memory sig2 = _sign(newPk, intent);
        escrow.claim(intent, sig2);
        assertEq(usdc.balanceOf(bob), 100e6);
    }

    function test_Claim_HighSMalleabilityReverts() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes32 d = _digest(intent, address(escrow));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, d);

        // Flip to the high-s counterpart.
        bytes32 secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 sHigh = bytes32(uint256(secp256k1n) - uint256(s));
        uint8 vFlip = v == 27 ? 28 : 27;
        bytes memory malleable = abi.encodePacked(r, sHigh, vFlip);

        vm.expectRevert();
        escrow.claim(intent, malleable);
    }

    function test_Claim_WrongChainIdFails() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);

        // Sign under a different chainId (forge chainid manipulation).
        uint256 original = block.chainid;
        vm.chainId(999);
        bytes memory sig = _sign(signerPk, intent);
        vm.chainId(original);

        vm.expectRevert(BridgeEscrow.InvalidSignature.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_WrongSrcChainIdReverts() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);

        // Server mislabels OPNet mainnet voucher for a testnet-configured escrow.
        intent.srcChainId = 1;
        bytes memory sig = _sign(signerPk, intent);

        vm.expectRevert(BridgeEscrow.InvalidSrcChainId.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_WrongVerifyingContractFails() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);

        // Sign using a different verifying contract address.
        bytes memory sig = _sign(signerPk, intent, address(0xDEAD));

        vm.expectRevert(BridgeEscrow.InvalidSignature.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_WrongRecipient_BobCannotRedirect() public {
        _fundEscrow(address(usdc), 1_000e6);

        // Signer authorizes funds → alice only.
        BridgeEscrow.ReleaseIntent memory originalIntent = _defaultIntent(address(usdc), alice, 100e6);
        bytes memory sig = _sign(signerPk, originalIntent);

        // Bob tries to submit a tampered intent that redirects funds to himself.
        BridgeEscrow.ReleaseIntent memory tampered = _defaultIntent(address(usdc), bob, 100e6);
        // Keep every field the same except `to`:
        tampered.opnetTxHash = originalIntent.opnetTxHash;
        tampered.opnetEventIndex = originalIntent.opnetEventIndex;
        tampered.burnNonce = originalIntent.burnNonce;
        tampered.opnetNonce = originalIntent.opnetNonce;

        vm.expectRevert(BridgeEscrow.InvalidSignature.selector);
        vm.prank(bob);
        escrow.claim(tampered, sig);

        // Original signed intent still works; funds land at alice not bob,
        // even when bob submits.
        uint256 aliceBefore = usdc.balanceOf(alice);
        vm.prank(bob);
        escrow.claim(originalIntent, sig);
        assertEq(usdc.balanceOf(alice), aliceBefore + 100e6);
        assertEq(usdc.balanceOf(bob), 0);
    }

    function test_Claim_WrongAmountFails() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes memory sig = _sign(signerPk, intent);

        intent.amount = 101e6; // attacker inflates
        vm.expectRevert(BridgeEscrow.InvalidSignature.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_WhenPausedReverts() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes memory sig = _sign(signerPk, intent);

        vm.prank(owner);
        escrow.pause();

        vm.expectRevert();
        escrow.claim(intent, sig);
    }

    function test_Claim_ZeroAmountReverts() public {
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 0);
        bytes memory sig = _sign(signerPk, intent);
        vm.expectRevert(BridgeEscrow.AmountZero.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_ZeroRecipientReverts() public {
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), address(0), 100e6);
        bytes memory sig = _sign(signerPk, intent);
        vm.expectRevert(BridgeEscrow.InvalidRecipient.selector);
        escrow.claim(intent, sig);
    }

    function test_Claim_UnsupportedTokenReverts() public {
        MockERC20 rando = new MockERC20("R", "R", 18);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(rando), bob, 100);
        bytes memory sig = _sign(signerPk, intent);
        vm.expectRevert(BridgeEscrow.TokenNotSupported.selector);
        escrow.claim(intent, sig);
    }

    // =====================================================================
    // Admin
    // =====================================================================

    function test_Admin_Pause_OnlyOwner() public {
        vm.expectRevert();
        escrow.pause();
        vm.prank(owner);
        escrow.pause();
        assertTrue(escrow.paused());
    }

    function test_Admin_Unpause_OnlyOwner() public {
        vm.prank(owner);
        escrow.pause();
        vm.expectRevert();
        escrow.unpause();
        vm.prank(owner);
        escrow.unpause();
        assertFalse(escrow.paused());
    }

    function test_Admin_SetSupportedToken_OnlyOwner() public {
        MockERC20 rando = new MockERC20("R", "R", 18);
        vm.expectRevert();
        escrow.setSupportedToken(address(rando), true);
        vm.prank(owner);
        escrow.setSupportedToken(address(rando), true);
        assertTrue(escrow.supportedToken(address(rando)));
        vm.prank(owner);
        escrow.setSupportedToken(address(rando), false);
        assertFalse(escrow.supportedToken(address(rando)));
    }

    function test_Admin_RotateSigner_OnlyOwner() public {
        // v2 — rotation = atomic migrateSignerSet([new], [old], 1). Each
        // migrate increments currentEpoch and the new signer must be
        // authorized in `isSigner`.
        address[] memory addList = new address[](1);
        addList[0] = address(0xFEED);
        address[] memory removeList = new address[](1);
        removeList[0] = signerAddr;

        vm.expectRevert();
        escrow.migrateSignerSet(addList, removeList, 1);

        uint32 oldEpoch = escrow.currentEpoch();
        vm.prank(owner);
        escrow.migrateSignerSet(addList, removeList, 1);
        assertEq(escrow.currentEpoch(), oldEpoch + 1);
        assertTrue(escrow.isSigner(address(0xFEED)));
        assertFalse(escrow.isSigner(signerAddr));
    }

    function test_Admin_AddSigner_ZeroReverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.ZeroAddress.selector);
        escrow.addSigner(address(0));
    }

    // =====================================================================
    // UUPS upgrade
    // =====================================================================

    function test_Upgrade_OnlyOwner() public {
        BridgeEscrowV2 v2Impl = new BridgeEscrowV2();
        vm.expectRevert();
        escrow.upgradeToAndCall(address(v2Impl), "");

        vm.prank(owner);
        escrow.upgradeToAndCall(address(v2Impl), "");

        assertEq(BridgeEscrowV2(address(escrow)).version(), "v2");
        // State preserved
        assertTrue(escrow.supportedToken(address(usdc)));
        assertTrue(escrow.isSigner(signerAddr));
    }

    function test_Upgrade_DoesNotCorruptState() public {
        _fundEscrow(address(usdc), 500e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 10e6);
        bytes memory sig = _sign(signerPk, intent);
        escrow.claim(intent, sig);

        BridgeEscrowV2 v2Impl = new BridgeEscrowV2();
        vm.prank(owner);
        escrow.upgradeToAndCall(address(v2Impl), "");

        assertTrue(escrow.signaturesUsed(intent.opnetNonce));
        assertTrue(escrow.usedSourceEvent(intent.opnetTxHash, intent.opnetEventIndex));
    }

    // =====================================================================
    // Emergency withdraw — Phase 1: onlyGuardian + whenPaused, fixed treasury
    // =====================================================================

    address internal guardian = address(0xC0DE);
    address internal treasuryAddr = address(0x7EA);

    /// @dev Configures Phase 1 emergency-drain prereqs: guardian + treasury
    ///      set, contract paused. Used by every emergencyWithdraw test below.
    function _armEmergency() internal {
        vm.startPrank(owner);
        if (escrow.guardian() == address(0)) escrow.setGuardian(guardian);
        if (escrow.treasury() == address(0)) escrow.setTreasury(treasuryAddr);
        if (!escrow.paused()) escrow.pause();
        vm.stopPrank();
    }

    function test_EmergencyWithdraw_Succeeds() public {
        _fundEscrow(address(usdc), 1_000e6);
        _armEmergency();

        uint256 escrowBefore = usdc.balanceOf(address(escrow));
        uint256 treasuryBefore = usdc.balanceOf(treasuryAddr);

        vm.prank(guardian);
        escrow.emergencyWithdraw(address(usdc), 250e6);

        assertEq(usdc.balanceOf(treasuryAddr), treasuryBefore + 250e6, "treasury credited");
        assertEq(usdc.balanceOf(address(escrow)), escrowBefore - 250e6, "escrow debited");
    }

    function test_EmergencyWithdraw_USDT_Succeeds() public {
        _fundEscrow(address(usdt), 500e6);
        _armEmergency();

        vm.prank(guardian);
        escrow.emergencyWithdraw(address(usdt), 500e6);

        assertEq(usdt.balanceOf(treasuryAddr), 500e6, "treasury received USDT via SafeERC20");
        assertEq(usdt.balanceOf(address(escrow)), 0, "escrow drained");
    }

    function test_EmergencyWithdraw_NotGuardianReverts() public {
        _fundEscrow(address(usdc), 1_000e6);
        _armEmergency();

        // Owner is no longer authorised — only the guardian is.
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.emergencyWithdraw(address(usdc), 1e6);

        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.emergencyWithdraw(address(usdc), 1e6);
    }

    function test_EmergencyWithdraw_NotPausedReverts() public {
        _fundEscrow(address(usdc), 1_000e6);
        // Guardian + treasury set but contract NOT paused — must revert.
        vm.startPrank(owner);
        escrow.setGuardian(guardian);
        escrow.setTreasury(treasuryAddr);
        vm.stopPrank();

        vm.prank(guardian);
        vm.expectRevert(); // Pausable: not paused
        escrow.emergencyWithdraw(address(usdc), 1e6);
    }

    function test_EmergencyWithdraw_ZeroTokenReverts() public {
        _armEmergency();
        vm.prank(guardian);
        vm.expectRevert(BridgeEscrow.ZeroAddress.selector);
        escrow.emergencyWithdraw(address(0), 1e6);
    }

    function test_EmergencyWithdraw_ZeroAmountReverts() public {
        _armEmergency();
        vm.prank(guardian);
        vm.expectRevert(BridgeEscrow.AmountZero.selector);
        escrow.emergencyWithdraw(address(usdc), 0);
    }

    function test_EmergencyWithdraw_TreasuryNotSetReverts() public {
        // Set guardian + pause, but skip treasury.
        vm.startPrank(owner);
        escrow.setGuardian(guardian);
        escrow.pause();
        vm.stopPrank();

        vm.prank(guardian);
        vm.expectRevert(BridgeEscrow.TreasuryNotSet.selector);
        escrow.emergencyWithdraw(address(usdc), 1e6);
    }

    function test_EmergencyWithdraw_InsufficientBalanceReverts() public {
        _armEmergency();
        vm.prank(guardian);
        vm.expectRevert();
        escrow.emergencyWithdraw(address(usdc), 1e6);
    }

    function test_EmergencyWithdraw_EmitsEvent() public {
        _fundEscrow(address(usdc), 1_000e6);
        _armEmergency();

        vm.prank(guardian);
        vm.expectEmit(true, true, true, true);
        emit BridgeEscrow.EmergencyWithdraw(address(usdc), treasuryAddr, 100e6, guardian);
        escrow.emergencyWithdraw(address(usdc), 100e6);
    }

    // =====================================================================
    // Phase 1 — set-once treasury + guardian
    // =====================================================================

    function test_SetTreasury_Succeeds() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit BridgeEscrow.TreasurySet(treasuryAddr);
        escrow.setTreasury(treasuryAddr);
        assertEq(escrow.treasury(), treasuryAddr);
    }

    function test_SetTreasury_OnlyOnceReverts() public {
        vm.startPrank(owner);
        escrow.setTreasury(treasuryAddr);
        vm.expectRevert(BridgeEscrow.TreasuryAlreadySet.selector);
        escrow.setTreasury(address(0xDEAD));
        vm.stopPrank();
    }

    function test_SetTreasury_ZeroReverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.ZeroAddress.selector);
        escrow.setTreasury(address(0));
    }

    function test_SetTreasury_OnlyOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        escrow.setTreasury(treasuryAddr);
    }

    function test_SetGuardian_Succeeds() public {
        vm.prank(owner);
        escrow.setGuardian(guardian);
        assertEq(escrow.guardian(), guardian);
    }

    function test_SetGuardian_OnlyOnceReverts() public {
        vm.startPrank(owner);
        escrow.setGuardian(guardian);
        vm.expectRevert(BridgeEscrow.GuardianAlreadySet.selector);
        escrow.setGuardian(address(0xDEAD));
        vm.stopPrank();
    }

    function test_SetGuardian_ZeroReverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.ZeroAddress.selector);
        escrow.setGuardian(address(0));
    }

    // =====================================================================
    // Phase 1 — M-of-N signer set
    // =====================================================================

    /// @dev Pack M-of-N sig blob: [uint8 numSigs][sig_0(65)][sig_1(65)]...
    function _packMofN(bytes[] memory sigs) internal pure returns (bytes memory blob) {
        require(sigs.length > 0 && sigs.length < 256, "bad numSigs");
        blob = abi.encodePacked(uint8(sigs.length));
        for (uint256 i; i < sigs.length; i++) {
            require(sigs[i].length == 65, "bad sig length");
            blob = abi.encodePacked(blob, sigs[i]);
        }
    }

    function test_Init_SeedsMofNAt1of1() public view {
        // Fresh deploy: signerThreshold = 1, signerCount = 1, isSigner[signer] = true
        assertEq(escrow.signerThreshold(), 1);
        assertEq(escrow.signerCount(), 1);
        assertTrue(escrow.isSigner(signerAddr));
    }

    function test_AddSigner_Succeeds() public {
        address s2 = vm.addr(0xBEE5);
        vm.prank(owner);
        escrow.addSigner(s2);
        assertTrue(escrow.isSigner(s2));
        assertEq(escrow.signerCount(), 2);
    }

    function test_AddSigner_DuplicateReverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.AlreadyASigner.selector);
        escrow.addSigner(signerAddr);
    }

    function test_AddSigner_ZeroReverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.ZeroAddress.selector);
        escrow.addSigner(address(0));
    }

    function test_AddSigner_OnlyOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        escrow.addSigner(vm.addr(0x1));
    }

    function test_RemoveSigner_BumpsEpoch() public {
        // Add a second signer first so we don't violate threshold ≤ count.
        address s2 = vm.addr(0xBEE5);
        vm.prank(owner);
        escrow.addSigner(s2);

        uint32 oldEpoch = escrow.currentEpoch();
        vm.prank(owner);
        escrow.removeSigner(s2);

        assertFalse(escrow.isSigner(s2));
        assertEq(escrow.signerCount(), 1);
        assertEq(escrow.currentEpoch(), oldEpoch + 1, "removeSigner bumps epoch");
    }

    function test_RemoveSigner_BelowThresholdReverts() public {
        // Cannot remove the only signer — would push count below threshold.
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.InvalidThreshold.selector);
        escrow.removeSigner(signerAddr);
    }

    function test_RemoveSigner_NotASignerReverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.NotASigner.selector);
        escrow.removeSigner(vm.addr(0xDEAD));
    }

    function test_SetThreshold_BumpsEpoch() public {
        address s2 = vm.addr(0xBEE5);
        vm.prank(owner);
        escrow.addSigner(s2);

        uint32 oldEpoch = escrow.currentEpoch();
        vm.prank(owner);
        escrow.setThreshold(2);
        assertEq(escrow.signerThreshold(), 2);
        assertEq(escrow.currentEpoch(), oldEpoch + 1);
    }

    function test_SetThreshold_AboveCountReverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.InvalidThreshold.selector);
        escrow.setThreshold(2); // signerCount is 1
    }

    function test_SetThreshold_ZeroReverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.InvalidThreshold.selector);
        escrow.setThreshold(0);
    }

    function test_MigrateSignerSet_AtomicOneToTwo() public {
        // Atomic 1-of-1 → 2-of-2 transition. No intermediate weakening.
        uint256 s2pk = 0xBEE5;
        uint256 s3pk = 0xCAFE;
        address s2 = vm.addr(s2pk);
        address s3 = vm.addr(s3pk);

        address[] memory addList = new address[](2);
        addList[0] = s2;
        addList[1] = s3;
        address[] memory removeList = new address[](1);
        removeList[0] = signerAddr;

        uint32 oldEpoch = escrow.currentEpoch();
        vm.prank(owner);
        escrow.migrateSignerSet(addList, removeList, 2);

        assertEq(escrow.signerCount(), 2);
        assertEq(escrow.signerThreshold(), 2);
        assertFalse(escrow.isSigner(signerAddr));
        assertTrue(escrow.isSigner(s2));
        assertTrue(escrow.isSigner(s3));
        assertEq(escrow.currentEpoch(), oldEpoch + 1);
    }

    function test_Claim_TwoOfTwo_Succeeds() public {
        _fundEscrow(address(usdc), 1_000e6);

        uint256 s2pk = 0xBEE5;
        address s2 = vm.addr(s2pk);
        vm.startPrank(owner);
        escrow.addSigner(s2);
        escrow.setThreshold(2);
        vm.stopPrank();

        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signRaw65(signerPk, intent);
        sigs[1] = _signRaw65(s2pk, intent);
        bytes memory blob = _packMofN(sigs);

        escrow.claim(intent, blob);
        assertEq(usdc.balanceOf(bob), 100e6);
    }

    function test_Claim_TwoOfThree_Succeeds() public {
        _fundEscrow(address(usdc), 1_000e6);

        uint256 s2pk = 0xBEE5;
        uint256 s3pk = 0xCAFE;
        address s2 = vm.addr(s2pk);
        address s3 = vm.addr(s3pk);
        vm.startPrank(owner);
        escrow.addSigner(s2);
        escrow.addSigner(s3);
        escrow.setThreshold(2);
        vm.stopPrank();

        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signRaw65(s2pk, intent);
        sigs[1] = _signRaw65(s3pk, intent); // s2 + s3 quorum, original signer not used
        bytes memory blob = _packMofN(sigs);

        escrow.claim(intent, blob);
        assertEq(usdc.balanceOf(bob), 100e6);
    }

    function test_Claim_BelowThresholdReverts() public {
        _fundEscrow(address(usdc), 1_000e6);

        uint256 s2pk = 0xBEE5;
        address s2 = vm.addr(s2pk);
        vm.startPrank(owner);
        escrow.addSigner(s2);
        escrow.setThreshold(2);
        vm.stopPrank();

        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        // Only 1 sig provided when 2 required.
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _signRaw65(signerPk, intent);
        bytes memory blob = _packMofN(sigs);

        vm.expectRevert(BridgeEscrow.InsufficientSignatures.selector);
        escrow.claim(intent, blob);
    }

    function test_Claim_DuplicateSignerReverts() public {
        _fundEscrow(address(usdc), 1_000e6);

        uint256 s2pk = 0xBEE5;
        address s2 = vm.addr(s2pk);
        vm.startPrank(owner);
        escrow.addSigner(s2);
        escrow.setThreshold(2);
        vm.stopPrank();

        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        // Same signer twice — must NOT count as 2 distinct.
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signRaw65(signerPk, intent);
        sigs[1] = _signRaw65(signerPk, intent);
        bytes memory blob = _packMofN(sigs);

        vm.expectRevert(BridgeEscrow.DuplicateSigner.selector);
        escrow.claim(intent, blob);
    }

    function test_Claim_UnauthorizedSignerReverts() public {
        _fundEscrow(address(usdc), 1_000e6);

        uint256 randomPk = 0xDEADBEEF;
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _signRaw65(randomPk, intent);
        bytes memory blob = _packMofN(sigs);

        vm.expectRevert(BridgeEscrow.InvalidSignature.selector);
        escrow.claim(intent, blob);
    }

    function test_Claim_BadBlobLengthReverts() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);

        // numSigs=2 but only one 65-byte sig follows.
        bytes memory blob = abi.encodePacked(uint8(2), new bytes(65));
        vm.expectRevert(BridgeEscrow.InvalidSigBlob.selector);
        escrow.claim(intent, blob);
    }

    // =====================================================================
    // Phase 1 — voucher cancellation
    // =====================================================================

    function test_CancelVoucher_BlocksClaim() public {
        _fundEscrow(address(usdc), 1_000e6);
        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(usdc), bob, 100e6);
        bytes memory sig = _sign(signerPk, intent);

        vm.prank(owner);
        escrow.cancelVoucher(intent.opnetNonce);
        assertTrue(escrow.cancelledVouchers(intent.opnetNonce));

        vm.expectRevert(BridgeEscrow.VoucherCancelled_.selector);
        escrow.claim(intent, sig);
    }

    function test_CancelVoucher_Idempotent() public {
        bytes32 nonce = keccak256("any");
        vm.prank(owner);
        escrow.cancelVoucher(nonce);
        // Second call should not revert.
        vm.prank(owner);
        escrow.cancelVoucher(nonce);
    }

    function test_CancelVoucher_OnlyOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        escrow.cancelVoucher(keccak256("x"));
    }

    // =====================================================================
    // Utility
    // =====================================================================

    function _fundEscrow(address token, uint256 amount) internal {
        vm.prank(alice);
        escrow.lock(token, amount, keccak256("seed"));
    }

    // =====================================================================
    // Modular unwrap fees (governor-settable, capped, default 0)
    // =====================================================================

    function test_UnwrapFee_DefaultsToZero() public view {
        assertEq(escrow.unwrapFeeBps(), 0);
        assertEq(escrow.unwrapMinFee(address(usdc)), 0);
        assertEq(escrow.unwrapMinFee(address(usdt)), 0);
    }

    function test_UnwrapFee_MaxFeeBpsConstant() public view {
        // 1000 bps = 10% — hard cap on what the governor can set.
        assertEq(escrow.MAX_FEE_BPS(), 1000);
    }

    function test_SetUnwrapFeeBps_Succeeds() public {
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit BridgeEscrow.UnwrapFeeBpsSet(0, 50);
        escrow.setUnwrapFeeBps(50);
        assertEq(escrow.unwrapFeeBps(), 50);
    }

    function test_SetUnwrapFeeBps_AtMax() public {
        vm.prank(owner);
        escrow.setUnwrapFeeBps(1000);
        assertEq(escrow.unwrapFeeBps(), 1000);
    }

    function test_SetUnwrapFeeBps_AboveMaxReverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.FeeBpsTooHigh.selector);
        escrow.setUnwrapFeeBps(1001);
    }

    function test_SetUnwrapFeeBps_OnlyOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        escrow.setUnwrapFeeBps(50);
    }

    function test_SetUnwrapFeeBps_ZeroResetsFee() public {
        vm.startPrank(owner);
        escrow.setUnwrapFeeBps(50);
        escrow.setUnwrapFeeBps(0);
        vm.stopPrank();
        assertEq(escrow.unwrapFeeBps(), 0);
    }

    function test_SetUnwrapMinFee_Succeeds() public {
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit BridgeEscrow.UnwrapMinFeeSet(address(usdc), 1_000_000);
        escrow.setUnwrapMinFee(address(usdc), 1_000_000); // $1.00 in 6 dec
        assertEq(escrow.unwrapMinFee(address(usdc)), 1_000_000);
        // USDT min stays at 0 — independent per-token slots.
        assertEq(escrow.unwrapMinFee(address(usdt)), 0);
    }

    function test_SetUnwrapMinFee_ZeroTokenReverts() public {
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.ZeroAddress.selector);
        escrow.setUnwrapMinFee(address(0), 100);
    }

    function test_SetUnwrapMinFee_OnlyOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        escrow.setUnwrapMinFee(address(usdc), 100);
    }

    // =====================================================================
    // Token modes — INVERSE_WRAPPED + NATIVE_BURN_MINT + POOLED_LOCK_RELEASE
    // =====================================================================

    function test_TokenMode_DefaultsToWrapped() public view {
        // USDC and USDT were registered via the legacy `setSupportedToken`
        // path in setUp(); they must be in WRAPPED mode by default.
        assertEq(uint256(escrow.tokenMode(address(usdc))), uint256(BridgeEscrow.TokenMode.WRAPPED));
        assertEq(uint256(escrow.tokenMode(address(usdt))), uint256(BridgeEscrow.TokenMode.WRAPPED));
    }

    function test_SetTokenMode_InverseWrapped_Succeeds() public {
        MockERC20 wrapped = new MockERC20("Wrapped MOTO", "wMOTO", 6);
        bytes32 opnetCanonical = bytes32(uint256(0xCAFE));
        vm.prank(owner);
        escrow.setTokenMode(address(wrapped), BridgeEscrow.TokenMode.INVERSE_WRAPPED, opnetCanonical);
        assertEq(uint256(escrow.tokenMode(address(wrapped))), uint256(BridgeEscrow.TokenMode.INVERSE_WRAPPED));
        assertEq(escrow.opnetCounterpartOf(address(wrapped)), opnetCanonical);
        assertTrue(escrow.supportedToken(address(wrapped)));
    }

    function test_SetTokenMode_SetOnce_Reverts() public {
        MockERC20 wrapped = new MockERC20("X", "X", 6);
        bytes32 cp = bytes32(uint256(1));
        vm.prank(owner);
        escrow.setTokenMode(address(wrapped), BridgeEscrow.TokenMode.NATIVE_BURN_MINT, cp);
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.TokenModeFinalized.selector);
        escrow.setTokenMode(address(wrapped), BridgeEscrow.TokenMode.WRAPPED, bytes32(0));
    }

    function test_SetTokenMode_NonWrappedRequiresOpnetCounterpart() public {
        MockERC20 wrapped = new MockERC20("X", "X", 6);
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.InvalidTokenMode.selector);
        escrow.setTokenMode(address(wrapped), BridgeEscrow.TokenMode.INVERSE_WRAPPED, bytes32(0));
    }

    function test_SetTokenMode_PooledLockRelease_Succeeds() public {
        MockERC20 moto = new MockERC20("MOTO", "MOTO", 6);
        bytes32 opnetMoto = bytes32(uint256(0xDEAD));
        vm.prank(owner);
        escrow.setTokenMode(address(moto), BridgeEscrow.TokenMode.POOLED_LOCK_RELEASE, opnetMoto);
        assertEq(uint256(escrow.tokenMode(address(moto))), uint256(BridgeEscrow.TokenMode.POOLED_LOCK_RELEASE));
        // Mode-4 tokens also pass through `lock` (just like mode-1).
        moto.mint(alice, 100e6);
        vm.startPrank(alice);
        moto.approve(address(escrow), type(uint256).max);
        (uint256 nonce, uint256 received) = escrow.lock(address(moto), 50e6, keccak256("rcp"));
        vm.stopPrank();
        assertEq(nonce, 1);
        assertEq(received, 50e6);
    }

    function test_Lock_RevertsForInverseWrappedToken() public {
        MockERC20 w = new MockERC20("W", "W", 6);
        vm.prank(owner);
        escrow.setTokenMode(address(w), BridgeEscrow.TokenMode.INVERSE_WRAPPED, bytes32(uint256(1)));
        w.mint(alice, 100e6);
        vm.startPrank(alice);
        w.approve(address(escrow), type(uint256).max);
        vm.expectRevert(BridgeEscrow.WrongMode.selector);
        escrow.lock(address(w), 1e6, keccak256("x"));
        vm.stopPrank();
    }

    function test_Claim_RevertsForInverseWrappedToken() public {
        MockERC20 w = new MockERC20("W", "W", 6);
        vm.prank(owner);
        escrow.setTokenMode(address(w), BridgeEscrow.TokenMode.INVERSE_WRAPPED, bytes32(uint256(1)));

        BridgeEscrow.ReleaseIntent memory intent = _defaultIntent(address(w), bob, 100e6);
        bytes memory sig = _sign(signerPk, intent);
        vm.expectRevert(BridgeEscrow.WrongMode.selector);
        escrow.claim(intent, sig);
    }

    function test_ProvisionInventory_AddsToBalance() public {
        MockERC20 moto = new MockERC20("MOTO", "MOTO", 6);
        vm.prank(owner);
        escrow.setTokenMode(address(moto), BridgeEscrow.TokenMode.POOLED_LOCK_RELEASE, bytes32(uint256(1)));

        moto.mint(owner, 1_000e6);
        uint256 escrowBefore = moto.balanceOf(address(escrow));

        vm.startPrank(owner);
        moto.approve(address(escrow), 1_000e6);
        escrow.provisionInventory(address(moto), 600e6);
        vm.stopPrank();

        assertEq(moto.balanceOf(address(escrow)), escrowBefore + 600e6);
    }

    function test_ProvisionInventory_OnlyOwner() public {
        MockERC20 moto = new MockERC20("MOTO", "MOTO", 6);
        vm.prank(owner);
        escrow.setTokenMode(address(moto), BridgeEscrow.TokenMode.POOLED_LOCK_RELEASE, bytes32(uint256(1)));
        moto.mint(alice, 100e6);
        vm.startPrank(alice);
        moto.approve(address(escrow), 100e6);
        vm.expectRevert();
        escrow.provisionInventory(address(moto), 50e6);
        vm.stopPrank();
    }

    function test_DrainInventory_GuardianOnlyWhenPaused() public {
        // Set up: register MOTO + provision + set treasury/guardian + pause.
        MockERC20 moto = new MockERC20("MOTO", "MOTO", 6);
        vm.prank(owner);
        escrow.setTokenMode(address(moto), BridgeEscrow.TokenMode.POOLED_LOCK_RELEASE, bytes32(uint256(1)));
        moto.mint(owner, 1_000e6);
        vm.startPrank(owner);
        moto.approve(address(escrow), 1_000e6);
        escrow.provisionInventory(address(moto), 1_000e6);
        escrow.setGuardian(guardian);
        escrow.setTreasury(treasuryAddr);
        escrow.pause();
        vm.stopPrank();

        // Owner can NOT drain (must be guardian).
        vm.prank(owner);
        vm.expectRevert(BridgeEscrow.NotGuardian.selector);
        escrow.drainInventory(address(moto), 100e6);

        // Guardian can drain to treasury.
        vm.prank(guardian);
        escrow.drainInventory(address(moto), 100e6);
        assertEq(moto.balanceOf(treasuryAddr), 100e6);
    }

    function test_ClaimMintWrapped_HappyPath_Mode2() public {
        // Deploy a WrappedERC20 owned by us, with bridge = escrow proxy.
        WrappedERC20 wmoto = new WrappedERC20(
            "Wrapped MOTO",
            "wMOTO",
            owner,
            address(escrow),
            EXPECTED_OPNET_CHAIN_ID,
            bytes32(uint256(0xC0DE))
        );
        vm.prank(owner);
        escrow.setTokenMode(address(wmoto), BridgeEscrow.TokenMode.INVERSE_WRAPPED, bytes32(uint256(0xC0DE)));

        BridgeEscrow.MintIntent memory mi = BridgeEscrow.MintIntent({
            wrappedToken: address(wmoto),
            to: bob,
            amount: 100e6,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: keccak256("opnet-tx-mint-1"),
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: keccak256("opnet-nonce-mint-1")
        });
        bytes memory sig = _signMintIntent(signerPk, mi);

        escrow.claimMintWrapped(mi, sig);
        assertEq(wmoto.balanceOf(bob), 100e6);
        assertTrue(escrow.signaturesUsed(mi.opnetNonce));
    }

    function test_ClaimMintWrapped_RevertsForWrappedToken() public {
        // USDC is mode WRAPPED; claimMintWrapped against it should revert.
        BridgeEscrow.MintIntent memory mi = BridgeEscrow.MintIntent({
            wrappedToken: address(usdc),
            to: bob,
            amount: 100e6,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: keccak256("x"),
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: keccak256("y")
        });
        bytes memory sig = _signMintIntent(signerPk, mi);
        vm.expectRevert(BridgeEscrow.WrongMode.selector);
        escrow.claimMintWrapped(mi, sig);
    }

    // =====================================================================
    // WrappedERC20 sanity
    // =====================================================================

    function test_WrappedERC20_Mint_OnlyBridge() public {
        WrappedERC20 wmoto = new WrappedERC20(
            "wMOTO", "wMOTO", owner, address(escrow), EXPECTED_OPNET_CHAIN_ID, bytes32(uint256(1))
        );
        vm.expectRevert(WrappedERC20.NotBridge.selector);
        wmoto.mintFromBridge(alice, 100);
    }

    function test_WrappedERC20_BurnForRelease_EmitsAndDecrements() public {
        WrappedERC20 wmoto = new WrappedERC20(
            "wMOTO", "wMOTO", owner, address(escrow), EXPECTED_OPNET_CHAIN_ID, bytes32(uint256(1))
        );
        vm.prank(address(escrow));
        wmoto.mintFromBridge(alice, 1_000e6);
        assertEq(wmoto.balanceOf(alice), 1_000e6);

        bytes32 opnetRcp = bytes32(uint256(0xBEEF));
        vm.prank(alice);
        wmoto.burnForRelease(opnetRcp, 250e6);
        assertEq(wmoto.balanceOf(alice), 750e6);
        assertEq(wmoto.burnNonce(), 1);
    }

    // =====================================================================
    // EIP-712 helper for MintIntent
    // =====================================================================

    bytes32 internal constant MINT_INTENT_TYPEHASH =
        keccak256(
            "MintIntent(address wrappedToken,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce)"
        );

    function _signMintIntent(uint256 pk, BridgeEscrow.MintIntent memory mi)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                MINT_INTENT_TYPEHASH,
                mi.wrappedToken,
                mi.to,
                mi.amount,
                mi.srcChainId,
                mi.opnetTxHash,
                mi.opnetEventIndex,
                mi.burnNonce,
                mi.signerEpoch,
                mi.opnetNonce
            )
        );
        bytes32 d = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(address(escrow)), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        bytes memory raw = abi.encodePacked(r, s, v);
        return abi.encodePacked(uint8(1), raw);
    }
}
