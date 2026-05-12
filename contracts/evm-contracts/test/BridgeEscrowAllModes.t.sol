// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {WrappedERC20} from "../src/WrappedERC20.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";

/// @title  BridgeEscrowAllModesTest
/// @notice Task D (#36) — coverage for the per-mode behaviour gaps that
///         the legacy BridgeEscrow.t.sol does not assert directly:
///
///           - Mode 3 (POOLED_LOCK_RELEASE) inventory drain on `claim`.
///             Verifies `flow.inventory` decrements on each claim and
///             that an insufficient-inventory claim reverts cleanly
///             before any token transfer (CEI invariant).
///
///           - Mode 2 (NATIVE_BURN_MINT) `claimMintWrapped` happy path.
///             The existing BridgeEscrow.t.sol covers the
///             INVERSE_WRAPPED case (mode 1) — this is the sister
///             coverage for the bridge-as-canonical-issuer mode.
///
///           - lock() mode dispatch: modes 1/2 are NOT lockable
///             (they go through WrappedERC20.burnForRelease on the
///             EVM side) — confirm the WrongMode revert.
///
/// @dev    Reuses the same EIP-712 helpers + signer keypair layout as
///         BridgeEscrow.t.sol but stands up its own fixture so the
///         parent test file's 99 cases don't run under this name.
contract BridgeEscrowAllModesTest is Test {
    bytes32 internal constant RELEASE_INTENT_TYPEHASH = keccak256(
        "ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce,uint256 grossSrcAmount,uint128 relayerTip,bytes32 flowId)"
    );

    bytes32 internal constant MINT_INTENT_TYPEHASH = keccak256(
        "MintIntent(address wrappedToken,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce,bytes32 flowId)"
    );

    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;
    uint64 internal constant TEST_EVM_CHAIN_ID = 1;
    address internal constant TEST_EVM_BRIDGE = address(0xE5C0);
    bytes32 internal constant TEST_OPNET_BRIDGE = bytes32(uint256(0xDEAD));
    bytes32 internal constant TEST_OPNET_MOTO = bytes32(uint256(0x4070));
    bytes32 internal constant TEST_OPNET_WMOTO = bytes32(uint256(0xC0FFEE));

    BridgeEscrow internal impl;
    BridgeEscrow internal escrow;

    MockERC20 internal moto;        // mode-3 POOLED_LOCK_RELEASE token
    WrappedERC20 internal wmoto;    // mode-2 NATIVE_BURN_MINT EVM-side twin

    bytes32 internal motoFlowId;
    bytes32 internal wmotoFlowId;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xB0B);

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

        // The WrappedERC20 ctor needs `bridge` = the proxy.
        wmoto = new WrappedERC20(
            "Wrapped MOTO",
            "wMOTO",
            owner,
            address(escrow),
            EXPECTED_OPNET_CHAIN_ID,
            TEST_OPNET_WMOTO
        );

        // Tag tokens with their bridge mode (legacy `tokenMode[]` lookup
        // path — still authoritative for lock/claim/claimMintWrapped
        // mode dispatch until the storage cleanup commit migrates them
        // to `flows[flowId].mode`).
        vm.startPrank(owner);
        escrow.setTokenMode(
            address(moto),
            BridgeEscrow.TokenMode.POOLED_LOCK_RELEASE,
            TEST_OPNET_MOTO
        );
        escrow.setTokenMode(
            address(wmoto),
            BridgeEscrow.TokenMode.NATIVE_BURN_MINT,
            TEST_OPNET_WMOTO
        );

        // Register the mode-3 flow (real-asset pool — claim path
        // requires the flow record to exist with sufficient inventory).
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

        // Mode-2 flow record for completeness — claimMintWrapped does
        // not bind to flowId in its current shape (MintIntent has no
        // flowId field), but registering it documents the route and
        // sets up future flowId-binding migrations.
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
        vm.stopPrank();

        // Seed Alice with MOTO + approval (for the lock-side
        // provisioning step in mode-3 tests).
        moto.mint(alice, 1_000_000e6);
        vm.prank(alice);
        moto.approve(address(escrow), type(uint256).max);
    }

    // =====================================================================
    // Mode 3 — POOLED_LOCK_RELEASE inventory accounting on claim
    // =====================================================================

    /// @notice Alice locks MOTO (lock-side inventory bump), then a
    ///         release voucher drains some of that inventory back out
    ///         to Bob. After the claim:
    ///           1. wmoto.balanceOf(bob) == claimAmount
    ///           2. flow.inventory == lockedAmount - claimAmount
    function test_pooledRelease_drainsInventory() public {
        // 1. Alice provisions the pool via a normal lock.
        uint256 locked = 500e6;
        vm.prank(alice);
        escrow.lock(address(moto), locked, bytes32(uint256(0xCAFE)), motoFlowId);

        BridgeEscrow.FlowRecord memory before = escrow.getFlow(motoFlowId);
        assertEq(uint256(before.inventory), locked, "inventory after lock");

        // 2. Release voucher for half the pool.
        uint256 amount = 100e6;
        BridgeEscrow.ReleaseIntent memory intent = BridgeEscrow.ReleaseIntent({
            token: address(moto),
            to: bob,
            amount: amount,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: keccak256("opnet-tx-release-pool"),
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: keccak256("opnet-nonce-release-pool"),
            grossSrcAmount: amount,
            relayerTip: 0,
            flowId: motoFlowId
        });
        bytes memory sig = _signIntent(signerPk, intent);

        escrow.claim(intent, sig);

        // 3. Assertions.
        assertEq(moto.balanceOf(bob), amount, "bob received release");
        BridgeEscrow.FlowRecord memory after_ = escrow.getFlow(motoFlowId);
        assertEq(
            uint256(after_.inventory),
            locked - amount,
            "inventory decremented by gross"
        );
    }

    /// @notice With NO prior lock to provision the pool, a release
    ///         voucher must revert before any token movement.
    function test_pooledRelease_insufficientInventory_reverts() public {
        uint256 amount = 100e6;
        BridgeEscrow.ReleaseIntent memory intent = BridgeEscrow.ReleaseIntent({
            token: address(moto),
            to: bob,
            amount: amount,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: keccak256("opnet-tx-release-empty"),
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: keccak256("opnet-nonce-release-empty"),
            grossSrcAmount: amount,
            relayerTip: 0,
            flowId: motoFlowId
        });
        bytes memory sig = _signIntent(signerPk, intent);

        vm.expectRevert(BridgeEscrow.InsufficientFlowInventory.selector);
        escrow.claim(intent, sig);

        // Sanity: bob got nothing, replay guards were NOT written.
        assertEq(moto.balanceOf(bob), 0);
        assertFalse(escrow.signaturesUsed(intent.opnetNonce));
    }

    // =====================================================================
    // Mode 2 — NATIVE_BURN_MINT claimMintWrapped happy path
    // =====================================================================

    function test_claimMintWrapped_nativeBurnMint_happyPath() public {
        BridgeEscrow.MintIntent memory mi = BridgeEscrow.MintIntent({
            wrappedToken: address(wmoto),
            to: bob,
            amount: 100e6,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: keccak256("opnet-tx-mint-nbm"),
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: keccak256("opnet-nonce-mint-nbm"),
            flowId: wmotoFlowId
        });
        bytes memory sig = _signMintIntent(signerPk, mi);

        escrow.claimMintWrapped(mi, sig);

        assertEq(wmoto.balanceOf(bob), 100e6, "wmoto minted to bob");
        assertTrue(
            escrow.signaturesUsed(mi.opnetNonce),
            "opnet nonce marked used"
        );
    }

    // =====================================================================
    // lock() mode dispatch — modes 1 / 2 are NOT lockable
    // =====================================================================

    function test_lock_rejects_nativeBurnMint_token() public {
        // wmoto is mode NATIVE_BURN_MINT. setTokenMode auto-whitelists
        // the token in `supportedToken`, so the lock passes that gate
        // and falls through to the mode dispatch — which is the gate
        // we care about: WrongMode for modes 1/2 (their EVM-side path
        // is WrappedERC20.burnForRelease, NOT BridgeEscrow.lock).
        vm.prank(address(escrow));
        wmoto.mintFromBridge(alice, 100e6);
        vm.prank(alice);
        wmoto.approve(address(escrow), type(uint256).max);

        vm.prank(alice);
        vm.expectRevert(BridgeEscrow.WrongMode.selector);
        escrow.lock(address(wmoto), 50e6, bytes32(uint256(0xBEEF)), wmotoFlowId);
    }

    // =====================================================================
    // Helpers — EIP-712 sigs
    // =====================================================================

    function _signIntent(uint256 pk, BridgeEscrow.ReleaseIntent memory intent)
        internal
        view
        returns (bytes memory)
    {
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
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", escrow.domainSeparator(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        // Length-prefixed M-of-N blob: [uint8 numSigs][r||s||v].
        // The contract's _verifySignatures requires this even for 1-of-1.
        return abi.encodePacked(uint8(1), r, s, v);
    }

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
                mi.opnetNonce,
                mi.flowId
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", escrow.domainSeparator(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(uint8(1), r, s, v);
    }
}
