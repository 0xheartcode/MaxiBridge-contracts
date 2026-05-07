// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";

bytes32 constant RELEASE_INTENT_TYPEHASH =
    keccak256(
        "ReleaseIntent(address token,address to,uint256 amount,uint256 srcChainId,bytes32 opnetTxHash,uint32 opnetEventIndex,uint256 burnNonce,uint32 signerEpoch,bytes32 opnetNonce)"
    );

/// @notice Fork test: exercises BridgeEscrow against Sepolia's canonical
///         USDC and USDT. Skipped automatically when no RPC is configured.
contract BridgeEscrowForkTest is Test {
    // Default Sepolia tokens; overridable via FORK_USDC / FORK_USDT env.
    address internal constant SEPOLIA_USDC = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238;
    address internal constant SEPOLIA_USDT = 0x7169D38820dfd117C3FA1f22a697dBA58d90BA06;

    address internal forkUsdc;
    address internal forkUsdt;

    BridgeEscrow internal escrow;

    address internal owner = address(0xA11CE);
    uint256 internal signerPk = 0xA1B2C3D4;
    address internal signerAddr;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xB0B);

    /// @dev OPNet testnet network id (matches bridge CLAUDE.md domain separation).
    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;

    function setUp() public {
        string memory rpc = vm.envOr("SEPOLIA_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            rpc = vm.envOr("FORK_RPC_URL", string(""));
        }
        if (bytes(rpc).length == 0) {
            return; // tests below will no-op out.
        }
        vm.createSelectFork(rpc);

        // Default to Sepolia tokens; allow override via env for mainnet forks.
        forkUsdc = vm.envOr("FORK_USDC", SEPOLIA_USDC);
        forkUsdt = vm.envOr("FORK_USDT", SEPOLIA_USDT);

        signerAddr = vm.addr(signerPk);

        BridgeEscrow impl = new BridgeEscrow();
        address[] memory tokens = new address[](2);
        tokens[0] = forkUsdc;
        tokens[1] = forkUsdt;
        bytes memory init = abi.encodeCall(
            BridgeEscrow.initialize,
            (owner, signerAddr, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = BridgeEscrow(address(new ERC1967Proxy(address(impl), init)));

        // Seed balances via the `deal` cheat — handles most token storage layouts.
        deal(forkUsdc, alice, 10_000e6);
        deal(forkUsdt, alice, 10_000e6);
    }

    function _skipIfNoRpc() internal view returns (bool) {
        return address(escrow) == address(0);
    }

    function _hashIntent(BridgeEscrow.ReleaseIntent memory intent) internal pure returns (bytes32) {
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

    function _sign(uint256 pk, BridgeEscrow.ReleaseIntent memory intent) internal view returns (bytes memory) {
        bytes32 structHash = _hashIntent(intent);
        bytes32 d = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function test_Fork_Lock_USDC() public {
        if (_skipIfNoRpc()) return;
        vm.startPrank(alice);
        IERC20(forkUsdc).approve(address(escrow), type(uint256).max);
        (uint256 nonce_, uint256 received_) = escrow.lock(forkUsdc, 100e6, keccak256("r"));
        vm.stopPrank();
        assertEq(nonce_, 1);
        assertEq(received_, 100e6);
        assertEq(IERC20(forkUsdc).balanceOf(address(escrow)), 100e6);
    }

    /// @dev USDT fork test is skipped by default because `deal()` storage-layout
    ///      handling diverges for many USDT deployments on testnets (Aave-style
    ///      forks in particular). The real USDT semantics (no-return transferFrom)
    ///      are covered end-to-end in the unit tests against MockUSDT.
    ///      Set RUN_FORK_USDT=1 to force it when FORK_USDT points at a deal-friendly token.
    function test_Fork_Lock_USDT() public {
        if (_skipIfNoRpc()) return;
        if (vm.envOr("RUN_FORK_USDT", uint256(0)) == 0) return;
        vm.startPrank(alice);
        IERC20(forkUsdt).approve(address(escrow), type(uint256).max);
        (uint256 nonce_, uint256 received_) = escrow.lock(forkUsdt, 100e6, keccak256("r"));
        vm.stopPrank();
        assertEq(nonce_, 1);
        assertEq(received_, 100e6);
        assertEq(IERC20(forkUsdt).balanceOf(address(escrow)), 100e6);
    }

    function test_Fork_Claim_USDC_RoundTrip() public {
        if (_skipIfNoRpc()) return;
        vm.startPrank(alice);
        IERC20(forkUsdc).approve(address(escrow), type(uint256).max);
        escrow.lock(forkUsdc, 1_000e6, keccak256("rc"));
        vm.stopPrank();

        BridgeEscrow.ReleaseIntent memory intent = BridgeEscrow.ReleaseIntent({
            token: forkUsdc,
            to: bob,
            amount: 500e6,
            srcChainId: EXPECTED_OPNET_CHAIN_ID,
            opnetTxHash: keccak256("fork-tx"),
            opnetEventIndex: 0,
            burnNonce: 1,
            signerEpoch: escrow.currentEpoch(),
            opnetNonce: keccak256("fork-n"),
            grossSrcAmount: 500e6,
            relayerTip: 0
        });
        bytes memory sig = _sign(signerPk, intent);
        escrow.claim(intent, sig);
        assertEq(IERC20(forkUsdc).balanceOf(bob), 500e6);
    }
}
