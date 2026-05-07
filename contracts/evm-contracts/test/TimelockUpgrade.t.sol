// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {BridgeEscrow} from "../src/BridgeEscrow.sol";
import {BridgeEscrowV2} from "./mocks/BridgeEscrowV2.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {TestableBridgeEscrow} from "./mocks/TestableBridgeEscrow.sol";

interface IUUPS {
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
}

interface IOwnable {
    function owner() external view returns (address);
    function transferOwnership(address newOwner) external;
}

/// @notice Deferred-Work item #8 — verifies the SHAPE of the timelock-gated
///         upgrade flow. The actual mainnet ceremony is done from a Safe by
///         a human operator; these tests guarantee the on-chain machinery
///         (timelock + UUPS owner transfer + delay enforcement) wires up
///         correctly so a misconfigured ceremony cannot succeed silently.
contract TimelockUpgradeTest is Test {
    uint256 internal constant MIN_DELAY = 7 days;
    uint256 internal constant EXPECTED_OPNET_CHAIN_ID = 2;

    BridgeEscrow internal impl;
    BridgeEscrow internal escrow;
    TimelockController internal timelock;

    MockERC20 internal usdc;
    MockUSDT internal usdt;

    address internal deployer = address(0xDEAD11E5);
    address internal proposer = address(0x5AFE); // stand-in for the governance Safe
    address internal initialSigner = address(0x516E);
    address internal randomEoa = address(0xBADBAD);

    bytes32 internal constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 internal constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 internal constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");
    bytes32 internal constant DEFAULT_ADMIN_ROLE = 0x00;

    function setUp() public {
        // 1. Deploy supporting tokens
        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdt = new MockUSDT();

        // 2. Deploy escrow (proxy + impl) under the deployer EOA
        vm.startPrank(deployer);
        impl = BridgeEscrow(address(new TestableBridgeEscrow()));

        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(usdt);

        bytes memory initData = abi.encodeCall(
            BridgeEscrow.initialize,
            (deployer, initialSigner, EXPECTED_OPNET_CHAIN_ID, tokens)
        );
        escrow = BridgeEscrow(address(new ERC1967Proxy(address(impl), initData)));

        // Make the deployer the guardian (set-once) so we can exercise the
        // emergencyWithdraw path post-transfer in the relevant test.
        escrow.setGuardian(deployer);
        vm.stopPrank();

        // 3. Deploy a real OZ TimelockController with min-delay = 7 days
        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = address(0); // open-execute (matches deploy script)

        timelock = new TimelockController(
            MIN_DELAY,
            proposers,
            executors,
            address(0) // burn admin role at construction
        );

        // 4. Transfer escrow ownership: deployer EOA -> timelock
        vm.prank(deployer);
        IOwnable(address(escrow)).transferOwnership(address(timelock));
        assertEq(IOwnable(address(escrow)).owner(), address(timelock), "owner != timelock");
    }

    // ---------------------------------------------------------------------
    // Build an upgrade payload — used by multiple tests
    // ---------------------------------------------------------------------

    function _buildUpgradeCall() internal returns (address newImpl, bytes memory call) {
        newImpl = address(new BridgeEscrowV2());
        call = abi.encodeWithSelector(
            IUUPS.upgradeToAndCall.selector,
            newImpl,
            bytes("")
        );
    }

    // ---------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------

    /// @dev `execute` before the 7-day delay elapses must revert. We schedule
    ///      from the proposer, then try to execute one second early.
    function test_UpgradeBeforeDelay_Reverts() public {
        (, bytes memory call) = _buildUpgradeCall();
        bytes32 salt = keccak256("upgrade-1");

        vm.prank(proposer);
        timelock.schedule(address(escrow), 0, call, bytes32(0), salt, MIN_DELAY);

        // Warp to delay - 1 — still locked.
        vm.warp(block.timestamp + MIN_DELAY - 1);

        // OZ TimelockController reverts with TimelockUnexpectedOperationState
        // if you call execute on an operation that is not yet "Ready".
        vm.expectRevert();
        timelock.execute(address(escrow), 0, call, bytes32(0), salt);
    }

    /// @dev After the 7-day delay, anyone (executor=address(0) -> open) can
    ///      execute, and the escrow's ERC-1967 implementation slot must point
    ///      at the new impl with the V2 marker visible.
    function test_UpgradeAfterDelay_Succeeds() public {
        (address newImpl, bytes memory call) = _buildUpgradeCall();
        bytes32 salt = keccak256("upgrade-2");

        vm.prank(proposer);
        timelock.schedule(address(escrow), 0, call, bytes32(0), salt, MIN_DELAY);

        vm.warp(block.timestamp + MIN_DELAY + 1);

        // Anyone executes — open-execute pattern.
        vm.prank(randomEoa);
        timelock.execute(address(escrow), 0, call, bytes32(0), salt);

        // ERC-1967 implementation slot points at newImpl.
        bytes32 implSlot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        bytes32 stored = vm.load(address(escrow), implSlot);
        assertEq(address(uint160(uint256(stored))), newImpl, "impl slot not updated");

        // Functional sanity: V2 has a `version()` returning "v2".
        BridgeEscrowV2 asV2 = BridgeEscrowV2(address(escrow));
        assertEq(asV2.version(), "v2", "v2 not wired");
    }

    /// @dev A non-proposer EOA cannot schedule. OZ AccessControl reverts with
    ///      AccessControlUnauthorizedAccount(account, role).
    function test_NonProposer_CannotSchedule() public {
        (, bytes memory call) = _buildUpgradeCall();
        bytes32 salt = keccak256("upgrade-3");

        vm.prank(randomEoa);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                randomEoa,
                PROPOSER_ROLE
            )
        );
        timelock.schedule(address(escrow), 0, call, bytes32(0), salt, MIN_DELAY);
    }

    /// @dev After the ownership transfer, the deployer EOA is no longer owner
    ///      and cannot bypass the timelock by calling upgradeToAndCall directly.
    ///      OZ Ownable reverts with OwnableUnauthorizedAccount(deployer).
    function test_DeployerCannotUpgradeDirectly() public {
        (address newImpl, ) = _buildUpgradeCall();

        vm.prank(deployer);
        vm.expectRevert(); // OwnableUnauthorizedAccount(deployer)
        IUUPS(address(escrow)).upgradeToAndCall(newImpl, bytes(""));
    }

    /// @dev Even with the timelock owning the escrow, `emergencyWithdraw`
    ///      remains a guardian-gated path — it does NOT route through the
    ///      owner role at all. Confirm it still works under the new ownership.
    function test_TimelockCannotBeBypassed_emergencyWithdraw() public {
        // Fund the escrow with some USDC so emergencyWithdraw has something to drain.
        usdc.mint(address(escrow), 1_000e6);

        // Set treasury (owner = timelock — schedule the call through it).
        bytes memory setTreasuryCall =
            abi.encodeWithSignature("setTreasury(address)", address(0xCAFE));
        bytes32 salt1 = keccak256("set-treasury");
        vm.prank(proposer);
        timelock.schedule(address(escrow), 0, setTreasuryCall, bytes32(0), salt1, MIN_DELAY);
        vm.warp(block.timestamp + MIN_DELAY + 1);
        vm.prank(randomEoa);
        timelock.execute(address(escrow), 0, setTreasuryCall, bytes32(0), salt1);

        // Pause via timelock (whenPaused gate on emergencyWithdraw).
        bytes memory pauseCall = abi.encodeWithSignature("pause()");
        bytes32 salt2 = keccak256("pause-call");
        vm.prank(proposer);
        timelock.schedule(address(escrow), 0, pauseCall, bytes32(0), salt2, MIN_DELAY);
        vm.warp(block.timestamp + MIN_DELAY + 1);
        vm.prank(randomEoa);
        timelock.execute(address(escrow), 0, pauseCall, bytes32(0), salt2);

        // Guardian (deployer in setUp) calls emergencyWithdraw directly — no
        // timelock involved — and the funds reach treasury. This proves the
        // guardian path is independent of `owner` and remains a working
        // fast-exit even when ownership is delay-gated.
        uint256 before = usdc.balanceOf(address(0xCAFE));
        vm.prank(deployer);
        escrow.emergencyWithdraw(address(usdc), 1_000e6);
        assertEq(usdc.balanceOf(address(0xCAFE)) - before, 1_000e6, "drain to treasury");
    }
}
