// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {VestingVault} from "../src/VestingVault.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @notice Stand-alone ERC20 that under-delivers on transferFrom (1% skim)
///         to exercise the balance-delta check in `depositFor`. Kept
///         self-contained because the shared MockERC20 doesn't declare
///         transferFrom virtual.
contract MockSkimmingERC20 {
    string public constant NAME = "SKIM";
    string public constant SYMBOL = "SKIM";
    uint8 public constant DECIMALS = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "ERC20: balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    /// Sends only 99% of the requested value to the destination.
    function transferFrom(address from, address to, uint256 value)
        external
        returns (bool)
    {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= value, "ERC20: allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - value;
        }
        require(balanceOf[from] >= value, "ERC20: balance");
        uint256 skimmed = value / 100;
        uint256 net = value - skimmed;
        balanceOf[from] -= value;
        balanceOf[to] += net;
        emit Transfer(from, to, net);
        return true;
    }
}

contract VestingVaultTest is Test {
    VestingVault internal vault;
    MockERC20 internal token;

    address internal bridge = address(0xB81D9E);
    address internal alice  = address(0xA11CE);
    address internal bob    = address(0xB0B);
    address internal stranger = address(0xBADBAD);

    uint64 internal constant VESTING_BLOCKS = 50_400; // ~7 days @ 12s

    function setUp() public {
        token = new MockERC20("Moto", "MOTO", 18);
        vault = new VestingVault(IERC20(address(token)), bridge, VESTING_BLOCKS);

        // Fund + approve the bridge so it can push into the vault.
        token.mint(bridge, 1_000_000 ether);
        vm.prank(bridge);
        token.approve(address(vault), type(uint256).max);
    }

    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    function test_Constructor_StoresImmutables() public view {
        assertEq(address(vault.TOKEN()), address(token));
        assertEq(vault.BRIDGE(), bridge);
        assertEq(vault.VESTING_BLOCKS(), VESTING_BLOCKS);
    }

    function test_Constructor_RejectsZeroToken() public {
        vm.expectRevert(VestingVault.ZeroAddress.selector);
        new VestingVault(IERC20(address(0)), bridge, VESTING_BLOCKS);
    }

    function test_Constructor_RejectsZeroBridge() public {
        vm.expectRevert(VestingVault.ZeroAddress.selector);
        new VestingVault(IERC20(address(token)), address(0), VESTING_BLOCKS);
    }

    function test_Constructor_RejectsZeroVestingBlocks() public {
        vm.expectRevert(VestingVault.ZeroVestingDuration.selector);
        new VestingVault(IERC20(address(token)), bridge, 0);
    }

    // ------------------------------------------------------------------
    // depositFor — access control + input validation
    // ------------------------------------------------------------------

    function test_DepositFor_OnlyBridge() public {
        vm.prank(stranger);
        vm.expectRevert(VestingVault.NotBridge.selector);
        vault.depositFor(alice, 100 ether, bytes32(uint256(1)));
    }

    function test_DepositFor_RejectsZeroBeneficiary() public {
        vm.prank(bridge);
        vm.expectRevert(VestingVault.ZeroAddress.selector);
        vault.depositFor(address(0), 100 ether, bytes32(uint256(1)));
    }

    function test_DepositFor_RejectsZeroAmount() public {
        vm.prank(bridge);
        vm.expectRevert(VestingVault.ZeroAmount.selector);
        vault.depositFor(alice, 0, bytes32(uint256(1)));
    }

    function test_DepositFor_RejectsAmountAboveUint128() public {
        vm.prank(bridge);
        vm.expectRevert(VestingVault.AmountOverflow.selector);
        vault.depositFor(alice, uint256(type(uint128).max) + 1, bytes32(uint256(1)));
    }

    function test_DepositFor_RejectsDuplicateScheduleKey() public {
        bytes32 key = bytes32(uint256(1));
        vm.prank(bridge);
        vault.depositFor(alice, 100 ether, key);

        vm.prank(bridge);
        vm.expectRevert(VestingVault.ScheduleAlreadyExists.selector);
        vault.depositFor(alice, 50 ether, key);
    }

    function test_DepositFor_HappyPath_StoresScheduleAndEmits() public {
        bytes32 key = keccak256("voucher-1");
        uint256 amount = 100 ether;

        vm.expectEmit(true, true, false, true, address(vault));
        emit VestingVault.Deposited(
            alice,
            key,
            // forge-lint: disable-next-line(unsafe-typecast)
            uint128(amount),
            uint64(block.number),
            uint64(block.number) + VESTING_BLOCKS
        );

        vm.prank(bridge);
        vault.depositFor(alice, amount, key);

        VestingVault.Schedule memory s = vault.getSchedule(alice, key);
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(s.total, uint128(amount));
        assertEq(s.claimed, 0);
        assertEq(s.startBlock, uint64(block.number));
        assertEq(s.endBlock, uint64(block.number) + VESTING_BLOCKS);
        assertFalse(s.clawedBack);
        assertEq(token.balanceOf(address(vault)), amount);
    }

    function test_DepositFor_MultipleSchedulesPerBeneficiary() public {
        vm.prank(bridge);
        vault.depositFor(alice, 100 ether, bytes32(uint256(1)));
        vm.prank(bridge);
        vault.depositFor(alice, 200 ether, bytes32(uint256(2)));
        vm.prank(bridge);
        vault.depositFor(alice, 300 ether, bytes32(uint256(3)));

        assertEq(token.balanceOf(address(vault)), 600 ether);
        assertEq(vault.getSchedule(alice, bytes32(uint256(1))).total, 100 ether);
        assertEq(vault.getSchedule(alice, bytes32(uint256(2))).total, 200 ether);
        assertEq(vault.getSchedule(alice, bytes32(uint256(3))).total, 300 ether);
    }

    function test_DepositFor_BalanceDeltaCatchesShortfall() public {
        // Stand up a fresh vault using the skimming token (loses 1% on transfer).
        MockSkimmingERC20 skim = new MockSkimmingERC20();
        VestingVault skimVault = new VestingVault(
            IERC20(address(skim)),
            bridge,
            VESTING_BLOCKS
        );
        skim.mint(bridge, 1_000 ether);
        vm.prank(bridge);
        skim.approve(address(skimVault), type(uint256).max);

        vm.prank(bridge);
        vm.expectRevert(VestingVault.TokenTransferIncomplete.selector);
        skimVault.depositFor(alice, 100 ether, bytes32(uint256(1)));
    }

    // ------------------------------------------------------------------
    // claim — linear math
    // ------------------------------------------------------------------

    function test_Claim_RejectsUnknownSchedule() public {
        vm.prank(alice);
        vm.expectRevert(VestingVault.ScheduleNotFound.selector);
        vault.claim(bytes32(uint256(0xdead)));
    }

    function test_Claim_AtStart_NothingToClaim() public {
        _deposit(alice, 100 ether, bytes32(uint256(1)));

        vm.prank(alice);
        vm.expectRevert(VestingVault.NothingToClaim.selector);
        vault.claim(bytes32(uint256(1)));
    }

    function test_Claim_Halfway_HalfReleased() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);

        vm.roll(block.number + VESTING_BLOCKS / 2);

        uint128 preview = vault.previewClaimable(alice, key);
        // Half-vest math is exact when total*elapsed is divisible by duration.
        // 100e18 * 25_200 / 50_400 = 50e18 exactly.
        assertEq(preview, 50 ether);

        vm.prank(alice);
        uint128 claimed = vault.claim(key);
        assertEq(claimed, 50 ether);
        assertEq(token.balanceOf(alice), 50 ether);
        assertEq(vault.getSchedule(alice, key).claimed, 50 ether);
    }

    function test_Claim_AfterEnd_FullReleased() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);

        vm.roll(block.number + VESTING_BLOCKS + 1);

        vm.prank(alice);
        uint128 claimed = vault.claim(key);
        assertEq(claimed, 100 ether);
        assertEq(token.balanceOf(alice), 100 ether);
    }

    function test_Claim_IncrementalDrains() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);

        // First quarter
        vm.roll(block.number + VESTING_BLOCKS / 4);
        vm.prank(alice);
        uint128 c1 = vault.claim(key);
        assertEq(c1, 25 ether);

        // Second quarter
        vm.roll(block.number + VESTING_BLOCKS / 4);
        vm.prank(alice);
        uint128 c2 = vault.claim(key);
        assertEq(c2, 25 ether);

        // After end
        vm.roll(block.number + VESTING_BLOCKS);
        vm.prank(alice);
        uint128 c3 = vault.claim(key);
        assertEq(c3, 50 ether);

        assertEq(token.balanceOf(alice), 100 ether);
    }

    function test_Claim_NothingNewSinceLastClaim_Reverts() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);
        vm.roll(block.number + VESTING_BLOCKS / 2);

        vm.prank(alice);
        vault.claim(key);

        // Same block, no new vest.
        vm.prank(alice);
        vm.expectRevert(VestingVault.NothingToClaim.selector);
        vault.claim(key);
    }

    function test_Claim_OnlyOwnSchedule() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);
        vm.roll(block.number + VESTING_BLOCKS);

        // Bob has no schedule under the same key.
        vm.prank(bob);
        vm.expectRevert(VestingVault.ScheduleNotFound.selector);
        vault.claim(key);
    }

    // ------------------------------------------------------------------
    // clawback
    // ------------------------------------------------------------------

    function test_Clawback_OnlyBridge() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);

        vm.prank(stranger);
        vm.expectRevert(VestingVault.NotBridge.selector);
        vault.clawback(alice, key);
    }

    function test_Clawback_RejectsUnknown() public {
        vm.prank(bridge);
        vm.expectRevert(VestingVault.ScheduleNotFound.selector);
        vault.clawback(alice, bytes32(uint256(0xdead)));
    }

    function test_Clawback_AtStart_FullReturn() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);

        uint256 bridgeBefore = token.balanceOf(bridge);
        vm.prank(bridge);
        uint128 returned = vault.clawback(alice, key);

        assertEq(returned, 100 ether);
        assertEq(token.balanceOf(bridge), bridgeBefore + 100 ether);
        assertEq(token.balanceOf(alice), 0);

        VestingVault.Schedule memory s = vault.getSchedule(alice, key);
        assertEq(s.claimed, s.total, "schedule terminal");
        assertTrue(s.clawedBack, "clawback marker");
    }

    function test_Clawback_Midway_SplitsCorrectly() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);
        vm.roll(block.number + VESTING_BLOCKS / 2);

        uint256 bridgeBefore = token.balanceOf(bridge);
        uint256 aliceBefore = token.balanceOf(alice);

        vm.prank(bridge);
        uint128 returned = vault.clawback(alice, key);

        assertEq(returned, 50 ether, "unvested returns to bridge");
        assertEq(token.balanceOf(bridge), bridgeBefore + 50 ether);
        assertEq(token.balanceOf(alice), aliceBefore + 50 ether, "vested-unclaimed paid to beneficiary");
        assertEq(token.balanceOf(address(vault)), 0, "vault drained for this schedule");

        // Subsequent claim is a no-op (terminal).
        vm.prank(alice);
        vm.expectRevert(VestingVault.NothingToClaim.selector);
        vault.claim(key);
    }

    function test_Clawback_AfterPartialClaim_OnlyReturnsRemaining() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);

        // Alice claims half.
        vm.roll(block.number + VESTING_BLOCKS / 2);
        vm.prank(alice);
        vault.claim(key);

        // Move to 75% then clawback.
        vm.roll(block.number + VESTING_BLOCKS / 4);

        uint256 bridgeBefore = token.balanceOf(bridge);
        uint256 aliceBefore = token.balanceOf(alice);

        vm.prank(bridge);
        uint128 returned = vault.clawback(alice, key);

        assertEq(returned, 25 ether, "remaining 25% returns to bridge");
        assertEq(
            token.balanceOf(alice),
            aliceBefore + 25 ether,
            "extra 25% vested between claim and clawback paid out"
        );
        assertEq(token.balanceOf(bridge), bridgeBefore + 25 ether);
    }

    function test_Clawback_AfterFull_Reverts() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);
        vm.roll(block.number + VESTING_BLOCKS + 1);

        vm.prank(alice);
        vault.claim(key);

        vm.prank(bridge);
        vm.expectRevert(VestingVault.ScheduleNotFound.selector);
        vault.clawback(alice, key);
    }

    function test_Clawback_Idempotent_SecondAttempt_Reverts() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);

        vm.prank(bridge);
        vault.clawback(alice, key);

        vm.prank(bridge);
        vm.expectRevert(VestingVault.ScheduleNotFound.selector);
        vault.clawback(alice, key);
    }

    // ------------------------------------------------------------------
    // previewClaimable
    // ------------------------------------------------------------------

    function test_PreviewClaimable_TracksClaim() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);

        assertEq(vault.previewClaimable(alice, key), 0);

        vm.roll(block.number + VESTING_BLOCKS / 4);
        assertEq(vault.previewClaimable(alice, key), 25 ether);

        vm.prank(alice);
        vault.claim(key);
        assertEq(vault.previewClaimable(alice, key), 0);

        vm.roll(block.number + VESTING_BLOCKS / 4);
        assertEq(vault.previewClaimable(alice, key), 25 ether);
    }

    function test_PreviewClaimable_ZeroForUnknown() public view {
        assertEq(vault.previewClaimable(alice, bytes32(uint256(0xbeef))), 0);
    }

    function test_PreviewClaimable_AfterEnd_Caps() public {
        bytes32 key = bytes32(uint256(1));
        _deposit(alice, 100 ether, key);
        vm.roll(block.number + VESTING_BLOCKS * 100);
        assertEq(vault.previewClaimable(alice, key), 100 ether);
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    function _deposit(address beneficiary, uint256 amount, bytes32 key) internal {
        vm.prank(bridge);
        vault.depositFor(beneficiary, amount, key);
    }
}
