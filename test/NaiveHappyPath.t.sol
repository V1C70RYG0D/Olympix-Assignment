// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {IShareVault} from "../src/interfaces/IShareVault.sol";
import {SafeVault} from "../src/safe/SafeVault.sol";
import {VulnerableVault} from "../src/vulnerable/VulnerableVault.sol";
import {SafeLendingMarket} from "../src/safe/SafeLendingMarket.sol";

/// @notice The "100% coverage" trap. These are the kind of unit tests a team
///         ships: they exercise every public function on the happy path and
///         give green coverage. They PASS on the correct contract - and, as the
///         mutation gate shows, they keep passing after the inflation bug is
///         re-introduced. Coverage lies; only an adversarial / invariant test
///         (or mutation testing) reveals the protection is untested.
contract NaiveVaultHappyPath is Test {
    MockERC20 internal token;
    SafeVault internal vault;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        token = new MockERC20("Curve USD", "crvUSD", 18);
        vault = new SafeVault(token);
    }

    function test_depositAndRedeem() public {
        uint256 aliceAmt = 100e18;
        uint256 bobAmt = 50e18;

        token.mint(alice, aliceAmt);
        token.mint(bob, bobAmt);

        vm.startPrank(alice);
        token.approve(address(vault), type(uint256).max);
        uint256 aliceShares = vault.deposit(aliceAmt);
        vm.stopPrank();
        assertGt(aliceShares, 0, "alice gets shares");

        vm.startPrank(bob);
        token.approve(address(vault), type(uint256).max);
        uint256 bobShares = vault.deposit(bobAmt);
        vm.stopPrank();
        assertGt(bobShares, 0, "bob gets shares");

        // Read-only surface (coverage for convert* + totalAssets).
        assertGt(vault.convertToAssets(aliceShares), 0);
        assertGt(vault.convertToShares(1e18), 0);
        assertEq(vault.totalAssets(), aliceAmt + bobAmt);

        // Everyone redeems and gets ~their money back.
        vm.prank(alice);
        uint256 aliceOut = vault.redeem(aliceShares);
        vm.prank(bob);
        uint256 bobOut = vault.redeem(bobShares);

        assertApproxEqAbs(aliceOut, aliceAmt, 1e12, "alice ~whole");
        assertApproxEqAbs(bobOut, bobAmt, 1e12, "bob ~whole");
    }
}

contract NaiveMarketHappyPath is Test {
    MockERC20 internal crvUSD;
    MockERC20 internal reUSD;
    VulnerableVault internal oracle; // used honestly here - no donation
    SafeLendingMarket internal market;
    address internal user = makeAddr("user");

    function setUp() public {
        crvUSD = new MockERC20("Curve USD", "crvUSD", 18);
        reUSD = new MockERC20("Resupply USD", "reUSD", 18);
        oracle = new VulnerableVault(crvUSD);
        market = new SafeLendingMarket(reUSD, IShareVault(address(oracle)));
        reUSD.mint(address(market), 1_000_000e18);
    }

    function test_borrowHappyPath() public {
        uint256 collat = 1_000e18;
        crvUSD.mint(user, collat);

        vm.startPrank(user);
        crvUSD.approve(address(oracle), type(uint256).max);
        uint256 shares = oracle.deposit(collat); // 1:1, no manipulation
        oracle.approve(address(market), type(uint256).max);
        market.depositCollateral(shares);

        uint256 borrowAmt = 500e18; // well within 95% LTV
        market.borrow(borrowAmt);
        vm.stopPrank();

        assertEq(reUSD.balanceOf(user), borrowAmt, "user received the loan");
        assertGt(market.debt(user), 0, "debt recorded");
    }
}
