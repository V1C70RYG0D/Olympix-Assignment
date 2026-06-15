// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockERC20} from "../mocks/MockERC20.sol";
import {IShareVault} from "../interfaces/IShareVault.sol";

/// @title SafeLendingMarket - the hardened Resupply-shape pair.
///
///        FIX-6 (kills P7): `require(exchangeRate > 0)`.
///              the literal one line Resupply was missing. A collateral price
///              so extreme that `1e36 / price` truncates to 0 now reverts
///              instead of disabling the LTV check.
///
///        ROOT FIX (kills P6 at the source): pair this market with a vault
///              whose price cannot be inflated - SafeVault's internal accounting
///              (FIX-1) + virtual shares (FIX-2). If the collateral price can
///              never be donated upward, the rate can never be driven to 0 and
///              FIX-6 never even has to fire. This is the durable fix and it is
///              the SAME root fix as the vault: do not derive a security value
///              from a donatable balance.
///
///        We keep BOTH: defense in depth. `require(exchangeRate > 0)` stops the
///        exact on-chain replay; non-manipulable pricing stops the whole class.
contract SafeLendingMarket {
    uint256 public constant PRECISION = 1e18;
    uint256 public constant RATE_PRECISION = 1e36;
    uint256 public constant LTV_BPS = 9500;

    MockERC20 public immutable debtAsset;
    IShareVault public immutable collateralVault;

    mapping(address => uint256) public collateralShares;
    mapping(address => uint256) public debt;

    event Borrow(address indexed who, uint256 amount, uint256 exchangeRate);

    constructor(MockERC20 _debtAsset, IShareVault _collateralVault) {
        debtAsset = _debtAsset;
        collateralVault = _collateralVault;
    }

    function price() public view returns (uint256) {
        return collateralVault.convertToAssets(PRECISION);
    }

    function exchangeRate() public view returns (uint256) {
        uint256 rate = RATE_PRECISION / price();
        require(rate > 0, "zero exchange rate"); // FIX-6
        return rate;
    }

    function collateralValue(address who) public view returns (uint256) {
        return collateralShares[who];
    }

    function debtValue(address who) public view returns (uint256) {
        return (debt[who] * exchangeRate()) / PRECISION;
    }

    function depositCollateral(uint256 shares) external {
        require(collateralVault.transferFrom(msg.sender, address(this), shares), "xfer");
        collateralShares[msg.sender] += shares;
    }

    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
        require(debtValue(msg.sender) * 10_000 <= collateralValue(msg.sender) * LTV_BPS, "exceeds LTV");
        require(debtAsset.transfer(msg.sender, amount), "reserve xfer");
        emit Borrow(msg.sender, amount, exchangeRate());
    }

    function withdrawCollateral(uint256 shares) external {
        collateralShares[msg.sender] -= shares;
        require(debtValue(msg.sender) * 10_000 <= collateralValue(msg.sender) * LTV_BPS, "exceeds LTV");
        require(collateralVault.transfer(msg.sender, shares), "xfer");
    }
}
