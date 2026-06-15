// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockERC20} from "../mocks/MockERC20.sol";
import {IShareVault} from "../interfaces/IShareVault.sol";

/// @title VulnerableLendingMarket - a faithful model of the Resupply
///        (26 June 2025, ~$9.56M, Ethereum) exploit.
///
/// @dev   Resupply's `ResupplyPairCore._updateExchangeRate` computed:
///
///            _exchangeRate = 1e36 / IOracle(oracle).getPrices(collateral);
///
///        where `getPrices` is a `convertToAssets(1e18)`-style ERC-4626 share
///        price. Two defects:
///
///        (P6) DONATABLE PRICE > NUMERATOR FLOORS THE RATE TO ZERO.
///             the collateral is a donatable ERC-4626 vault. The attacker
///             donated 2,000 crvUSD and minted 1 wei of shares, pushing the
///             share price above 1e36, so `1e36 / price` truncated to 0.
///
///        (P7) NO `require(exchangeRate > 0)`.
///             nothing rejected a zero rate. With `exchangeRate == 0`, the LTV
///             term `debt * rate` is 0, so the solvency check passes for ANY
///             borrow - the attacker minted 10M reUSD against ~1 wei of
///             collateral.
///
///        This is the same root cause as VulnerableVault, one layer up: a
///        donatable share price feeding a truncating division whose rounding
///        silently disables a security check.
contract VulnerableLendingMarket {
    uint256 public constant PRECISION = 1e18;
    uint256 public constant RATE_PRECISION = 1e36; // Resupply's 1e36 numerator
    uint256 public constant LTV_BPS = 9500; // 95%

    MockERC20 public immutable debtAsset; // reUSD-style reserve we lend out
    IShareVault public immutable collateralVault; // external, donatable ERC-4626

    mapping(address => uint256) public collateralShares;
    mapping(address => uint256) public debt; // recorded debt, in debt-asset units

    event Borrow(address indexed who, uint256 amount, uint256 exchangeRate);

    constructor(MockERC20 _debtAsset, IShareVault _collateralVault) {
        debtAsset = _debtAsset;
        collateralVault = _collateralVault;
    }

    /// @dev assets per 1e18 collateral shares - read live from the donatable vault.
    function price() public view returns (uint256) {
        return collateralVault.convertToAssets(PRECISION);
    }

    /// @dev (P6)(P7) inverse rate, truncating division, no `> 0` guard.
    function exchangeRate() public view returns (uint256) {
        return RATE_PRECISION / price();
    }

    /// @dev Simplification of Fraxlend's full LTV expression: collateral is the
    ///      raw share count, NOT run through the price. This is load-neutral for
    ///      the bug being modelled - the exploit is the rate-to-zero collapse on
    ///      the DEBT term, not the collateral term - and at the honest price of
    ///      1e18 the share count equals the collateral's value anyway.
    function collateralValue(address who) public view returns (uint256) {
        return collateralShares[who];
    }

    /// @dev debt valued through the (manipulable) rate - collapses to 0 when rate is 0.
    function debtValue(address who) public view returns (uint256) {
        return (debt[who] * exchangeRate()) / PRECISION;
    }

    function depositCollateral(uint256 shares) external {
        require(collateralVault.transferFrom(msg.sender, address(this), shares), "xfer");
        collateralShares[msg.sender] += shares;
    }

    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
        // LTV check: debt value must stay within LTV of collateral value.
        // When exchangeRate() == 0, debtValue == 0, so this passes unconditionally.
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
