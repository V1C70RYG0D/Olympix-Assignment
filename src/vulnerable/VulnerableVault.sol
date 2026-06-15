// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockERC20} from "../mocks/MockERC20.sol";

/// @title VulnerableVault - an ERC-4626-style share vault with the exact bug
///        class behind the zkLend (Feb 2025) and Resupply (Jun 2025) exploits,
///        and the long lineage of "first-depositor / donation" share-inflation
///        attacks.
///
/// @dev   THREE properties combine to make it exploitable. InflationGuard flags
///        each one. Remove any single property and the attack dies - which is
///        precisely what the mutation gate verifies.
///
///        (P1) PRICE READ FROM A DONATABLE BALANCE
///             `totalAssets()` returns `asset.balanceOf(address(this))`, so a
///             plain ERC-20 transfer ("donation") into the vault inflates the
///             price-per-share without minting any shares.
///
///        (P2) NO VIRTUAL SHARES / DECIMALS OFFSET
///             share math is the raw `assets * supply / totalAssets`. On a near
///             empty pool there is nothing to dampen the price, so it can be
///             pushed arbitrarily high.
///
///        (P3) ROUNDING TOWARD ZERO WITH NO `shares > 0` GUARD
///             integer floor division lets a real, non-zero deposit mint ZERO
///             shares. The depositor's assets are absorbed by existing holders.
///
///        This is the canonical share-inflation primitive. `convertToAssets`
///        exposes the same manipulable price to any external consumer (see
///        VulnerableLendingMarket), which is how the same root cause turns into
///        a multi-million-dollar under-collateralized borrow.
contract VulnerableVault {
    MockERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Deposit(address indexed caller, uint256 assets, uint256 shares);
    event Redeem(address indexed caller, uint256 shares, uint256 assets);
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(MockERC20 _asset) {
        asset = _asset;
    }

    /// @dev (P1) Price is read straight off the contract's token balance, so a
    ///      direct `asset.transfer(vault, x)` donation moves it.
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    /// @dev assets per `shares` - the "oracle" external protocols read.
    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return shares;
        // (P3) floor division.
        return (shares * totalAssets()) / supply;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return assets;
        // (P2) no virtual offset, (P3) floor division.
        return (assets * supply) / totalAssets();
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        // Preview against current state (pre-transfer), classic 4626 ordering.
        shares = convertToShares(assets);
        // (P3) NO `require(shares > 0)` - a non-zero deposit can mint 0 shares.
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer failed");
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
        emit Deposit(msg.sender, assets, shares);
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        require(asset.transfer(msg.sender, assets), "transfer failed");
        emit Redeem(msg.sender, shares, assets);
    }

    // --- minimal ERC-20 surface for the share token (needed as collateral) ---

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "insufficient allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "insufficient balance");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}
