// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockERC20} from "../mocks/MockERC20.sol";

/// @title SafeVault - the hardened vault. Every defect from VulnerableVault is
///        closed with a *named, independently-removable* defense, so the
///        mutation gate can prove each one is actually load-bearing.
///
///        FIX-1 (kills P1): INTERNAL ASSET ACCOUNTING.
///              `totalAssets()` returns the storage variable `_internalAssets`,
///              incremented only on deposit. A raw token donation no longer
///              moves the price. (This is the single most important fix.)
///
///        FIX-2 (kills P2): VIRTUAL SHARES / DECIMALS OFFSET (OZ-style).
///              share math carries `+ 10**OFFSET` virtual shares and `+ 1`
///              virtual asset, so an empty pool cannot be pushed to an extreme
///              price and rounding can never reach zero for a real deposit.
///
///        FIX-3 (kills P3): EXPLICIT `shares > 0` GUARD.
///              a non-zero deposit that would mint zero shares reverts instead
///              of silently donating the assets to existing holders.
contract SafeVault {
    uint256 private constant OFFSET = 3; // 10**3 = 1000 virtual shares (OZ decimals offset)

    MockERC20 public immutable asset;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // FIX-1: assets tracked internally, NOT via balanceOf.
    uint256 private _internalAssets;

    event Deposit(address indexed caller, uint256 assets, uint256 shares);
    event Redeem(address indexed caller, uint256 shares, uint256 assets);
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(MockERC20 _asset) {
        asset = _asset;
    }

    /// FIX-1: donation-resistant - reads internal accounting, not the balance.
    function totalAssets() public view returns (uint256) {
        return _internalAssets;
    }

    /// FIX-2: virtual shares/assets dampen the price on an empty pool.
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return (shares * (totalAssets() + 1)) / (totalSupply + 10 ** OFFSET);
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return (assets * (totalSupply + 10 ** OFFSET)) / (totalAssets() + 1);
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = convertToShares(assets);
        // FIX-3: a real deposit must mint real shares.
        require(shares > 0, "zero shares");
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer failed");
        _internalAssets += assets; // FIX-1
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
        emit Deposit(msg.sender, assets, shares);
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        _internalAssets -= assets; // FIX-1
        require(asset.transfer(msg.sender, assets), "transfer failed");
        emit Redeem(msg.sender, shares, assets);
    }

    // --- minimal ERC-20 surface for the share token ---

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
