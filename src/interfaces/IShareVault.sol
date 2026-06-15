// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice The minimal share-vault surface an external protocol (e.g. a lending
///         market pricing collateral) reads. This is the trust boundary that
///         the zkLend / Resupply / ERC-4626 bug class lives on: a price derived
///         from `convertToAssets` that an attacker can move with a token donation.
interface IShareVault {
    function asset() external view returns (address);
    function totalSupply() external view returns (uint256);
    function totalAssets() external view returns (uint256);

    /// @dev assets returned for a given number of shares - the manipulable "price".
    function convertToAssets(uint256 shares) external view returns (uint256);
    function convertToShares(uint256 assets) external view returns (uint256);

    function deposit(uint256 assets) external returns (uint256 shares);
    function redeem(uint256 shares) external returns (uint256 assets);

    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}
