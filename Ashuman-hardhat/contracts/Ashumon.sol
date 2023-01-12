// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract Ashumon is ERC20, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(BURNER_ROLE, msg.sender);
    }

    // override the decimal function
    function decimals() public view virtual override returns (uint8) {
        return 6;
    }

    /*
     * mint 'amount' tokens on address passed in 'to' as parameter
     * Requirements:
     * to address cannot be zero
     * amount should be greater than 0
     * only called by address which is granted as MINTER_ROLE
     */

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        require(to != address(0), "Cannot mint to zero address");
        require(amount > 0, "Invalid amount");
        _mint(to, amount);
    }

    /*
     * burn 'amount' tokens from address passed in 'account' as parameter
     * Requirements:
     * to address cannot be zero
     * amount should be greater than 0
     * only called by address which is granted as BURNER_ROLE
     */

    function burn(address account, uint256 amount)
        external
        onlyRole(BURNER_ROLE)
    {
        require(account != address(0), "Cannot be zero address");
        require(amount > 0, "Invalid amount");
        _burn(account, amount);
    }
}