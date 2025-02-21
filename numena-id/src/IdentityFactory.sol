// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./Identity.sol";  // Changed to relative path

contract IdentityFactory is Ownable {
    address public implementationContract;
    mapping(address => address) public userToIdentity;
    
    event IdentityCreated(address indexed user, address identity);

    constructor(address _implementation) {
        implementationContract = _implementation;
    }

    function createIdentity() external returns (address) {
        require(userToIdentity[msg.sender] == address(0), "Identity already exists");
        
        // Create new proxy
        address clone = Clones.clone(implementationContract);
        
        // Initialize the identity
        Identity(clone).initialize(msg.sender);
        
        // Store the mapping
        userToIdentity[msg.sender] = clone;
        
        emit IdentityCreated(msg.sender, clone);
        return clone;
    }

    function getIdentity(address user) external view returns (address) {
        return userToIdentity[user];
    }
}