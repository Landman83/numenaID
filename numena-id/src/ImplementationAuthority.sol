// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";

contract ImplementationAuthority is Ownable {
    address private _implementation;
    
    event ImplementationUpdated(address indexed newImplementation);
    
    constructor(address implementation) {
        require(implementation != address(0), "Invalid implementation");
        _implementation = implementation;
        emit ImplementationUpdated(implementation);
    }
    
    function updateImplementation(address newImplementation) external onlyOwner {
        require(newImplementation != address(0), "Invalid implementation");
        _implementation = newImplementation;
        emit ImplementationUpdated(newImplementation);
    }
    
    function getImplementation() external view returns (address) {
        return _implementation;
    }
}