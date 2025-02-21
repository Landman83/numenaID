// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract Identity is Initializable, OwnableUpgradeable {
    mapping(bytes32 => bytes32) private claims;
    
    function initialize(address owner) public initializer {
        __Ownable_init();
        _transferOwnership(owner);
    }
    
    function setClaim(bytes32 _key, bytes32 _value) external onlyOwner {
        claims[_key] = _value;
    }
    
    function getClaim(bytes32 _key) external view returns (bytes32) {
        return claims[_key];
    }
}