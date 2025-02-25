// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../src/Identity.sol";
import "../src/IdentityFactory.sol";
import "../src/ImplementationAuthority.sol";

contract DeployScript is Script {
    function run() external {
        // Use Anvil's default private key
        uint256 deployerPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        
        vm.startBroadcast(deployerPrivateKey);

        // Deploy implementation in library mode
        Identity implementation = new Identity();
        
        // Deploy authority with implementation
        ImplementationAuthority authority = new ImplementationAuthority(address(implementation));
        
        // Deploy factory with authority
        IdentityFactory factory = new IdentityFactory(address(authority));
        
        vm.stopBroadcast();

        // Log addresses for verification
        console.log("Implementation:", address(implementation));
        console.log("Authority:", address(authority));
        console.log("Factory:", address(factory));
    }
}