// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Script} from "forge-std/Script.sol";
import "../src/Identity.sol";
import "../src/IdentityFactory.sol";

contract DeployIdentity is Script {
    function run() external {
        vm.startBroadcast();

        // Deploy implementation
        Identity implementation = new Identity();
        
        // Deploy factory
        IdentityFactory factory = new IdentityFactory(address(implementation));

        vm.stopBroadcast();
    }
}
