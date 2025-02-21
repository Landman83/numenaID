// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/Identity.sol";
import "../src/IdentityFactory.sol";

contract IdentityTest is Test {
    IdentityFactory public factory;
    Identity public implementation;
    address public alice = address(0x1);

    function setUp() public {
        // Deploy implementation
        implementation = new Identity();
        
        // Deploy factory
        factory = new IdentityFactory(address(implementation));
    }

    function testCreateIdentity() public {
        // Create identity for alice
        vm.prank(alice);
        address identityAddress = factory.createIdentity();
        
        // Verify identity was created
        assertEq(factory.getIdentity(alice), identityAddress, "Identity not created correctly");
        
        // Verify alice is the owner
        Identity identity = Identity(identityAddress);
        assertEq(identity.owner(), alice, "Owner not set correctly");
        
        // Verify can't create second identity
        vm.prank(alice);
        vm.expectRevert("Identity already exists");
        factory.createIdentity();
    }
} 