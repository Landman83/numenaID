// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/Identity.sol";
import "../src/IdentityFactory.sol";
import "../src/ImplementationAuthority.sol";

contract IdentityFactoryTest is Test {
    IdentityFactory public factory;
    Identity public implementation;
    ImplementationAuthority public authority;
    
    address public owner = address(0x1);
    address public user1 = address(0x2);
    address public user2 = address(0x3);
    address public tokenFactory = address(0x4);
    
    event IdentityCreated(address indexed wallet, address indexed identity, string salt);
    event WalletLinked(address indexed wallet, address indexed identity);
    event WalletUnlinked(address indexed wallet, address indexed identity);
    event TokenFactoryAdded(address indexed factory);
    event TokenFactoryRemoved(address indexed factory);
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy contracts
        implementation = new Identity();
        authority = new ImplementationAuthority(address(implementation));
        factory = new IdentityFactory(address(authority));
        
        vm.stopPrank();
    }
    
    function testCreateIdentity() public {
        string memory salt = "test-salt";
        
        vm.startPrank(user1);
        
        // Don't check the specific address in the event
        vm.expectEmit(true, false, true, true);
        emit IdentityCreated(user1, address(0), salt);
        
        address identityAddress = factory.createIdentity(salt);
        
        assertTrue(identityAddress != address(0), "Identity not created");
        assertEq(factory.getIdentity(user1), identityAddress, "Identity not linked to wallet");
        
        vm.stopPrank();
    }
    
    function testCannotReuseSalt() public {
        string memory salt = "test-salt";
        
        vm.prank(user1);
        factory.createIdentity(salt);
        
        vm.prank(user2);
        vm.expectRevert("Salt already taken");
        factory.createIdentity(salt);
    }
    
    function testCannotCreateMultipleIdentities() public {
        vm.startPrank(user1);
        
        factory.createIdentity("salt1");
        
        vm.expectRevert("Wallet already has identity");
        factory.createIdentity("salt2");
        
        vm.stopPrank();
    }
    
    function testLinkWallet() public {
        vm.prank(user1);
        address identity = factory.createIdentity("test-salt");
        
        vm.prank(user1);
        vm.expectEmit(true, true, true, true);
        emit WalletLinked(user2, identity);
        factory.linkWallet(user2);
        
        assertEq(factory.getIdentity(user2), identity, "Wallet not linked");
    }
    
    function testCannotLinkWalletToMultipleIdentities() public {
        // Create first identity and link wallet
        vm.prank(user1);
        factory.createIdentity("salt1");
        
        // Try to link already linked wallet
        vm.prank(user2);
        address identity2 = factory.createIdentity("salt2");
        
        vm.prank(user2);
        vm.expectRevert("Wallet already linked");
        factory.linkWallet(user1);
    }
    
    function testUnlinkWallet() public {
        // Create identity and link wallet
        vm.prank(user1);
        address identity = factory.createIdentity("test-salt");
        
        vm.prank(user1);
        factory.linkWallet(user2);
        
        // Unlink wallet
        vm.prank(user1);
        vm.expectEmit(true, true, true, true);
        emit WalletUnlinked(user2, identity);
        factory.unlinkWallet(user2);
        
        assertEq(factory.getIdentity(user2), address(0), "Wallet not unlinked");
    }
    
    function testCannotUnlinkSelf() public {
        vm.prank(user1);
        factory.createIdentity("test-salt");
        
        vm.prank(user1);
        vm.expectRevert("Cannot unlink self");
        factory.unlinkWallet(user1);
    }
    
    function testTokenFactoryManagement() public {
        vm.startPrank(owner);
        
        // Add token factory
        vm.expectEmit(true, true, true, true);
        emit TokenFactoryAdded(tokenFactory);
        factory.addTokenFactory(tokenFactory);
        
        // Remove token factory
        vm.expectEmit(true, true, true, true);
        emit TokenFactoryRemoved(tokenFactory);
        factory.removeTokenFactory(tokenFactory);
        
        vm.stopPrank();
    }
    
    function testOnlyOwnerCanManageTokenFactories() public {
        vm.prank(user1);
        vm.expectRevert("Ownable: caller is not the owner");
        factory.addTokenFactory(tokenFactory);
        
        vm.prank(user1);
        vm.expectRevert("Ownable: caller is not the owner");
        factory.removeTokenFactory(tokenFactory);
    }
    
    function testGetWallets() public {
        // Create identity and link wallets
        vm.prank(user1);
        address identity = factory.createIdentity("test-salt");
        
        vm.prank(user1);
        factory.linkWallet(user2);
        
        // Get wallets
        address[] memory wallets = factory.getWallets(identity);
        assertEq(wallets.length, 2, "Wrong number of wallets");
        assertEq(wallets[0], user1, "Wrong wallet address");
        assertEq(wallets[1], user2, "Wrong wallet address");
    }
    
    function testImplementationAuthority() public {
        assertEq(
            factory.implementationAuthority(),
            address(authority),
            "Wrong implementation authority"
        );
    }
}