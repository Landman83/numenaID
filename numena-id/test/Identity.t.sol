// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/Identity.sol";
import "../src/IdentityFactory.sol";

contract IdentityTest is Test {
    IdentityFactory public factory;
    Identity public implementation;
    Identity public identityContract;
    
    address public owner = address(0x1);
    address public claimIssuer = address(0x2);
    address public randomUser = address(0x3);
    
    // Claim data - using actual topics from documentation
    uint256 constant INDIVIDUAL_INVESTOR = 10101000100000;  // From docs
    uint256 constant STRING_SCHEME = 10101000666003;       // From docs
    bytes constant CLAIM_SIGNATURE = "signature";
    bytes constant CLAIM_DATA = "data";
    string constant CLAIM_URI = "uri";
    
    // Events to test
    event ClaimAdded(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
    event ClaimRemoved(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
    event KeyAdded(bytes32 indexed key, uint256 indexed purpose, uint256 indexed keyType);
    
    function setUp() public {
        // Deploy implementation and factory
        implementation = new Identity();
        factory = new IdentityFactory(address(implementation));
        
        // Create identity for owner
        vm.prank(owner);
        address identityAddress = factory.createIdentity();
        identityContract = Identity(identityAddress);
        
        // Add claim issuer key
        bytes32 issuerKey = keccak256(abi.encode(claimIssuer));
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit KeyAdded(issuerKey, 3, 1);
        identityContract.addKey(issuerKey, 3); // 3 = CLAIM_SIGNER_KEY
    }
    
    function testClaimSignerKeyManagement() public {
        bytes32 issuerKey = keccak256(abi.encode(claimIssuer));
        assertTrue(identityContract.keyHasPurpose(issuerKey, 3), "Claim signer key should exist");
        
        bytes32 randomKey = keccak256(abi.encode(randomUser));
        assertFalse(identityContract.keyHasPurpose(randomKey, 3), "Random user should not have claim key");
    }
    
    function testClaimAddition() public {
        vm.prank(claimIssuer);
        
        bytes32 expectedClaimId = keccak256(abi.encodePacked(INDIVIDUAL_INVESTOR, claimIssuer));
        
        vm.expectEmit(true, true, true, true);
        emit ClaimAdded(expectedClaimId, INDIVIDUAL_INVESTOR, claimIssuer);
        
        bytes32 claimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            CLAIM_DATA,
            CLAIM_URI
        );
        
        (
            uint256 topic,
            uint256 scheme,
            address issuer,
            bytes memory signature,
            bytes memory data,
            string memory uri
        ) = identityContract.getClaim(claimId);
        
        assertEq(topic, INDIVIDUAL_INVESTOR, "Wrong topic");
        assertEq(scheme, STRING_SCHEME, "Wrong scheme");
        assertEq(issuer, claimIssuer, "Wrong issuer");
        assertEq(signature, CLAIM_SIGNATURE, "Wrong signature");
        assertEq(data, CLAIM_DATA, "Wrong data");
        assertEq(uri, CLAIM_URI, "Wrong URI");
    }
    
    function testOnlyIssuerCanAddClaim() public {
        vm.prank(claimIssuer);
        vm.expectRevert("Issuer must be sender");
        identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            randomUser, // Different from msg.sender
            CLAIM_SIGNATURE,
            CLAIM_DATA,
            CLAIM_URI
        );
    }
    
    function testClaimRemoval() public {
        // First add a claim
        vm.prank(claimIssuer);
        bytes32 claimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            CLAIM_DATA,
            CLAIM_URI
        );
        
        // Test removal by issuer
        vm.prank(claimIssuer);
        vm.expectEmit(true, true, true, true);
        emit ClaimRemoved(claimId, INDIVIDUAL_INVESTOR, claimIssuer);
        identityContract.removeClaim(claimId);
        
        // Verify claim was removed
        vm.expectRevert("Claim does not exist");
        identityContract.getClaim(claimId);
    }
    
    function testManagementKeyCanRemoveClaim() public {
        // Add claim
        vm.prank(claimIssuer);
        bytes32 claimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            CLAIM_DATA,
            CLAIM_URI
        );
        
        // Remove using management key (owner)
        vm.prank(owner);
        identityContract.removeClaim(claimId);
        
        // Verify removal
        vm.expectRevert("Claim does not exist");
        identityContract.getClaim(claimId);
    }
    
    function testRandomUserCannotRemoveClaim() public {
        // Add claim
        vm.prank(claimIssuer);
        bytes32 claimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            CLAIM_DATA,
            CLAIM_URI
        );
        
        // Try to remove with random user
        vm.prank(randomUser);
        vm.expectRevert("Only claim issuer or management key can remove claim");
        identityContract.removeClaim(claimId);
    }
} 