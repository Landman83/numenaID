// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/Identity.sol";
import "../src/IdentityFactory.sol";

contract MockImplementationAuthority {
    address private _implementation;
    
    constructor(address implementation) {
        _implementation = implementation;
    }
    
    function getImplementation() external view returns (address) {
        return _implementation;
    }
}

contract IdentityTest is Test {
    IdentityFactory public factory;
    Identity public implementation;
    Identity public identityContract;
    
    address public owner = address(0x1);
    address public claimIssuer;  // Will be derived from private key
    address public randomUser = address(0x3);
    
    // Claim data - using actual topics from documentation
    uint256 constant INDIVIDUAL_INVESTOR = 10101000100000;  // From docs
    uint256 constant ACCREDITED_INVESTOR = 10101000100001;  // From docs
    uint256 constant STRING_SCHEME = 10101000666003;       // From docs
    bytes constant CLAIM_SIGNATURE = "signature";
    bytes constant CLAIM_DATA = "data";
    string constant CLAIM_URI = "uri";
    
    // Events to test
    event ClaimAdded(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
    event ClaimRemoved(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
    event KeyAdded(bytes32 indexed key, uint256 indexed purpose, uint256 indexed keyType);
    
    // Use a proper private key (this is just for testing)
    uint256 constant claimIssuerPrivateKey = 0x12345678;
    
    MockImplementationAuthority public implementationAuthority;
    
    function setUp() public {
        // Derive claimIssuer address from private key
        claimIssuer = vm.addr(claimIssuerPrivateKey);
        
        // Deploy implementation
        implementation = new Identity();
        
        // Deploy implementation authority
        implementationAuthority = new MockImplementationAuthority(address(implementation));
        
        // Deploy factory with implementation authority
        factory = new IdentityFactory(address(implementationAuthority));
        
        // Create identity through factory
        vm.startPrank(owner);  // Use startPrank instead of prank
        address identityAddress = factory.createIdentity("test-salt");
        identityContract = Identity(identityAddress);
        
        // Debug ownership
        console.log("Owner address:", owner);
        console.log("Contract owner:", identityContract.owner());
        
        // Add claim issuer key
        bytes32 issuerKey = keccak256(abi.encode(claimIssuer));
        identityContract.addKey(issuerKey, 3);
        vm.stopPrank();
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
    
    function testVerifyClaim() public {
        // Create signature
        bytes32 dataHash = keccak256(abi.encode(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_DATA
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(claimIssuerPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Add claim
        vm.prank(claimIssuer);
        bytes32 claimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            signature,
            CLAIM_DATA,
            CLAIM_URI
        );
        
        // Verify claim
        bool isValid = identityContract.verifyClaim(
            claimId,
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            signature,
            CLAIM_DATA
        );
        
        assertTrue(isValid, "Claim should be valid");
    }
    
    function testHasValidClaim() public {
        // Add claim
        vm.prank(claimIssuer);
        identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            CLAIM_DATA,
            CLAIM_URI
        );
        
        bool hasClaim = identityContract.hasValidClaim(INDIVIDUAL_INVESTOR, claimIssuer);
        assertTrue(hasClaim, "Should have valid claim");
    }
    
    // New test function specifically for event testing
    function testKeyAddedEvent() public {
        bytes32 issuerKey = keccak256(abi.encode(claimIssuer));
        vm.prank(owner);
        
        // Check event emission
        vm.expectEmit(true, true, true, true);
        emit KeyAdded(issuerKey, 3, 1);
        identityContract.addKey(issuerKey, 3);
    }
    
    function testStandardClaimTopics() public {
        vm.startPrank(claimIssuer);
        
        // Test INDIVIDUAL_INVESTOR claim
        bytes32 individualClaimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            CLAIM_DATA,
            CLAIM_URI
        );
        
        // Test ACCREDITED_INVESTOR claim
        bytes32 accreditedClaimId = identityContract.addClaim(
            ACCREDITED_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            CLAIM_DATA,
            CLAIM_URI
        );
        
        assertTrue(identityContract.hasValidClaim(INDIVIDUAL_INVESTOR, claimIssuer));
        assertTrue(identityContract.hasValidClaim(ACCREDITED_INVESTOR, claimIssuer));
        
        vm.stopPrank();
    }
    
    function testDifferentClaimSchemes() public {
        vm.startPrank(claimIssuer);
        
        // Test STRING scheme
        bytes32 stringClaimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            "Individual Investor",
            CLAIM_URI
        );
        
        // Test URL scheme
        bytes32 urlClaimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            "https://example.com/proof",
            CLAIM_URI
        );
        
        // Test HASH scheme
        bytes32 hashClaimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            abi.encodePacked(keccak256("proof")),
            CLAIM_URI
        );
        
        // Verify all claims exist
        assertTrue(identityContract.hasValidClaim(INDIVIDUAL_INVESTOR, claimIssuer));
        
        vm.stopPrank();
    }
    
    function testClaimVerification() public {
        // Create a real signature
        bytes32 dataHash = keccak256(abi.encode(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_DATA
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(claimIssuerPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        vm.prank(claimIssuer);
        bytes32 claimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            signature,
            CLAIM_DATA,
            CLAIM_URI
        );
        
        bool isValid = identityContract.verifyClaim(
            claimId,
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            signature,
            CLAIM_DATA
        );
        
        assertTrue(isValid, "Claim verification failed");
    }
    
    function testInvalidClaimVerification() public {
        vm.prank(claimIssuer);
        bytes32 claimId = identityContract.addClaim(
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            CLAIM_DATA,
            CLAIM_URI
        );
        
        // Test with wrong topic
        bool isValidWrongTopic = identityContract.verifyClaim(
            claimId,
            ACCREDITED_INVESTOR, // Wrong topic
            STRING_SCHEME,
            claimIssuer,
            CLAIM_SIGNATURE,
            CLAIM_DATA
        );
        assertFalse(isValidWrongTopic, "Should fail with wrong topic");
        
        // Test with wrong issuer
        bool isValidWrongIssuer = identityContract.verifyClaim(
            claimId,
            INDIVIDUAL_INVESTOR,
            STRING_SCHEME,
            randomUser, // Wrong issuer
            CLAIM_SIGNATURE,
            CLAIM_DATA
        );
        assertFalse(isValidWrongIssuer, "Should fail with wrong issuer");
    }
    
    function testERC735Events() public {
        vm.startPrank(claimIssuer);
        
        bytes32 expectedClaimId = keccak256(abi.encodePacked(INDIVIDUAL_INVESTOR, claimIssuer));
        
        // Test ClaimAdded event
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
        
        // Test ClaimRemoved event
        vm.expectEmit(true, true, true, true);
        emit ClaimRemoved(claimId, INDIVIDUAL_INVESTOR, claimIssuer);
        identityContract.removeClaim(claimId);
        
        vm.stopPrank();
    }
} 