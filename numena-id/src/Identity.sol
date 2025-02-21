// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract Identity is Initializable, OwnableUpgradeable {
    // Key data structure
    struct Key {
        uint256[] purposes;  // Array of purposes (1 = Management, 3 = Claim Signer)
        uint256 keyType;     // Type of key (1 = ECDSA)
        bool exists;
    }

    // Storage for claims
    struct Claim {
        uint256 topic;      // Standardized topics from docs (e.g., 10101000100000 for INDIVIDUAL_INVESTOR)
        uint256 scheme;     // How data is encoded (e.g., 10101000666003 for STRING)
        address issuer;     // Who issued the claim
        bytes signature;    // Issuer's signature
        bytes data;        // The actual claim data
        string uri;        // Optional reference to off-chain data
        bool exists;
    }

    // Constants for key purposes
    uint256 private constant _MANAGEMENT_KEY = 1;
    uint256 private constant _ACTION_KEY = 2;
    uint256 private constant _CLAIM_SIGNER_KEY = 3;
    uint256 private constant _ENCRYPTION_KEY = 4;

    // Add these constants for standardized claim topics
    uint256 constant INDIVIDUAL_INVESTOR = 10101000100000;
    uint256 constant ACCREDITED_INVESTOR = 10101000100001;
    uint256 constant INSTITUTIONAL_INVESTOR = 10101000100002;
    
    // Claim schemes
    uint256 constant SCHEME_STRING = 10101000666003;
    uint256 constant SCHEME_URL = 10101000666004;
    uint256 constant SCHEME_HASH = 10101000666005;

    // Storage for keys
    mapping(bytes32 => Key) private _keys;
    mapping(uint256 => bytes32[]) private _keysByPurpose;
    
    mapping(bytes32 => Claim) private _claims;
    mapping(uint256 => bytes32[]) private _claimsByTopic;
    
    // Events (as per ERC734 & ERC735)
    event KeyAdded(bytes32 indexed key, uint256 indexed purpose, uint256 indexed keyType);
    event KeyRemoved(bytes32 indexed key, uint256 indexed purpose, uint256 indexed keyType);
    event ClaimAdded(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
    event ClaimRemoved(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
    
    function initialize(address owner) public initializer {
        __Ownable_init();
        _transferOwnership(owner);
        
        // Add owner as management key
        bytes32 ownerKey = keccak256(abi.encode(owner));
        _addKey(ownerKey, _MANAGEMENT_KEY, 1); // 1 is ECDSA key type
    }

    function _addKey(bytes32 _key, uint256 _purpose, uint256 _type) internal {
        if (!_keys[_key].exists) {
            _keys[_key].purposes = new uint256[](1);
            _keys[_key].purposes[0] = _purpose;
            _keys[_key].keyType = _type;
            _keys[_key].exists = true;
        } else {
            _keys[_key].purposes.push(_purpose);
        }
        
        _keysByPurpose[_purpose].push(_key);
        
        emit KeyAdded(_key, _purpose, _type);
    }

    function addKey(bytes32 _key, uint256 _purpose) external onlyOwner {
        require(
            _purpose == _MANAGEMENT_KEY || 
            _purpose == _ACTION_KEY || 
            _purpose == _CLAIM_SIGNER_KEY,
            "Invalid key purpose"
        );
        
        _addKey(_key, _purpose, 1); // 1 is ECDSA key type
    }
    
    function removeKey(bytes32 _key, uint256 _purpose) external onlyOwner {
        require(_purpose == _MANAGEMENT_KEY || _purpose == _ACTION_KEY, "Invalid key purpose");
        require(_keys[_key].exists, "Key does not exist");
        
        // Remove purpose from key's purposes array
        uint256[] storage purposes = _keys[_key].purposes;
        uint256 index = 0;
        for (uint256 i = 0; i < purposes.length; i++) {
            if (purposes[i] != _purpose) {
                if (index != i) {
                    purposes[index] = purposes[i];
                }
                index++;
            }
        }
        if (index != purposes.length) {
            purposes.pop();
        }
        
        // Remove key from _keysByPurpose
        bytes32[] storage purposeKeys = _keysByPurpose[_purpose];
        index = 0;
        for (uint256 i = 0; i < purposeKeys.length; i++) {
            if (purposeKeys[i] != _key) {
                if (index != i) {
                    purposeKeys[index] = purposeKeys[i];
                }
                index++;
            }
        }
        if (index != purposeKeys.length) {
            purposeKeys.pop();
        }
        
        emit KeyRemoved(_key, _purpose, _keys[_key].keyType);
    }
    
    // Modifier for claim signers
    modifier onlyClaimKey() {
        require(
            keyHasPurpose(keccak256(abi.encode(msg.sender)), 3),
            "Sender does not have claim signer key"
        );
        _;
    }

    function addClaim(
        uint256 _topic,
        uint256 _scheme,
        address _issuer,
        bytes calldata _signature,
        bytes calldata _data,
        string calldata _uri
    ) external onlyClaimKey returns (bytes32 claimId) {
        require(_issuer == msg.sender, "Issuer must be sender");
        
        claimId = keccak256(abi.encodePacked(_topic, _issuer));
        
        _claims[claimId] = Claim({
            topic: _topic,
            scheme: _scheme,
            issuer: _issuer,
            signature: _signature,
            data: _data,
            uri: _uri,
            exists: true
        });
        
        _claimsByTopic[_topic].push(claimId);
        
        emit ClaimAdded(claimId, _topic, _issuer);
    }
    
    function removeClaim(bytes32 _claimId) external {
        Claim storage claim = _claims[_claimId];
        require(claim.exists, "Claim does not exist");
        
        // Only the issuer or a management key can remove the claim
        bytes32 senderKey = keccak256(abi.encode(msg.sender));
        require(
            claim.issuer == msg.sender || keyHasPurpose(senderKey, _MANAGEMENT_KEY),
            "Only claim issuer or management key can remove claim"
        );

        uint256 topic = claim.topic;
        address issuer = claim.issuer;
        
        // Remove from claims mapping
        delete _claims[_claimId];
        
        // Remove from claimsByTopic array
        bytes32[] storage claims = _claimsByTopic[topic];
        uint256 index = 0;
        for (uint256 i = 0; i < claims.length; i++) {
            if (claims[i] != _claimId) {
                if (index != i) {
                    claims[index] = claims[i];
                }
                index++;
            }
        }
        if (index != claims.length) {
            claims.pop();
        }
        
        emit ClaimRemoved(_claimId, topic, issuer);
    }
    
    function keyHasPurpose(bytes32 _key, uint256 _purpose) public view returns (bool) {
        if (!_keys[_key].exists) return false;
        
        uint256[] storage purposes = _keys[_key].purposes;
        for (uint256 i = 0; i < purposes.length; i++) {
            if (purposes[i] == _purpose) {
                return true;
            }
        }
        return false;
    }
    
    function getClaim(bytes32 _claimId) external view returns (
        uint256 topic,
        uint256 scheme,
        address issuer,
        bytes memory signature,
        bytes memory data,
        string memory uri
    ) {
        Claim storage claim = _claims[_claimId];
        require(claim.issuer != address(0), "Claim does not exist");
        
        return (
            claim.topic,
            claim.scheme,
            claim.issuer,
            claim.signature,
            claim.data,
            claim.uri
        );
    }

    // Verify a specific claim
    function verifyClaim(
        bytes32 _claimId,
        uint256 _topic,
        uint256 _scheme,
        address _issuer,
        bytes memory _signature,
        bytes memory _data
    ) external view returns (bool) {
        Claim storage claim = _claims[_claimId];
        
        // Check claim exists
        if (!claim.exists) return false;
        
        // Verify claim matches stored data
        if (claim.topic != _topic) return false;
        if (claim.scheme != _scheme) return false;
        if (claim.issuer != _issuer) return false;
        
        // Verify issuer has claim signer key
        bytes32 issuerKey = keccak256(abi.encode(_issuer));
        if (!keyHasPurpose(issuerKey, _CLAIM_SIGNER_KEY)) return false;
        
        // Verify signature
        bytes32 dataHash = keccak256(abi.encode(_topic, _scheme, _issuer, _data));
        address recoveredSigner = recover(dataHash, _signature);
        if (recoveredSigner != _issuer) return false;
        
        return true;
    }
    
    // Helper function to recover signer from signature
    function recover(bytes32 _hash, bytes memory _signature) internal pure returns (address) {
        require(_signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }
        
        if (v < 27) {
            v += 27;
        }
        
        require(v == 27 || v == 28, "Invalid signature 'v' value");
        
        return ecrecover(_hash, v, r, s);
    }
    
    // Convenience function to check if an identity has a specific claim type
    function hasValidClaim(
        uint256 _topic,
        address _issuer
    ) external view returns (bool) {
        bytes32 claimId = keccak256(abi.encodePacked(_topic, _issuer));
        Claim storage claim = _claims[claimId];
        
        if (!claim.exists) return false;
        
        // Verify issuer still has claim signer key
        bytes32 issuerKey = keccak256(abi.encode(_issuer));
        return keyHasPurpose(issuerKey, _CLAIM_SIGNER_KEY);
    }
}

interface IERC735 {
    event ClaimRequested(uint256 indexed claimType, uint256 scheme, address indexed issuer, bytes signature, bytes data, string uri);
    event ClaimAdded(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
    event ClaimRemoved(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
    event ClaimChanged(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
}