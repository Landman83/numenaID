// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./Identity.sol";

contract IdentityFactory is Ownable {
    // Implementation authority address
    address private immutable _implementationAuthority;
    
    // Identity tracking
    mapping(address => address) private _userIdentity;
    mapping(address => address[]) private _wallets;
    mapping(string => bool) private _saltTaken;
    
    // Token factory tracking
    mapping(address => bool) private _tokenFactories;
    
    // Events
    event IdentityCreated(address indexed wallet, address indexed identity, string salt);
    event WalletLinked(address indexed wallet, address indexed identity);
    event WalletUnlinked(address indexed wallet, address indexed identity);
    event TokenFactoryAdded(address indexed factory);
    event TokenFactoryRemoved(address indexed factory);
    
    constructor(address implementationAuthority) {
        require(implementationAuthority != address(0), "Invalid implementation authority");
        _implementationAuthority = implementationAuthority;
    }
    
    /**
     * @dev Creates a new identity with a deterministic address using CREATE2
     * @param _salt Unique identifier for the identity
     */
    function createIdentity(string calldata _salt) external returns (address) {
        require(!_saltTaken[_salt], "Salt already taken");
        require(_userIdentity[msg.sender] == address(0), "Wallet already has identity");
        
        // Create clone of implementation
        address identity = Clones.cloneDeterministic(
            IImplementationAuthority(_implementationAuthority).getImplementation(),
            keccak256(abi.encodePacked(_salt))
        );
        
        // Initialize the identity
        Identity(identity).initialize(msg.sender);
        
        // Update mappings
        _saltTaken[_salt] = true;
        _userIdentity[msg.sender] = identity;
        _wallets[identity].push(msg.sender);
        
        emit IdentityCreated(msg.sender, identity, _salt);
        emit WalletLinked(msg.sender, identity);
        
        return identity;
    }
    
    /**
     * @dev Links additional wallet to existing identity
     */
    function linkWallet(address _wallet) external {
        require(_wallet != address(0), "Invalid wallet address");
        require(_userIdentity[_wallet] == address(0), "Wallet already linked");
        require(_userIdentity[msg.sender] != address(0), "No identity for sender");
        
        address identity = _userIdentity[msg.sender];
        _userIdentity[_wallet] = identity;
        _wallets[identity].push(_wallet);
        
        emit WalletLinked(_wallet, identity);
    }
    
    /**
     * @dev Unlinks wallet from identity
     */
    function unlinkWallet(address _wallet) external {
        require(_wallet != msg.sender, "Cannot unlink self");
        require(_userIdentity[msg.sender] == _userIdentity[_wallet], "Not linked to same identity");
        
        address identity = _userIdentity[_wallet];
        delete _userIdentity[_wallet];
        
        // Remove wallet from _wallets array
        address[] storage wallets = _wallets[identity];
        for (uint256 i = 0; i < wallets.length; i++) {
            if (wallets[i] == _wallet) {
                wallets[i] = wallets[wallets.length - 1];
                wallets.pop();
                break;
            }
        }
        
        emit WalletUnlinked(_wallet, identity);
    }
    
    /**
     * @dev Adds a token factory
     */
    function addTokenFactory(address _factory) external onlyOwner {
        require(_factory != address(0), "Invalid factory address");
        require(!_tokenFactories[_factory], "Factory already added");
        
        _tokenFactories[_factory] = true;
        emit TokenFactoryAdded(_factory);
    }
    
    /**
     * @dev Removes a token factory
     */
    function removeTokenFactory(address _factory) external onlyOwner {
        require(_tokenFactories[_factory], "Factory not found");
        
        _tokenFactories[_factory] = false;
        emit TokenFactoryRemoved(_factory);
    }
    
    /**
     * @dev Returns the identity for a wallet
     */
    function getIdentity(address _wallet) external view returns (address) {
        return _userIdentity[_wallet];
    }
    
    /**
     * @dev Returns all wallets for an identity
     */
    function getWallets(address _identity) external view returns (address[] memory) {
        return _wallets[_identity];
    }
    
    /**
     * @dev Checks if a salt is already taken
     */
    function isSaltTaken(string calldata _salt) external view returns (bool) {
        return _saltTaken[_salt];
    }
    
    /**
     * @dev Returns the implementation authority address
     */
    function implementationAuthority() external view returns (address) {
        return _implementationAuthority;
    }
    
    /**
     * @dev Internal function to deploy contract using CREATE2
     */
    function _deploy(string memory salt, bytes memory bytecode) private returns (address) {
        bytes32 saltBytes = keccak256(abi.encodePacked(salt));
        address addr;
        
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), saltBytes)
            if iszero(extcodesize(addr)) {
                revert(0, 0)
            }
        }
        
        return addr;
    }
    
    /**
     * @dev Returns the initialization bytecode for the identity
     */
    function _getInitializationCode(
        address implementation,
        address initialOwner
    ) private pure returns (bytes memory) {
        return abi.encodePacked(
            type(Identity).creationCode,
            abi.encode(implementation, initialOwner)
        );
    }
}

interface IImplementationAuthority {
    function getImplementation() external view returns (address);
}