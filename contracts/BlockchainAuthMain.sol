// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseStructures.sol";
import "./UserManagement.sol";
import "./DeviceManagement.sol";
import "./NetworkManagement.sol";
import "./AuthenticationManager.sol";

/**
 * @title Blockchain Wireless Network Identity Authentication System Main Contract
 * @notice Integrated main contract interface for user, device, network, and authentication management
 * @dev This contract serves as a unified entry point, referencing all functional module contracts
 */
contract BlockchainAuthMain is BaseStructures {
    // Child contract instances
    UserManagement public userManager;
    DeviceManagement public deviceManager;
    NetworkManagement public networkManager;
    AuthenticationManager public authManager;

    // System administrator address
    address public systemAdmin;

    // System configuration
    uint256 public deploymentTimestamp;
    string public version = "1.0.0";
    string public name = "Blockchain Auth System";

    event AuthChallengeGenerated(bytes32 indexed did, bytes32 indexed networkId, bytes32 challenge, uint256 expiresAt);
    event TokenIssued(bytes32 indexed did, bytes32 indexed tokenId, uint256 expiresAt);

    /**
     * @dev Constructor, deploys and initializes all child contracts
     */
    constructor() {
        // Record system administrator and deployment time
        systemAdmin = msg.sender;
        deploymentTimestamp = block.timestamp;

        // Deploy child contracts
        userManager = new UserManagement(systemAdmin);
        deviceManager = new DeviceManagement(address(userManager));
        networkManager = new NetworkManagement(address(userManager));
        authManager = new AuthenticationManager(
            address(deviceManager),
            address(networkManager)
        );
    }

    // =================================
    // User management delegated functions
    // =================================

    /**
     * @dev Register new user
     */
    function registerUser(
        string calldata name,
        string calldata email,
        bytes calldata publicKey,
        bytes calldata signature
    ) external returns (bool success, string memory message) {
        return userManager.registerUser(name, email, publicKey, signature, msg.sender);
    }

    /**
     * @dev Update user information
     */
    function updateUserInfo(
        string calldata name,
        string calldata email,
        bytes calldata publicKey
    ) external returns (bool success, string memory message) {
        return userManager.updateUserInfo(name, email, publicKey,msg.sender);
    }

    /**
     * @dev Get user information
     */
    function getUserInfo(address userAddress) external view returns (
        string memory name,
        string memory email,
        bytes memory publicKey,
        uint256 registeredAt,
        bool isActive,
        uint256 deviceCount,
        uint256 networkCount,
        UserRole role,
        address authorizedBy
    ) {
        return userManager.getUserInfo(userAddress);
    }

    /**
     * @dev A user checks if they are registered
     */
    function isRegisteredUser(address user) external view returns (bool) {
        return userManager.isRegisteredUser(user);
    }

    /**
     * @dev Get total number of users
     */
    function getUserCount() external view returns (uint256 count) {
        return userManager.getUserCount();
    }

    /**
     * @dev Get paginated user list
     */
    function getUserList(uint256 offset, uint256 limit) external view returns (
        address[] memory userAddresses,
        string[] memory names,
        bool[] memory isActives,
        UserRole[] memory roles
    ) {
        return userManager.getUserList(offset, limit);
    }

    function deactivateUser() external returns (bool success, string memory message) {
        return userManager.deactivateUser(msg.sender);
    }
    // =================================
    // Device management delegated functions
    // =================================

    /**
     * @dev Register new device
     */
    function registerDevice(
        bytes32 deviceType,
        bytes32 did,
        bytes calldata publicKey,
        string calldata name,
        bytes32 metadata
//        bytes calldata signature
    ) external returns (bool success, string memory message) {
        return deviceManager.registerDevice(deviceType, did, publicKey, name, metadata, msg.sender);
    }

    /**
     * @dev Get device information
     */
    function getDeviceInfo(bytes32 did) external view returns (
        bytes32 deviceType,
        address owner,
        bytes memory publicKey,
        uint256 registeredAt,
        bool isActive,
        string memory name,
        bytes32 metadata,
        address authorizedBy,
        address userAddress
    ) {
        return deviceManager.getDeviceInfo(did);
    }

    /**
     * @dev Update device information
     */
    function updateDeviceInfo(bytes32 did, string calldata name, bytes32 metadata)
    external returns (bool success, string memory message) {
        return deviceManager.updateDeviceInfo(did, name, metadata);
    }

    /**
     * @dev Deactivate device
     */
    function deactivateDevice(bytes32 did) external returns (bool success, string memory message) {
        return deviceManager.deactivateDevice(did);
    }

    /**
     * @dev Get list of devices owned by user
     */
    function getOwnerDevices(address owner) external view returns (bytes32[] memory) {
        return deviceManager.getOwnerDevices(owner);
    }

    /**
     * @dev Transfer device ownership
     */
    function transferDevice(bytes32 did, address newOwner)
    external returns (bool success, string memory message) {
        return deviceManager.transferDevice(did, newOwner);
    }

    // =================================
    // Network management delegated functions
    // =================================

    /**
     * @dev Create new wireless network
     */
    function createNetwork(bytes32 networkId, string calldata _name)
    external returns (bool success, string memory message) {
        return networkManager.createNetwork(msg.sender, networkId, _name);
    }

    /**
     * @dev Grant device access to network
     */
    function grantAccess(bytes32 did, bytes32 networkId)
    external returns (bool success, string memory message) {
        return networkManager.grantAccess(did, networkId, msg.sender);
    }

    /**
     * @dev Batch grant multiple devices access to network
     */
    function batchGrantAccess(bytes32[] calldata dids, bytes32 networkId)
    external returns (uint256 successCount) {
        return networkManager.batchGrantAccess(dids, networkId,msg.sender);
    }

    /**
     * @dev Revoke device access to network
     */
    function revokeAccess(bytes32 did, bytes32 networkId)
    external returns (bool success, string memory message) {
        return networkManager.revokeAccess(did, networkId);
    }

    /**
     * @dev Check if device has access to network
     */
    function checkAccess(bytes32 did, bytes32 networkId)
    external view returns (bool hasAccess) {
        return networkManager.checkAccess(did, networkId);
    }

    /**
     * @dev Get list of networks owned by user
     */
    function getOwnerNetworks(address owner) external view returns (bytes32[] memory) {
        return networkManager.getOwnerNetworks(owner);
    }

    // =================================
    // Authentication delegated functions
    // =================================

    /**
     * @dev Generate authentication challenge
     */
    function generateAuthChallenge(bytes32 did, bytes32 networkId)
    external returns (bytes32 challenge, uint256 expiresAt) {
        (bytes32 _challenge, uint256 _expiresAt) = authManager.generateAuthChallenge(did, networkId);

//        emit AuthChallengeGenerated(did, networkId, _challenge, _expiresAt);

        return (_challenge, _expiresAt);
    }

    /**
     * @dev Get device's latest authentication challenge
     */
    function getLatestChallenge(bytes32 did) external view returns (bytes32 challenge, uint256 timestamp) {
        return authManager.getLatestChallenge(did);
    }

    /**
     * @dev Authenticate device and issue access token
     */
    function authenticate(bytes32 did, bytes32 networkId, bytes32 challenge, bytes calldata signature)
    external returns (bytes32 tokenId) {
        bytes32 tokenId=authManager.authenticate(did, networkId, challenge, signature);
        uint256 expiresAt = block.timestamp + 1 days;
        emit TokenIssued(did, tokenId, expiresAt);
        return tokenId;
    }

    /**
     * @dev Validate if access token is valid
     */
    function validateToken(bytes32 tokenId) external view returns (bool valid) {
        return authManager.validateToken(tokenId);
    }

    /**
     * @dev Revoke access token
     */
    function revokeToken(bytes32 tokenId) external returns (bool success, string memory message) {
        return authManager.revokeToken(tokenId);
    }

    /**
     * @dev Get number of authentication logs for device
     */
    function getAuthLogCount(bytes32 did) external view returns (uint256 count) {
        return authManager.getAuthLogCount(did);
    }

    /**
     * @dev Get specific authentication log for device
     */
    function getAuthLog(bytes32 did, uint256 index) external view returns (
        address verifier,
        bytes32 challengeHash,
        uint256 timestamp,
        bool success
    ) {
        return authManager.getAuthLog(did, index);
    }

    /**
     * @dev Get paginated authentication logs for device
     */
    function getAuthLogs(bytes32 did, uint256 offset, uint256 limit)
    external view returns (
        address[] memory verifiers,
        uint256[] memory timestamps,
        bool[] memory successes
    ) {
        return authManager.getAuthLogs(did, offset, limit);
    }
}