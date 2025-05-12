// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseStructures.sol";
import "./CryptoUtils.sol";
import "./UserManagement.sol";

/**
 * @title Device Management Contract
 * @notice Handles device registration, updates, deactivation, and other functions
 */
contract DeviceManagement is BaseStructures, CryptoUtils {
    // =================================
    // Storage Mappings
    // =================================

    mapping(bytes32 => Device) internal devices;             // DID => Device
    mapping(address => bytes32[]) internal ownerDevices;     // Owner => DIDs
    mapping(bytes32 => mapping(bytes32 => bool)) internal deviceNetworkAccess; // DID => Network ID => Has access
    mapping(bytes32 => bool) internal usedChallenges;        // Used challenges => Is used
    mapping(bytes32 => uint256) internal challengeTimestamps; // Challenge => Creation timestamp

    // User management contract instance
    UserManagement internal userManager;

    // =================================
    // Event Definitions
    // =================================

    event DeviceRegistered(bytes32 indexed did, address indexed owner, bytes32 deviceType, string name, address authorizedBy);
    event DeviceAssignedToUser(bytes32 indexed did, address indexed userAddress);
    event DeviceDeactivated(bytes32 indexed did);
    event RegistrationChallenge(bytes32 indexed did, bytes32 challenge, uint256 expiresAt);
    event RegistrationVerified(bytes32 indexed did);
    event DeviceTransferred(bytes32 indexed did, address indexed fromUser, address indexed toUser);

    // =================================
    // Modifiers
    // =================================

    /**
     * @dev Only allow device owner to call
     */
    modifier onlyDeviceOwner(bytes32 did) {
        require(devices[did].owner == msg.sender, "Only device owner can perform this action");
        _;
    }

    /**
     * @dev Only allow registered and active users to call
     */
    modifier onlyActiveUser(address sender) {
        require(userManager.isRegisteredUser(sender), "Requires registered user");
        _;
    }

    // =================================
    // Constructor
    // =================================

    /**
     * @dev Constructor, sets the user management contract address
     */
    constructor(address _userManagerAddress) {
        userManager = UserManagement(_userManagerAddress);
    }// =================================
    // Device Management Functions
    // =================================

    /**
     * @dev Register new device and assign to user
     * @param deviceType Device type
     * @param did Device's decentralized identifier
     * @param publicKey Device's public key
     * @param name Device name
     * @param metadata Device metadata hash
     */
    function registerDevice(
        bytes32 deviceType,
        bytes32 did,
        bytes calldata publicKey,
        string calldata name,
        bytes32 metadata,
        address sender
    ) external onlyActiveUser (sender) returns (bool success, string memory message) {
        if (devices[did].owner != address(0)) {
            return (false, "Device already registered");
        }

        if (publicKey.length == 0) {
            return (false, "Invalid public key");
        }

        address authorizer;

        // Simplified handling, assumes users can register devices themselves
        authorizer = msg.sender;

        bool deviceRegistry = _registerDeviceInternal(
            deviceType,
            did,
            publicKey,
            name,
            metadata,
            authorizer
        );

        if (!deviceRegistry) {
            return (false, "Device registration failed");
        }

        // Add device to user's device list (this function needs to be implemented in the user management contract)
        // Implementation method may need to be adjusted, or notification via events

        return (true, "Registration successful");
    }

    /**
     * @dev Internal function: Generate generic challenge value
     * @param context Challenge context (like "auth", "registration", "keyUpdate", etc.)
     * @param data1 Context-related data1 (like device DID)
     * @param data2 Context-related data2 (like network ID)
     * @return Generated challenge value
     */
    function _generateChallenge(
        string memory context,
        bytes32 data1,
        bytes32 data2
    ) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(
            context,
            data1,
            data2,
            block.timestamp,
            blockhash(block.number - 1),
            msg.sender
        ));
    }

    /**
     * @dev Internal device registration implementation
     */
    function _registerDeviceInternal(
        bytes32 deviceType,
        bytes32 did,
        bytes calldata publicKey,
        string calldata name,
        bytes32 metadata,
        address authorizedBy
    ) internal returns (bool){
        // Register device
        devices[did] = Device({
            owner: msg.sender,
            deviceType: deviceType,
            did: did,
            publicKey: publicKey,
            registeredAt: block.timestamp,
            isActive: true,
            name: name,
            metadata: metadata,
            authorizedBy: authorizedBy,
            userAddress: msg.sender
        });

        // Update index
        ownerDevices[msg.sender].push(did);

        // Generate registration challenge for the newly registered device to verify it actually possesses the private key
        bytes32 challenge = _generateChallenge("registration", did, bytes32(0));
        challengeTimestamps[challenge] = block.timestamp;

        // Trigger events
        emit DeviceRegistered(did, msg.sender, deviceType, name, authorizedBy);
        emit RegistrationChallenge(did, challenge, block.timestamp + AUTH_CHALLENGE_EXPIRY);

        return true;
    }

    /**
     * @dev Transfer device ownership
     * @param did Device ID
     * @param newOwner New owner address
     */
    function transferDevice(bytes32 did, address newOwner)
    external onlyDeviceOwner(did) returns (bool success, string memory message) {
        // Verify new owner is an active user
        require(userManager.isRegisteredUser(newOwner), "New owner must be registered user");

        // Save original owner information for events
        address originalOwner = devices[did].owner;
//        address originalUserAddress = devices[did].userAddress;

        // Remove from original owner's device list
        _removeDeviceFromOwner(did, originalOwner);

        // Update device owner
        devices[did].owner = newOwner;
        devices[did].userAddress = newOwner;

        // Add device to new owner's device list
        ownerDevices[newOwner].push(did);

        // Trigger event
        emit DeviceTransferred(did, originalOwner, newOwner);

        return (true, "Device transferred successfully");
    }

    /**
     * @dev Remove device from owner's list
     * @param did Device ID
     * @param owner Owner address
     */
    function _removeDeviceFromOwner(bytes32 did, address owner) internal {
        bytes32[] storage devicesList = ownerDevices[owner];
        for (uint i = 0; i < devicesList.length; i++) {
            if (devicesList[i] == did) {
                // Delete by moving the last element to the current position and popping the last element
                devicesList[i] = devicesList[devicesList.length - 1];
                devicesList.pop();
                break;
            }
        }
    }

    /**
     * @dev Get device information
     * @param did Device's decentralized identifier
     * @return deviceType Device type
     * @return owner Device owner
     * @return publicKey Device public key
     * @return registeredAt Registration time
     * @return isActive Whether device is active
     * @return name Device name
     * @return metadata Device metadata
     * @return authorizedBy User who authorized registration
     * @return userAddress User address the device belongs to
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
        Device storage device = devices[did];
        require(device.owner != address(0), "Device not found");

        return (
            device.deviceType,
            device.owner,
            device.publicKey,
            device.registeredAt,
            device.isActive,
            device.name,
            device.metadata,
            device.authorizedBy,
            device.userAddress
        );
    }

    /**
     * @dev Deactivate device
     * @param did Device's decentralized identifier
     */
    function deactivateDevice(bytes32 did) external returns (bool success, string memory message) {
        require(
            devices[did].owner == msg.sender ||
            devices[did].userAddress == msg.sender,
            "Not authorized to deactivate device"
        );
        require(devices[did].isActive, "Device already inactive");

        devices[did].isActive = false;

        emit DeviceDeactivated(did);

        return (true, "Device deactivated successfully");
    }

    /**
     * @dev Update device information
     * @param did Device's decentralized identifier
     * @param name New device name
     * @param metadata New metadata hash
     */
    function updateDeviceInfo(bytes32 did, string calldata name, bytes32 metadata)
    external returns (bool success, string memory message) {
        // Allow device owner or device's user to update device information
        require(
            devices[did].owner == msg.sender ||
            devices[did].userAddress == msg.sender,
            "Not authorized to update device info"
        );
        require(devices[did].isActive, "Device is not active");

        devices[did].name = name;
        devices[did].metadata = metadata;

        return (true, "Device info updated successfully");
    }

    /**
     * @dev Get list of devices owned by user
     * @param owner Device owner
     * @return devices List of device DIDs
     */
    function getOwnerDevices(address owner) external view returns (bytes32[] memory) {
        return ownerDevices[owner];
    }
}