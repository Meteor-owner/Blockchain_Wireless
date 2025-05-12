// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseStructures.sol";
import "./UserManagement.sol";

/**
 * @title Network Management Contract
 * @notice Handles creation and access permission management of wireless networks
 */
contract NetworkManagement is BaseStructures {
    // =================================
    // Storage Mappings
    // =================================

    mapping(bytes32 => Network) internal networks;           // Network ID => Network
    mapping(address => bytes32[]) internal ownerNetworks;    // Owner => Network IDs
    mapping(bytes32 => mapping(bytes32 => bool)) internal deviceNetworkAccess; // DID => Network ID => Has access

    // User management contract instance
    UserManagement internal userManager;

    // System default network
    bytes32 public defaultNetworkId;
    string public defaultNetworkName = "Default WiFi Network";

    // =================================
    // Event Definitions
    // =================================

    event NetworkCreated(bytes32 indexed networkId, address indexed owner, string name);
    event AccessGranted(bytes32 indexed did, bytes32 indexed networkId);
    event AccessRevoked(bytes32 indexed did, bytes32 indexed networkId);

    // =================================
    // Modifiers
    // =================================

    /**
     * @dev Only allow network owner to call
     */
    modifier onlyNetworkOwner(bytes32 networkId) {
        require(networks[networkId].owner == msg.sender, "Only network owner can perform this action");
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
     * @dev Constructor, sets the user management contract address and creates default network
     */
    constructor(address _userManagerAddress) {
        userManager = UserManagement(_userManagerAddress);

        // Create default network
        defaultNetworkId = keccak256(abi.encodePacked("default-network", block.timestamp));
        networks[defaultNetworkId] = Network({
            owner: msg.sender,
            networkId: defaultNetworkId,
            name: defaultNetworkName,
            createdAt: block.timestamp,
            isActive: true
        });

        ownerNetworks[msg.sender].push(defaultNetworkId);
        emit NetworkCreated(defaultNetworkId, msg.sender, defaultNetworkName);
    }

    // =================================
    // Network Management Functions
    // =================================

    /**
     * @dev Create new wireless network
     * @param networkId Network identifier
     * @param name Network name
     * @return success Whether successful
     * @return message Return message
     */
    function createNetwork(address sender, bytes32 networkId, string calldata name)
        external onlyActiveUser (sender) returns (bool success, string memory message) {
        if (networks[networkId].owner != address(0)) {
            return (false, "Network already exists");
        }

        networks[networkId] = Network({
            owner: sender,
            networkId: networkId,
            name: name,
            createdAt: block.timestamp,
            isActive: true
        });

        ownerNetworks[sender].push(networkId);

        emit NetworkCreated(networkId, sender, name);

        return (true, "Network created successfully");
    }

    /**
     * @dev Grant device access to network
     * @param did Device's decentralized identifier
     * @param networkId Network identifier
     * @return success Whether successful
     * @return message Return message
     */
    function grantAccess(bytes32 did, bytes32 networkId, address sender)
        external returns (bool success, string memory message) {
        // Verify permission: only network owner can grant access
        bool isAuthorized = networks[networkId].owner == sender;

        if (!isAuthorized) {
            return (false, "Not authorized to grant access");
        }

        if (!networks[networkId].isActive) {
            return (false, "Network is not active");
        }

        deviceNetworkAccess[did][networkId] = true;

        emit AccessGranted(did, networkId);

        return (true, "Access granted successfully");
    }

    /**
     * @dev Batch grant devices access to network
     * @param dids Device DID array
     * @param networkId Network identifier
     * @return successCount Number of successfully authorized devices
     */
    function batchGrantAccess(bytes32[] calldata dids, bytes32 networkId, address sender)
        external returns (uint256 successCount) {
        // Verify permission
        bool isAuthorized = networks[networkId].owner == sender;

        require(isAuthorized, "Not authorized to grant access");
        require(networks[networkId].isActive, "Network is not active");

        successCount = 0;

        for (uint i = 0; i < dids.length; i++) {
            deviceNetworkAccess[dids[i]][networkId] = true;
            emit AccessGranted(dids[i], networkId);
            successCount++;
        }

        return successCount;
    }

    /**
     * @dev Revoke device access to network
     * @param did Device's decentralized identifier
     * @param networkId Network identifier
     * @return success Whether successful
     * @return message Return message
     */
    function revokeAccess(bytes32 did, bytes32 networkId)
        external returns (bool success, string memory message) {
        // Verify permission
        bool isAuthorized = networks[networkId].owner == msg.sender;

        if (!isAuthorized) {
            return (false, "Not authorized to revoke access");
        }

        deviceNetworkAccess[did][networkId] = false;

        emit AccessRevoked(did, networkId);

        return (true, "Access revoked successfully");
    }

    /**
     * @dev Check if device has access to network
     * @param did Device's decentralized identifier
     * @param networkId Network identifier
     * @return hasAccess Whether device has access
     */
    function checkAccess(bytes32 did, bytes32 networkId)
        external view returns (bool hasAccess) {
        return deviceNetworkAccess[did][networkId];
    }

    /**
     * @dev Get user's network list
     * @param owner Network owner
     * @return networks Network ID list
     */
    function getOwnerNetworks(address owner) external view returns (bytes32[] memory) {
        return ownerNetworks[owner];
    }
}