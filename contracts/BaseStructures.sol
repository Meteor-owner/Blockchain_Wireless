// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Base Data Structures and Constants
 * @notice Contains all reusable data structure definitions
 */
contract BaseStructures {
    // =================================
    // Data Structure Definitions
    // =================================

    // User role types
    enum UserRole {
        NONE,           // Unregistered
        USER,           // Regular user
        NETWORK_ADMIN,  // Network administrator
        SYSTEM_ADMIN    // System administrator
    }

    // User information structure
    struct User {
        address userAddress;     // User address
        string name;             // Username
        string email;            // User email (optional)
        bytes publicKey;         // User's main public key
        uint256 registeredAt;    // Registration timestamp
        bool isActive;           // Whether user is active
        bytes32[] devices;       // List of DIDs owned by the user
        bytes32[] networks;      // List of network IDs created by the user
        UserRole role;           // User role
        address authorizedBy;    // Administrator who authorized the registration
    }

    // Device information structure
    struct Device {
        address owner;         // Device owner
        bytes32 deviceType;    // Device type (e.g., smartphone, laptop, iot)
        bytes32 did;           // Decentralized Identity Identifier
        bytes publicKey;       // Device public key
        uint256 registeredAt;  // Registration timestamp
        bool isActive;         // Whether device is active
        string name;           // Device name
        bytes32 metadata;      // Device metadata hash
        address authorizedBy;  // Address of user who authorized registration
        address userAddress;   // User address the device belongs to
    }

    // Authentication record structure
    struct AuthLog {
        bytes32 did;           // Device DID
        address verifier;      // Verifier address (AP)
        bytes32 challengeHash; // Challenge hash
        uint256 timestamp;     // Authentication timestamp
        bool success;          // Whether authentication was successful
    }

    // Access token structure
    struct AccessToken {
        bytes32 did;           // Associated device DID
        bytes32 tokenId;       // Token ID
        uint256 issuedAt;      // Issue time
        uint256 expiresAt;     // Expiration time
        bool isRevoked;        // Whether token has been revoked
    }

    // Network structure
    struct Network {
        address owner;         // Network owner
        bytes32 networkId;     // Network identifier
        string name;           // Network name
        uint256 createdAt;     // Creation time
        bool isActive;         // Whether network is active
    }

    // User login challenge structure
    struct LoginChallenge {
        address userAddress;    // User address
        bytes32 challengeValue; // Challenge value
        uint256 timestamp;      // Generation time
        uint256 expiresAt;      // Expiration time
    }

    // User registration request structure
    struct RegistrationRequest {
        string username;        // Requested username
        string email;           // Requested email
        bytes publicKey;        // Requested public key
        uint256 requestedAt;    // Request time
        bool isProcessed;       // Whether request has been processed
        address approvedBy;     // Administrator address who approved
    }

    // =================================
    // Constant Definitions
    // =================================

    // Challenge expiration times
    uint256 internal constant LOGIN_CHALLENGE_EXPIRY = 5 minutes;
    uint256 internal constant AUTH_CHALLENGE_EXPIRY = 15 minutes;
    uint256 internal constant REGISTRATION_REQUEST_EXPIRY = 7 days;
}