// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseStructures.sol";
import "./CryptoUtils.sol";
import "./DeviceManagement.sol";
import "./NetworkManagement.sol";

/**
 * @title Authentication Manager Contract
 * @notice Handles device authentication, token management, and audit logs
 */
contract AuthenticationManager is BaseStructures, CryptoUtils {
    // =================================
    // Storage Mappings
    // =================================

    mapping(bytes32 => AccessToken) internal accessTokens;   // Token ID => Access token
    mapping(bytes32 => AuthLog[]) internal authLogs;         // DID => Authentication logs
    mapping(bytes32 => bool) internal usedChallenges;        // Used challenges => Is used
    mapping(bytes32 => uint256) internal challengeTimestamps; // Challenge => Creation timestamp
    mapping(bytes32 => bytes32) public latestChallenges; // DID => Latest challenge

    // Device management and network management contract instances
    DeviceManagement internal deviceManager;
    NetworkManagement internal networkManager;

    // =================================
    // Event Definitions
    // =================================

    event AuthenticationAttempt(bytes32 indexed did, bytes32 indexed networkId, bool success);
    event TokenIssued(bytes32 indexed did, bytes32 indexed tokenId, uint256 expiresAt);
    event TokenRevoked(bytes32 indexed tokenId);
    event AuthChallengeGenerated(bytes32 indexed did, bytes32 indexed networkId, bytes32 challenge, uint256 expiresAt);
    // =================================
    // Constructor
    // =================================

    /**
     * @dev Constructor, sets device management and network management contract addresses
     */
    constructor(address _deviceManagerAddress, address _networkManagerAddress) {
        deviceManager = DeviceManagement(_deviceManagerAddress);
        networkManager = NetworkManagement(_networkManagerAddress);
    }

    // =================================
    // Authentication Related Functions
    // =================================

    /**
     * @dev Generate authentication challenge
     * @param did Device's decentralized identifier
     * @param networkId Network identifier
     * @return challenge Generated challenge value
     * @return expiresAt Challenge expiration time
     */
    function generateAuthChallenge(bytes32 did, bytes32 networkId)
    external returns (bytes32 challenge, uint256 expiresAt) {
        // Generate random challenge
        challenge = keccak256(abi.encodePacked(
            did,
            networkId,
            block.timestamp,
            blockhash(block.number - 1)
        ));

        // Record challenge creation time and latest challenge
//        challengeTimestamps[challenge] = block.timestamp + AUTH_CHALLENGE_EXPIRY;
//        latestChallenges[did] = challenge;  // Store the latest challenge for this DID
//        expiresAt = block.timestamp + AUTH_CHALLENGE_EXPIRY;
        expiresAt = block.timestamp + AUTH_CHALLENGE_EXPIRY;
        challengeTimestamps[challenge] = expiresAt;
        latestChallenges[did] = challenge;

        // Trigger event
        emit AuthChallengeGenerated(did, networkId, challenge, expiresAt);

        return (challenge, expiresAt);
    }

    function getLatestChallenge(bytes32 did) external view returns (bytes32, uint256) {
        bytes32 challenge = latestChallenges[did];
        uint256 timestamp = challengeTimestamps[challenge];
        return (challenge, timestamp);
    }

    /**
     * @dev Verify device and issue access token
     * @param did Device's decentralized identifier
     * @param networkId Network identifier
     * @param challenge Challenge value
     * @param signature Challenge signature
     * @return tokenId Access token ID
     */
    function authenticate(bytes32 did, bytes32 networkId, bytes32 challenge, bytes calldata signature)
    external returns (bytes32 tokenId) {
        // Anti-replay attack check
        require(!usedChallenges[challenge], "Challenge already used");
        require(challengeTimestamps[challenge] > 0, "Unknown challenge");

        require(
            block.timestamp <= challengeTimestamps[challenge],
            "Challenge expired"
        );

        // Immediately mark challenge as used, regardless of authentication success
        usedChallenges[challenge] = true;

        // Check access permission
        bool hasAccess = networkManager.checkAccess(did, networkId);
        if (!hasAccess) {
            // Record failure and return immediately
            _recordAuthenticationAttempt(did, networkId, challenge, false);
            revert("No access rights");
        }

        // Verify signature
        (
            ,
            ,
            bytes memory publicKey,
            ,
            bool isActive,
            ,
            ,
            ,
        ) = deviceManager.getDeviceInfo(did);

        // Check if device is active
        if (!isActive) {
            _recordAuthenticationAttempt(did, networkId, challenge, false);
            revert("Device is inactive");
        }

        // Construct message hash to verify
        bytes32 messageHash = keccak256(abi.encodePacked(did, challenge));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        // Verify signature
        address recoveredAddress = recoverSigner(ethSignedMessageHash, signature);
        address deviceAddress = publicKeyToAddress(publicKey);

        bool validSignature = (recoveredAddress != address(0) && recoveredAddress == deviceAddress);

        if (!validSignature) {
            // Record failure and return immediately
            _recordAuthenticationAttempt(did, networkId, challenge, false);
            revert("Invalid signature");
        }

        // Authentication successful - record and issue token
        _recordAuthenticationAttempt(did, networkId, challenge, true);

        // Issue access token
        tokenId = _issueToken(did);

        return tokenId;
    }

    /**
     * @dev Record authentication attempt
     * @param did Device's decentralized identifier
     * @param networkId Network identifier
     * @param challenge Challenge value
     * @param success Whether successful
     */
    function _recordAuthenticationAttempt(
        bytes32 did,
        bytes32 networkId,
        bytes32 challenge,
        bool success
    ) internal {
        authLogs[did].push(AuthLog({
            did: did,
            verifier: msg.sender,
            challengeHash: challenge,
            timestamp: block.timestamp,
            success: success
        }));

        emit AuthenticationAttempt(did, networkId, success);
    }

    /**
     * @dev Issue token
     * @param did Device's decentralized identifier
     * @return tokenId Token ID
     */
    function _issueToken(bytes32 did) internal returns (bytes32) {
        bytes32 tokenId = keccak256(abi.encodePacked(did, block.timestamp, blockhash(block.number - 1)));
        uint256 expiresAt = block.timestamp + 1 days;

        accessTokens[tokenId] = AccessToken({
            did: did,
            tokenId: tokenId,
            issuedAt: block.timestamp,
            expiresAt: expiresAt,
            isRevoked: false
        });

        emit TokenIssued(did, tokenId, expiresAt);

        return tokenId;
    }

    /**
     * @dev Validate if access token is valid
     * @param tokenId Token ID
     * @return valid Whether token is valid
     */
    function validateToken(bytes32 tokenId) external view returns (bool valid) {
        AccessToken storage token = accessTokens[tokenId];

        return (token.tokenId == tokenId &&
            !token.isRevoked &&
            block.timestamp <= token.expiresAt);
    }

    /**
     * @dev Revoke access token
     * @param tokenId Token ID
     * @return success Whether successful
     * @return message Return message
     */
    function revokeToken(bytes32 tokenId) external returns (bool success, string memory message) {
        AccessToken storage token = accessTokens[tokenId];
        bytes32 did = token.did;

        if (token.tokenId != tokenId) {
            return (false, "Token does not exist");
        }

        if (token.isRevoked) {
            return (false, "Token already revoked");
        }

        // Get device information, check permissions
        (
            ,  // deviceType (not needed)
            address owner,
            ,  // publicKey (not needed)
            ,  // registeredAt (not needed)
            ,  // isActive (not needed)
            ,  // name (not needed)
            ,  // metadata (not needed)
            ,  // authorizedBy (not needed)
            address userAddress
        ) = deviceManager.getDeviceInfo(did);

        // Allow device owner or device's user to revoke token
        bool isAuthorized = (owner == msg.sender || userAddress == msg.sender);

        if (!isAuthorized) {
            return (false, "Not authorized to revoke token");
        }

        token.isRevoked = true;

        emit TokenRevoked(tokenId);

        return (true, "Token revoked successfully");
    }

    // =================================
    // Audit Log Related Functions
    // =================================

    /**
     * @dev Get number of authentication logs for device
     * @param did Device's decentralized identifier
     * @return count Number of authentication logs
     */
    function getAuthLogCount(bytes32 did) external view returns (uint256 count) {
        return authLogs[did].length;
    }

    /**
     * @dev Get specific authentication log for device
     * @param did Device's decentralized identifier
     * @param index Log index
     * @return verifier Verifier address
     * @return challengeHash Challenge hash
     * @return timestamp Authentication time
     * @return success Authentication result
     */
    function getAuthLog(bytes32 did, uint256 index) external view returns (
        address verifier,
        bytes32 challengeHash,
        uint256 timestamp,
        bool success
    ) {
        require(index < authLogs[did].length, "Index out of bounds");

        AuthLog storage log = authLogs[did][index];

        return (
            log.verifier,
            log.challengeHash,
            log.timestamp,
            log.success
        );
    }

    /**
     * @dev Get paginated authentication logs for device
     * @param did Device's decentralized identifier
     * @param offset Starting index
     * @param limit Limit count
     * @return verifiers Verifier address array
     * @return timestamps Timestamp array
     * @return successes Authentication result array
     */
    function getAuthLogs(bytes32 did, uint256 offset, uint256 limit)
    external view returns (
        address[] memory verifiers,
        uint256[] memory timestamps,
        bool[] memory successes
    ) {
        uint256 logCount = authLogs[did].length;

        if (offset >= logCount) {
            // Return empty arrays
            return (new address[](0), new uint256[](0), new bool[](0));
        }

        // Calculate actual number of logs to return
        uint256 count = logCount - offset;
        if (count > limit) {
            count = limit;
        }

        // Initialize return arrays
        verifiers = new address[](count);
        timestamps = new uint256[](count);
        successes = new bool[](count);

        // Populate arrays
        for (uint256 i = 0; i < count; i++) {
            AuthLog storage log = authLogs[did][offset + i];
            verifiers[i] = log.verifier;
            timestamps[i] = log.timestamp;
            successes[i] = log.success;
        }

        return (verifiers, timestamps, successes);
    }

    /**
     * @dev Clean up expired challenge records
     * @param challenges Array of challenge values to clean
     * @param batchSize Batch processing size
     * @return cleanedCount Number of challenges cleaned
     */
    function cleanupExpiredChallenges(bytes32[] calldata challenges, uint256 batchSize)
    external returns (uint256 cleanedCount) {
        uint256 count = challenges.length < batchSize ? challenges.length : batchSize;
        cleanedCount = 0;

        for (uint i = 0; i < count; i++) {
            bytes32 challenge = challenges[i];
            if (block.timestamp - challengeTimestamps[challenge] > AUTH_CHALLENGE_EXPIRY) {
                delete challengeTimestamps[challenge];
                delete usedChallenges[challenge];
                cleanedCount++;
            }
        }

        return cleanedCount;
    }
}