// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseStructures.sol";
import "./CryptoUtils.sol";

/**
 * @title User Management Contract
 * @notice Handles user registration, login, and permission management
 */
contract UserManagement is BaseStructures, CryptoUtils {
    // =================================
    // Storage Mappings
    // =================================

    mapping(address => User) internal users;                 // User address => User information
    mapping(string => address) internal userNames;           // Username => User address (for checking name uniqueness)
    mapping(address => bool) internal registeredUsers;       // Records registered users
    mapping(bytes => address) internal publicKeyAddressCache; // Cache for converted addresses
    mapping(address => LoginChallenge) internal loginChallenges; // User address => Login challenge
    mapping(bytes32 => RegistrationRequest) internal registrationRequests; // Registration request ID => Registration request
    mapping(address => bytes32[]) internal pendingRequests;  // User address => Pending registration requests

    address[] internal allUsers;                             // Array of all user addresses

    // System administrator address
    address public systemAdmin;
    // =================================
    // Event Definitions
    // =================================

    event UserRegistered(address indexed userAddress, string name, UserRole role, address authorizedBy);
    event UserUpdated(address indexed userAddress, string name);
    event UserDeactivated(address indexed userAddress);
    event LoginChallengeGenerated(address indexed userAddress, bytes32 challenge, uint256 expiresAt);
    event LoginSuccess(address indexed userAddress, uint256 timestamp);
    event LoginFailed(address indexed userAddress, uint256 timestamp);
    event RoleChanged(address indexed userAddress, UserRole oldRole, UserRole newRole, address changedBy);
    event RegistrationRequestCreated(bytes32 indexed requestId, string username, address approver);
    event RegistrationRequestApproved(bytes32 indexed requestId, address approvedBy);
    event RegistrationRequestRejected(bytes32 indexed requestId, address rejectedBy);
    event UserLoginSessionStarted(address indexed userAddress, uint256 timestamp, uint256 expiresAt);

    // =================================
    // Modifiers
    // =================================

    /**
     * @dev Only allow system administrator to call
     */
    modifier onlySystemAdmin() {
        require(
            msg.sender == systemAdmin ||
            (users[msg.sender].role == UserRole.SYSTEM_ADMIN && users[msg.sender].isActive),
            "Only system admin can perform this action"
        );
        _;
    }

    /**
     * @dev Only allow network administrator or system administrator to call
     */
    modifier onlyNetworkAdminOrAbove() {
        require(
            msg.sender == systemAdmin ||
            ((users[msg.sender].role == UserRole.NETWORK_ADMIN ||
                users[msg.sender].role == UserRole.SYSTEM_ADMIN) &&
                users[msg.sender].isActive),
            "Requires network admin privileges or above"
        );
        _;
    }

    /**
     * @dev Only allow registered and active users to call
     */
    modifier onlyActiveUser(address sender) {
        require(registeredUsers[sender] && users[sender].isActive,
            "Requires active registered user");
        _;
    }

    // =================================
    // Constructor
    // =================================

    /**
     * @dev Constructor, sets system administrator
     */
    constructor(address _admin) {
        systemAdmin = _admin;
        registeredUsers[_admin] = true;

        // Register system administrator as the first user
        _registerUser(_admin, "System Admin", "admin@admin.com", new bytes(0), UserRole.SYSTEM_ADMIN, address(0));
    }

    // =================================
    // User Login Related Functions
    // =================================

    /**
     * @dev Generate user login challenge
     * @param userAddress User address
     * @return challenge Generated challenge value
     * @return expiresAt Challenge expiration time
     */
    function generateLoginChallenge(address userAddress) external returns (bytes32 challenge, uint256 expiresAt) {
        require(userAddress != address(0), "Invalid user address");

        // Generate random challenge
        bytes32 challengeValue = keccak256(abi.encodePacked(
            "login",
            userAddress,
            block.timestamp,
            blockhash(block.number - 1),
            msg.sender
        ));

        // Set expiration time
        uint256 expires = block.timestamp + LOGIN_CHALLENGE_EXPIRY;

        // Save challenge
        loginChallenges[userAddress] = LoginChallenge({
            userAddress: userAddress,
            challengeValue: challengeValue,
            timestamp: block.timestamp,
            expiresAt: expires
        });

        // Trigger event
        emit LoginChallengeGenerated(userAddress, challengeValue, expires);

        return (challengeValue, expires);
    }

    /**
     * @dev Verify user login
     * @param userAddress User address
     * @param challenge Challenge value
     * @param signature Signature
     * @return success Whether verification successful
     * @return userRole User role
     */
    function verifyLogin(address userAddress, bytes32 challenge, bytes calldata signature)
    external returns (bool success, UserRole userRole) {

        // Verify user is registered
        require(registeredUsers[userAddress], "User not registered");
        require(users[userAddress].isActive, "User is not active");

        // Verify challenge is valid
        LoginChallenge memory loginChallenge = loginChallenges[userAddress];
        require(loginChallenge.challengeValue == challenge, "Invalid challenge");
        require(block.timestamp <= loginChallenge.expiresAt, "Challenge expired");

        // Get user public key
        bytes memory publicKey = users[userAddress].publicKey;
        require(publicKey.length > 0, "User has no public key");

        // Construct message hash to verify
        bytes32 messageHash = keccak256(abi.encodePacked(userAddress, challenge));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        // Verify signature
        address recoveredAddress = recoverSigner(ethSignedMessageHash, signature);
        address userPubKeyAddress = getPublicKeyAddress(publicKey);

        bool isValid = (recoveredAddress != address(0) && recoveredAddress == userPubKeyAddress);

        if (isValid) {
            // Verification successful, record login and trigger events
            emit LoginSuccess(userAddress, block.timestamp);
            emit UserLoginSessionStarted(userAddress, block.timestamp, block.timestamp + 1 days);
            return (true, users[userAddress].role);
        } else {
            // Verification failed, record failure
            emit LoginFailed(userAddress, block.timestamp);
            return (false, UserRole.NONE);
        }
    }

    // =================================
    // User Management Related Functions
    // =================================

    /**
     * @dev Create user registration request
     * @param name Username
     * @param email User email
     * @param publicKey User public key
     * @param approverAddress Approver address
     * @return requestId Registration request ID
     */
    function createRegistrationRequest(
        string calldata name,
        string calldata email,
        bytes calldata publicKey,
        address approverAddress
    ) external returns (bytes32 requestId) {
        // Validate parameters
        require(bytes(name).length > 0, "Username cannot be empty");
        require(userNames[name] == address(0), "Username already taken");
        require(publicKey.length > 0, "Public key cannot be empty");
        require(approverAddress != address(0), "Approver address cannot be empty");

        // Verify approver must be administrator
        require(
            users[approverAddress].role == UserRole.SYSTEM_ADMIN ||
            users[approverAddress].role == UserRole.NETWORK_ADMIN,
            "Approver must be admin"
        );

        // Generate request ID
        requestId = keccak256(abi.encodePacked(
            name,
            msg.sender,
            publicKey,
            block.timestamp
        ));

        // Save registration request
        registrationRequests[requestId] = RegistrationRequest({
            username: name,
            email: email,
            publicKey: publicKey,
            requestedAt: block.timestamp,
            isProcessed: false,
            approvedBy: address(0)
        });

        // Add request to approver's pending requests
        pendingRequests[approverAddress].push(requestId);

        // Trigger event
        emit RegistrationRequestCreated(requestId, name, approverAddress);

        return requestId;
    }

    /**
     * @dev Approve user registration request
     * @param requestId Registration request ID
     * @param userAddress User address
     * @param role Assigned user role
     * @return success Whether successful
     */
    function approveRegistrationRequest(
        bytes32 requestId,
        address userAddress,
        UserRole role
    ) external onlyNetworkAdminOrAbove returns (bool success) {
        // Verify request exists and is not processed
        RegistrationRequest storage request = registrationRequests[requestId];
        require(request.requestedAt > 0, "Registration request not found");
        require(!request.isProcessed, "Request already processed");
        require(block.timestamp - request.requestedAt <= REGISTRATION_REQUEST_EXPIRY, "Request expired");

        // Regular administrators can only assign regular user role
        if (users[msg.sender].role == UserRole.NETWORK_ADMIN) {
            require(role == UserRole.USER, "Network admin can only assign USER role");
        }

        // Mark request as processed
        request.isProcessed = true;
        request.approvedBy = msg.sender;

        // Register user
        _registerUser(
            userAddress,
            request.username,
            request.email,
            request.publicKey,
            role,
            msg.sender
        );

        // Trigger event
        emit RegistrationRequestApproved(requestId, msg.sender);

        return true;
    }

    /**
     * @dev Reject user registration request
     * @param requestId Registration request ID
     * @return success Whether successful
     */
    function rejectRegistrationRequest(bytes32 requestId)
    external onlyNetworkAdminOrAbove returns (bool success) {
        // Verify request exists and is not processed
        RegistrationRequest storage request = registrationRequests[requestId];
        require(request.requestedAt > 0, "Registration request not found");
        require(!request.isProcessed, "Request already processed");

        // Mark request as processed
        request.isProcessed = true;

        // Trigger event
        emit RegistrationRequestRejected(requestId, msg.sender);

        return true;
    }

    /**
     * @dev Get list of pending registration requests for user
     * @return requests Request ID array
     */
    function getPendingRequests() external view onlyNetworkAdminOrAbove returns (bytes32[] memory) {
        return pendingRequests[msg.sender];
    }

    /**
     * @dev Get registration request details
     * @param requestId Registration request ID
     * @return username Username
     * @return email Email
     * @return publicKey Public key
     * @return requestedAt Request time
     * @return isProcessed Whether processed
     * @return approvedBy Approver
     */
    function getRegistrationRequestInfo(bytes32 requestId) external view returns (
        string memory username,
        string memory email,
        bytes memory publicKey,
        uint256 requestedAt,
        bool isProcessed,
        address approvedBy
    ) {
        RegistrationRequest memory request = registrationRequests[requestId];
        require(request.requestedAt > 0, "Registration request not found");

        return (
            request.username,
            request.email,
            request.publicKey,
            request.requestedAt,
            request.isProcessed,
            request.approvedBy
        );
    }

    /**
     * @dev Register new user
     * @param name Username
     * @param email User email (optional)
     * @param publicKey User public key
     * @param signature Administrator signature (can be empty for direct registration by system administrator)
     * @return success Whether successful
     * @return message Return message
     */
    function registerUser(
        string calldata name,
        string calldata email,
        bytes calldata publicKey,
        bytes calldata signature,
        address originalSender
    ) external returns (bool success, string memory message) {
        // Check if username already exists
        if (userNames[name] != address(0)) {
            return (false, "Username already taken");
        }

        // Check if user is already registered
        if (users[originalSender].userAddress != address(0)) {
            return (false, "User already registered");
        }

        // Validate public key
        if (publicKey.length == 0) {
            return (false, "Public key cannot be empty");
        }

        address authorizer;

        // If signature provided, verify signature
        if (signature.length > 0) {
            // Construct message hash
            bytes32 messageHash = keccak256(abi.encodePacked(
                msg.sender,
                name,
                email,
                publicKey
            ));

            bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                messageHash
            ));

            // Verify signature
            authorizer = recoverSigner(ethSignedMessageHash, signature);

            // Check signer's permissions
            if (users[authorizer].role != UserRole.SYSTEM_ADMIN &&
                users[authorizer].role != UserRole.NETWORK_ADMIN) {
                return (false, "Signature must be from an admin");
            }
        } else {
            // No signature, allow self-registration (for test environment only)
            // This part should be removed in production environment
            authorizer = msg.sender;
            //return (false, "Signature must not be empty!")
        }

        // Register user
        UserRole role = UserRole.USER;
        success = _registerUser(originalSender, name, email, publicKey, role, authorizer);

        if (success) {
            return (true, "User registered successfully");
        } else {
            return (false, "Failed to register user");
        }
    }
    /**
     * @dev Internal function: Register new user
     * @param userAddress User address
     * @param name Username
     * @param email User email
     * @param publicKey User public key
     * @param role User role
     * @param authorizedBy Administrator who authorized registration
     * @return success Whether registration successful
     */
    function _registerUser(
        address userAddress,
        string memory name,
        string memory email,
        bytes memory publicKey,
        UserRole role,
        address authorizedBy
    ) internal returns (bool success) {
        // Create user
        users[userAddress] = User({
            userAddress: userAddress,
            name: name,
            email: email,
            publicKey: publicKey,
            registeredAt: block.timestamp,
            isActive: true,
            devices: new bytes32[](0),
            networks: new bytes32[](0),
            role: role,
            authorizedBy: authorizedBy
        });

        // Add username mapping
        userNames[name] = userAddress;

        // Add user to all users array
        allUsers.push(userAddress);

        // Mark as registered user
        registeredUsers[userAddress] = true;

        emit UserRegistered(userAddress, name, role, authorizedBy);

        return true;
    }

    /**
     * @dev Update user information
     * @param name New username
     * @param email New user email
     * @param publicKey New public key (if unchanged, pass empty)
     */
    function updateUserInfo(
        string calldata name,
        string calldata email,
        bytes calldata publicKey,
        address sender
    ) external onlyActiveUser(sender) returns (bool success, string memory message) {
        // Check if user is registered
        if (users[sender].userAddress == address(0)) {
            return (false, "User not registered");
        }

        // If username changed, check if new username already exists
        if (keccak256(abi.encodePacked(users[sender].name)) != keccak256(abi.encodePacked(name))) {
            if (userNames[name] != address(0)) {
                return (false, "Username already taken");
            }
            // Delete old username mapping
            delete userNames[users[sender].name];
            // Add new username mapping
            userNames[name] = sender;
        }

        // Update user information
        users[sender].name = name;
        users[sender].email = email;

        // If new public key provided, update it
        if (publicKey.length > 0) {
            users[sender].publicKey = publicKey;
        }

        emit UserUpdated(sender, name);

        return (true, "User information updated successfully");
    }

    /**
     * @dev Deactivate user account
     */
    function deactivateUser(address sender) external onlyActiveUser(sender) returns (bool success, string memory message) {
        // Check if user is registered
        if (users[sender].userAddress == address(0)) {
            return (false, "User not registered");
        }

        // System administrator cannot deactivate themselves
        if (users[sender].role == UserRole.SYSTEM_ADMIN && msg.sender == systemAdmin) {
            return (false, "System admin cannot deactivate themselves");
        }

        // Deactivate user account
        users[sender].isActive = false;

        emit UserDeactivated(sender);

        return (true, "User deactivated successfully");
    }

    /**
     * @dev Administrator changes user role
     * @param userAddress User address
     * @param newRole New role
     */
    function changeUserRole(address userAddress, UserRole newRole)
    external onlySystemAdmin returns (bool success, string memory message) {
        // Check if user is registered
        require(users[userAddress].userAddress != address(0), "User not registered");

        // Cannot modify system administrator
        if (userAddress == systemAdmin) {
            return (false, "Cannot change role of main system admin");
        }

        // Save old role
        UserRole oldRole = users[userAddress].role;

        // Update role
        users[userAddress].role = newRole;

        // Trigger event
        emit RoleChanged(userAddress, oldRole, newRole, msg.sender);

        return (true, "User role changed successfully");
    }

    /**
     * @dev Get user information
     * @param userAddress User address
     * @return name Username
     * @return email User email
     * @return publicKey User public key
     * @return registeredAt Registration time
     * @return isActive Whether active
     * @return deviceCount Number of owned devices
     * @return networkCount Number of created networks
     * @return role User role
     * @return authorizedBy Administrator who authorized registration
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
        User storage user = users[userAddress];
        require(user.userAddress != address(0), "User not found");

        return (
            user.name,
            user.email,
            user.publicKey,
            user.registeredAt,
            user.isActive,
            user.devices.length,
            user.networks.length,
            user.role,
            user.authorizedBy
        );
    }

    /**
     * @dev Get address from public key (with cache)
     */
    function getPublicKeyAddress(bytes memory publicKey) internal returns (address) {
        // If exists in cache, return directly
        if (publicKeyAddressCache[publicKey] != address(0)) {
            return publicKeyAddressCache[publicKey];
        }

        // Calculate address
        address addr = publicKeyToAddress(publicKey);

        // Cache result
        publicKeyAddressCache[publicKey] = addr;

        return addr;
    }

    /**
     * @dev Check if user is registered
     * @param user User address
     * @return Whether registered
     */
    function isRegisteredUser(address user) external view returns (bool) {
        return registeredUsers[user];
    }

    /**
     * @dev Get total number of users
     * @return count User count
     */
    function getUserCount() external view returns (uint256 count) {
        return allUsers.length;
    }

    /**
     * @dev Get paginated user list
     * @param offset Starting index
     * @param limit Count limit
     * @return userAddresses User address array
     * @return names Username array
     * @return isActives Whether active array
     * @return roles User role array
     */
    function getUserList(uint256 offset, uint256 limit) external view returns (
        address[] memory userAddresses,
        string[] memory names,
        bool[] memory isActives,
        UserRole[] memory roles
    ) {
        require(offset < allUsers.length, "Offset out of range");

        uint256 size = limit;
        if (offset + limit > allUsers.length) {
            size = allUsers.length - offset;
        }

        userAddresses = new address[](size);
        names = new string[](size);
        isActives = new bool[](size);
        roles = new UserRole[](size);

        for (uint256 i = 0; i < size; i++) {
            address userAddress = allUsers[offset + i];
            User storage user = users[userAddress];

            userAddresses[i] = userAddress;
            names[i] = user.name;
            isActives[i] = user.isActive;
            roles[i] = user.role;
        }

        return (userAddresses, names, isActives, roles);
    }

    /**
     * @dev Get user's device list
     * @param userAddress User address
     * @return deviceIds Device ID array
     * @return deviceNames Device name array
     * @return deviceTypes Device type array
     * @return isActives Whether device active array
     */
    function getUserDevices(address userAddress) external view returns (
        bytes32[] memory deviceIds,
        string[] memory deviceNames,
        bytes32[] memory deviceTypes,
        bool[] memory isActives
    ) {
        User storage user = users[userAddress];
        require(user.userAddress != address(0), "User not found");

        uint256 deviceCount = user.devices.length;
        deviceIds = new bytes32[](deviceCount);
        deviceNames = new string[](deviceCount);
        deviceTypes = new bytes32[](deviceCount);
        isActives = new bool[](deviceCount);

        // This requires a method to get device information from device ID
        // This implementation assumes a deviceInfo mapping is available
        // If not, you need to adjust this part of the code

        // Since this function may need to depend on information in the DeviceManagement contract
        // which we cannot access directly, we only return device IDs here
        for (uint256 i = 0; i < deviceCount; i++) {
            deviceIds[i] = user.devices[i];
            // Other fields set to empty or default values
            deviceNames[i] = "";
            deviceTypes[i] = bytes32(0);
            isActives[i] = true;
        }

        return (deviceIds, deviceNames, deviceTypes, isActives);
    }
}