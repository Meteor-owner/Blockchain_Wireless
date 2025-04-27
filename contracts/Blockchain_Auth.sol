// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Blockchain_Auth {
    // =================================
    // 数据结构定义
    // =================================

    // 用户角色类型
    enum UserRole {
        NONE,           // 未注册
        USER,           // 普通用户
        NETWORK_ADMIN,  // 网络管理员
        SYSTEM_ADMIN    // 系统管理员
    }

    // 用户信息结构
    struct User {
        address userAddress;     // 用户地址
        string name;             // 用户名称
        string email;            // 用户邮箱（可选）
        bytes publicKey;         // 用户主公钥
        uint256 registeredAt;    // 注册时间戳
        bool isActive;           // 用户是否活跃
        bytes32[] devices;       // 用户拥有的设备DID列表
        bytes32[] networks;      // 用户创建的网络ID列表
        UserRole role;           // 用户角色
        address authorizedBy;    // 授权注册的管理员
    }

    // 设备信息结构
    struct Device {
        address owner;         // 设备所有者
        bytes32 deviceType;    // 设备类型(如smartphone, laptop, iot)
        bytes32 did;           // 分布式身份标识符
        bytes publicKey;       // 设备公钥
        uint256 registeredAt;  // 注册时间戳
        bool isActive;         // 设备是否活跃
        string name;           // 设备名称
        bytes32 metadata;      // 设备元数据哈希
        address authorizedBy;  // 授权注册的用户地址
        address userAddress;   // 设备归属的用户地址
    }

    // 认证记录结构
    struct AuthLog {
        bytes32 did;           // 设备DID
        address verifier;      // 验证者地址(AP)
        bytes32 challengeHash; // 挑战哈希
        uint256 timestamp;     // 认证时间戳
        bool success;          // 认证是否成功
    }

    // 访问令牌结构
    struct AccessToken {
        bytes32 did;           // 关联的设备DID
        bytes32 tokenId;       // 令牌ID
        uint256 issuedAt;      // 发行时间
        uint256 expiresAt;     // 过期时间
        bool isRevoked;        // 是否已被撤销
    }

    // 网络结构
    struct Network {
        address owner;         // 网络所有者
        bytes32 networkId;     // 网络标识符
        string name;           // 网络名称
        uint256 createdAt;     // 创建时间
        bool isActive;         // 网络是否活跃
    }

    // 用户登录挑战结构
    struct LoginChallenge {
        address userAddress;    // 用户地址
        bytes32 challengeValue; // 挑战值
        uint256 timestamp;      // 生成时间
        uint256 expiresAt;      // 过期时间
    }

    // 用户注册授权请求结构
    struct RegistrationRequest {
        string username;        // 请求的用户名
        string email;           // 请求的邮箱
        bytes publicKey;        // 请求的公钥
        uint256 requestedAt;    // 请求时间
        bool isProcessed;       // 是否已处理
        address approvedBy;     // 批准的管理员地址
    }

    // =================================
    // 存储映射
    // =================================

    mapping(address => User) private users;                   // 用户地址 => 用户信息
    mapping(string => address) private userNames;             // 用户名 => 用户地址 (用于检查名称唯一性)
    mapping(bytes32 => Device) private devices;               // DID => 设备
    mapping(address => bytes32[]) private ownerDevices;       // 所有者 => DIDs
    mapping(bytes32 => Network) private networks;             // 网络ID => 网络
    mapping(address => bytes32[]) private ownerNetworks;      // 所有者 => 网络IDs
    mapping(bytes32 => mapping(bytes32 => bool)) private deviceNetworkAccess; // DID => 网络ID => 有无访问权限
    mapping(bytes32 => AccessToken) private accessTokens;     // 令牌ID => 访问令牌
    mapping(bytes32 => AuthLog[]) private authLogs;           // DID => 认证日志
    mapping(address => bool) private registeredUsers;         // 记录已注册用户
    mapping(bytes => address) private publicKeyAddressCache;  // 缓存转换后的地址

    // 新增映射
    mapping(address => LoginChallenge) private loginChallenges;     // 用户地址 => 登录挑战
    mapping(bytes32 => bool) private usedChallenges;                // 已使用的挑战值 => 是否已使用
    mapping(bytes32 => uint256) private challengeTimestamps;        // 挑战值 => 创建时间戳
    mapping(bytes32 => RegistrationRequest) private registrationRequests; // 注册请求ID => 注册请求
    mapping(address => bytes32[]) private pendingRequests;          // 用户地址 => 待处理的注册请求

    address[] private allUsers;                               // 所有用户地址数组

    // =================================
    // 常量定义
    // =================================

    // 挑战过期时间
    uint256 private constant LOGIN_CHALLENGE_EXPIRY = 5 minutes;
    uint256 private constant AUTH_CHALLENGE_EXPIRY = 15 minutes;
    uint256 private constant REGISTRATION_REQUEST_EXPIRY = 7 days;

    // 系统管理员地址
    address public systemAdmin;

    // 系统默认网络
    bytes32 public defaultNetworkId;
    string public defaultNetworkName = "Default WiFi Network";

    // =================================
    // 事件定义
    // =================================

    // 原有事件
    event UserRegistered(address indexed userAddress, string name, UserRole role, address authorizedBy);
    event UserUpdated(address indexed userAddress, string name);
    event UserDeactivated(address indexed userAddress);
    event DeviceRegistered(bytes32 indexed did, address indexed owner, bytes32 deviceType, string name, address authorizedBy);
    event DeviceAssignedToUser(bytes32 indexed did, address indexed userAddress);
    event DeviceDeactivated(bytes32 indexed did);
    event NetworkCreated(bytes32 indexed networkId, address indexed owner, string name);
    event AccessGranted(bytes32 indexed did, bytes32 indexed networkId);
    event AccessRevoked(bytes32 indexed did, bytes32 indexed networkId);
    event AuthenticationAttempt(bytes32 indexed did, bytes32 indexed networkId, bool success);
    event TokenIssued(bytes32 indexed did, bytes32 indexed tokenId, uint256 expiresAt);
    event TokenRevoked(bytes32 indexed tokenId);
    event RegistrationChallenge(bytes32 indexed did, bytes32 challenge, uint256 expiresAt);
    event RegistrationVerified(bytes32 indexed did);
    event AuthChallengeGenerated(bytes32 indexed did, bytes32 indexed networkId, bytes32 challenge, uint256 expiresAt);

    // 新增事件
    event LoginChallengeGenerated(address indexed userAddress, bytes32 challenge, uint256 expiresAt);
    event LoginSuccess(address indexed userAddress, uint256 timestamp);
    event LoginFailed(address indexed userAddress, uint256 timestamp);
    event RoleChanged(address indexed userAddress, UserRole oldRole, UserRole newRole, address changedBy);
    event RegistrationRequestCreated(bytes32 indexed requestId, string username, address approver);
    event RegistrationRequestApproved(bytes32 indexed requestId, address approvedBy);
    event RegistrationRequestRejected(bytes32 indexed requestId, address rejectedBy);
    event UserLoginSessionStarted(address indexed userAddress, uint256 timestamp, uint256 expiresAt);
    event DeviceTransferred(bytes32 indexed did, address indexed fromUser, address indexed toUser);

    // =================================
    // 修饰器
    // =================================

    /**
     * @dev 只允许系统管理员调用
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
     * @dev 只允许网络管理员或系统管理员调用
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
     * @dev 只允许已注册且活跃的用户调用
     */
    modifier onlyActiveUser() {
        require(registeredUsers[msg.sender] && users[msg.sender].isActive,
                "Requires active registered user");
        _;
    }

    /**
     * @dev 只允许设备所有者调用
     */
    modifier onlyDeviceOwner(bytes32 did) {
        require(devices[did].owner == msg.sender, "Only device owner can perform this action");
        _;
    }

    /**
     * @dev 只允许网络所有者调用
     */
    modifier onlyNetworkOwner(bytes32 networkId) {
        require(networks[networkId].owner == msg.sender, "Only network owner can perform this action");
        _;
    }

    // =================================
    // 构造函数
    // =================================

    /**
     * @dev 构造函数，设置系统管理员
     */
    constructor() {
        systemAdmin = msg.sender;
        registeredUsers[msg.sender] = true;

        // 创建默认网络
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

        // 注册系统管理员为第一个用户
        _registerUser(msg.sender, "System Admin", "", new bytes(0), UserRole.SYSTEM_ADMIN, address(0));
    }

    // =================================
    // 用户登录相关函数
    // =================================

    /**
     * @dev 生成用户登录挑战
     * @param userAddress 用户地址
     * @return challenge 生成的挑战值
     * @return expiresAt 挑战过期时间
     */
    function generateLoginChallenge(address userAddress) external returns (bytes32 challenge, uint256 expiresAt) {
        require(userAddress != address(0), "Invalid user address");

        // 生成随机挑战
        bytes32 challengeValue = keccak256(abi.encodePacked(
            "login",
            userAddress,
            block.timestamp,
            blockhash(block.number - 1),
            msg.sender
        ));

        // 设置过期时间
        uint256 expires = block.timestamp + LOGIN_CHALLENGE_EXPIRY;

        // 保存挑战
        loginChallenges[userAddress] = LoginChallenge({
            userAddress: userAddress,
            challengeValue: challengeValue,
            timestamp: block.timestamp,
            expiresAt: expires
        });

        // 触发事件
        emit LoginChallengeGenerated(userAddress, challengeValue, expires);

        return (challengeValue, expires);
    }

    /**
     * @dev 验证用户登录
     * @param userAddress 用户地址
     * @param challenge 挑战值
     * @param signature 签名
     * @return success 是否验证成功
     * @return userRole 用户角色
     */
    function verifyLogin(address userAddress, bytes32 challenge, bytes calldata signature)
        external returns (bool success, UserRole userRole) {

        // 验证用户是否注册
        require(registeredUsers[userAddress], "User not registered");
        require(users[userAddress].isActive, "User is not active");

        // 验证挑战是否有效
        LoginChallenge memory loginChallenge = loginChallenges[userAddress];
        require(loginChallenge.challengeValue == challenge, "Invalid challenge");
        require(block.timestamp <= loginChallenge.expiresAt, "Challenge expired");
        require(!usedChallenges[challenge], "Challenge already used");

        // 标记挑战为已使用
        usedChallenges[challenge] = true;

        // 获取用户公钥
        bytes memory publicKey = users[userAddress].publicKey;
        require(publicKey.length > 0, "User has no public key");

        // 构建要验证的消息哈希
        bytes32 messageHash = keccak256(abi.encodePacked(userAddress, challenge));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        // 验证签名
        address recoveredAddress = recoverSigner(ethSignedMessageHash, signature);
        address userPubKeyAddress = getPublicKeyAddress(publicKey);

        bool isValid = (recoveredAddress != address(0) && recoveredAddress == userPubKeyAddress);

        if (isValid) {
            // 验证成功，记录登录并触发事件
            emit LoginSuccess(userAddress, block.timestamp);
            emit UserLoginSessionStarted(userAddress, block.timestamp, block.timestamp + 1 days);
            return (true, users[userAddress].role);
        } else {
            // 验证失败，记录失败
            emit LoginFailed(userAddress, block.timestamp);
            return (false, UserRole.NONE);
        }
    }

    // =================================
    // 用户管理相关函数
    // =================================

    /**
     * @dev 创建用户注册请求
     * @param name 用户名称
     * @param email 用户邮箱
     * @param publicKey 用户公钥
     * @param approverAddress 批准者地址
     * @return requestId 注册请求ID
     */
    function createRegistrationRequest(
        string calldata name,
        string calldata email,
        bytes calldata publicKey,
        address approverAddress
    ) external returns (bytes32 requestId) {
        // 验证参数
        require(bytes(name).length > 0, "Username cannot be empty");
        require(userNames[name] == address(0), "Username already taken");
        require(publicKey.length > 0, "Public key cannot be empty");
        require(approverAddress != address(0), "Approver address cannot be empty");

        // 验证批准者必须是管理员
        require(
            users[approverAddress].role == UserRole.SYSTEM_ADMIN ||
            users[approverAddress].role == UserRole.NETWORK_ADMIN,
            "Approver must be admin"
        );

        // 生成请求ID
        requestId = keccak256(abi.encodePacked(
            name,
            msg.sender,
            publicKey,
            block.timestamp
        ));

        // 保存注册请求
        registrationRequests[requestId] = RegistrationRequest({
            username: name,
            email: email,
            publicKey: publicKey,
            requestedAt: block.timestamp,
            isProcessed: false,
            approvedBy: address(0)
        });

        // 将请求添加到批准者的待处理请求中
        pendingRequests[approverAddress].push(requestId);

        // 触发事件
        emit RegistrationRequestCreated(requestId, name, approverAddress);

        return requestId;
    }

    /**
     * @dev 批准用户注册请求
     * @param requestId 注册请求ID
     * @param userAddress 用户地址
     * @param role 分配的用户角色
     * @return success 是否成功
     */
    function approveRegistrationRequest(
        bytes32 requestId,
        address userAddress,
        UserRole role
    ) external onlyNetworkAdminOrAbove returns (bool success) {
        // 验证请求存在且未处理
        RegistrationRequest storage request = registrationRequests[requestId];
        require(request.requestedAt > 0, "Registration request not found");
        require(!request.isProcessed, "Request already processed");
        require(block.timestamp - request.requestedAt <= REGISTRATION_REQUEST_EXPIRY, "Request expired");

        // 普通管理员只能分配普通用户角色
        if (users[msg.sender].role == UserRole.NETWORK_ADMIN) {
            require(role == UserRole.USER, "Network admin can only assign USER role");
        }

        // 标记请求为已处理
        request.isProcessed = true;
        request.approvedBy = msg.sender;

        // 注册用户
        _registerUser(
            userAddress,
            request.username,
            request.email,
            request.publicKey,
            role,
            msg.sender
        );

        // 触发事件
        emit RegistrationRequestApproved(requestId, msg.sender);

        return true;
    }

    /**
     * @dev 拒绝用户注册请求
     * @param requestId 注册请求ID
     * @return success 是否成功
     */
    function rejectRegistrationRequest(bytes32 requestId)
        external onlyNetworkAdminOrAbove returns (bool success) {
        // 验证请求存在且未处理
        RegistrationRequest storage request = registrationRequests[requestId];
        require(request.requestedAt > 0, "Registration request not found");
        require(!request.isProcessed, "Request already processed");

        // 标记请求为已处理
        request.isProcessed = true;

        // 触发事件
        emit RegistrationRequestRejected(requestId, msg.sender);

        return true;
    }

    /**
     * @dev 获取用户的待处理注册请求列表
     * @return requests 请求ID数组
     */
    function getPendingRequests() external view onlyNetworkAdminOrAbove returns (bytes32[] memory) {
        return pendingRequests[msg.sender];
    }

    /**
     * @dev 获取注册请求详情
     * @param requestId 注册请求ID
     * @return username 用户名
     * @return email 邮箱
     * @return publicKey 公钥
     * @return requestedAt 请求时间
     * @return isProcessed 是否已处理
     * @return approvedBy 批准人
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
     * @dev 注册新用户
     * @param name 用户名称
     * @param email 用户邮箱（可选）
     * @param publicKey 用户公钥
     * @param signature 管理员签名（系统管理员直接注册时可为空）
     * @return success 是否成功
     * @return message 返回消息
     */
    function registerUser(
        string calldata name,
        string calldata email,
        bytes calldata publicKey,
        bytes calldata signature
    ) external returns (bool success, string memory message) {
        // 检查用户名是否已存在
        if (userNames[name] != address(0)) {
            return (false, "Username already taken");
        }

        // 检查用户是否已注册
        if (users[msg.sender].userAddress != address(0)) {
            return (false, "User already registered");
        }

        // 验证公钥
        if (publicKey.length == 0) {
            return (false, "Public key cannot be empty");
        }

        address authorizer;

        // 如果是系统管理员调用，可以直接注册
        if (msg.sender == systemAdmin) {
            authorizer = systemAdmin;
            success = _registerUser(msg.sender, name, email, publicKey, UserRole.USER, authorizer);
        } else {
            // 非管理员需要管理员签名授权
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

            authorizer = recoverSigner(ethSignedMessageHash, signature);

            // 验证授权者是管理员
            if (users[authorizer].role != UserRole.SYSTEM_ADMIN &&
                users[authorizer].role != UserRole.NETWORK_ADMIN) {
                return (false, "Signature must be from an admin");
            }

            // 网络管理员只能注册普通用户
            UserRole role = UserRole.USER;

            success = _registerUser(msg.sender, name, email, publicKey, role, authorizer);
        }

        if (success) {
            return (true, "User registered successfully");
        } else {
            return (false, "Failed to register user");
        }
    }

    /**
     * @dev 更新用户信息
     * @param name 新用户名称
     * @param email 新用户邮箱
     * @param publicKey 新公钥（如保持不变可传空）
     */
    function updateUserInfo(
        string calldata name,
        string calldata email,
        bytes calldata publicKey
    ) external onlyActiveUser returns (bool success, string memory message) {
        // 检查用户是否已注册
        if (users[msg.sender].userAddress == address(0)) {
            return (false, "User not registered");
        }

        // 如果用户名有变更，检查新用户名是否已存在
        if (keccak256(abi.encodePacked(users[msg.sender].name)) != keccak256(abi.encodePacked(name))) {
            if (userNames[name] != address(0)) {
                return (false, "Username already taken");
            }
            // 删除旧用户名映射
            delete userNames[users[msg.sender].name];
            // 添加新用户名映射
            userNames[name] = msg.sender;
        }

        // 更新用户信息
        users[msg.sender].name = name;
        users[msg.sender].email = email;

        // 如果提供了新公钥，则更新
        if (publicKey.length > 0) {
            users[msg.sender].publicKey = publicKey;
        }

        emit UserUpdated(msg.sender, name);

        return (true, "User information updated successfully");
    }

    /**
     * @dev 内部函数：注册新用户
     * @param userAddress 用户地址
     * @param name 用户名称
     * @param email 用户邮箱
     * @param publicKey 用户公钥
     * @param role 用户角色
     * @param authorizedBy 授权注册的管理员
     * @return success 注册是否成功
     */
    function _registerUser(
        address userAddress,
        string memory name,
        string memory email,
        bytes memory publicKey,
        UserRole role,
        address authorizedBy
    ) internal returns (bool success) {
        // 创建用户
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

        // 添加用户名映射
        userNames[name] = userAddress;

        // 将用户添加到所有用户数组
        allUsers.push(userAddress);

        // 标记为已注册用户
        registeredUsers[userAddress] = true;

        emit UserRegistered(userAddress, name, role, authorizedBy);

        return true;
    }

    /**
     * @dev 停用用户账户
     */
    function deactivateUser() external onlyActiveUser returns (bool success, string memory message) {
        // 检查用户是否已注册
        if (users[msg.sender].userAddress == address(0)) {
            return (false, "User not registered");
        }

        // 系统管理员不能停用自己
        if (users[msg.sender].role == UserRole.SYSTEM_ADMIN && msg.sender == systemAdmin) {
            return (false, "System admin cannot deactivate themselves");
        }

        // 停用用户账户
        users[msg.sender].isActive = false;

        emit UserDeactivated(msg.sender);

        return (true, "User deactivated successfully");
    }

    /**
     * @dev 管理员修改用户角色
     * @param userAddress 用户地址
     * @param newRole 新角色
     */
    function changeUserRole(address userAddress, UserRole newRole)
        external onlySystemAdmin returns (bool success, string memory message) {
        // 检查用户是否已注册
        require(users[userAddress].userAddress != address(0), "User not registered");

        // 不能修改系统管理员
        if (userAddress == systemAdmin) {
            return (false, "Cannot change role of main system admin");
        }

        // 保存旧角色
        UserRole oldRole = users[userAddress].role;

        // 更新角色
        users[userAddress].role = newRole;

        // 触发事件
        emit RoleChanged(userAddress, oldRole, newRole, msg.sender);

        return (true, "User role changed successfully");
    }

    /**
     * @dev 获取用户信息
     * @param userAddress 用户地址
     * @return name 用户名称
     * @return email 用户邮箱
     * @return publicKey 用户公钥
     * @return registeredAt 注册时间
     * @return isActive 是否活跃
     * @return deviceCount 拥有的设备数量
     * @return networkCount 创建的网络数量
     * @return role 用户角色
     * @return authorizedBy 授权注册的管理员
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

    // =================================
    // 设备管理相关函数
    // =================================

    /**
     * @dev 注册新设备并分配给用户
     * @param deviceType 设备类型
     * @param did 设备的分布式标识符
     * @param publicKey 设备的公钥
     * @param name 设备名称
     * @param metadata 设备元数据哈希
     * @param signature 授权者对注册数据的签名
     */
    function registerDevice(
        bytes32 deviceType,
        bytes32 did,
        bytes calldata publicKey,
        string calldata name,
        bytes32 metadata,
        bytes calldata signature
    ) external onlyActiveUser returns (bool success, string memory message) {
        if (devices[did].owner != address(0)) {
            return (false, "Device already registered");
        }

        if (publicKey.length == 0) {
            return (false, "Invalid public key");
        }

        address authorizer;

        if (msg.sender == systemAdmin || users[msg.sender].role == UserRole.SYSTEM_ADMIN) {
            authorizer = msg.sender;
        } else {
            bytes32 messageHash = getSignatureMessageHash(deviceType, did, publicKey, name, metadata, msg.sender);
            authorizer = recoverSigner(messageHash, signature);

            // 验证授权者是否有权限
            if (!registeredUsers[authorizer] ||
                (users[authorizer].role != UserRole.SYSTEM_ADMIN &&
                 users[authorizer].role != UserRole.NETWORK_ADMIN &&
                 authorizer != msg.sender)) {
                return (false, "Authorizer not registered or not authorized");
            }
        }

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

        // 将设备添加到用户的设备列表
        users[msg.sender].devices.push(did);

        // 更新设备的用户地址
        devices[did].userAddress = msg.sender;

        emit DeviceAssignedToUser(did, msg.sender);

        return (true, "Registration successful");
    }

    /**
     * @dev 内部函数：生成通用挑战值
     * @param context 挑战值上下文（如"auth"、"registration"、"keyUpdate"等）
     * @param data1 上下文相关数据1（如设备DID）
     * @param data2 上下文相关数据2（如网络ID）
     * @return 生成的挑战值
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
     * @dev 设备注册内部实现
     */
    function _registerDeviceInternal(
        bytes32 deviceType,
        bytes32 did,
        bytes calldata publicKey,
        string calldata name,
        bytes32 metadata,
        address authorizedBy
    ) internal returns (bool){
        // 注册设备
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
            userAddress: msg.sender  // 默认设置为消息发送者
        });

        // 更新索引
        ownerDevices[msg.sender].push(did);

        // 为新注册的设备生成注册挑战，用于验证设备确实拥有私钥
        bytes32 challenge = _generateChallenge("registration", did, bytes32(0));
        challengeTimestamps[challenge] = block.timestamp;

        // 触发事件
        emit DeviceRegistered(did, msg.sender, deviceType, name, authorizedBy);
        emit RegistrationChallenge(did, challenge, block.timestamp + AUTH_CHALLENGE_EXPIRY);

        // 为网络所有者自己的设备自动授予访问权限
        bytes32[] memory ownedNetworks = ownerNetworks[msg.sender];
        for (uint i = 0; i < ownedNetworks.length; i++) {
            deviceNetworkAccess[did][ownedNetworks[i]] = true;
            emit AccessGranted(did, ownedNetworks[i]);
        }

        if (ownedNetworks.length == 0) {
            deviceNetworkAccess[did][defaultNetworkId] = true;
            emit AccessGranted(did, defaultNetworkId);
        }

        return (true);
    }

    /**
     * @dev 转移设备所有权
     * @param did 设备ID
     * @param newOwner 新所有者地址
     */
    function transferDevice(bytes32 did, address newOwner)
        external onlyDeviceOwner(did) returns (bool success, string memory message) {
        // 验证新所有者是活跃用户
        require(registeredUsers[newOwner] && users[newOwner].isActive, "New owner must be active user");

        // 保存原始所有者信息用于事件
        address originalOwner = devices[did].owner;
        address originalUserAddress = devices[did].userAddress;

        // 从原所有者的设备列表中移除
        _removeDeviceFromOwner(did, originalOwner);

        // 如果设备分配给了不同的用户，也从该用户的列表中移除
        if (originalUserAddress != address(0) && originalUserAddress != originalOwner) {
            _removeDeviceFromUser(did, originalUserAddress);
        }

        // 更新设备所有者
        devices[did].owner = newOwner;
        devices[did].userAddress = newOwner;

        // 将设备添加到新所有者的设备列表
        ownerDevices[newOwner].push(did);
        users[newOwner].devices.push(did);

        // 触发事件
        emit DeviceTransferred(did, originalOwner, newOwner);

        return (true, "Device transferred successfully");
    }

    /**
     * @dev 从设备所有者的列表中移除设备
     * @param did 设备ID
     * @param owner 所有者地址
     */
    function _removeDeviceFromOwner(bytes32 did, address owner) internal {
        bytes32[] storage devicesList = ownerDevices[owner];
        for (uint i = 0; i < devicesList.length; i++) {
            if (devicesList[i] == did) {
                // 通过将最后一个元素移至当前位置并弹出最后一个元素来删除
                devicesList[i] = devicesList[devicesList.length - 1];
                devicesList.pop();
                break;
            }
        }
    }

    /**
     * @dev 从用户的设备列表中移除设备
     * @param did 设备ID
     * @param userAddress 用户地址
     */
    function _removeDeviceFromUser(bytes32 did, address userAddress) internal {
        bytes32[] storage devicesList = users[userAddress].devices;
        for (uint i = 0; i < devicesList.length; i++) {
            if (devicesList[i] == did) {
                // 通过将最后一个元素移至当前位置并弹出最后一个元素来删除
                devicesList[i] = devicesList[devicesList.length - 1];
                devicesList.pop();
                break;
            }
        }
    }

    /**
     * @dev 从签名恢复签名者地址
     * @param messageHash 消息哈希
     * @param signature 签名
     * @return 签名者地址
     */
    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        // 从签名中提取r, s, v
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // 如果是新的签名标准，需要调整v值
        if (v < 27) {
            v += 27;
        }

        // 恢复签名者地址
        return ecrecover(messageHash, v, r, s);
    }

    /**
     * @dev 构建要签名的消息哈希
     * @param deviceType 设备类型
     * @param did 设备的分布式标识符
     * @param publicKey 设备的公钥
     * @param name 设备名称
     * @param metadata 设备元数据哈希
     * @param owner 设备所有者
     * @return 消息哈希
     */
    function getSignatureMessageHash(
        bytes32 deviceType,
        bytes32 did,
        bytes memory publicKey,
        string memory name,
        bytes32 metadata,
        address owner
    ) public pure returns (bytes32) {
        bytes32 messageHash = keccak256(abi.encodePacked(deviceType, did, publicKey, name, metadata, owner));

        // 添加以太坊签名前缀（防止签名被用于其他用途）
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    }

    /**
     * @dev 将公钥转换为以太坊地址
     * @param publicKey 公钥
     * @return 对应的以太坊地址
     */
    function publicKeyToAddress(bytes memory publicKey) internal pure returns (address) {
        // 避免额外的内存分配和循环
        bytes32 hash;

        // 直接处理公钥，跳过复制操作
        assembly {
            // 如果公钥以0x04开头（非压缩格式），则跳过第一个字节
            let offset := 0
            if eq(byte(0, mload(add(publicKey, 32))), 0x04) {
                offset := 1
            }

            // 计算keccak256哈希，避免创建新的内存
            hash := keccak256(add(add(publicKey, 32), offset), sub(mload(publicKey), offset))
        }

        // 从哈希中提取地址（末尾20字节）
        return address(uint160(uint256(hash)));
    }

    function getPublicKeyAddress(bytes memory publicKey) internal returns (address) {
        // 如果缓存中存在，直接返回
        if (publicKeyAddressCache[publicKey] != address(0)) {
            return publicKeyAddressCache[publicKey];
        }

        // 计算地址
        address addr = publicKeyToAddress(publicKey);

        // 缓存结果
        publicKeyAddressCache[publicKey] = addr;

        return addr;
    }

    /**
     * @dev 获取设备信息
     * @param did 设备的分布式标识符
     * @return deviceType 设备类型
     * @return owner 设备所有者
     * @return publicKey 设备公钥
     * @return registeredAt 注册时间
     * @return isActive 设备是否活跃
     * @return name 设备名称
     * @return metadata 设备元数据
     * @return authorizedBy 授权注册的用户
     * @return userAddress 设备归属的用户地址
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
     * @dev 停用设备
     * @param did 设备的分布式标识符
     */
    function deactivateDevice(bytes32 did) external returns (bool success, string memory message) {
        require(
            devices[did].owner == msg.sender ||
            devices[did].userAddress == msg.sender ||
            users[msg.sender].role == UserRole.SYSTEM_ADMIN,
            "Not authorized to deactivate device"
        );
        require(devices[did].isActive, "Device already inactive");

        devices[did].isActive = false;

        emit DeviceDeactivated(did);

        return (true, "Device deactivated successfully");
    }

    /**
     * @dev 更新设备信息
     * @param did 设备的分布式标识符
     * @param name 新的设备名称
     * @param metadata 新的元数据哈希
     */
    function updateDeviceInfo(bytes32 did, string calldata name, bytes32 metadata)
        external returns (bool success, string memory message) {
        // 允许设备所有者或设备的用户或管理员更新设备信息
        require(
            devices[did].owner == msg.sender ||
            devices[did].userAddress == msg.sender ||
            users[msg.sender].role == UserRole.SYSTEM_ADMIN,
            "Not authorized to update device info"
        );
        require(devices[did].isActive, "Device is not active");

        devices[did].name = name;
        devices[did].metadata = metadata;

        return (true, "Device info updated successfully");
    }

    // =================================
    // 认证相关函数
    // =================================

    /**
     * @dev 生成认证挑战
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @return challenge 生成的挑战值
     * @return expiresAt 挑战过期时间
     */
    function generateAuthChallenge(bytes32 did, bytes32 networkId)
        external returns (bytes32 challenge, uint256 expiresAt) {
        // 简化验证
        require(devices[did].isActive, "Device is inactive");
        require(networks[networkId].isActive, "Network is inactive");

        // 使用更高效的方式生成挑战
        challenge = keccak256(abi.encodePacked(
            did,
            networkId,
            block.timestamp,
            blockhash(block.number - 1)
        ));

        // 记录挑战创建时间
        challengeTimestamps[challenge] = block.timestamp;
        expiresAt = block.timestamp + AUTH_CHALLENGE_EXPIRY;

        // 触发事件
        emit AuthChallengeGenerated(did, networkId, challenge, expiresAt);

        return (challenge, expiresAt);
    }

    /**
     * @dev 验证设备并发放访问令牌
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @param challenge 挑战值
     * @param signature 挑战的签名
     * @return tokenId 访问令牌ID
     */
    function authenticate(bytes32 did, bytes32 networkId, bytes32 challenge, bytes calldata signature)
        external returns (bytes32 tokenId) {
        // 验证调用者是网络所有者或授权的访问点
        require(
            networks[networkId].owner == msg.sender ||
            users[msg.sender].role == UserRole.SYSTEM_ADMIN ||
            users[msg.sender].role == UserRole.NETWORK_ADMIN,
            "Not authorized to authenticate"
        );

        // 验证设备和网络状态
        require(devices[did].isActive, "Device is inactive");
        require(networks[networkId].isActive, "Network is inactive");

        // 防重放攻击检查
        require(!usedChallenges[challenge], "Challenge already used");
        require(challengeTimestamps[challenge] > 0, "Unknown challenge");
        require(
            block.timestamp - challengeTimestamps[challenge] <= AUTH_CHALLENGE_EXPIRY,
            "Challenge expired"
        );

        // 立即标记挑战为已使用，无论认证是否成功
        usedChallenges[challenge] = true;

        // 检查访问权限
        bool hasAccess = deviceNetworkAccess[did][networkId];
        if (!hasAccess) {
            // 记录失败并立即返回
            _recordAuthenticationAttempt(did, networkId, challenge, false);
            revert("No access rights");
        }

        // 验证签名
        bool validSignature = verifySignature(did, challenge, signature);
        if (!validSignature) {
            // 记录失败并立即返回
            _recordAuthenticationAttempt(did, networkId, challenge, false);
            revert("Invalid signature");
        }

        // 认证成功 - 记录并发放令牌
        _recordAuthenticationAttempt(did, networkId, challenge, true);

        // 发放访问令牌
        tokenId = _issueToken(did);

        return tokenId;
    }

    /**
     * @dev 验证设备的签名
     * @param did 设备的分布式标识符
     * @param challenge 挑战值
     * @param signature 挑战的签名
     * @return 验证结果
     */
    function verifySignature(bytes32 did, bytes32 challenge, bytes calldata signature) public view returns (bool) {
        Device storage device = devices[did];
        require(device.owner != address(0), "Device not found");
        require(device.isActive, "Device is not active");

        // 优化签名长度检查
        if (signature.length != 65) return false;

        // 构建要验证的消息哈希
        bytes32 messageHash = keccak256(abi.encodePacked(did, challenge));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        // 高效从calldata提取签名组件
        uint8 v;
        bytes32 r;
        bytes32 s;

        assembly {
            // 从calldata直接读取，避免内存复制
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // 调整v值
        if (v < 27) v += 27;

        // 使用ecrecover
        address recoveredAddress = ecrecover(ethSignedMessageHash, v, r, s);

        // 计算设备公钥对应的地址
        address deviceAddress = publicKeyToAddress(device.publicKey);

        return recoveredAddress != address(0) && recoveredAddress == deviceAddress;
    }

    /**
     * @dev 记录认证尝试
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @param challenge 挑战值
     * @param success 是否成功
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
     * @dev 发放令牌
     * @param did 设备的分布式标识符
     * @return tokenId 令牌ID
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
     * @dev 验证访问令牌是否有效
     * @param tokenId 令牌ID
     * @return valid 令牌是否有效
     */
    function validateToken(bytes32 tokenId) external view returns (bool valid) {
        AccessToken storage token = accessTokens[tokenId];

        return (token.tokenId == tokenId &&
            !token.isRevoked &&
            block.timestamp <= token.expiresAt);
    }

    /**
     * @dev 撤销访问令牌
     * @param tokenId 令牌ID
     * @return success 是否成功
     * @return message 返回消息
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

        // 允许设备所有者、设备的用户、网络所有者或管理员撤销令牌
        bool isAuthorized =
            devices[did].owner == msg.sender ||
            devices[did].userAddress == msg.sender ||
            users[msg.sender].role == UserRole.SYSTEM_ADMIN ||
            users[msg.sender].role == UserRole.NETWORK_ADMIN;

        if (!isAuthorized) {
            return (false, "Not authorized to revoke token");
        }

        token.isRevoked = true;

        emit TokenRevoked(tokenId);

        return (true, "Token revoked successfully");
    }

    // =================================
    // 网络管理相关函数
    // =================================

    /**
     * @dev 创建新的无线网络
     * @param networkId 网络标识符
     * @param name 网络名称
     * @return success 是否成功
     * @return message 返回消息
     */
    function createNetwork(bytes32 networkId, string calldata name)
        external onlyActiveUser returns (bool success, string memory message) {
        if (networks[networkId].owner != address(0)) {
            return (false, "Network already exists");
        }

        networks[networkId] = Network({
            owner: msg.sender,
            networkId: networkId,
            name: name,
            createdAt: block.timestamp,
            isActive: true
        });

        ownerNetworks[msg.sender].push(networkId);

        // 将网络添加到用户的网络列表
        users[msg.sender].networks.push(networkId);

        emit NetworkCreated(networkId, msg.sender, name);

        return (true, "Network created successfully");
    }

    /**
     * @dev 授予设备访问网络的权限
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @return success 是否成功
     * @return message 返回消息
     */
    function grantAccess(bytes32 did, bytes32 networkId)
        external returns (bool success, string memory message) {
        // 验证权限：只有网络所有者或管理员可以授予访问权限
        bool isAuthorized =
            networks[networkId].owner == msg.sender ||
            users[msg.sender].role == UserRole.SYSTEM_ADMIN;

        if (!isAuthorized) {
            return (false, "Not authorized to grant access");
        }

        if (!devices[did].isActive) {
            return (false, "Device is not active");
        }

        if (!networks[networkId].isActive) {
            return (false, "Network is not active");
        }

        deviceNetworkAccess[did][networkId] = true;

        emit AccessGranted(did, networkId);

        return (true, "Access granted successfully");
    }

    /**
     * @dev 批量授予设备访问网络的权限
     * @param dids 设备DID数组
     * @param networkId 网络标识符
     * @return successCount 成功授权的设备数量
     */
    function batchGrantAccess(bytes32[] calldata dids, bytes32 networkId)
        external returns (uint256 successCount) {
        // 验证权限
        bool isAuthorized =
            networks[networkId].owner == msg.sender ||
            users[msg.sender].role == UserRole.SYSTEM_ADMIN;

        require(isAuthorized, "Not authorized to grant access");
        require(networks[networkId].isActive, "Network is not active");

        successCount = 0;

        for (uint i = 0; i < dids.length; i++) {
            if (devices[dids[i]].isActive) {
                deviceNetworkAccess[dids[i]][networkId] = true;
                emit AccessGranted(dids[i], networkId);
                successCount++;
            }
        }

        return successCount;
    }

    /**
     * @dev 撤销设备访问网络的权限
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @return success 是否成功
     * @return message 返回消息
     */
    function revokeAccess(bytes32 did, bytes32 networkId)
        external returns (bool success, string memory message) {
        // 验证权限
        bool isAuthorized =
            networks[networkId].owner == msg.sender ||
            users[msg.sender].role == UserRole.SYSTEM_ADMIN;

        if (!isAuthorized) {
            return (false, "Not authorized to revoke access");
        }

        deviceNetworkAccess[did][networkId] = false;

        emit AccessRevoked(did, networkId);

        return (true, "Access revoked successfully");
    }

    /**
     * @dev 检查设备是否有权访问网络
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @return hasAccess 是否有访问权限
     */
    function checkAccess(bytes32 did, bytes32 networkId)
        external view returns (bool hasAccess) {
        return deviceNetworkAccess[did][networkId];
    }

    // =================================
    // 审计日志相关函数
    // =================================

    /**
     * @dev 获取设备的认证日志数量
     * @param did 设备的分布式标识符
     * @return count 认证日志数量
     */
    function getAuthLogCount(bytes32 did) external view returns (uint256 count) {
        return authLogs[did].length;
    }

    /**
     * @dev 获取设备的特定认证日志
     * @param did 设备的分布式标识符
     * @param index 日志索引
     * @return verifier 验证者地址
     * @return challengeHash 挑战哈希
     * @return timestamp 认证时间
     * @return success 认证结果
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
     * @dev 分页获取设备的认证日志
     * @param did 设备的分布式标识符
     * @param offset 起始索引
     * @param limit 数量限制
     * @return verifiers 验证者地址数组
     * @return timestamps 时间戳数组
     * @return successes 认证结果数组
     */
    function getAuthLogs(bytes32 did, uint256 offset, uint256 limit)
        external view returns (
            address[] memory verifiers,
            uint256[] memory timestamps,
            bool[] memory successes
        ) {
        uint256 logCount = authLogs[did].length;

        if (offset >= logCount) {
            // 返回空数组
            return (new address[](0), new uint256[](0), new bool[](0));
        }

        // 计算实际要返回的日志数量
        uint256 count = logCount - offset;
        if (count > limit) {
            count = limit;
        }

        // 初始化返回数组
        verifiers = new address[](count);
        timestamps = new uint256[](count);
        successes = new bool[](count);

        // 填充数组
        for (uint256 i = 0; i < count; i++) {
            AuthLog storage log = authLogs[did][offset + i];
            verifiers[i] = log.verifier;
            timestamps[i] = log.timestamp;
            successes[i] = log.success;
        }

        return (verifiers, timestamps, successes);
    }

    // =================================
    // 工具函数
    // =================================

    /**
     * @dev 获取所有用户数量
     * @return count 用户数量
     */
    function getUserCount() external view returns (uint256 count) {
        return allUsers.length;
    }

    /**
     * @dev 获取分页的用户列表
     * @param offset 起始索引
     * @param limit 数量限制
     * @return userAddresses 用户地址数组
     * @return names 用户名称数组
     * @return isActives 是否活跃数组
     * @return roles 用户角色数组
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
     * @dev 获取用户拥有的设备列表
     * @param owner 设备所有者
     * @return devices 设备DID列表
     */
    function getOwnerDevices(address owner) external view returns (bytes32[] memory) {
        return ownerDevices[owner];
    }

    /**
     * @dev 获取用户的网络列表
     * @param owner 网络所有者
     * @return networks 网络ID列表
     */
    function getOwnerNetworks(address owner) external view returns (bytes32[] memory) {
        return ownerNetworks[owner];
    }

    /**
     * @dev 获取用户的设备列表
     * @param userAddress 用户地址
     * @return deviceIds 设备ID数组
     * @return deviceNames 设备名称数组
     * @return deviceTypes 设备类型数组
     * @return isActives 设备是否活跃数组
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

        for (uint256 i = 0; i < deviceCount; i++) {
            bytes32 did = user.devices[i];
            Device storage device = devices[did];

            deviceIds[i] = did;
            deviceNames[i] = device.name;
            deviceTypes[i] = device.deviceType;
            isActives[i] = device.isActive;
        }

        return (deviceIds, deviceNames, deviceTypes, isActives);
    }

    /**
     * @dev 检查用户是否已注册
     * @param user 用户地址
     * @return 是否已注册
     */
    function isRegisteredUser(address user) external view returns (bool) {
        return registeredUsers[user];
    }

    /**
     * @dev 清理过期的挑战记录
     * @param challenges 要清理的挑战值数组
     * @param batchSize 批处理大小
     * @return cleanedCount 已清理的挑战数量
     */
    function cleanupExpiredChallenges(bytes32[] calldata challenges, uint256 batchSize)
        external onlySystemAdmin returns (uint256 cleanedCount) {
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