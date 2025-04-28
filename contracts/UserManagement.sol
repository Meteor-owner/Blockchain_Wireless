// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseStructures.sol";
import "./CryptoUtils.sol";

/**
 * @title 用户管理合约
 * @notice 处理用户注册、登录和权限管理
 */
contract UserManagement is BaseStructures, CryptoUtils {
    // =================================
    // 存储映射
    // =================================

    mapping(address => User) internal users;                 // 用户地址 => 用户信息
    mapping(string => address) internal userNames;           // 用户名 => 用户地址 (用于检查名称唯一性)
    mapping(address => bool) internal registeredUsers;       // 记录已注册用户
    mapping(bytes => address) internal publicKeyAddressCache; // 缓存转换后的地址
    mapping(address => LoginChallenge) internal loginChallenges; // 用户地址 => 登录挑战
    mapping(bytes32 => RegistrationRequest) internal registrationRequests; // 注册请求ID => 注册请求
    mapping(address => bytes32[]) internal pendingRequests;  // 用户地址 => 待处理的注册请求

    address[] internal allUsers;                             // 所有用户地址数组

    // 系统管理员地址
    address public systemAdmin;

    // =================================
    // 事件定义
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

    // =================================
    // 构造函数
    // =================================

    /**
     * @dev 构造函数，设置系统管理员
     */
    constructor() {
        systemAdmin = msg.sender;
        registeredUsers[msg.sender] = true;

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

    /**
     * @dev 从公钥获取地址（带缓存）
     */
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
     * @dev 检查用户是否已注册
     * @param user 用户地址
     * @return 是否已注册
     */
    function isRegisteredUser(address user) external view returns (bool) {
        return registeredUsers[user];
    }

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
    ){

    }
}