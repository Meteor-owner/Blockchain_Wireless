// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IdentityManager
 * @dev 管理无线网络中设备身份验证的智能合约
 */
contract IdentityManager {
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

    // 存储映射
    mapping(bytes32 => Device) private devices;            // DID => 设备
    mapping(address => bytes32[]) private ownerDevices;    // 所有者 => DIDs
    mapping(bytes32 => Network) private networks;          // 网络ID => 网络
    mapping(address => bytes32[]) private ownerNetworks;   // 所有者 => 网络IDs
    mapping(bytes32 => mapping(bytes32 => bool)) private deviceNetworkAccess; // DID => 网络ID => 有无访问权限
    mapping(bytes32 => AccessToken) private accessTokens;  // 令牌ID => 访问令牌
    mapping(bytes32 => AuthLog[]) private authLogs;        // DID => 认证日志
    mapping(address => bool) private registeredUsers;      // 记录已注册用户
    mapping(bytes => address) private publicKeyAddressCache; //缓存转换后的地址

    // 事件
    event DeviceRegistered(bytes32 indexed did, address indexed owner, bytes32 deviceType, string name, address authorizedBy);
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

    // 存储注册挑战
    mapping(bytes32 => bytes32) private registrationChallenges;
    mapping(bytes32 => uint256) private challengeExpiry;
    // 存储已使用的挑战值，防止重放攻击
    mapping(bytes32 => bool) private usedChallenges;
    // 设置挑战值的过期时间
    uint256 private constant CHALLENGE_EXPIRY = 15 minutes;
    // 存储挑战值的创建时间
    mapping(bytes32 => uint256) private challengeTimestamps;

    // 注册验证超时时间（默认10分钟）
    uint256 private constant CHALLENGE_TIMEOUT = 10 minutes;

    // 系统管理员地址（可以直接注册而不需要授权）
    address public systemAdmin;

    // 系统默认网络
    bytes32 public defaultNetworkId;
    string public defaultNetworkName = "Default WiFi Network";

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
    }

    /**
     * @dev 修改系统管理员
     * @param newAdmin 新的管理员地址
     */
    function changeSystemAdmin(address newAdmin) external {
        require(msg.sender == systemAdmin, "Only admin can change admin");
        require(newAdmin != address(0), "Invalid address");
        systemAdmin = newAdmin;
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
     * @dev 注册新设备（新用户注册，需要老用户签名）
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
    ) external returns (bool success, string memory message) {
        if (devices[did].owner != address(0)) {
            return (false, "Device already registered");
        }

        if (publicKey.length == 0) {
            return (false, "Invalid public key");
        }

        address authorizer;

        if (msg.sender == systemAdmin) {
            authorizer = systemAdmin;
        } else {
            bytes32 messageHash = getSignatureMessageHash(deviceType, did, publicKey, name, metadata, msg.sender);
            authorizer = recoverSigner(messageHash, signature);

            if (!registeredUsers[authorizer]) {
                return (false, "Authorizer not registered");
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
            return (false, "Device already registered");
        }

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
            authorizedBy: authorizedBy
        });

        // 更新索引
        ownerDevices[msg.sender].push(did);

        // 标记用户为已注册用户
        registeredUsers[msg.sender] = true;

        // 为新注册的设备生成注册挑战，用于验证设备确实拥有私钥
        bytes32 challenge = _generateChallenge("registration", did, bytes32(0));
        registrationChallenges[did] = challenge;
        challengeExpiry[did] = block.timestamp + CHALLENGE_TIMEOUT;

        // 触发事件
        emit DeviceRegistered(did, msg.sender, deviceType, name, authorizedBy);
        emit RegistrationChallenge(did, challenge, challengeExpiry[did]);

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
     * @dev 验证设备注册（防止伪造私钥）
     * @param did 设备的分布式标识符
     * @param signature 对挑战的签名
     */
    function verifyRegistration(bytes32 did, bytes calldata signature) external {
        require(devices[did].owner == msg.sender, "Not device owner");
        require(block.timestamp <= challengeExpiry[did], "Challenge expired");
        require(registrationChallenges[did] != bytes32(0), "No pending challenge");

        bytes32 challenge = registrationChallenges[did];
        bool isValid = verifySignature(did, challenge, signature);

        require(isValid, "Invalid signature");

        // 清除挑战
        delete registrationChallenges[did];
        delete challengeExpiry[did];

        emit RegistrationVerified(did);

        // 为验证成功的设备颁发初始访问令牌
        issueInitialToken(did);
    }

    /**
     * @dev 为新验证的设备颁发初始访问令牌
     * @param did 设备的分布式标识符
     */
    function issueInitialToken(bytes32 did) internal returns (bytes32) {
        // 生成令牌ID
        bytes32 tokenId = keccak256(abi.encodePacked("initial", did, msg.sender, block.timestamp));
        uint256 expiresAt = block.timestamp + 1 days; // 24小时有效期

        // 创建令牌
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
     * @dev 获取设备的注册挑战
     * @param did 设备的分布式标识符
     * @return challenge 挑战值
     * @return expiresAt 过期时间
     */
    function getRegistrationChallenge(bytes32 did) external view returns (bytes32 challenge, uint256 expiresAt) {
        require(devices[did].owner == msg.sender, "Not device owner");
        require(block.timestamp <= challengeExpiry[did], "Challenge expired");

        return (registrationChallenges[did], challengeExpiry[did]);
    }

    /**
     * @dev 停用设备
     * @param did 设备的分布式标识符
     */
    function deactivateDevice(bytes32 did) external {
        require(devices[did].owner == msg.sender, "Not device owner");
        require(devices[did].isActive, "Device already inactive");

        devices[did].isActive = false;

        emit DeviceDeactivated(did);
    }

    /**
     * @dev 创建新的无线网络
     * @param networkId 网络标识符
     * @param name 网络名称
     */
    function createNetwork(bytes32 networkId, string calldata name) external {
        require(networks[networkId].owner == address(0), "Network already exists");

        networks[networkId] = Network({
            owner: msg.sender,
            networkId: networkId,
            name: name,
            createdAt: block.timestamp,
            isActive: true
        });

        ownerNetworks[msg.sender].push(networkId);

        emit NetworkCreated(networkId, msg.sender, name);
    }

    /**
     * @dev 授予设备访问网络的权限
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     */
    function grantAccess(bytes32 did, bytes32 networkId) external {
        require(networks[networkId].owner == msg.sender, "Not network owner");
        require(devices[did].isActive, "Device is not active");
        require(networks[networkId].isActive, "Network is not active");

        deviceNetworkAccess[did][networkId] = true;

        emit AccessGranted(did, networkId);
    }

    /**
     * @dev 批量授予设备访问网络的权限
     * @param dids 设备DID数组
     * @param networkId 网络标识符
     */
    function batchGrantAccess(bytes32[] calldata dids, bytes32 networkId) external {
        require(networks[networkId].owner == msg.sender, "Not network owner");
        require(networks[networkId].isActive, "Network is not active");

        for (uint i = 0; i < dids.length; i++) {
            if (devices[dids[i]].isActive) {
                deviceNetworkAccess[dids[i]][networkId] = true;
                emit AccessGranted(dids[i], networkId);
            }
        }
    }

    /**
     * @dev 撤销设备访问网络的权限
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     */
    function revokeAccess(bytes32 did, bytes32 networkId) external {
        require(networks[networkId].owner == msg.sender, "Not network owner");

        deviceNetworkAccess[did][networkId] = false;

        emit AccessRevoked(did, networkId);
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

        // 构建要验证的消息哈希 - 使用更高效的方法
//        bytes32 messageHash = keccak256(abi.encodePacked(did, challenge));
//        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
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
     * @dev 生成认证挑战
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @return 生成的挑战值
     */
    function generateAuthChallenge(bytes32 did, bytes32 networkId) external returns (bytes32) {
        // 简化验证
        if (!devices[did].isActive || !networks[networkId].isActive) {
            revert("Device or network inactive");
        }

        // 使用更高效的方式生成挑战
        bytes32 challenge = keccak256(abi.encodePacked(did, networkId, block.timestamp, blockhash(block.number - 1)));

        // 记录挑战
        challengeTimestamps[challenge] = block.timestamp;

        // 触发事件
        emit AuthChallengeGenerated(did, networkId, challenge, block.timestamp + CHALLENGE_EXPIRY);

        return challenge;
    }

    /**
     * @dev 验证设备并发放访问令牌
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @param challenge 挑战值
     * @param signature 挑战的签名
     * @return tokenId 访问令牌ID
     */
    function authenticate(bytes32 did, bytes32 networkId, bytes32 challenge, bytes calldata signature) external returns (bytes32) {
        require(networks[networkId].owner == msg.sender, "Not network owner or authorized AP");

        // 只检查必要的条件
        if (!devices[did].isActive || !networks[networkId].isActive) {
            revert("Device or network inactive");
        }

        // 防重放攻击检查 - 优化顺序，首先检查最可能快速失败的条件
        if (usedChallenges[challenge]) revert("Challenge already used");
        if (challengeTimestamps[challenge] == 0) revert("Unknown challenge");
        if (block.timestamp - challengeTimestamps[challenge] > CHALLENGE_EXPIRY) revert("Challenge expired");

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
        bytes32 tokenId = _issueToken(did);

        return tokenId;
    }

    /**
     * @dev 记录认证尝试
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @param challenge 挑战值
     */
    function _recordAuthenticationAttempt(bytes32 did, bytes32 networkId, bytes32 challenge, bool success) internal {
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
     * @return tokenId
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
     * @dev 定期清理过期的挑战记录，减少存储空间使用（可由管理员调用）
     * @param challenges 要清理的挑战值数组
     */
    function cleanupExpiredChallenges(bytes32[] calldata challenges, uint256 batchSize) external {
        require(msg.sender == systemAdmin, "Only admin can cleanup");

        uint256 count = challenges.length < batchSize ? challenges.length : batchSize;

        for (uint i = 0; i < count; i++) {
            bytes32 challenge = challenges[i];
            if (block.timestamp - challengeTimestamps[challenge] > CHALLENGE_EXPIRY) {
                delete challengeTimestamps[challenge];
                delete usedChallenges[challenge];
            }
        }
    }

    /**
     * @dev 验证访问令牌是否有效
     * @param tokenId 令牌ID
     * @return 令牌是否有效
     */
    function validateToken(bytes32 tokenId) external view returns (bool) {
        AccessToken storage token = accessTokens[tokenId];

        return (token.tokenId == tokenId &&
            !token.isRevoked &&
            block.timestamp <= token.expiresAt);
    }

    /**
     * @dev 撤销访问令牌
     * @param tokenId 令牌ID
     */
    function revokeToken(bytes32 tokenId) external {
        AccessToken storage token = accessTokens[tokenId];
        bytes32 did = token.did;

        require(token.tokenId == tokenId, "Token does not exist");
        require(!token.isRevoked, "Token already revoked");
        require(devices[did].owner == msg.sender ||
        networks[tokenId].owner == msg.sender,
            "Not authorized to revoke");

        token.isRevoked = true;

        emit TokenRevoked(tokenId);
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
     */
    function getDeviceInfo(bytes32 did) external view returns (
        bytes32 deviceType,
        address owner,
        bytes memory publicKey,
        uint256 registeredAt,
        bool isActive,
        string memory name,
        bytes32 metadata,
        address authorizedBy
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
            device.authorizedBy
        );
    }

    /**
     * @dev 更新设备信息
     * @param did 设备的分布式标识符
     * @param name 新的设备名称
     * @param metadata 新的元数据哈希
     */
    function updateDeviceInfo(bytes32 did, string calldata name, bytes32 metadata) external {
        require(devices[did].owner == msg.sender, "Not device owner");
        require(devices[did].isActive, "Device is not active");

        devices[did].name = name;
        devices[did].metadata = metadata;
    }

    /**
     * @dev 获取用户的设备列表
     * @param owner 设备所有者
     * @return 设备DID列表
     */
    function getOwnerDevices(address owner) external view returns (bytes32[] memory) {
        return ownerDevices[owner];
    }

    /**
     * @dev 获取用户的网络列表
     * @param owner 网络所有者
     * @return 网络ID列表
     */
    function getOwnerNetworks(address owner) external view returns (bytes32[] memory) {
        return ownerNetworks[owner];
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
     * @dev 检查设备是否有权访问网络
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @return 是否有访问权限
     */
    function checkAccess(bytes32 did, bytes32 networkId) external view returns (bool) {
        return deviceNetworkAccess[did][networkId];
    }

    /**
     * @dev 获取设备的认证日志数量
     * @param did 设备的分布式标识符
     * @return 认证日志数量
     */
    function getAuthLogCount(bytes32 did) external view returns (uint256) {
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
}