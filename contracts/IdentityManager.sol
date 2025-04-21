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
    
    // 事件
    event DeviceRegistered(bytes32 indexed did, address indexed owner, bytes32 deviceType);
    event DeviceDeactivated(bytes32 indexed did);
    event NetworkCreated(bytes32 indexed networkId, address indexed owner, string name);
    event AccessGranted(bytes32 indexed did, bytes32 indexed networkId);
    event AccessRevoked(bytes32 indexed did, bytes32 indexed networkId);
    event AuthenticationAttempt(bytes32 indexed did, bytes32 indexed networkId, bool success);
    event TokenIssued(bytes32 indexed did, bytes32 indexed tokenId, uint256 expiresAt);
    event TokenRevoked(bytes32 indexed tokenId);

    /**
     * @dev 注册新设备
     * @param deviceType 设备类型
     * @param did 设备的分布式标识符
     * @param publicKey 设备的公钥
     */
    function registerDevice(bytes32 deviceType, bytes32 did, bytes calldata publicKey) external {
        require(devices[did].owner == address(0), "Device already registered");
        
        devices[did] = Device({
            owner: msg.sender,
            deviceType: deviceType,
            did: did,
            publicKey: publicKey,
            registeredAt: block.timestamp,
            isActive: true
        });
        
        ownerDevices[msg.sender].push(did);
        
        emit DeviceRegistered(did, msg.sender, deviceType);
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
        // 在实际实现中，这里应该使用ECDSA进行签名验证
        // 此示例简化了这一过程
        return true; // 假设始终验证成功
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
        require(devices[did].isActive, "Device is not active");
        require(networks[networkId].isActive, "Network is not active");
        
        bool hasAccess = deviceNetworkAccess[did][networkId];
        bool validSignature = false;
        
        if (hasAccess) {
            validSignature = verifySignature(did, challenge, signature);
        }
        
        // 记录认证尝试
        authLogs[did].push(AuthLog({
            did: did,
            verifier: msg.sender,
            challengeHash: challenge,
            timestamp: block.timestamp,
            success: validSignature && hasAccess
        }));
        
        emit AuthenticationAttempt(did, networkId, validSignature && hasAccess);
        
        if (validSignature && hasAccess) {
            // 发放访问令牌
            bytes32 tokenId = keccak256(abi.encodePacked(did, block.timestamp, blockhash(block.number - 1)));
            uint256 expiresAt = block.timestamp + 1 days; // 默认24小时有效期
            
            accessTokens[tokenId] = AccessToken({
                did: did,
                tokenId: tokenId,
                issuedAt: block.timestamp,
                expiresAt: expiresAt,
                isRevoked: false
            });
            
            emit TokenIssued(did, tokenId, expiresAt);
            
            return tokenId;
        } else {
            revert("Authentication failed");
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
     */
    function getDeviceInfo(bytes32 did) external view returns (
        bytes32 deviceType,
        address owner,
        bytes memory publicKey,
        uint256 registeredAt,
        bool isActive
    ) {
        Device storage device = devices[did];
        require(device.owner != address(0), "Device not found");
        
        return (
            device.deviceType,
            device.owner,
            device.publicKey,
            device.registeredAt,
            device.isActive
        );
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