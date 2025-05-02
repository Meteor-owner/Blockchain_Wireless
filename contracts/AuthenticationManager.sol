// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseStructures.sol";
import "./CryptoUtils.sol";
import "./DeviceManagement.sol";
import "./NetworkManagement.sol";

/**
 * @title 认证管理合约
 * @notice 处理设备认证、令牌管理和审计日志
 */
contract AuthenticationManager is BaseStructures, CryptoUtils {
    // =================================
    // 存储映射
    // =================================

    mapping(bytes32 => AccessToken) internal accessTokens;   // 令牌ID => 访问令牌
    mapping(bytes32 => AuthLog[]) internal authLogs;         // DID => 认证日志
    mapping(bytes32 => bool) internal usedChallenges;        // 已使用的挑战值 => 是否已使用
    mapping(bytes32 => uint256) internal challengeTimestamps; // 挑战值 => 创建时间戳
    mapping(bytes32 => bytes32) public latestChallenges; // DID => 最新挑战

    // 设备管理和网络管理合约实例
    DeviceManagement internal deviceManager;
    NetworkManagement internal networkManager;

    // =================================
    // 事件定义
    // =================================

    event AuthenticationAttempt(bytes32 indexed did, bytes32 indexed networkId, bool success);
    event TokenIssued(bytes32 indexed did, bytes32 indexed tokenId, uint256 expiresAt);
    event TokenRevoked(bytes32 indexed tokenId);
    event AuthChallengeGenerated(bytes32 indexed did, bytes32 indexed networkId, bytes32 challenge, uint256 expiresAt);

    // =================================
    // 构造函数
    // =================================

    /**
     * @dev 构造函数，设置设备管理和网络管理合约地址
     */
    constructor(address _deviceManagerAddress, address _networkManagerAddress) {
        deviceManager = DeviceManagement(_deviceManagerAddress);
        networkManager = NetworkManagement(_networkManagerAddress);
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
        // 生成随机挑战
        challenge = keccak256(abi.encodePacked(
            did,
            networkId,
            block.timestamp,
            blockhash(block.number - 1)
        ));

        // 记录挑战创建时间和最新挑战
//        challengeTimestamps[challenge] = block.timestamp + AUTH_CHALLENGE_EXPIRY;
//        latestChallenges[did] = challenge;  // 存储此DID的最新挑战
//        expiresAt = block.timestamp + AUTH_CHALLENGE_EXPIRY;
        expiresAt = block.timestamp + AUTH_CHALLENGE_EXPIRY;
        challengeTimestamps[challenge] = expiresAt;
        latestChallenges[did] = challenge;

        // 触发事件
        emit AuthChallengeGenerated(did, networkId, challenge, expiresAt);

        return (challenge, expiresAt);
    }

    function getLatestChallenge(bytes32 did) external view returns (bytes32, uint256) {
        bytes32 challenge = latestChallenges[did];
        uint256 timestamp = challengeTimestamps[challenge];
        return (challenge, timestamp);
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
        // 防重放攻击检查
        require(!usedChallenges[challenge], "Challenge already used");
        require(challengeTimestamps[challenge] > 0, "Unknown challenge");

        require(
            block.timestamp <= challengeTimestamps[challenge],
            "Challenge expired"
        );

        // 立即标记挑战为已使用，无论认证是否成功
        usedChallenges[challenge] = true;

        // 检查访问权限
        bool hasAccess = networkManager.checkAccess(did, networkId);
        if (!hasAccess) {
            // 记录失败并立即返回
            _recordAuthenticationAttempt(did, networkId, challenge, false);
            revert("No access rights");
        }

        // 验证签名
        (
            bytes32 deviceType,
            address owner,
            bytes memory publicKey,
            uint256 registeredAt,
            bool isActive,
            string memory name,
            bytes32 metadata,
            address authorizedBy,
            address userAddress
        ) = deviceManager.getDeviceInfo(did);

        // 检查设备是否活跃
        if (!isActive) {
            _recordAuthenticationAttempt(did, networkId, challenge, false);
            revert("Device is inactive");
        }

        // 构建要验证的消息哈希
        bytes32 messageHash = keccak256(abi.encodePacked(did, challenge));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        // 验证签名
        address recoveredAddress = recoverSigner(ethSignedMessageHash, signature);
        address deviceAddress = publicKeyToAddress(publicKey);

        bool validSignature = (recoveredAddress != address(0) && recoveredAddress == deviceAddress);

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

        // 获取设备信息，检查权限
        (
            ,  // deviceType (不需要)
            address owner,
            ,  // publicKey (不需要)
            ,  // registeredAt (不需要)
            ,  // isActive (不需要)
            ,  // name (不需要)
            ,  // metadata (不需要)
            ,  // authorizedBy (不需要)
            address userAddress
        ) = deviceManager.getDeviceInfo(did);

        // 允许设备所有者或设备的用户撤销令牌
        bool isAuthorized = (owner == msg.sender || userAddress == msg.sender);

        if (!isAuthorized) {
            return (false, "Not authorized to revoke token");
        }

        token.isRevoked = true;

        emit TokenRevoked(tokenId);

        return (true, "Token revoked successfully");
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

    /**
     * @dev 清理过期的挑战记录
     * @param challenges 要清理的挑战值数组
     * @param batchSize 批处理大小
     * @return cleanedCount 已清理的挑战数量
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