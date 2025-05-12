// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseStructures.sol";
import "./UserManagement.sol";
import "./DeviceManagement.sol";
import "./NetworkManagement.sol";
import "./AuthenticationManager.sol";

/**
 * @title 区块链无线网络身份验证系统主合约
 * @notice 集成用户、设备、网络和认证管理的主合约接口
 * @dev 此合约作为统一入口，引用各个功能模块合约
 */
contract BlockchainAuthMain is BaseStructures {
    // 子合约实例
    UserManagement public userManager;
    DeviceManagement public deviceManager;
    NetworkManagement public networkManager;
    AuthenticationManager public authManager;

    // 系统管理员地址
    address public systemAdmin;

    // 系统配置
    uint256 public deploymentTimestamp;
    string public version = "1.0.0";
    string public name = "Blockchain Auth System";

    event AuthChallengeGenerated(bytes32 indexed did, bytes32 indexed networkId, bytes32 challenge, uint256 expiresAt);
    event TokenIssued(bytes32 indexed did, bytes32 indexed tokenId, uint256 expiresAt);

    /**
     * @dev 构造函数，部署并初始化所有子合约
     */
    constructor() {
        // 记录系统管理员和部署时间
        systemAdmin = msg.sender;
        deploymentTimestamp = block.timestamp;

        // 部署子合约
        userManager = new UserManagement(systemAdmin);
        deviceManager = new DeviceManagement(address(userManager));
        networkManager = new NetworkManagement(address(userManager));
        authManager = new AuthenticationManager(
            address(deviceManager),
            address(networkManager)
        );
    }

    // =================================
    // 用户管理相关委托函数
    // =================================

    /**
     * @dev 注册新用户
     */
    function registerUser(
        string calldata name,
        string calldata email,
        bytes calldata publicKey,
        bytes calldata signature
    ) external returns (bool success, string memory message) {
        return userManager.registerUser(name, email, publicKey, signature, msg.sender);
    }

    /**
     * @dev 更新用户信息
     */
    function updateUserInfo(
        string calldata name,
        string calldata email,
        bytes calldata publicKey
    ) external returns (bool success, string memory message) {
        return userManager.updateUserInfo(name, email, publicKey,msg.sender);
    }

    /**
     * @dev 获取用户信息
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
        return userManager.getUserInfo(userAddress);
    }

    /**
     * @dev A user checks if they are registered
     */
    function isRegisteredUser(address user) external view returns (bool) {
        return userManager.isRegisteredUser(user);
    }

    /**
     * @dev 获取所有用户数量
     */
    function getUserCount() external view returns (uint256 count) {
        return userManager.getUserCount();
    }

    /**
     * @dev 获取分页的用户列表
     */
    function getUserList(uint256 offset, uint256 limit) external view returns (
        address[] memory userAddresses,
        string[] memory names,
        bool[] memory isActives,
        UserRole[] memory roles
    ) {
        return userManager.getUserList(offset, limit);
    }

    // =================================
    // 设备管理相关委托函数
    // =================================

    /**
     * @dev 注册新设备
     */
    function registerDevice(
        bytes32 deviceType,
        bytes32 did,
        bytes calldata publicKey,
        string calldata name,
        bytes32 metadata,
        bytes calldata signature
    ) external returns (bool success, string memory message) {
        return deviceManager.registerDevice(deviceType, did, publicKey, name, metadata, signature, msg.sender);
    }

    /**
     * @dev 获取设备信息
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
        return deviceManager.getDeviceInfo(did);
    }

    /**
     * @dev 更新设备信息
     */
    function updateDeviceInfo(bytes32 did, string calldata name, bytes32 metadata)
    external returns (bool success, string memory message) {
        return deviceManager.updateDeviceInfo(did, name, metadata);
    }

    /**
     * @dev 停用设备
     */
    function deactivateDevice(bytes32 did) external returns (bool success, string memory message) {
        return deviceManager.deactivateDevice(did);
    }

    /**
     * @dev 获取用户拥有的设备列表
     */
    function getOwnerDevices(address owner) external view returns (bytes32[] memory) {
        return deviceManager.getOwnerDevices(owner);
    }

    /**
     * @dev 转移设备所有权
     */
    function transferDevice(bytes32 did, address newOwner)
    external returns (bool success, string memory message) {
        return deviceManager.transferDevice(did, newOwner);
    }

    // =================================
    // 网络管理相关委托函数
    // =================================

    /**
     * @dev 创建新的无线网络
     */
    function createNetwork(bytes32 networkId, string calldata name)
    external returns (bool success, string memory message) {
        return networkManager.createNetwork(msg.sender, networkId, name);
    }

    /**
     * @dev 授予设备访问网络的权限
     */
    function grantAccess(bytes32 did, bytes32 networkId)
    external returns (bool success, string memory message) {
        return networkManager.grantAccess(did, networkId, msg.sender);
    }

    /**
     * @dev 批量授予设备访问网络的权限
     */
    function batchGrantAccess(bytes32[] calldata dids, bytes32 networkId)
    external returns (uint256 successCount) {
        return networkManager.batchGrantAccess(dids, networkId,msg.sender);
    }

    /**
     * @dev 撤销设备访问网络的权限
     */
    function revokeAccess(bytes32 did, bytes32 networkId)
    external returns (bool success, string memory message) {
        return networkManager.revokeAccess(did, networkId);
    }

    /**
     * @dev 检查设备是否有权访问网络
     */
    function checkAccess(bytes32 did, bytes32 networkId)
    external view returns (bool hasAccess) {
        return networkManager.checkAccess(did, networkId);
    }

    /**
     * @dev 获取用户的网络列表
     */
    function getOwnerNetworks(address owner) external view returns (bytes32[] memory) {
        return networkManager.getOwnerNetworks(owner);
    }

    // =================================
    // 认证相关委托函数
    // =================================

    /**
     * @dev 生成认证挑战
     */
    function generateAuthChallenge(bytes32 did, bytes32 networkId)
    external returns (bytes32 challenge, uint256 expiresAt) {
        (bytes32 _challenge, uint256 _expiresAt) = authManager.generateAuthChallenge(did, networkId);

//        emit AuthChallengeGenerated(did, networkId, _challenge, _expiresAt);

        return (_challenge, _expiresAt);
    }

    /**
     * @dev 获取设备的最新认证挑战
     */
    function getLatestChallenge(bytes32 did) external view returns (bytes32 challenge, uint256 timestamp) {
        return authManager.getLatestChallenge(did);
    }

    /**
     * @dev 验证设备并发放访问令牌
     */
    function authenticate(bytes32 did, bytes32 networkId, bytes32 challenge, bytes calldata signature)
    external returns (bytes32 tokenId) {
        bytes32 tokenId=authManager.authenticate(did, networkId, challenge, signature);
        uint256 expiresAt = block.timestamp + 1 days;
        emit TokenIssued(did, tokenId, expiresAt);
        return tokenId;
    }

    /**
     * @dev 验证访问令牌是否有效
     */
    function validateToken(bytes32 tokenId) external view returns (bool valid) {
        return authManager.validateToken(tokenId);
    }

    /**
     * @dev 撤销访问令牌
     */
    function revokeToken(bytes32 tokenId) external returns (bool success, string memory message) {
        return authManager.revokeToken(tokenId);
    }

    /**
     * @dev 获取设备的认证日志数量
     */
    function getAuthLogCount(bytes32 did) external view returns (uint256 count) {
        return authManager.getAuthLogCount(did);
    }

    /**
     * @dev 获取设备的特定认证日志
     */
    function getAuthLog(bytes32 did, uint256 index) external view returns (
        address verifier,
        bytes32 challengeHash,
        uint256 timestamp,
        bool success
    ) {
        return authManager.getAuthLog(did, index);
    }

    /**
     * @dev 分页获取设备的认证日志
     */
    function getAuthLogs(bytes32 did, uint256 offset, uint256 limit)
    external view returns (
        address[] memory verifiers,
        uint256[] memory timestamps,
        bool[] memory successes
    ) {
        return authManager.getAuthLogs(did, offset, limit);
    }
}