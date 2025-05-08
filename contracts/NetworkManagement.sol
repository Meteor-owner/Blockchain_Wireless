// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseStructures.sol";
import "./UserManagement.sol";

/**
 * @title 网络管理合约
 * @notice 处理无线网络的创建、访问权限管理等功能
 */
contract NetworkManagement is BaseStructures {
    // =================================
    // 存储映射
    // =================================

    mapping(bytes32 => Network) internal networks;           // 网络ID => 网络
    mapping(address => bytes32[]) internal ownerNetworks;    // 所有者 => 网络IDs
    mapping(bytes32 => mapping(bytes32 => bool)) internal deviceNetworkAccess; // DID => 网络ID => 有无访问权限

    // 用户管理合约实例
    UserManagement internal userManager;

    // 系统默认网络
    bytes32 public defaultNetworkId;
    string public defaultNetworkName = "Default WiFi Network";

    // =================================
    // 事件定义
    // =================================

    event NetworkCreated(bytes32 indexed networkId, address indexed owner, string name);
    event AccessGranted(bytes32 indexed did, bytes32 indexed networkId);
    event AccessRevoked(bytes32 indexed did, bytes32 indexed networkId);

    // =================================
    // 修饰器
    // =================================

    /**
     * @dev 只允许网络所有者调用
     */
    modifier onlyNetworkOwner(bytes32 networkId) {
        require(networks[networkId].owner == msg.sender, "Only network owner can perform this action");
        _;
    }

    /**
     * @dev 只允许已注册且活跃的用户调用
     */
    modifier onlyActiveUser(address sender) {
        require(userManager.isRegisteredUser(sender), "Requires registered user");
        _;
    }

    // =================================
    // 构造函数
    // =================================

    /**
     * @dev 构造函数，设置用户管理合约地址和创建默认网络
     */
    constructor(address _userManagerAddress) {
        userManager = UserManagement(_userManagerAddress);

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
     * @dev 授予设备访问网络的权限
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @return success 是否成功
     * @return message 返回消息
     */
    function grantAccess(bytes32 did, bytes32 networkId, address sender)
        external returns (bool success, string memory message) {
        // 验证权限：只有网络所有者可以授予访问权限
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
     * @dev 批量授予设备访问网络的权限
     * @param dids 设备DID数组
     * @param networkId 网络标识符
     * @return successCount 成功授权的设备数量
     */
    function batchGrantAccess(bytes32[] calldata dids, bytes32 networkId)
        external returns (uint256 successCount) {
        // 验证权限
        bool isAuthorized = networks[networkId].owner == msg.sender;

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
     * @dev 撤销设备访问网络的权限
     * @param did 设备的分布式标识符
     * @param networkId 网络标识符
     * @return success 是否成功
     * @return message 返回消息
     */
    function revokeAccess(bytes32 did, bytes32 networkId)
        external returns (bool success, string memory message) {
        // 验证权限
        bool isAuthorized = networks[networkId].owner == msg.sender;

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

    /**
     * @dev 获取用户的网络列表
     * @param owner 网络所有者
     * @return networks 网络ID列表
     */
    function getOwnerNetworks(address owner) external view returns (bytes32[] memory) {
        return ownerNetworks[owner];
    }
}