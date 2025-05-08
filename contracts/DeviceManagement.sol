// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseStructures.sol";
import "./CryptoUtils.sol";
import "./UserManagement.sol";

/**
 * @title 设备管理合约
 * @notice 处理设备注册、更新、停用等功能
 */
contract DeviceManagement is BaseStructures, CryptoUtils {
    // =================================
    // 存储映射
    // =================================

    mapping(bytes32 => Device) internal devices;             // DID => 设备
    mapping(address => bytes32[]) internal ownerDevices;     // 所有者 => DIDs
    mapping(bytes32 => mapping(bytes32 => bool)) internal deviceNetworkAccess; // DID => 网络ID => 有无访问权限
    mapping(bytes32 => bool) internal usedChallenges;        // 已使用的挑战值 => 是否已使用
    mapping(bytes32 => uint256) internal challengeTimestamps; // 挑战值 => 创建时间戳

    // 用户管理合约实例
    UserManagement internal userManager;

    // =================================
    // 事件定义
    // =================================

    event DeviceRegistered(bytes32 indexed did, address indexed owner, bytes32 deviceType, string name, address authorizedBy);
    event DeviceAssignedToUser(bytes32 indexed did, address indexed userAddress);
    event DeviceDeactivated(bytes32 indexed did);
    event RegistrationChallenge(bytes32 indexed did, bytes32 challenge, uint256 expiresAt);
    event RegistrationVerified(bytes32 indexed did);
    event DeviceTransferred(bytes32 indexed did, address indexed fromUser, address indexed toUser);

    // =================================
    // 修饰器
    // =================================

    /**
     * @dev 只允许设备所有者调用
     */
    modifier onlyDeviceOwner(bytes32 did) {
        require(devices[did].owner == msg.sender, "Only device owner can perform this action");
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
     * @dev 构造函数，设置用户管理合约地址
     */
    constructor(address _userManagerAddress) {
        userManager = UserManagement(_userManagerAddress);
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
        bytes calldata signature,
        address sender
    ) external onlyActiveUser (sender) returns (bool success, string memory message) {
        if (devices[did].owner != address(0)) {
            return (false, "Device already registered");
        }

        if (publicKey.length == 0) {
            return (false, "Invalid public key");
        }

        address authorizer;

        // 这里简化处理，假设用户可以自行注册设备
        authorizer = msg.sender;

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

        // 将设备添加到用户的设备列表（此函数需要在用户管理合约中实现）
        // 这里可能需要调整实现方式，或者通过事件通知用户管理合约

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
            userAddress: msg.sender
        });

        // 更新索引
        ownerDevices[msg.sender].push(did);

        // 为新注册的设备生成注册挑战，用于验证设备确实拥有私钥
        bytes32 challenge = _generateChallenge("registration", did, bytes32(0));
        challengeTimestamps[challenge] = block.timestamp;

        // 触发事件
        emit DeviceRegistered(did, msg.sender, deviceType, name, authorizedBy);
        emit RegistrationChallenge(did, challenge, block.timestamp + AUTH_CHALLENGE_EXPIRY);

        return true;
    }

    /**
     * @dev 转移设备所有权
     * @param did 设备ID
     * @param newOwner 新所有者地址
     */
    function transferDevice(bytes32 did, address newOwner)
        external onlyDeviceOwner(did) returns (bool success, string memory message) {
        // 验证新所有者是活跃用户
        require(userManager.isRegisteredUser(newOwner), "New owner must be registered user");

        // 保存原始所有者信息用于事件
        address originalOwner = devices[did].owner;
        address originalUserAddress = devices[did].userAddress;

        // 从原所有者的设备列表中移除
        _removeDeviceFromOwner(did, originalOwner);

        // 更新设备所有者
        devices[did].owner = newOwner;
        devices[did].userAddress = newOwner;

        // 将设备添加到新所有者的设备列表
        ownerDevices[newOwner].push(did);

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
            devices[did].userAddress == msg.sender,
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
        // 允许设备所有者或设备的用户更新设备信息
        require(
            devices[did].owner == msg.sender ||
            devices[did].userAddress == msg.sender,
            "Not authorized to update device info"
        );
        require(devices[did].isActive, "Device is not active");

        devices[did].name = name;
        devices[did].metadata = metadata;

        return (true, "Device info updated successfully");
    }

    /**
     * @dev 获取用户拥有的设备列表
     * @param owner 设备所有者
     * @return devices 设备DID列表
     */
    function getOwnerDevices(address owner) external view returns (bytes32[] memory) {
        return ownerDevices[owner];
    }
}