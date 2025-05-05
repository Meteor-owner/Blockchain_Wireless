// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title 基础数据结构和常量定义
 * @notice 包含所有可以复用的数据结构定义
 */
contract BaseStructures {
    // =================================
    // 数据结构定义
    // =================================

    // 用户角色类型
    enum UserRole {
        NONE,           // 未注册pip
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
    // 常量定义
    // =================================

    // 挑战过期时间
    uint256 internal constant LOGIN_CHALLENGE_EXPIRY = 5 minutes;
    uint256 internal constant AUTH_CHALLENGE_EXPIRY = 15 minutes;
    uint256 internal constant REGISTRATION_REQUEST_EXPIRY = 7 days;
}