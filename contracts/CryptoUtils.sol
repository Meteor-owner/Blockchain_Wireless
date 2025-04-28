// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title 加密工具库
 * @notice 提供签名验证和加密相关功能
 */
contract CryptoUtils {
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
}