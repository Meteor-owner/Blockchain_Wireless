// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Cryptographic Utility Library
 * @notice Provides signature verification and encryption-related functionality
 */
contract CryptoUtils {
    /**
     * @dev Convert public key to Ethereum address
     * @param publicKey Public key
     * @return Corresponding Ethereum address
     */
    function publicKeyToAddress(bytes memory publicKey) internal pure returns (address) {
        // Avoid additional memory allocation and loops
        bytes32 hash;

        // Directly process the public key, skip copy operations
        assembly {
            // If the public key starts with 0x04 (uncompressed format), skip the first byte
            let offset := 0
            if eq(byte(0, mload(add(publicKey, 32))), 0x04) {
                offset := 1
            }

            // Calculate keccak256 hash, avoid creating new memory
            hash := keccak256(add(add(publicKey, 32), offset), sub(mload(publicKey), offset))
        }

        // Extract address from hash (last 20 bytes)
        return address(uint160(uint256(hash)));
    }

    /**
     * @dev Recover signer address from signature
     * @param messageHash Message hash
     * @param signature Signature
     * @return Signer address
     */
    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        // Extract r, s, v from signature
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // If using new signature standard, adjust v value
        if (v < 27) {
            v += 27;
        }

        // Recover signer address
        return ecrecover(messageHash, v, r, s);
    }

    /**
     * @dev Construct message hash to be signed
     * @param deviceType Device type
     * @param did Device's decentralized identifier
     * @param publicKey Device's public key
     * @param name Device name
     * @param metadata Device metadata hash
     * @param owner Device owner
     * @return Message hash
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

        // Add Ethereum signature prefix (prevents signature from being used for other purposes)
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    }
}