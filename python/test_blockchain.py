"""
区块链无线网络身份验证系统 - Python 接口测试
CSEC5615 云安全项目 - 更新版本
基于Blockchain_Auth.sol合约
"""

import json
import os
import time
import hashlib
import ecdsa
import uuid
import base64
import binascii
import traceback
from typing import Dict, List, Tuple, Any
from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
from eth_account.messages import encode_defunct
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()


class BlockChainClient:
    """与Blockchain_Auth智能合约的Python接口"""

    def __init__(self, network="localhost", contract_address=None):
        """初始化Web3连接和合约接口"""
        # 设置Web3连接
        if network == "localhost":
            self.w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        elif network == "sepolia":
            # 需要在环境变量中设置 INFURA_API_KEY
            infura_key = os.getenv("INFURA_KEY")
            if not infura_key:
                raise ValueError("使用Sepolia网络需要设置INFURA_KEY环境变量")
            self.w3 = Web3(Web3.HTTPProvider(f"https://sepolia.infura.io/v3/{infura_key}"))
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        else:
            raise ValueError(f"不支持的网络: {network}")

        # 检查连接
        if not self.w3.is_connected():
            raise ConnectionError(f"无法连接到 {network} 网络")

        print(f"成功连接到 {network} 网络")

        # 加载私钥和账户
        private_key = os.getenv("PRIVATE_KEY")
        if not private_key:
            raise ValueError("未找到PRIVATE_KEY环境变量")

        if not private_key.startswith("0x"):
            private_key = f"0x{private_key}"

        self.account = Account.from_key(private_key)
        print(f"使用账户: {self.account.address}")

        # 合约地址
        if contract_address:
            self.contract_address = Web3.to_checksum_address(contract_address)
            print(f"使用提供的合约地址: {self.contract_address}")
        else:
            # 从deployments目录加载合约地址
            deployment_file = f"./deployments/blockchain-auth-{network}.json"
            if os.path.exists(deployment_file):
                try:
                    with open(deployment_file, 'r') as f:
                        deployment_data = json.load(f)
                        self.contract_address = Web3.to_checksum_address(
                            deployment_data['mainContract']['address']
                        )
                    print(f"从部署文件加载合约地址: {self.contract_address}")
                except Exception as e:
                    raise ValueError(f"加载部署信息失败: {str(e)}")
            else:
                raise ValueError(f"未找到合约部署信息: {deployment_file}")

        # 加载合约ABI
        abi_file = f"./artifacts/contracts/BlockchainAuthMain.sol/BlockchainAuthMain.json"
        if not os.path.exists(abi_file):
            raise ValueError(f"未找到合约ABI文件: {abi_file}")

        try:
            with open(abi_file, 'r') as f:
                contract_json = json.load(f)
                self.contract_abi = contract_json['abi']
            print(f"成功加载合约ABI")
        except Exception as e:
            raise ValueError(f"加载合约ABI失败: {str(e)}")

        # 实例化合约
        try:
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=self.contract_abi
            )
            print(f"成功实例化合约: {self.contract_address}")
        except Exception as e:
            raise ValueError(f"实例化合约失败: {str(e)}")

    def create_did(self, device_type: str, uuid_val: str = None) -> Dict:
        """创建分布式标识符(DID)"""
        if not uuid_val:
            uuid_val = str(uuid.uuid4())

        # 创建DID
        did = f"did:identity-chain:{uuid_val}"

        # 使用SHA-256确保得到32字节长度
        did_hash = hashlib.sha256(did.encode()).digest()

        # 将设备类型转换为bytes32
        device_type_bytes = self.w3.to_bytes(text=device_type).ljust(32, b'\0')
        device_type_hex = self.w3.to_hex(device_type_bytes)

        return {
            'did': did,
            'did_bytes32': "0x" + did_hash.hex(),
            'device_type_bytes32': device_type_hex
        }

    def generate_keys(self) -> Dict[str, str]:
        """生成ECDSA密钥对"""
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()

        private_key_hex = private_key.to_string().hex()
        public_key_hex = public_key.to_string().hex()

        return {
            'private_key': private_key_hex,
            'public_key': public_key_hex,
            'private_key_obj': private_key,
            'public_key_obj': public_key
        }

    def create_network(self, network_name: str) -> Dict:
        """创建新的无线网络"""
        try:
            # 生成网络ID
            network_id = f"net:{uuid.uuid4()}"

            # 转换为bytes32
            network_id_hash = hashlib.sha256(network_id.encode()).digest()
            network_id_bytes32 = "0x" + network_id_hash.hex()

            # 构建交易
            tx = self.contract.functions.createNetwork(
                self.w3.to_bytes(hexstr=network_id_bytes32),
                network_name
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }

            if result['success']:
                result['network_id'] = network_id
                result['network_id_bytes32'] = network_id_bytes32
                result['network_name'] = network_name

            return result
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def register_device(self, device_type: str, did_info: Dict, keys: Dict,
                        name: str = "", metadata: str = "") -> Dict:
        """注册设备到区块链"""
        try:
            # 确保device_type是bytes32类型
            if isinstance(device_type, str):
                device_type_bytes = self.w3.to_bytes(text=device_type).ljust(32, b'\0')
            else:
                device_type_bytes = self.w3.to_bytes(hexstr=device_type).ljust(32, b'\0')

            # 确保DID是bytes32类型
            did_bytes32 = self.w3.to_bytes(hexstr=did_info['did_bytes32'])

            # 准备公钥 (这已经是bytes类型)
            public_key_bytes = bytes.fromhex(keys['public_key'])

            # 处理设备名称和元数据
            if not name:
                name = f"{device_type}_{uuid.uuid4().hex[:8]}"

            # 创建元数据哈希
            if not metadata:
                metadata = f"metadata_{uuid.uuid4().hex}"
            metadata_bytes32 = self.w3.to_bytes(text=metadata).ljust(32, b'\0')

            # 这里假设系统管理员直接授权注册
            signature = b''

            # 构建交易
            tx = self.contract.functions.registerDevice(
                device_type_bytes,  # 设备类型 (bytes32)
                did_bytes32,  # 设备DID (bytes32)
                public_key_bytes,  # 公钥 (bytes)
                name,  # 设备名称 (string)
                metadata_bytes32,  # 元数据哈希 (bytes32)
                signature  # 签名，空签名表示管理员直接调用
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'gas_used': tx_receipt.gasUsed,
                'device_name': name,
                'metadata': metadata
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def grant_access(self, did_bytes32: str, network_id_bytes32: str) -> Dict:
        """授予设备访问网络的权限"""
        try:
            # 构建交易
            tx = self.contract.functions.grantAccess(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32)
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def revoke_access(self, did_bytes32: str, network_id_bytes32: str) -> Dict:
        """撤销设备访问网络的权限"""
        try:
            # 构建交易
            tx = self.contract.functions.revokeAccess(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32)
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def sign_challenge(self, private_key_hex: str, did_bytes32: str, challenge: str) -> str:
        """使用私钥签名挑战，生成以太坊风格的签名"""
        try:
            # 确保私钥格式正确
            if not private_key_hex.startswith('0x'):
                private_key = f"0x{private_key_hex}"
            else:
                private_key = private_key_hex

            # 确保DID是bytes32格式
            if did_bytes32.startswith('0x'):
                did_bytes = bytes.fromhex(did_bytes32[2:])
            else:
                did_bytes = bytes.fromhex(did_bytes32)

            # 确保challenge是bytes32格式
            if challenge.startswith('0x'):
                challenge_bytes = bytes.fromhex(challenge[2:])
            else:
                challenge_bytes = bytes.fromhex(challenge)

            # 按照合约中的逻辑构建消息哈希
            # 首先拼接DID和挑战值
            message_bytes = did_bytes + challenge_bytes
            # 计算keccak256哈希
            message_hash = Web3.keccak(message_bytes)

            # 创建以太坊签名消息
            eth_message = encode_defunct(primitive=message_hash)

            # 使用私钥签名
            account = Account.from_key(private_key)
            signed_message = account.sign_message(eth_message)

            # 返回签名结果
            return signed_message.signature.hex()
        except Exception as e:
            print(f"签名失败: {str(e)}")
            traceback.print_exc()
            return ""

    def generate_auth_challenge(self, did_bytes32: str, network_id_bytes32: str) -> Dict:
        try:
            # # 调用合约方法并直接获取返回值
            # challenge, expires_at = self.contract.functions.generateAuthChallenge(
            #     self.w3.to_bytes(hexstr=did_bytes32),
            #     self.w3.to_bytes(hexstr=network_id_bytes32)
            # ).call({'from': self.account.address})

            # 构建交易
            tx = self.contract.functions.generateAuthChallenge(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32)
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            challenge_result = self.get_latest_challenge(did_bytes32)
            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'challenge': challenge_result['challenge'],
                'expires_at': challenge_result['expires_at']
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_latest_challenge(self, did_bytes32: str) -> Dict:
        """获取设备的最新挑战值

        Args:
            did_bytes32: 设备的分布式标识符 (bytes32格式)

        Returns:
            Dict: 包含最新挑战值的字典
        """
        try:
            # 将did确保为bytes32
            did_bytes32_bytes = self.w3.to_bytes(hexstr=did_bytes32)

            # 调用合约方法
            challenge, timestamp = self.contract.functions.getLatestChallenge(
                did_bytes32_bytes
            ).call({'from': self.account.address})

            return {
                'success': True,
                'challenge': self.w3.to_hex(challenge),
                'expires_at': timestamp
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def authenticate(self, did_bytes32: str, network_id_bytes32: str, challenge: str, signature: str) -> Dict:
        """验证设备并获取访问令牌"""
        try:
            # 将did和network_id确保为bytes32
            did_bytes32_bytes = self.w3.to_bytes(hexstr=did_bytes32)
            network_id_bytes32_bytes = self.w3.to_bytes(hexstr=network_id_bytes32)

            # 将挑战转换为bytes32
            if challenge.startswith('0x'):
                challenge_bytes32 = self.w3.to_bytes(hexstr=challenge)
            else:
                challenge_hash = hashlib.sha256(challenge.encode()).digest()
                challenge_bytes32 = challenge_hash

            # 将签名转换为bytes
            if signature.startswith('0x'):
                signature_bytes = self.w3.to_bytes(hexstr=signature)
            else:
                signature_bytes = bytes.fromhex(signature)

            # 估计需要的gas
            gas_estimate = self.contract.functions.authenticate(
                did_bytes32_bytes,
                network_id_bytes32_bytes,
                challenge_bytes32,
                signature_bytes
            ).estimate_gas({'from': self.account.address})

            gas_with_buffer = int(gas_estimate * 2)  # 添加50%的缓冲

            # 构建交易
            tx = self.contract.functions.authenticate(
                did_bytes32_bytes,
                network_id_bytes32_bytes,
                challenge_bytes32,
                signature_bytes
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': gas_with_buffer,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # 解析事件日志以获取令牌ID
            token_id = None
            if tx_receipt.status == 1:
                logs = self.contract.events.TokenIssued().process_receipt(tx_receipt)
                if logs:
                    token_id = self.w3.to_hex(logs[0]['args']['tokenId'])

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'token_id': token_id,
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def validate_token(self, token_id: str) -> Dict:
        """验证访问令牌是否有效"""
        try:
            # 调用合约方法
            is_valid = self.contract.functions.validateToken(
                self.w3.to_bytes(hexstr=token_id)
            ).call({'from': self.account.address})

            return {
                'valid': is_valid
            }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }

    def revoke_token(self, token_id: str) -> Dict:
        """撤销访问令牌"""
        try:
            # 构建交易
            tx = self.contract.functions.revokeToken(
                self.w3.to_bytes(hexstr=token_id)
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_device_info(self, did_bytes32: str) -> Dict:
        """获取设备信息"""
        try:
            # 调用合约方法
            device_info = self.contract.functions.getDeviceInfo(
                self.w3.to_bytes(hexstr=did_bytes32)
            ).call({'from': self.account.address})

            return {
                'success': True,
                'device_type': self.w3.to_text(device_info[0]).rstrip('\x00'),
                'owner': device_info[1],
                'public_key': device_info[2].hex(),
                'registered_at': device_info[3],
                'is_active': device_info[4],
                'name': device_info[5],
                'metadata': self.w3.to_hex(device_info[6]),
                'authorized_by': device_info[7],
                'user_address': device_info[8]  # 新合约增加的字段
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def update_device_info(self, did_bytes32: str, name: str, metadata: str) -> Dict:
        """更新设备信息

        Args:
            did_bytes32: 设备的分布式标识符 (bytes32格式)
            name: 新的设备名称
            metadata: 新的设备元数据

        Returns:
            Dict: 包含操作结果的字典
        """
        try:
            # 转换metadata为bytes32
            if isinstance(metadata, str):
                if metadata.startswith('0x'):
                    metadata_bytes32 = self.w3.to_bytes(hexstr=metadata)
                else:
                    metadata_bytes32 = self.w3.to_bytes(text=metadata).ljust(32, b'\0')
            else:
                metadata_bytes32 = metadata

            # 构建交易
            tx = self.contract.functions.updateDeviceInfo(
                self.w3.to_bytes(hexstr=did_bytes32),
                name,
                metadata_bytes32
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'new_name': name,
                'new_metadata': metadata
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def deactivate_device(self, did_bytes32: str) -> Dict:
        """停用设备

        Args:
            did_bytes32: 设备的分布式标识符 (bytes32格式)

        Returns:
            Dict: 包含操作结果的字典
        """
        try:
            # 构建交易
            tx = self.contract.functions.deactivateDevice(
                self.w3.to_bytes(hexstr=did_bytes32)
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_owner_devices(self) -> Dict:
        """获取用户拥有的设备列表

        Returns:
            Dict: 包含设备列表的字典
        """
        try:
            # 调用合约方法
            devices = self.contract.functions.getOwnerDevices(
                self.account.address
            ).call({'from': self.account.address})

            # 转换为可读格式
            device_list = [self.w3.to_hex(did) for did in devices]

            return {
                'success': True,
                'device_count': len(device_list),
                'devices': device_list
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_owner_networks(self) -> Dict:
        """获取用户拥有的网络列表

        Returns:
            Dict: 包含网络列表的字典
        """
        try:
            # 调用合约方法
            networks = self.contract.functions.getOwnerNetworks(
                self.account.address
            ).call({'from': self.account.address})

            # 转换为可读格式
            network_list = [self.w3.to_hex(nid) for nid in networks]

            return {
                'success': True,
                'network_count': len(network_list),
                'networks': network_list
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def check_access(self, did_bytes32: str, network_id_bytes32: str) -> Dict:
        """检查设备是否有权访问网络"""
        try:
            # 调用合约方法
            has_access = self.contract.functions.checkAccess(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32)
            ).call({'from': self.account.address})

            return {
                'success': True,
                'has_access': has_access
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_auth_logs(self, did_bytes32: str) -> Dict:
        """获取设备的认证日志"""
        try:
            # 获取日志数量
            log_count = self.contract.functions.getAuthLogCount(
                self.w3.to_bytes(hexstr=did_bytes32)
            ).call({'from': self.account.address})

            logs = []
            for i in range(log_count):
                log_info = self.contract.functions.getAuthLog(
                    self.w3.to_bytes(hexstr=did_bytes32),
                    i
                ).call({'from': self.account.address})

                logs.append({
                    'verifier': log_info[0],
                    'challenge_hash': self.w3.to_hex(log_info[1]),
                    'timestamp': log_info[2],
                    'success': log_info[3]
                })

            return {
                'success': True,
                'log_count': log_count,
                'logs': logs
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    # 用户管理相关功能
    def register_user(self, name: str, email: str) -> Dict:
        """注册新用户

        Args:
            name: 用户名称
            email: 用户邮箱（可选）

        Returns:
            Dict: 包含操作结果的字典
        """
        try:
            # 构建交易
            tx = self.contract.functions.registerUser(
                name,
                email,
                b'',  # 如果是普通用户注册，不需要提供公钥
                b''  # 如果是普通用户注册，不需要提供签名
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def update_user_info(self, name: str, email: str) -> Dict:
        """更新用户信息

        Args:
            name: 新用户名称
            email: 新用户邮箱

        Returns:
            Dict: 包含操作结果的字典
        """
        try:
            # 构建交易
            tx = self.contract.functions.updateUserInfo(
                name,
                email,
                b''  # 如果不更新公钥，传入空字节
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def deactivate_user(self) -> Dict:
        """停用用户账户

        Returns:
            Dict: 包含操作结果的字典
        """
        try:
            # 构建交易
            tx = self.contract.functions.deactivateUser().build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_user_info(self, user_address=None) -> Dict:
        """获取用户信息

        Args:
            user_address: 用户地址，默认为当前账户

        Returns:
            Dict: 包含用户信息的字典
        """
        try:
            if user_address is None:
                user_address = self.account.address

            # 调用合约方法
            user_info = self.contract.functions.getUserInfo(
                user_address
            ).call({'from': self.account.address})

            return {
                'success': True,
                'name': user_info[0],
                'email': user_info[1],
                'public_key': user_info[2].hex() if user_info[2] else '',
                'registered_at': user_info[3],
                'is_active': user_info[4],
                'device_count': user_info[5],
                'network_count': user_info[6],
                'role': user_info[7],
                'authorized_by': user_info[8]
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def is_registered_user(self, user_address=None) -> Dict:
        """检查用户是否已注册

        Args:
            user_address: 用户地址，默认为当前账户

        Returns:
            Dict: 包含检查结果的字典
        """
        try:
            if user_address is None:
                user_address = self.account.address

            # 调用合约方法
            is_registered = self.contract.functions.isRegisteredUser(
                user_address
            ).call({'from': self.account.address})

            return {
                'success': True,
                'is_registered': is_registered
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'is_registered': False,
                'traceback': traceback.format_exc()
            }

    def get_user_count(self) -> Dict:
        """获取所有用户数量

        Returns:
            Dict: 包含用户数量的字典
        """
        try:
            # 调用合约方法
            count = self.contract.functions.getUserCount().call({'from': self.account.address})

            return {
                'success': True,
                'count': count
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'count': 0,
                'traceback': traceback.format_exc()
            }

    def get_user_list(self, offset: int, limit: int) -> Dict:
        """获取分页的用户列表

        Args:
            offset: 起始索引
            limit: 数量限制

        Returns:
            Dict: 包含用户列表的字典
        """
        try:
            # 调用合约方法
            result = self.contract.functions.getUserList(
                offset,
                limit
            ).call({'from': self.account.address})

            return {
                'success': True,
                'addresses': result[0],
                'names': result[1],
                'is_actives': result[2],
                'roles': result[3]
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'addresses': [],
                'names': [],
                'is_actives': [],
                'roles': [],
                'traceback': traceback.format_exc()
            }

    def get_user_devices(self, user_address=None) -> Dict:
        """获取用户的设备列表

        Args:
            user_address: 用户地址，默认为当前账户

        Returns:
            Dict: 包含设备列表的字典
        """
        try:
            if user_address is None:
                user_address = self.account.address

            # 调用合约方法
            result = self.contract.functions.getUserDevices(
                user_address
            ).call({'from': self.account.address})

            return {
                'success': True,
                'device_ids': result[0],
                'device_names': result[1],
                'device_types': result[2],
                'is_actives': result[3]
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'device_ids': [],
                'device_names': [],
                'device_types': [],
                'is_actives': [],
                'traceback': traceback.format_exc()
            }

    def assign_device_to_user(self, device_id: str, user_address: str) -> Dict:
        """将设备分配给特定用户

        Args:
            device_id: 设备ID
            user_address: 用户地址

        Returns:
            Dict: 包含操作结果的字典
        """
        try:
            # 构建交易
            tx = self.contract.functions.transferDevice(
                self.w3.to_bytes(hexstr=device_id),
                user_address
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
