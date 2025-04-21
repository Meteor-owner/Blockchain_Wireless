"""
区块链无线网络身份验证系统 - Python 接口测试
CSEC5615 云安全项目
"""

import json
import os
import time
import hashlib
import ecdsa
import uuid
import base64
import binascii
from typing import Dict, List, Tuple, Any
from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
from eth_account.messages import encode_defunct
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

class IdentityChainClient:
    """与IdentityManager智能合约的Python接口"""

    def __init__(self, network="localhost", contract_address=None):
        """初始化Web3连接和合约接口"""
        import web3
        web3_version = web3.__version__
        print(f"使用Web3.py版本: {web3_version}")
        self.web3_major_version = int(web3_version.split('.')[0])

        # 根据版本差异设置属性名
        if self.web3_major_version >= 6:
            self.raw_tx_attr = 'raw_transaction'
        else:
            self.raw_tx_attr = 'rawTransaction'

        # 设置Web3连接
        if network == "localhost":
            self.w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        # ... 其他网络设置 ...

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
            deployment_file = f"./deployments/identity-manager-{network}.json"
            if os.path.exists(deployment_file):
                try:
                    with open(deployment_file, 'r') as f:
                        deployment_data = json.load(f)
                        self.contract_address = Web3.to_checksum_address(
                            deployment_data['contract']['address']
                        )
                    print(f"从部署文件加载合约地址: {self.contract_address}")
                except Exception as e:
                    raise ValueError(f"加载部署信息失败: {str(e)}")
            else:
                raise ValueError(f"未找到合约部署信息: {deployment_file}")

        # 加载合约ABI
        abi_file = "./artifacts/contracts/IdentityManager.sol/IdentityManager.json"
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

            # 验证合约有效性
            try:
                # 尝试调用一个简单的view函数来验证合约
                # 例如，如果合约有一个简单的函数，如getOwnerNetworks
                test_call = self.contract.functions.getOwnerNetworks(
                    self.account.address
                ).call()
                print(f"合约验证成功: {test_call}")
            except Exception as e:
                print(f"合约验证警告(不一定是错误): {str(e)}")
        except Exception as e:
            raise ValueError(f"实例化合约失败: {str(e)}")

    def create_did(self, device_type: str, uuid_val: str = None) -> Dict:
        """创建分布式标识符(DID)"""
        if not uuid_val:
            import uuid
            uuid_val = str(uuid.uuid4())

        # 创建DID
        did = f"did:identity-chain:{uuid_val}"

        # 使用SHA-256确保得到32字节长度
        import hashlib
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

    def register_device(self, device_type: str, did_info: Dict, keys: Dict) -> Dict:
        """注册设备到区块链"""
        try:
            # 确保device_type是bytes32类型
            if isinstance(device_type, str):
                # 将设备类型转换为bytes32
                device_type_bytes = self.w3.to_bytes(text=device_type).ljust(32, b'\0')
            else:
                device_type_bytes = self.w3.to_bytes(hexstr=device_type).ljust(32, b'\0')

            # 确保DID是bytes32类型
            did_bytes32 = self.w3.to_bytes(hexstr=did_info['did_bytes32'])

            # 准备公钥 (这已经是bytes类型)
            public_key_bytes = bytes.fromhex(keys['public_key'])

            print(f"参数类型检查:")
            print(f"- device_type_bytes: {type(device_type_bytes)}, 长度: {len(device_type_bytes)}")
            print(f"- did_bytes32: {type(did_bytes32)}, 长度: {len(did_bytes32)}")
            print(f"- public_key_bytes: {type(public_key_bytes)}, 长度: {len(public_key_bytes)}")

            # 构建交易
            tx = self.contract.functions.registerDevice(
                device_type_bytes,  # 确保是bytes32
                did_bytes32,  # 确保是bytes32
                public_key_bytes  # 这是bytes类型
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 使用动态属性获取raw_transaction
            raw_tx = getattr(signed_tx, self.raw_tx_attr)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'gas_used': tx_receipt.gasUsed
            }
        except Exception as e:
            import traceback
            print(f"注册设备时发生错误: {str(e)}")
            print(traceback.format_exc())
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def create_network(self, network_name: str) -> Dict:
        """创建新的无线网络"""
        try:
            # 生成网络ID
            network_id = f"net:{uuid.uuid4()}"

            # 转换为bytes32
            import hashlib
            network_id_hash = hashlib.sha256(network_id.encode()).digest()
            network_id_bytes32 = "0x" + network_id_hash.hex()

            # 使用通用函数发送交易
            result = self.send_transaction(
                self.contract.functions.createNetwork,
                Web3.to_bytes(hexstr=network_id_bytes32),
                network_name
            )

            if result['success']:
                result['network_id'] = network_id
                result['network_id_bytes32'] = network_id_bytes32

            return result
        except Exception as e:
            import traceback
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
            # tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            raw_tx = getattr(signed_tx, self.raw_tx_attr)
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)

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
            # tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            raw_tx = getattr(signed_tx, self.raw_tx_attr)
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)

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
    
    def sign_challenge(self, private_key_hex: str, challenge: str) -> str:
        """使用私钥签名挑战"""
        try:
            # 将私钥转换为对象
            private_key = ecdsa.SigningKey.from_string(
                bytes.fromhex(private_key_hex), 
                curve=ecdsa.SECP256k1
            )
            
            # 签名挑战
            signature = private_key.sign(challenge.encode())
            
            return signature.hex()
        except Exception as e:
            print(f"签名失败: {str(e)}")
            return ""
    
    def authenticate(self, did_bytes32: str, network_id_bytes32: str, challenge: str, signature: str) -> Dict:
        """验证设备并获取访问令牌"""
        try:
            # 将挑战转换为bytes32
            challenge_bytes = self.w3.to_bytes(text=challenge).ljust(32, b'\0')
            challenge_bytes32 = self.w3.to_hex(challenge_bytes)
            
            # 将签名转换为bytes
            signature_bytes = bytes.fromhex(signature)
            
            # 构建交易
            tx = self.contract.functions.authenticate(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32),
                self.w3.to_bytes(hexstr=challenge_bytes32),
                signature_bytes
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })
            
            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)
            
            # 发送交易
            # tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            raw_tx = getattr(signed_tx, self.raw_tx_attr)
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
            
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
                'error': str(e)
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
            # tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            raw_tx = getattr(signed_tx, self.raw_tx_attr)
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)

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
                'is_active': device_info[4]
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def check_access(self, did_bytes32: str, network_id_bytes32: str) -> Dict:
        """检查设备是否有访问网络的权限"""
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

    def send_transaction(self, tx_func, *args, **kwargs):
        """通用的交易发送函数，处理不同版本的Web3.py"""
        try:
            # 构建交易
            tx = tx_func(*args, **kwargs).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': kwargs.get('gas', 500000),
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

            # 兼容性处理
            if hasattr(signed_tx, 'rawTransaction'):
                raw_tx = signed_tx.rawTransaction  # Web3.py v5
            else:
                raw_tx = signed_tx.raw_transaction  # Web3.py v6

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'receipt': tx_receipt,
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            import traceback
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }


# 演示区块链无线身份验证系统的使用
def run_demo():
    """运行完整的演示流程"""
    import uuid
    import time
    
    print("======== 区块链无线网络身份验证系统演示 ========")
    
    # 初始化连接
    try:
        client = IdentityChainClient(network="localhost")
        print(f"已连接到区块链网络，使用账户: {client.account.address}")
    except Exception as e:
        print(f"连接失败: {str(e)}")
        return
    
    # 步骤1: 创建网络
    print("\n步骤1: 创建无线网络...")
    network_result = client.create_network("家庭Wi-Fi网络")
    
    if not network_result['success']:
        print(f"创建网络失败: {network_result.get('error', '未知错误')}")
        return
    
    network_id = network_result['network_id']
    network_id_bytes32 = network_result['network_id_bytes32']
    print(f"已创建网络: {network_id}")
    
    # 步骤2: 注册设备
    print("\n步骤2: 注册设备...")
    devices = []
    device_types = ["smartphone", "laptop", "smart_tv", "iot_device"]
    device_names = ["Alice的手机", "Bob的笔记本电脑", "客厅智能电视", "智能恒温器"]
    
    for i, (device_type, name) in enumerate(zip(device_types, device_names)):
        # 创建设备标识
        did_info = client.create_did(device_type)
        
        # 生成密钥对
        keys = client.generate_keys()
        
        # 注册设备
        register_result = client.register_device(device_type, did_info, keys)
        
        if register_result['success']:
            print(f"注册设备成功: {name} (DID: {did_info['did']})")
            devices.append({
                'name': name,
                'type': device_type,
                'did': did_info['did'],
                'did_bytes32': did_info['did_bytes32'],
                'keys': keys
            })
        else:
            print(f"注册设备失败: {name}")
    
    if not devices:
        print("没有设备注册成功，演示终止")
        return
    
    # 步骤3: 授予设备访问权限
    print("\n步骤3: 授予设备访问网络的权限...")
    for device in devices:
        result = client.grant_access(device['did_bytes32'], network_id_bytes32)
        if result['success']:
            print(f"已授权设备访问网络: {device['name']}")
        else:
            print(f"授权失败: {device['name']}")
    
    # 步骤4: 模拟设备认证流程
    print("\n步骤4: 模拟设备认证流程...")
    for device in devices:
        print(f"\n正在认证设备: {device['name']}")
        
        # 生成挑战
        challenge = f"auth_{uuid.uuid4()}"
        print(f"生成挑战: {challenge}")
        
        # 设备签名挑战
        signature = client.sign_challenge(device['keys']['private_key'], challenge)
        print(f"设备签名挑战: {signature[:20]}...")
        
        # 验证设备并获取令牌
        auth_result = client.authenticate(device['did_bytes32'], network_id_bytes32, challenge, signature)
        
        if auth_result['success']:
            token_id = auth_result['token_id']
            print(f"认证成功! 获得访问令牌: {token_id}")
            
            # 验证令牌有效性
            token_valid = client.validate_token(token_id)
            print(f"令牌有效性检查: {'有效' if token_valid['valid'] else '无效'}")
            
            # 记录令牌以便稍后撤销
            device['token_id'] = token_id
        else:
            print(f"认证失败: {auth_result.get('error', '未知错误')}")
    
    # 步骤5: 查看认证日志
    print("\n步骤5: 查看设备认证日志...")
    for device in devices:
        logs_result = client.get_auth_logs(device['did_bytes32'])
        if logs_result['success']:
            print(f"\n{device['name']} 的认证日志 (共 {logs_result['log_count']} 条):")
            for idx, log in enumerate(logs_result['logs']):
                print(f"  [{idx+1}] 时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log['timestamp']))}")
                print(f"      结果: {'成功' if log['success'] else '失败'}")
        else:
            print(f"获取认证日志失败: {device['name']}")
    
    # 步骤6: 撤销一个设备的访问权限
    print("\n步骤6: 撤销设备访问权限...")
    if len(devices) > 0:
        device = devices[-1]  # 选择最后一个设备
        result = client.revoke_access(device['did_bytes32'], network_id_bytes32)
        if result['success']:
            print(f"已撤销设备访问权限: {device['name']}")
            
            # 验证权限已撤销
            access_check = client.check_access(device['did_bytes32'], network_id_bytes32)
            if access_check['success']:
                print(f"权限检查结果: {'有权限' if access_check['has_access'] else '无权限'}")
        else:
            print(f"撤销访问权限失败: {device['name']}")
    
    # 步骤7: 撤销一个令牌
    print("\n步骤7: 撤销访问令牌...")
    if len(devices) > 1 and 'token_id' in devices[0]:
        device = devices[0]  # 选择第一个设备
        result = client.revoke_token(device['token_id'])
        if result['success']:
            print(f"已撤销访问令牌: {device['name']}")
            
            # 验证令牌已撤销
            token_valid = client.validate_token(device['token_id'])
            print(f"令牌有效性检查: {'有效' if token_valid['valid'] else '无效'}")
        else:
            print(f"撤销令牌失败: {device['name']}")
    
    print("\n演示完成!")


if __name__ == "__main__":
    run_demo()