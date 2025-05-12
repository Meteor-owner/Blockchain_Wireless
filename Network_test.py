"""
区块链无线网络身份验证系统 - 网络创建与用户授权测试脚本
CSEC5615 云安全项目
"""

import os
import time
import uuid
import hashlib
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv
import json
import traceback

# 加载环境变量
load_dotenv()


class NetworkCreationTest:
    """网络创建和用户授权测试类"""

    def __init__(self, network="localhost"):
        """初始化Web3连接和合约接口"""
        # 设置Web3连接
        if network == "localhost":
            self.w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        else:
            raise ValueError(f"不支持的网络: {network}")

        # 检查连接
        if not self.w3.is_connected():
            raise ConnectionError(f"无法连接到 {network} 网络")

        print(f"成功连接到 {network} 网络")

        # 加载主账户私钥
        private_key = os.getenv("PRIVATE_KEY")
        if not private_key:
            raise ValueError("未找到PRIVATE_KEY环境变量")

        if not private_key.startswith("0x"):
            private_key = f"0x{private_key}"

        self.admin_account = Account.from_key(private_key)
        print(f"使用管理员账户: {self.admin_account.address}")

        # 从deployments目录加载合约地址
        deployment_file = f"./deployments/blockchain-auth-{network}.json"
        if not os.path.exists(deployment_file):
            raise ValueError(f"未找到合约部署信息: {deployment_file}")

        with open(deployment_file, 'r') as f:
            deployment_data = json.load(f)
            self.contract_address = Web3.to_checksum_address(
                deployment_data['mainContract']['address']
            )
        print(f"主合约地址: {self.contract_address}")

        # 加载合约ABI
        self.load_contract_abis()

        # 实例化合约
        self.main_contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.main_abi
        )

        # 获取并实例化用户管理和网络管理合约
        self.user_manager_address = self.main_contract.functions.userManager().call()
        self.network_manager_address = self.main_contract.functions.networkManager().call()

        self.user_manager_contract = self.w3.eth.contract(
            address=self.user_manager_address,
            abi=self.user_manager_abi
        )

        self.network_manager_contract = self.w3.eth.contract(
            address=self.network_manager_address,
            abi=self.network_manager_abi
        )

        print(f"UserManagement合约地址: {self.user_manager_address}")
        print(f"NetworkManagement合约地址: {self.network_manager_address}")

        # 检查系统管理员
        self.system_admin = self.main_contract.functions.systemAdmin().call()
        print(f"系统管理员: {self.system_admin}")
        print(f"当前账户是否为系统管理员: {self.admin_account.address.lower() == self.system_admin.lower()}")

        # 测试用户账户列表，将在测试中填充
        self.test_accounts = []

    def load_contract_abis(self):
        """加载所有需要的合约ABI"""
        # 加载主合约ABI
        main_abi_file = "./artifacts/contracts/BlockchainAuthMain.sol/BlockchainAuthMain.json"
        with open(main_abi_file, 'r') as f:
            contract_json = json.load(f)
            self.main_abi = contract_json['abi']

        # 加载UserManagement合约ABI
        user_abi_file = "./artifacts/contracts/UserManagement.sol/UserManagement.json"
        with open(user_abi_file, 'r') as f:
            contract_json = json.load(f)
            self.user_manager_abi = contract_json['abi']

        # 加载NetworkManagement合约ABI
        network_abi_file = "./artifacts/contracts/NetworkManagement.sol/NetworkManagement.json"
        with open(network_abi_file, 'r') as f:
            contract_json = json.load(f)
            self.network_manager_abi = contract_json['abi']

    def check_admin_registration(self):
        """检查管理员是否已注册为用户"""
        try:
            result = self.main_contract.functions.isRegisteredUser(
                self.admin_account.address
            ).call()

            print(f"管理员账户 {self.admin_account.address} 注册状态: {'已注册' if result else '未注册'}")
            return result
        except Exception as e:
            print(f"❌ 检查管理员注册状态异常: {str(e)}")
            return False

    def register_admin_as_user(self):
        """注册管理员为系统用户"""
        try:
            # 生成新的密钥对
            keys = self.generate_keys()
            public_key_bytes = bytes.fromhex(keys['public_key'])

            admin_name = "System Administrator"
            admin_email = "admin@example.com"

            print(f"注册管理员: {admin_name}, {admin_email}")

            # 构建交易
            tx = self.main_contract.functions.registerUser(
                admin_name,
                admin_email,
                public_key_bytes,
                b''  # 空签名，因为默认管理员有自注册权限
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名并发送交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }
        except Exception as e:
            print(f"❌ 管理员注册异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def generate_keys(self):
        """生成公私钥对"""
        private_key = self.w3.eth.account.create().key
        acct = Account.from_key(private_key)
        public_key = acct._key_obj.public_key.to_bytes()

        return {
            'private_key': private_key.hex(),
            'public_key': public_key.hex(),
            'address': acct.address
        }

    def create_new_accounts(self, count=3):
        """创建新的以太坊账户并转入一些ETH"""
        accounts = []
        for i in range(count):
            # 创建新账户
            acct = Account.create()
            print(f"创建新账户 #{i + 1}: {acct.address}")

            # 从主账户转账ETH
            tx = {
                'to': acct.address,
                'value': self.w3.to_wei(1, 'ether'),
                'gas': 21000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address)
            }
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # 检查新账户余额
            balance = self.w3.eth.get_balance(acct.address)
            print(f"  账户余额: {self.w3.from_wei(balance, 'ether')} ETH")

            accounts.append({
                'address': acct.address,
                'private_key': acct.key.hex(),
                'account_obj': acct,
                'balance': self.w3.from_wei(balance, 'ether')
            })

        return accounts

    def register_user_from_account(self, account, name, email):
        """从指定账户注册用户"""
        try:
            # 生成新的密钥对
            keys = self.generate_keys()
            public_key_bytes = bytes.fromhex(keys['public_key'])

            print(f"从账户 {account['address']} 注册用户: {name}, {email}")

            # 构建交易
            tx = self.main_contract.functions.registerUser(
                name,
                email,
                public_key_bytes,
                b''  # 空签名
            ).build_transaction({
                'from': account['address'],
                'nonce': self.w3.eth.get_transaction_count(account['address']),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名并发送交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, account['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            user_info = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'public_key': keys['public_key'],
                'address': account['address'],
                'name': name,
                'email': email
            }

            if user_info['success']:
                print(f"✅ 用户注册成功: {name}")
            else:
                print(f"❌ 用户注册失败: {name}")

            return user_info
        except Exception as e:
            print(f"❌ 用户注册异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def create_network(self, name):
        """创建新无线网络"""
        try:
            # 生成网络ID
            network_id = f"net:{uuid.uuid4()}"
            # 转换为bytes32
            network_id_hash = hashlib.sha256(network_id.encode()).digest()
            network_id_bytes32 = "0x" + network_id_hash.hex()

            print(f"创建新网络: {name}, ID: {network_id}")

            # 构建交易
            tx = self.main_contract.functions.createNetwork(
                self.w3.to_bytes(hexstr=network_id_bytes32),
                name
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名并发送交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            network_info = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'network_id': network_id,
                'network_id_bytes32': network_id_bytes32,
                'name': name
            }

            if network_info['success']:
                print(f"✅ 网络创建成功: {name}")
            else:
                print(f"❌ 网络创建失败: {name}")

            return network_info
        except Exception as e:
            print(f"❌ 网络创建异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def create_did(self, device_type):
        """创建设备ID (DID)"""
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

    def register_device(self, device_type, name, owner_account):
        """注册设备"""
        try:
            # 创建设备ID
            did_info = self.create_did(device_type)

            # 生成密钥对
            keys = self.generate_keys()
            public_key_bytes = bytes.fromhex(keys['public_key'])

            # 创建元数据
            metadata = f"metadata_{uuid.uuid4().hex[:8]}"
            metadata_bytes32 = self.w3.to_bytes(text=metadata).ljust(32, b'\0')

            print(f"为用户 {owner_account['address']} 注册设备: {name}, 类型: {device_type}")

            # 构建交易
            tx = self.main_contract.functions.registerDevice(
                self.w3.to_bytes(text=device_type).ljust(32, b'\0'),
                self.w3.to_bytes(hexstr=did_info['did_bytes32']),
                public_key_bytes,
                name,
                metadata_bytes32,
                b''  # 空签名
            ).build_transaction({
                'from': owner_account['address'],
                'nonce': self.w3.eth.get_transaction_count(owner_account['address']),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名并发送交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, owner_account['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            device_info = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'did': did_info['did'],
                'did_bytes32': did_info['did_bytes32'],
                'device_type': device_type,
                'name': name,
                'metadata': metadata,
                'owner': owner_account['address'],
                'keys': keys
            }

            if device_info['success']:
                print(f"✅ 设备注册成功: {name}")
            else:
                print(f"❌ 设备注册失败: {name}")

            return device_info
        except Exception as e:
            print(f"❌ 设备注册异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def listen_for_access_granted_events(self, tx_receipt, did_bytes32=None, network_id_bytes32=None):
        """监听并解析AccessGranted事件"""
        try:
            # 创建事件过滤器
            access_granted_filter = self.network_manager_contract.events.AccessGranted().process_receipt(tx_receipt)

            if not access_granted_filter:
                print("⚠️ 未检测到AccessGranted事件")
                return []

            events = []
            for event in access_granted_filter:
                event_did = self.w3.to_hex(event.args.did)
                event_network = self.w3.to_hex(event.args.networkId)

                # 如果指定了DID和网络ID，则过滤事件
                if (did_bytes32 is None or event_did.lower() == did_bytes32.lower()) and \
                        (network_id_bytes32 is None or event_network.lower() == network_id_bytes32.lower()):

                    events.append({
                        'did': event_did,
                        'networkId': event_network,
                        'event': event
                    })

                    print(f"📢 检测到AccessGranted事件:")
                    # print(f"  设备DID: {event_did}")
                    # print(f"  网络ID: {event_network}")

                    # 检查DID和网络ID是否与我们期望的匹配
                    if did_bytes32 and event_did.lower() != did_bytes32.lower():
                        print(f"⚠️ 警告: 事件中的DID与预期不匹配")
                        print(f"  预期: {did_bytes32}")
                        print(f"  实际: {event_did}")

                    if network_id_bytes32 and event_network.lower() != network_id_bytes32.lower():
                        print(f"⚠️ 警告: 事件中的网络ID与预期不匹配")
                        print(f"  预期: {network_id_bytes32}")
                        print(f"  实际: {event_network}")

            if not events:
                print(f"⚠️ 未找到与指定参数匹配的AccessGranted事件")
                if did_bytes32:
                    print(f"  查找DID: {did_bytes32}")
                if network_id_bytes32:
                    print(f"  查找网络ID: {network_id_bytes32}")

            return events
        except Exception as e:
            print(f"❌ 监听AccessGranted事件异常: {str(e)}")
            print(traceback.format_exc())
            return []

    def grant_network_access(self, did_bytes32, network_id_bytes32):
        """授予设备访问网络的权限"""
        try:
            print(f"授予设备 {did_bytes32} 访问网络 {network_id_bytes32} 的权限")

            # 转换为bytes32
            did_bytes = self.w3.to_bytes(hexstr=did_bytes32)
            network_bytes = self.w3.to_bytes(hexstr=network_id_bytes32)

            # 构建交易
            tx = self.main_contract.functions.grantAccess(
                did_bytes,
                network_bytes
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名并发送交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            print(f"授权交易已发送，哈希: {self.w3.to_hex(tx_hash)}")

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # 监听AccessGranted事件
            events = self.listen_for_access_granted_events(tx_receipt, did_bytes32, network_id_bytes32)

            # 记录区块号，方便后续查询历史事件
            block_number = tx_receipt.blockNumber
            print(f"交易已确认，区块号: {block_number}")

            # 打印交易状态
            if tx_receipt.status == 1:
                print(f"✅ 交易成功执行")
            else:
                print(f"❌ 交易执行失败")

            # 延迟一会，让区块链状态更新
            print("等待区块链状态同步...")
            time.sleep(2)

            # 查询授权状态
            access_check = self.check_network_access(did_bytes32, network_id_bytes32)
            print(f"授权后访问状态: {'有权限' if access_check['has_access'] else '无权限'}")

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': block_number,
                'events': events,
                'has_access': access_check['has_access']
            }
        except Exception as e:
            print(f"❌ 授予访问权限异常: {str(e)}")
            print(traceback.format_exc())
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def check_network_access(self, did_bytes32, network_id_bytes32):
        """检查设备是否有权访问网络"""
        try:
            did_bytes = self.w3.to_bytes(hexstr=did_bytes32)
            network_bytes = self.w3.to_bytes(hexstr=network_id_bytes32)

            # print(f"检查权限 - DID: {did_bytes32}")
            # print(f"检查权限 - 网络ID: {network_id_bytes32}")

            result = self.main_contract.functions.checkAccess(
                did_bytes,
                network_bytes
            ).call()

            return {
                'success': True,
                'has_access': result
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'has_access': False
            }

    def batch_grant_access(self, did_list, network_id_bytes32):
        """批量授予多个设备访问网络的权限"""
        try:
            # 将DID列表转换为bytes32列表
            did_bytes32_list = [self.w3.to_bytes(hexstr=did) for did in did_list]

            print(f"批量授予 {len(did_list)} 个设备访问网络的权限")

            # 构建交易
            tx = self.main_contract.functions.batchGrantAccess(
                did_bytes32_list,
                self.w3.to_bytes(hexstr=network_id_bytes32)
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 2000000,  # 批量操作可能需要更多gas
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名并发送交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # 尝试获取返回的成功计数
            success_count = 0
            if tx_receipt.status == 1:
                # 这里可能需要从事件日志中解析成功计数
                success_count = len(did_list)  # 假设全部成功

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'success_count': success_count
            }

            if result['success']:
                print(f"✅ 批量授权成功: {success_count} 个设备")
            else:
                print(f"❌ 批量授权失败")

            return result
        except Exception as e:
            print(f"❌ 批量授权异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_owner_networks(self, owner_address=None):
        """获取用户所拥有的网络列表"""
        try:
            if owner_address is None:
                owner_address = self.admin_account.address

            networks = self.main_contract.functions.getOwnerNetworks(owner_address).call()

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
                'network_count': 0,
                'networks': []
            }

    def deactivate_device(self, device_info, account=None):
        """停用设备

        Args:
            device_info: 包含设备信息的字典
            account: 执行停用操作的账户（默认为设备所有者）

        Returns:
            包含操作结果的字典
        """
        try:
            # 如果未指定账户，默认使用设备所有者的账户
            if account is None:
                # 查找拥有此设备的测试账户
                owner_address = device_info['owner']
                account = next((acc for acc in self.test_accounts if acc['address'] == owner_address), None)

                # 如果找不到对应账户，使用管理员账户
                if account is None:
                    account = {'address': self.admin_account.address, 'private_key': self.admin_account.key.hex()}
                    print(f"未找到设备所有者账户，使用管理员账户停用设备")

            print(f"停用设备: {device_info['name']} (DID: {device_info['did']})")
            print(f"执行账户: {account['address']}")

            # 构建交易
            tx = self.main_contract.functions.deactivateDevice(
                self.w3.to_bytes(hexstr=device_info['did_bytes32'])
            ).build_transaction({
                'from': account['address'],
                'nonce': self.w3.eth.get_transaction_count(account['address']),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名并发送交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, account['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }

            if result['success']:
                print(f"✅ 设备 {device_info['name']} 停用成功")
            else:
                print(f"❌ 设备 {device_info['name']} 停用失败")

            return result
        except Exception as e:
            print(f"❌ 设备停用异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_device_info(self, did_bytes32):
        """获取设备信息"""
        try:
            result = self.main_contract.functions.getDeviceInfo(
                self.w3.to_bytes(hexstr=did_bytes32)
            ).call()

            return {
                'success': True,
                'device_type': self.w3.to_text(result[0]).rstrip('\x00'),
                'owner': result[1],
                'public_key': result[2].hex() if result[2] else '',
                'registered_at': result[3],
                'is_active': result[4],
                'name': result[5],
                'metadata': self.w3.to_hex(result[6]),
                'authorized_by': result[7],
                'user_address': result[8]
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def revoke_network_access(self, did_bytes32, network_id_bytes32):
        """撤销设备访问网络的权限"""
        try:
            print(f"撤销设备 {did_bytes32} 访问网络 {network_id_bytes32} 的权限")

            # 构建交易
            tx = self.main_contract.functions.revokeAccess(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32)
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名并发送交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }

            if result['success']:
                print(f"✅ 成功撤销访问权限")
            else:
                print(f"❌ 撤销访问权限失败")

            return result
        except Exception as e:
            print(f"❌ 撤销访问权限异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def run_network_tests(self):
        """运行网络创建和授权测试"""
        print("\n" + "=" * 80)
        print("开始网络创建和授权测试")
        print("=" * 80)

        # 步骤0: 确保管理员已注册为用户
        print("\n" + "-" * 60)
        print("步骤0: 确保管理员已注册为用户")
        print("-" * 60)

        # 检查管理员是否已注册
        is_registered = self.check_admin_registration()
        if not is_registered:
            print("管理员尚未注册为用户，先注册管理员...")
            admin_reg_result = self.register_admin_as_user()
            if not admin_reg_result['success']:
                print("❌ 管理员注册失败，测试终止")
                return
            print("✅ 管理员注册成功")
        else:
            print("✅ 管理员已注册为用户")

        # 步骤1: 创建测试用户账户
        print("\n" + "-" * 60)
        print("步骤1: 创建测试用户账户")
        print("-" * 60)

        # 创建3个新用户账户
        self.test_accounts = self.create_new_accounts(3)

        # 为每个账户注册用户
        users = []
        for idx, account in enumerate(self.test_accounts):
            user_name = f"Network Test User {idx + 1}"
            user_email = f"netuser{idx + 1}@example.com"

            # 注册用户
            user_info = self.register_user_from_account(account, user_name, user_email)
            if user_info['success']:
                users.append(user_info)

        print(f"成功注册 {len(users)} 个测试用户")

        # 步骤2: 管理员创建网络
        print("\n" + "-" * 60)
        print("步骤2: 管理员创建网络")
        print("-" * 60)

        # 创建新网络
        network_name = "CSEC5615 测试无线网络"
        network_info = self.create_network(network_name)

        if not network_info['success']:
            print("❌ 网络创建失败，测试终止")
            return

        print(f"网络详情:")
        print(f"  名称: {network_info['name']}")
        print(f"  ID: {network_info['network_id']}")
        print(f"  ID (bytes32): {network_info['network_id_bytes32']}")

        # 获取管理员的网络列表
        admin_networks = self.get_owner_networks()
        if admin_networks['success']:
            print(f"管理员拥有 {admin_networks['network_count']} 个网络:")
            for idx, net_id in enumerate(admin_networks['networks']):
                print(f"  [{idx + 1}] {net_id}")

        # 步骤3: 为每个用户注册设备
        print("\n" + "-" * 60)
        print("步骤3: 为每个用户注册设备")
        print("-" * 60)

        devices = []
        device_types = ["smartphone", "laptop", "tablet"]

        for idx, user in enumerate(users):
            device_type = device_types[idx % len(device_types)]
            device_name = f"{user['name']}的{device_type}"

            # 注册设备
            device_info = self.register_device(
                device_type,
                device_name,
                self.test_accounts[idx]  # 对应的账户
            )

            if device_info['success']:
                devices.append(device_info)
                print(f"设备详情:")
                print(f"  名称: {device_info['name']}")
                print(f"  DID: {device_info['did']}")
                print(f"  DID (bytes32): {device_info['did_bytes32']}")
                print(f"  所有者: {device_info['owner']}")

        print(f"成功注册 {len(devices)} 个设备")

        # 步骤4: 管理员授予设备访问网络的权限
        print("\n" + "-" * 60)
        print("步骤4: 管理员授予设备访问网络的权限 - 单独授权")
        print("-" * 60)

        # 单独授权测试
        if devices:
            # 选择第一个设备进行单独授权测试
            test_device = devices[0]

            # 检查当前访问状态
            access_check = self.check_network_access(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )
            print(f"授权前访问状态: {'有权限' if access_check['has_access'] else '无权限'}")

            # 授予访问权限
            grant_result = self.grant_network_access(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            if grant_result['success']:
                # 再次检查访问状态
                access_check = self.check_network_access(
                    test_device['did_bytes32'],
                    network_info['network_id_bytes32']
                )
                print(f"授权后访问状态: {'有权限' if access_check['has_access'] else '无权限'}")

        # 步骤5: 批量授权
        print("\n" + "-" * 60)
        print("步骤5: 管理员授予设备访问网络的权限 - 批量授权")
        print("-" * 60)

        if len(devices) > 1:
            # 选择剩余设备进行批量授权
            remaining_devices = devices[1:]
            device_dids = [device['did_bytes32'] for device in remaining_devices]

            # 检查当前访问状态
            for idx, device in enumerate(remaining_devices):
                access_check = self.check_network_access(
                    device['did_bytes32'],
                    network_info['network_id_bytes32']
                )
                print(f"设备 {idx + 1} 授权前状态: {'有权限' if access_check['has_access'] else '无权限'}")

            # 批量授予访问权限
            batch_result = self.batch_grant_access(
                device_dids,
                network_info['network_id_bytes32']
            )

            if batch_result['success']:
                print(f"批量授权结果: 成功授权 {batch_result['success_count']} 个设备")

                # 再次检查访问状态
                for idx, device in enumerate(remaining_devices):
                    access_check = self.check_network_access(
                        device['did_bytes32'],
                        network_info['network_id_bytes32']
                    )
                    print(f"设备 {idx + 1} 授权后状态: {'有权限' if access_check['has_access'] else '无权限'}")

        # 步骤6: 验证所有设备的访问权限
        print("\n" + "-" * 60)
        print("步骤6: 验证所有设备的访问权限")
        print("-" * 60)

        all_access_granted = True
        for idx, device in enumerate(devices):
            access_check = self.check_network_access(
                device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            if access_check['has_access']:
                print(f"✅ 设备 {device['name']} 已成功获得网络访问权限")
            else:
                print(f"❌ 设备 {device['name']} 未获得网络访问权限")
                all_access_granted = False

        if all_access_granted:
            print("\n✅ 所有设备都已成功获得网络访问权限")
        else:
            print("\n❌ 部分设备未能获得网络访问权限")

        print("\n" + "=" * 80)
        if all_access_granted:
            print("测试结果: 成功 ✅")
        else:
            print("测试结果: 部分失败 ⚠️")
        print("=" * 80)

        print("\n" + "-" * 60)
        print("步骤7: 测试设备停用功能")
        print("-" * 60)

        if devices:
            # 选择一个设备进行停用测试
            test_device = devices[0]

            # 获取设备当前状态
            device_status = self.get_device_info(test_device['did_bytes32'])
            if device_status['success']:
                print(f"设备当前状态:")
                print(f"  名称: {device_status['name']}")
                print(f"  所有者: {device_status['owner']}")
                print(f"  是否活跃: {'是' if device_status['is_active'] else '否'}")

                if device_status['is_active']:
                    # 执行设备停用
                    owner_account = next((acc for acc in self.test_accounts if acc['address'] == test_device['owner']),
                                         None)
                    deactivate_result = self.deactivate_device(test_device, owner_account)

                    if deactivate_result['success']:
                        # 再次获取设备状态，确认是否已停用
                        updated_status = self.get_device_info(test_device['did_bytes32'])
                        if updated_status['success']:
                            print(f"设备停用后状态:")
                            print(f"  名称: {updated_status['name']}")
                            print(f"  是否活跃: {'是' if updated_status['is_active'] else '否'}")

                            if not updated_status['is_active']:
                                print(f"✅ 设备成功停用")
                            else:
                                print(f"❌ 设备停用操作成功，但设备仍处于活跃状态")
                    else:
                        print(f"❌ 设备停用操作失败: {deactivate_result.get('error', '未知错误')}")
                else:
                    print(f"设备已经处于停用状态，跳过停用测试")
            else:
                print(f"❌ 获取设备信息失败: {device_status.get('error', '未知错误')}")
        else:
            print(f"没有可用的测试设备，跳过停用测试")

        # 步骤8: 测试停用后的网络访问权限
        print("\n" + "-" * 60)
        print("步骤8: 测试停用后的网络访问权限")
        print("-" * 60)

        if devices and 'deactivate_result' in locals() and deactivate_result.get('success', False):
            # 检查停用后的设备是否仍有网络访问权限
            access_check = self.check_network_access(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            print(f"停用后设备访问状态: {'有权限' if access_check['has_access'] else '无权限'}")

            if access_check['has_access']:
                print(f"⚠️ 注意: 设备虽然已停用，但仍然保留网络访问权限")
                print(f"这可能是合约设计的预期行为，停用设备不会自动撤销网络访问权限")
            else:
                print(f"✅ 设备停用后，网络访问权限已被撤销")

            # 尝试撤销已停用设备的访问权限
            print("\n尝试显式撤销已停用设备的访问权限...")
            revoke_result = self.revoke_network_access(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            if revoke_result['success']:
                print(f"✅ 成功撤销已停用设备的访问权限")

                # 再次检查访问状态
                access_check = self.check_network_access(
                    test_device['did_bytes32'],
                    network_info['network_id_bytes32']
                )
                print(f"撤销后设备访问状态: {'有权限' if access_check['has_access'] else '无权限'}")
            else:
                print(f"❌ 撤销已停用设备的访问权限失败: {revoke_result.get('error', '未知错误')}")

        print("\n" + "=" * 80)
        print("网络创建和授权测试完成")
        print("=" * 80)


if __name__ == "__main__":
    try:
        test = NetworkCreationTest()
        test.run_network_tests()
    except Exception as e:
        print(f"测试过程中出错: {str(e)}")
        traceback.print_exc()
