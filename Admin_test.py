"""
区块链无线网络身份验证系统 - 系统管理功能测试
CSEC5615 云安全项目
"""

import os
import time
import uuid
import hashlib
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from dotenv import load_dotenv
import json
import traceback

# 加载环境变量
load_dotenv()


class SystemManagementTest:
    """系统管理功能测试类"""

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

        # 获取并实例化各个子合约
        self.user_manager_address = self.main_contract.functions.userManager().call()
        self.device_manager_address = self.main_contract.functions.deviceManager().call()
        self.network_manager_address = self.main_contract.functions.networkManager().call()
        self.auth_manager_address = self.main_contract.functions.authManager().call()

        # 实例化用户管理合约
        self.user_manager_contract = self.w3.eth.contract(
            address=self.user_manager_address,
            abi=self.user_manager_abi
        )

        print(f"UserManagement合约地址: {self.user_manager_address}")
        print(f"DeviceManagement合约地址: {self.device_manager_address}")
        print(f"NetworkManagement合约地址: {self.network_manager_address}")
        print(f"AuthenticationManager合约地址: {self.auth_manager_address}")

        # 检查系统管理员
        self.system_admin = self.main_contract.functions.systemAdmin().call()
        self.user_manager_admin = self.user_manager_contract.functions.systemAdmin().call()

        print(f"系统管理员: {self.system_admin}")
        print(f"用户管理合约管理员: {self.user_manager_admin}")
        print(f"当前账户是否为系统管理员: {self.admin_account.address.lower() == self.system_admin.lower()}")

        # 角色常量
        self.USER_ROLE = {
            "NONE": 0,
            "USER": 1,
            "NETWORK_ADMIN": 2,
            "SYSTEM_ADMIN": 3
        }

        # 测试账户和用户列表
        self.test_accounts = []
        self.test_users = []
        self.admin_users = []
        self.network_admin_users = []
        self.regular_users = []

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

    def get_role_text(self, role_id):
        """将角色ID转换为文本描述"""
        roles = {
            0: "未注册",
            1: "普通用户",
            2: "网络管理员",
            3: "系统管理员"
        }
        return roles.get(role_id, f"未知角色({role_id})")

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

            user_info = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'address': self.admin_account.address,
                'name': admin_name,
                'email': admin_email,
                'keys': keys,
                'role': self.USER_ROLE["SYSTEM_ADMIN"]
            }

            if user_info['success']:
                print(f"✅ 管理员注册成功")
                self.admin_users.append(user_info)
            else:
                print(f"❌ 管理员注册失败")

            return user_info
        except Exception as e:
            print(f"❌ 管理员注册异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

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
                'private_key': keys['private_key'],
                'address': account['address'],
                'name': name,
                'email': email,
                'account': account,
                'role': self.USER_ROLE["USER"]  # 默认为普通用户
            }

            if user_info['success']:
                print(f"✅ 用户注册成功: {name}")
                self.test_users.append(user_info)
                self.regular_users.append(user_info)
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

    def change_user_role(self, user_address, new_role):
        """管理员修改用户角色"""
        try:
            # 检查当前账户是否为系统管理员
            if self.admin_account.address.lower() != self.system_admin.lower():
                print("❌ 当前账户不是系统管理员，无法修改用户角色")
                return {
                    'success': False,
                    'error': "Not system admin"
                }

            role_text = self.get_role_text(new_role)
            print(f"修改用户 {user_address} 角色为: {role_text}")

            # 构建交易
            tx = self.user_manager_contract.functions.changeUserRole(
                user_address,
                new_role
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

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'user_address': user_address,
                'new_role': new_role
            }

            if result['success']:
                print(f"✅ 用户角色修改成功")

                # 更新测试用户列表中的角色
                for user in self.test_users:
                    if user['address'].lower() == user_address.lower():
                        user['role'] = new_role

                        # 重新分类用户
                        if new_role == self.USER_ROLE["NETWORK_ADMIN"]:
                            if user not in self.network_admin_users:
                                self.network_admin_users.append(user)
                            if user in self.regular_users:
                                self.regular_users.remove(user)
                        elif new_role == self.USER_ROLE["SYSTEM_ADMIN"]:
                            if user not in self.admin_users:
                                self.admin_users.append(user)
                            if user in self.network_admin_users:
                                self.network_admin_users.remove(user)
                            if user in self.regular_users:
                                self.regular_users.remove(user)

            else:
                print(f"❌ 用户角色修改失败")

            return result
        except Exception as e:
            print(f"❌ 修改用户角色异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_user_info(self, user_address):
        """获取用户信息"""
        try:
            user_info = self.main_contract.functions.getUserInfo(user_address).call()

            result = {
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

            return result
        except Exception as e:
            print(f"❌ 获取用户信息异常: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def get_user_count(self):
        """获取系统中的用户数量"""
        try:
            count = self.main_contract.functions.getUserCount().call()
            return {
                'success': True,
                'count': count
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'count': 0
            }

    def get_user_list(self, offset, limit):
        """获取用户列表"""
        try:
            result = self.main_contract.functions.getUserList(offset, limit).call()
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
                'error': str(e)
            }

    def update_user_info(self, account, name, email, public_key=None):
        """更新用户信息"""
        try:
            print(f"更新用户 {account['address']} 信息: {name}, {email}")

            # 先检查用户是否已注册且活跃
            user_check = self.get_user_info(account['address'])
            if not user_check['success']:
                print(f"❌ 无法获取用户信息，可能用户未注册")
                return {
                    'success': False,
                    'error': "User not registered"
                }

            if not user_check['is_active']:
                print(f"❌ 用户已停用，无法更新信息")
                return {
                    'success': False,
                    'error': "User is not active"
                }

            print(f"✅ 用户已注册且活跃，继续更新信息")

            # 如果提供了新公钥，使用新公钥；否则使用空字节
            if public_key:
                if isinstance(public_key, str):
                    if public_key.startswith('0x'):
                        public_key_bytes = bytes.fromhex(public_key[2:])
                    else:
                        public_key_bytes = bytes.fromhex(public_key)
                else:
                    public_key_bytes = public_key
            else:
                public_key_bytes = b''

            # 确保私钥正确
            if 'private_key' not in account:
                print(f"❌ 账户对象中没有私钥")
                return {
                    'success': False,
                    'error': "Account object missing private key"
                }

            # 构建交易
            tx = self.main_contract.functions.updateUserInfo(
                name,
                email,
                public_key_bytes
            ).build_transaction({
                'from': account['address'],
                'nonce': self.w3.eth.get_transaction_count(account['address']),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名并发送交易
            try:
                signed_tx = self.w3.eth.account.sign_transaction(tx, account['private_key'])
                tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

                # 等待交易确认
                tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

                result = {
                    'success': tx_receipt.status == 1,
                    'tx_hash': self.w3.to_hex(tx_hash),
                    'block_number': tx_receipt.blockNumber,
                    'new_name': name,
                    'new_email': email
                }

                if result['success']:
                    print(f"✅ 用户信息更新成功")

                    # 更新测试用户列表中的信息
                    for user in self.test_users:
                        if user['address'].lower() == account['address'].lower():
                            user['name'] = name
                            user['email'] = email
                            if public_key:
                                if isinstance(public_key, str):
                                    user['public_key'] = public_key
                                else:
                                    user['public_key'] = public_key.hex()
                else:
                    print(f"❌ 用户信息更新失败")

                return result
            except Exception as tx_error:
                print(f"❌ 交易执行出错: {str(tx_error)}")
                return {
                    'success': False,
                    'error': str(tx_error),
                    'traceback': traceback.format_exc()
                }
        except Exception as e:
            print(f"❌ 更新用户信息异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def deactivate_user(self, account):
        """停用用户账户"""
        try:
            print(f"停用用户账户: {account['address']}")

            # 构建交易
            tx = self.main_contract.functions.deactivateUser().build_transaction({
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
                print(f"✅ 用户账户成功停用")

                # 更新测试用户状态
                for user in self.test_users:
                    if user['address'].lower() == account['address'].lower():
                        user['is_active'] = False
            else:
                print(f"❌ 用户账户停用失败")

            return result
        except Exception as e:
            print(f"❌ 停用用户账户异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def generate_login_challenge(self, user_address):
        """生成用户登录挑战"""
        try:
            print(f"为用户 {user_address} 生成登录挑战...")

            # 构建交易
            tx = self.user_manager_contract.functions.generateLoginChallenge(
                user_address
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

            # 尝试从事件中获取挑战值
            challenge = None
            expires_at = None

            if tx_receipt.status == 1:
                try:
                    # 解析事件获取挑战值
                    event_filter = self.user_manager_contract.events.LoginChallengeGenerated().process_receipt(
                        tx_receipt)
                    if event_filter and len(event_filter) > 0:
                        for evt in event_filter:
                            challenge = self.w3.to_hex(evt['args']['challenge'])
                            expires_at = evt['args']['expiresAt']
                            print(f"从事件中获取挑战值: {challenge}")
                            print(f"挑战过期时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_at))}")
                except Exception as e:
                    print(f"解析挑战事件异常: {str(e)}")
                    # 可能需要通过其他方式获取挑战值
                    challenge = None
                    expires_at = None

            result = {
                'success': tx_receipt.status == 1 and challenge is not None,
                'tx_hash': self.w3.to_hex(tx_hash),
                'challenge': challenge,
                'expires_at': expires_at
            }

            if result['success']:
                print(f"✅ 登录挑战生成成功")
            else:
                print(f"❌ 登录挑战生成失败或无法获取挑战值")

            return result
        except Exception as e:
            print(f"❌ 生成登录挑战异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def sign_login_challenge(self, private_key_hex, user_address, challenge):
        """使用私钥签名登录挑战"""
        try:
            # 确保私钥格式正确
            if not private_key_hex.startswith('0x'):
                private_key = f"0x{private_key_hex}"
            else:
                private_key = private_key_hex

            # 确保challenge是bytes32格式
            if challenge.startswith('0x'):
                challenge_bytes = bytes.fromhex(challenge[2:])
            else:
                challenge_bytes = bytes.fromhex(challenge)

            user_address_bytes = Web3.to_bytes(hexstr=user_address)

            # 构建消息哈希 - 按照合约中的逻辑
            message_bytes = user_address_bytes + challenge_bytes
            message_hash = Web3.keccak(message_bytes)

            # 创建以太坊签名消息
            eth_message = encode_defunct(primitive=message_hash)

            # 使用私钥签名
            account = Account.from_key(private_key)
            signed_message = account.sign_message(eth_message)

            # 返回签名结果
            signature = signed_message.signature.hex()
            print(f"✅ 成功签名登录挑战: {signature[:20]}...")
            return signature
        except Exception as e:
            print(f"❌ 签名登录挑战异常: {str(e)}")
            print(traceback.format_exc())
            return ""

    def verify_login(self, user_address, challenge, signature):
        """验证用户登录"""
        try:
            print(f"验证用户 {user_address} 的登录...")

            # 将签名转换为bytes
            if signature.startswith('0x'):
                signature_bytes = self.w3.to_bytes(hexstr=signature)
            else:
                signature_bytes = bytes.fromhex(signature)

            # 调用合约验证登录
            tx = self.user_manager_contract.functions.verifyLogin(
                user_address,
                self.w3.to_bytes(hexstr=challenge) if challenge.startswith('0x') else self.w3.to_bytes(text=challenge),
                signature_bytes
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

            # 尝试从事件中获取登录结果
            login_success = False
            user_role = None

            if tx_receipt.status == 1:
                try:
                    # 检查LoginSuccess事件
                    success_events = self.user_manager_contract.events.LoginSuccess().process_receipt(tx_receipt)
                    if success_events and len(success_events) > 0:
                        login_success = True
                        print(f"检测到成功登录事件")

                    # 也可以检查LoginFailed事件
                    failed_events = self.user_manager_contract.events.LoginFailed().process_receipt(tx_receipt)
                    if failed_events and len(failed_events) > 0:
                        login_success = False
                        print(f"检测到登录失败事件")

                    # 尝试从函数返回值获取用户角色
                    # 这可能需要改为调用view函数，因为在交易结果中获取返回值比较困难
                    user_info = self.get_user_info(user_address)
                    if user_info['success']:
                        user_role = user_info['role']
                except Exception as e:
                    print(f"解析登录事件异常: {str(e)}")

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'login_success': login_success,
                'user_role': user_role
            }

            if result['success'] and login_success:
                print(f"✅ 用户登录验证成功")
                print(f"  用户角色: {self.get_role_text(user_role)}")
            else:
                print(f"❌ 用户登录验证失败")

            return result
        except Exception as e:
            print(f"❌ 验证登录异常: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def run_system_management_tests(self):
        """运行系统管理功能测试"""
        print("\n" + "=" * 80)
        print("开始系统管理功能测试")
        print("=" * 80)

        # 步骤0: 准备测试环境
        print("\n" + "-" * 60)
        print("步骤0: 准备测试环境")
        print("-" * 60)

        # 检查管理员是否已注册
        is_registered = self.check_admin_registration()
        if not is_registered:
            print("管理员未注册，先注册管理员...")
            admin_reg_result = self.register_admin_as_user()
            if not admin_reg_result['success']:
                print("❌ 管理员注册失败，终止测试")
                return
            print("✅ 管理员注册成功")
        else:
            print("✅ 管理员已注册为用户")

            # 获取管理员信息
            admin_info = self.get_user_info(self.admin_account.address)
            if admin_info['success']:
                print(f"管理员信息:")
                print(f"  名称: {admin_info['name']}")
                print(f"  邮箱: {admin_info['email']}")
                print(f"  角色: {self.get_role_text(admin_info['role'])}")
                print(f"  注册时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(admin_info['registered_at']))}")
                print(f"  活跃状态: {'活跃' if admin_info['is_active'] else '已停用'}")

                # 更新admin_users列表
                self.admin_users.append({
                    'address': self.admin_account.address,
                    'name': admin_info['name'],
                    'email': admin_info['email'],
                    'role': admin_info['role'],
                    'account': {'address': self.admin_account.address, 'private_key': self.admin_account.key.hex()}
                })

            # 创建测试账户
        print("创建测试用户账户...")
        self.test_accounts = self.create_new_accounts(4)  # 创建4个测试账户

        # 步骤1: 用户注册与分类管理
        print("\n" + "-" * 60)
        print("步骤1: 用户注册与分类管理")
        print("-" * 60)

        # 注册测试用户
        for idx, account in enumerate(self.test_accounts):
            user_name = f"System Test User {idx + 1}"
            user_email = f"systestuser{idx + 1}@example.com"
            self.register_user_from_account(account, user_name, user_email)

        # 显示当前用户数量
        user_count = self.get_user_count()
        if user_count['success']:
            print(f"系统中共有 {user_count['count']} 个用户")

            # 获取用户列表
            users = self.get_user_list(0, user_count['count'])
            if users['success']:
                print(f"用户列表:")
                for i in range(len(users['addresses'])):
                    role_text = self.get_role_text(users['roles'][i])
                    print(
                        f"  [{i + 1}] {users['names'][i]} - {users['addresses'][i]} - {role_text} - {'活跃' if users['is_actives'][i] else '已停用'}")

        # 步骤2: 角色管理测试
        print("\n" + "-" * 60)
        print("步骤2: 角色管理测试")
        print("-" * 60)

        if len(self.test_users) >= 2:
            # 将第一个用户提升为网络管理员
            network_admin_candidate = self.test_users[0]

            print(f"将用户 {network_admin_candidate['name']} 提升为网络管理员")
            result = self.change_user_role(
                network_admin_candidate['address'],
                self.USER_ROLE["NETWORK_ADMIN"]
            )

            if result['success']:
                print(f"✅ 成功将用户提升为网络管理员")

                # 获取更新后的用户信息
                updated_info = self.get_user_info(network_admin_candidate['address'])
                if updated_info['success']:
                    print(f"更新后的用户角色: {self.get_role_text(updated_info['role'])}")

                    if updated_info['role'] == self.USER_ROLE["NETWORK_ADMIN"]:
                        print(f"✅ 用户角色已成功更新为网络管理员")
                    else:
                        print(f"❌ 用户角色更新失败")
            else:
                print(f"❌ 修改用户角色失败")

            # 将第二个用户提升为系统管理员
            system_admin_candidate = self.test_users[1]

            print(f"将用户 {system_admin_candidate['name']} 提升为系统管理员")
            result = self.change_user_role(
                system_admin_candidate['address'],
                self.USER_ROLE["SYSTEM_ADMIN"]
            )

            if result['success']:
                print(f"✅ 成功将用户提升为系统管理员")

                # 获取更新后的用户信息
                updated_info = self.get_user_info(system_admin_candidate['address'])
                if updated_info['success']:
                    print(f"更新后的用户角色: {self.get_role_text(updated_info['role'])}")

                    if updated_info['role'] == self.USER_ROLE["SYSTEM_ADMIN"]:
                        print(f"✅ 用户角色已成功更新为系统管理员")
                    else:
                        print(f"❌ 用户角色更新失败")
            else:
                print(f"❌ 修改用户角色失败")

            # 打印当前的角色分布
            print(f"\n当前用户角色分布:")
            print(f"  系统管理员: {len(self.admin_users)} 名")
            print(f"  网络管理员: {len(self.network_admin_users)} 名")
            print(f"  普通用户: {len(self.regular_users)} 名")

            users = self.get_user_list(0, user_count['count'])
            if users['success']:
                print(f"用户列表:")
                for i in range(len(users['addresses'])):
                    role_text = self.get_role_text(users['roles'][i])
                    print(
                        f"  [{i + 1}] {users['names'][i]} - {users['addresses'][i]} - {role_text} - {'活跃' if users['is_actives'][i] else '已停用'}")

        # 步骤3: 用户信息更新测试
        print("\n" + "-" * 60)
        print("步骤3: 用户信息更新测试")
        print("-" * 60)

        if len(self.regular_users) > 0:
            # 选择一个普通用户进行信息更新测试
            test_user = self.regular_users[0]

            # 获取原始用户信息
            original_info = self.get_user_info(test_user['address'])
            if original_info['success']:
                print(f"原始用户信息:")
                print(f"  名称: {original_info['name']}")
                print(f"  邮箱: {original_info['email']}")

                # 更新用户信息
                new_name = f"{original_info['name']}_Updated"
                new_email = f"updated_{uuid.uuid4().hex[:6]}@example.com"

                update_result = self.update_user_info(
                    test_user['account'],
                    new_name,
                    new_email
                )

                if update_result['success']:
                    print(f"✅ 用户信息更新成功")

                    # 验证更新后的信息
                    updated_info = self.get_user_info(test_user['address'])
                    if updated_info['success']:
                        print(f"更新后的用户信息:")
                        print(f"  名称: {updated_info['name']}")
                        print(f"  邮箱: {updated_info['email']}")

                        if updated_info['name'] == new_name and updated_info['email'] == new_email:
                            print(f"✅ 用户信息验证成功")
                        else:
                            print(f"❌ 用户信息验证失败")
                else:
                    print(f"❌ 用户信息更新失败")
        else:
            print("没有可用的普通用户，跳过用户信息更新测试")

        # 步骤4: 用户停用测试
        print("\n" + "-" * 60)
        print("步骤4: 用户停用测试")
        print("-" * 60)

        if len(self.regular_users) > 1:
            # 选择一个普通用户进行停用测试
            test_user = self.regular_users[1]

            # 获取原始用户状态
            original_info = self.get_user_info(test_user['address'])
            if original_info['success']:
                print(f"原始用户状态: {'活跃' if original_info['is_active'] else '已停用'}")

                if original_info['is_active']:
                    # 停用用户
                    deactivate_result = self.deactivate_user(test_user['account'])

                    if deactivate_result['success']:
                        print(f"✅ 用户停用操作成功")

                        # 验证用户状态
                        updated_info = self.get_user_info(test_user['address'])
                        if updated_info['success']:
                            print(f"更新后的用户状态: {'活跃' if updated_info['is_active'] else '已停用'}")

                            if not updated_info['is_active']:
                                print(f"✅ 用户成功停用")
                            else:
                                print(f"❌ 用户停用验证失败")
                    else:
                        print(f"❌ 用户停用操作失败")
                else:
                    print(f"用户已处于停用状态，跳过停用测试")
        else:
            print("没有足够的普通用户，跳过用户停用测试")

        # 步骤5: 用户登录测试
        print("\n" + "-" * 60)
        print("步骤5: 用户登录测试")
        print("-" * 60)

        if len(self.test_users) > 0:
            # 选择一个活跃的测试用户
            active_users = [user for user in self.test_users if user.get('is_active', True)]

            if active_users:
                test_user = active_users[0]

                print(f"测试用户 {test_user['name']} 的登录流程")

                # 5.1 生成登录挑战
                print("\n5.1 生成登录挑战")
                challenge_result = self.generate_login_challenge(test_user['address'])

                if challenge_result['success']:
                    # 5.2 签名挑战
                    print("\n5.2 用户签名挑战")
                    signature = self.sign_login_challenge(
                        test_user['private_key'],
                        test_user['address'],
                        challenge_result['challenge']
                    )

                    if signature:
                        # 5.3 验证登录
                        print("\n5.3 验证登录")
                        login_result = self.verify_login(
                            test_user['address'],
                            challenge_result['challenge'],
                            signature
                        )

                        if login_result['success'] and login_result['login_success']:
                            print(f"✅ 用户登录成功")
                            print(f"  用户角色: {self.get_role_text(login_result['user_role'])}")
                        else:
                            print(f"❌ 用户登录失败")
                    else:
                        print(f"❌ 签名挑战失败，跳过登录验证")
                else:
                    print(f"❌ 生成登录挑战失败，跳过后续步骤")
            else:
                print("没有活跃的测试用户，跳过登录测试")
        else:
            print("没有可用的测试用户，跳过登录测试")

        # 步骤6: 用户权限测试
        print("\n" + "-" * 60)
        print("步骤6: 用户权限测试")
        print("-" * 60)

        # 6.1 普通用户尝试更改其他用户的角色（应该失败）
        print("\n6.1 普通用户尝试更改其他用户的角色")

        if len(self.regular_users) > 0 and len(self.test_users) > 2:
            regular_user = self.regular_users[0]
            target_user = [user for user in self.test_users if user['address'] != regular_user['address']][0]

            print(f"普通用户 {regular_user['name']} 尝试将用户 {target_user['name']} 提升为网络管理员")

            # 保存当前nonce
            original_nonce = self.w3.eth.get_transaction_count(self.admin_account.address)

            try:
                # 构建交易（注意：这里我们预期会失败）
                tx = self.user_manager_contract.functions.changeUserRole(
                    target_user['address'],
                    self.USER_ROLE["NETWORK_ADMIN"]
                ).build_transaction({
                    'from': regular_user['address'],
                    'nonce': self.w3.eth.get_transaction_count(regular_user['address']),
                    'gas': 500000,
                    'gasPrice': self.w3.eth.gas_price
                })

                # 签名并发送交易
                signed_tx = self.w3.eth.account.sign_transaction(tx, regular_user['account']['private_key'])

                # 这里可能会抛出异常，因为权限不足
                tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

                # 等待交易确认
                tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

                if tx_receipt.status == 1:
                    print(f"❌ 普通用户成功修改了其他用户角色，这是一个安全问题！")
                else:
                    print(f"✅ 交易被接受但执行失败，权限检查正常")
            except Exception as e:
                print(f"✅ 交易被拒绝，权限检查正常: {str(e)}")
        else:
            print("没有足够的用户进行权限测试，跳过")

        # 6.2 系统管理员修改用户角色（应该成功）
        print("\n6.2 系统管理员修改用户角色")

        if len(self.admin_users) > 0 and len(self.regular_users) > 0:
            admin_user = self.admin_users[0]
            regular_user = self.regular_users[0]

            print(f"系统管理员 {admin_user['name']} 尝试将普通用户 {regular_user['name']} 提升为网络管理员")

            # 使用系统管理员账户
            result = self.change_user_role(
                regular_user['address'],
                self.USER_ROLE["NETWORK_ADMIN"]
            )

            if result['success']:
                print(f"✅ 系统管理员成功修改了用户角色")

                # 验证用户角色
                updated_info = self.get_user_info(regular_user['address'])
                if updated_info['success']:
                    print(f"更新后的用户角色: {self.get_role_text(updated_info['role'])}")

                    if updated_info['role'] == self.USER_ROLE["NETWORK_ADMIN"]:
                        print(f"✅ 用户角色已成功更新为网络管理员")
                    else:
                        print(f"❌ 用户角色更新验证失败")
            else:
                print(f"❌ 系统管理员修改用户角色失败")
        else:
            print("没有足够的用户进行权限测试，跳过")

        # 步骤7: 错误登录测试
        print("\n" + "-" * 60)
        print("步骤7: 错误登录测试")
        print("-" * 60)

        if len(self.test_users) > 0:
            test_user = self.test_users[0]

            # 7.1 使用错误的私钥签名
            print("\n7.1 使用错误的私钥签名")

            # 生成登录挑战
            challenge_result = self.generate_login_challenge(test_user['address'])

            if challenge_result['success']:
                # 生成一个新的私钥（与用户私钥不同）
                wrong_keys = self.generate_keys()
                wrong_private_key = wrong_keys['private_key']

                # 使用错误的私钥签名
                wrong_signature = self.sign_login_challenge(
                    wrong_private_key,
                    test_user['address'],
                    challenge_result['challenge']
                )

                if wrong_signature:
                    # 尝试登录验证
                    login_result = self.verify_login(
                        test_user['address'],
                        challenge_result['challenge'],
                        wrong_signature
                    )

                    if login_result['success'] and login_result['login_success']:
                        print(f"❌ 使用错误私钥登录成功，这是一个安全问题！")
                    else:
                        print(f"✅ 使用错误私钥登录被拒绝，系统安全")
                else:
                    print(f"签名失败，跳过验证")
            else:
                print(f"生成挑战失败，跳过错误私钥测试")

            # 7.2 使用错误的挑战值
            print("\n7.2 使用错误的挑战值")

            # 生成登录挑战
            challenge_result = self.generate_login_challenge(test_user['address'])

            if challenge_result['success']:
                # 签名挑战
                signature = self.sign_login_challenge(
                    test_user['private_key'],
                    test_user['address'],
                    challenge_result['challenge']
                )

                if signature:
                    # 修改挑战值
                    fake_challenge = "0x" + "1" * 64  # 全1的挑战值，应该是无效的

                    # 尝试使用错误的挑战值登录
                    login_result = self.verify_login(
                        test_user['address'],
                        fake_challenge,
                        signature
                    )

                    if login_result['success'] and login_result['login_success']:
                        print(f"❌ 使用错误挑战值登录成功，这是一个安全问题！")
                    else:
                        print(f"✅ 使用错误挑战值登录被拒绝，系统安全")
                else:
                    print(f"签名失败，跳过验证")
            else:
                print(f"生成挑战失败，跳过错误挑战测试")
        else:
            print("没有可用的测试用户，跳过错误登录测试")

        # 步骤8: 用户删除测试
        # print("\n" + "-" * 60)
        # print("步骤8: 用户删除测试")
        # print("-" * 60)
        #
        # if len(self.regular_users) > 0:
        #     # 选择一个普通用户进行删除测试
        #     test_user = self.regular_users[0]
        #
        #     print(f"测试删除用户: {test_user['name']} ({test_user['address']})")
        #
        #     # 获取原始用户信息，确认用户存在
        #     original_info = self.get_user_info(test_user['address'])
        #     if original_info['success']:
        #         print(f"用户信息获取成功，确认用户存在")
        #         print(f"  名称: {original_info['name']}")
        #         print(f"  邮箱: {original_info['email']}")
        #         print(f"  角色: {self.get_role_text(original_info['role'])}")
        #
        #         # 执行用户删除操作
        #         # 如果合约中有专门的删除用户功能，使用以下代码：
        #         # delete_result = self.delete_user(test_user['address'])
        #
        #         # 如果没有专门的删除功能，使用停用用户作为替代方案
        #         print("使用停用用户功能作为删除用户的替代方案")
        #         delete_result = self.deactivate_user(test_user['account'])
        #
        #         if delete_result['success']:
        #             print(f"✅ 用户删除（停用）操作成功")
        #
        #             # 验证用户是否已被"删除"（停用）
        #             try:
        #                 updated_info = self.get_user_info(test_user['address'])
        #                 if updated_info['success']:
        #                     print(f"用户信息仍然可以获取，但状态已更改")
        #                     print(f"  名称: {updated_info['name']}")
        #                     print(f"  邮箱: {updated_info['email']}")
        #                     print(f"  状态: {'活跃' if updated_info['is_active'] else '已停用'}")
        #
        #                     if not updated_info['is_active']:
        #                         print(f"✅ 用户已成功停用（视为删除）")
        #                     else:
        #                         print(f"❌ 用户仍然处于活跃状态，删除操作未生效")
        #                 else:
        #                     print(f"❌ 无法获取用户信息，用户可能已彻底删除或出现错误")
        #             except Exception as e:
        #                 print(f"❌ 验证用户状态时出错: {str(e)}")
        #         else:
        #             print(f"❌ 用户删除操作失败: {delete_result.get('error', '未知错误')}")
        #     else:
        #         print(f"❌ 无法获取用户信息，跳过删除测试")
        # else:
        #     print("没有可用的普通用户，跳过用户删除测试")
        #
        # # 尝试验证用户是否可以访问系统
        # if 'delete_result' in locals() and delete_result['success']:
        #     print("\n验证被删除（停用）的用户是否还能登录系统")
        #
        #     # 生成登录挑战
        #     challenge_result = self.generate_login_challenge(test_user['address'])
        #
        #     if challenge_result['success']:
        #         # 签名挑战
        #         signature = self.sign_login_challenge(
        #             test_user['private_key'],
        #             test_user['address'],
        #             challenge_result['challenge']
        #         )
        #
        #         if signature:
        #             # 尝试登录验证
        #             login_result = self.verify_login(
        #                 test_user['address'],
        #                 challenge_result['challenge'],
        #                 signature
        #             )
        #
        #             if login_result['success'] and login_result['login_success']:
        #                 print(f"❌ 已停用（删除）的用户仍然可以登录，这可能是一个安全问题！")
        #             else:
        #                 print(f"✅ 已停用（删除）的用户无法登录，系统安全")
        #         else:
        #             print(f"签名失败，跳过验证")
        #     else:
        #         print(f"生成挑战失败，跳过登录测试")

        # 总结测试结果
        print("\n" + "=" * 80)
        print("系统管理功能测试完成")
        print("=" * 80)

        print("\n测试结果摘要:")
        print(f"  • 测试账户数量: {len(self.test_accounts)}")
        print(f"  • 测试用户数量: {len(self.test_users)}")
        print(f"  • 系统管理员数量: {len(self.admin_users)}")
        print(f"  • 网络管理员数量: {len(self.network_admin_users)}")
        print(f"  • 普通用户数量: {len(self.regular_users)}")

if __name__ == "__main__":
        try:
            test = SystemManagementTest()
            test.run_system_management_tests()
        except Exception as e:
            print(f"测试过程中出错: {str(e)}")
            traceback.print_exc()