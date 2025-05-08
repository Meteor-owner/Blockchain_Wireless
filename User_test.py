"""
区块链无线网络身份验证系统 - 用户注册测试脚本
CSEC5615 云安全项目
"""

import os
import time
import uuid
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv
import json
import traceback

# 加载环境变量
load_dotenv()


class UserRegistrationTest:
    """用户注册测试类"""

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

        self.main_account = Account.from_key(private_key)
        print(f"使用主账户: {self.main_account.address}")

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

        # 获取并实例化UserManagement合约
        self.user_manager_address = self.main_contract.functions.userManager().call()
        self.user_manager_contract = self.w3.eth.contract(
            address=self.user_manager_address,
            abi=self.user_manager_abi
        )

        # 检查系统管理员
        self.system_admin = self.main_contract.functions.systemAdmin().call()
        self.user_manager_admin = self.user_manager_contract.functions.systemAdmin().call()

        print(f"主合约管理员: {self.system_admin}")
        print(f"UserManagement管理员: {self.user_manager_admin}")
        print(f"当前账户是否为系统管理员: {self.main_account.address.lower() == self.system_admin.lower()}")

        # 获取Hardhat网络中的预设账户
        self.test_accounts = self.get_hardhat_accounts()
        print(f"加载了 {len(self.test_accounts)} 个测试账户")

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

    def get_hardhat_accounts(self):
        """获取Hardhat本地网络中的预设账户"""
        # Hardhat默认账户的私钥
        private_keys = [
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
            "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
            "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
            "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
        ]

        accounts = []
        for pk in private_keys:
            account = Account.from_key(pk)
            # 检查账户余额
            balance = self.w3.eth.get_balance(account.address)
            accounts.append({
                'address': account.address,
                'private_key': pk,
                'account_obj': account,
                'balance': self.w3.from_wei(balance, 'ether')
            })

        return accounts

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
                'nonce': self.w3.eth.get_transaction_count(self.main_account.address)
            }
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.main_account.key)
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

    def is_registered_user(self, address):
        """检查地址是否已注册为用户"""
        try:
            result = self.main_contract.functions.isRegisteredUser(address).call()
            return {
                'success': True,
                'is_registered': result
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'is_registered': False
            }

    def get_user_info(self, address):
        """获取用户信息"""
        try:
            result = self.main_contract.functions.getUserInfo(address).call()
            return {
                'success': True,
                'name': result[0],
                'email': result[1],
                'public_key': result[2].hex() if result[2] else '',
                'registered_at': result[3],
                'is_active': result[4],
                'device_count': result[5],
                'network_count': result[6],
                'role': result[7],
                'authorized_by': result[8]
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def register_user_as_admin(self, name, email, public_key=None):
        """使用管理员账户注册新用户"""
        try:
            if public_key is None:
                # 生成新的密钥对
                keys = self.generate_keys()
                public_key = keys['public_key']

            # 确保公钥格式正确
            if isinstance(public_key, str):
                if public_key.startswith('0x'):
                    public_key_bytes = bytes.fromhex(public_key[2:])
                else:
                    public_key_bytes = bytes.fromhex(public_key)
            else:
                public_key_bytes = public_key

            print(f"使用管理员账户注册用户: {name}, {email}, 公钥长度: {len(public_key_bytes)}字节")

            # 构建交易
            tx = self.main_contract.functions.registerUser(
                name,
                email,
                public_key_bytes,
                b''  # 空签名，因为是管理员调用
            ).build_transaction({
                'from': self.main_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.main_account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # 签名并发送交易
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.main_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # 等待交易确认
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'public_key': public_key if isinstance(public_key, str) else public_key.hex()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def register_user_from_account(self, account, name, email, public_key=None):
        """从指定账户注册用户"""
        try:
            if public_key is None:
                # 生成新的密钥对
                keys = self.generate_keys()
                public_key = keys['public_key']

            # 确保公钥格式正确
            if isinstance(public_key, str):
                if public_key.startswith('0x'):
                    public_key_bytes = bytes.fromhex(public_key[2:])
                else:
                    public_key_bytes = bytes.fromhex(public_key)
            else:
                public_key_bytes = public_key

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

            return {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'public_key': public_key if isinstance(public_key, str) else public_key.hex()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def update_user_info(self, account, name, email):
        """更新用户信息"""
        try:
            print(f"更新用户信息: {account['address']} -> {name}, {email}")

            # 构建交易
            tx = self.main_contract.functions.updateUserInfo(
                name,
                email,
                b''  # 不更新公钥
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

    def run_user_registration_tests(self):
        """运行所有用户注册测试"""
        print("\n" + "=" * 80)
        print("开始用户注册测试")
        print("=" * 80)

        # 测试1: 检查系统初始状态
        print("\n" + "-" * 60)
        print("测试1: 检查系统初始状态")
        print("-" * 60)

        user_count = self.get_user_count()
        if user_count['success']:
            print(f"系统中现有 {user_count['count']} 个用户")

            if user_count['count'] > 0:
                users = self.get_user_list(0, min(5, user_count['count']))
                if users['success']:
                    print("用户列表:")
                    for i in range(len(users['addresses'])):
                        role_text = self.get_role_text(users['roles'][i])
                        print(
                            f"  [{i + 1}] {users['names'][i]} - {users['addresses'][i]} - {role_text} - {'活跃' if users['is_actives'][i] else '已停用'}")

        # 测试2: 管理员注册新用户
        print("\n" + "-" * 60)
        print("测试2: 管理员注册新用户")
        print("-" * 60)

        admin_name = "Admin User"
        admin_email = "admin@example.com"
        admin_keys = self.generate_keys()

        admin_reg_result = self.register_user_as_admin(admin_name, admin_email, admin_keys['public_key'])
        if admin_reg_result['success']:
            print(f"✅ 管理员注册用户成功: {admin_name}")
            print(f"  交易哈希: {admin_reg_result['tx_hash']}")

            # 验证用户信息
            is_registered = self.is_registered_user(self.main_account.address)
            print(f"  用户注册状态: {'已注册' if is_registered['is_registered'] else '未注册'}")

            if is_registered['is_registered']:
                user_info = self.get_user_info(self.main_account.address)
                if user_info['success']:
                    print(f"  用户名: {user_info['name']}")
                    print(f"  邮箱: {user_info['email']}")
                    print(f"  角色: {self.get_role_text(user_info['role'])}")
        else:
            print(f"❌ 管理员注册用户失败")
            print(f"  错误: {admin_reg_result.get('error', '未知错误')}")

        # 测试3: 使用预设账户注册新用户
        print("\n" + "-" * 60)
        print("测试3: 使用预设账户注册新用户")
        print("-" * 60)

        # 选择一个预设账户
        test_account = self.test_accounts[1]  # 使用第二个预设账户

        # 检查账户是否已注册
        is_registered = self.is_registered_user(test_account['address'])
        if is_registered['is_registered']:
            print(f"❗ 账户 {test_account['address']} 已注册，跳过注册测试")
        else:
            # 注册新用户
            test_name = "Test User"
            test_email = "test@example.com"
            test_keys = self.generate_keys()

            reg_result = self.register_user_from_account(
                test_account,
                test_name,
                test_email,
                test_keys['public_key']
            )

            if reg_result['success']:
                print(f"✅ 测试账户注册成功: {test_name}")
                print(f"  交易哈希: {reg_result['tx_hash']}")

                # 验证用户信息
                is_registered = self.is_registered_user(test_account['address'])
                print(f"  用户注册状态: {'已注册' if is_registered['is_registered'] else '未注册'}")

                if is_registered['is_registered']:
                    user_info = self.get_user_info(test_account['address'])
                    if user_info['success']:
                        print(f"  用户名: {user_info['name']}")
                        print(f"  邮箱: {user_info['email']}")
                        print(f"  角色: {self.get_role_text(user_info['role'])}")
            else:
                print(f"❌ 测试账户注册失败")
                print(f"  错误: {reg_result.get('error', '未知错误')}")
                if 'traceback' in reg_result:
                    print(f"  详细错误: {reg_result['traceback']}")

        # 测试4: 创建新账户并注册多个用户
        print("\n" + "-" * 60)
        print("测试4: 创建新账户并注册多个用户")
        print("-" * 60)

        # 创建3个新账户
        new_accounts = self.create_new_accounts(3)

        for idx, account in enumerate(new_accounts):
            # 为每个账户注册一个用户
            user_name = f"New User {idx + 1}"
            user_email = f"user{idx + 1}@example.com"
            user_keys = self.generate_keys()

            # 注册用户
            reg_result = self.register_user_from_account(
                account,
                user_name,
                user_email,
                user_keys['public_key']
            )

            if reg_result['success']:
                print(f"✅ 新账户 {idx + 1} 注册成功: {user_name}")

                # 验证用户信息
                user_info = self.get_user_info(account['address'])
                if user_info['success']:
                    print(f"  用户名: {user_info['name']}")
                    print(f"  邮箱: {user_info['email']}")
                    print(f"  角色: {self.get_role_text(user_info['role'])}")
            else:
                print(f"❌ 新账户 {idx + 1} 注册失败")
                print(f"  错误: {reg_result.get('error', '未知错误')}")

        # 测试5: 尝试更新用户信息
        print("\n" + "-" * 60)
        print("测试5: 更新用户信息")
        print("-" * 60)

        if new_accounts:
            test_account = new_accounts[0]  # 使用第一个新账户

            # 检查账户是否已注册
            is_registered = self.is_registered_user(test_account['address'])
            if is_registered['is_registered']:
                # 获取原始用户信息
                original_info = self.get_user_info(test_account['address'])
                if original_info['success']:
                    print(f"原始用户信息:")
                    print(f"  用户名: {original_info['name']}")
                    print(f"  邮箱: {original_info['email']}")

                    # 更新用户信息
                    updated_name = f"{original_info['name']}_Updated"
                    updated_email = f"updated_{uuid.uuid4().hex[:6]}@example.com"

                    update_result = self.update_user_info(test_account, updated_name, updated_email)
                    if update_result['success']:
                        print(f"✅ 用户信息更新成功")

                        # 验证更新后的信息
                        updated_info = self.get_user_info(test_account['address'])
                        if updated_info['success']:
                            print(f"更新后用户信息:")
                            print(f"  用户名: {updated_info['name']}")
                            print(f"  邮箱: {updated_info['email']}")
                    else:
                        print(f"❌ 用户信息更新失败")
                        print(f"  错误: {update_result.get('error', '未知错误')}")
            else:
                print(f"❗ 账户未注册，无法测试更新功能")
        else:
            print("❗ 没有可用的测试账户，跳过更新测试")

        # 测试6: 获取最终用户列表
        print("\n" + "-" * 60)
        print("测试6: 获取最终用户列表")
        print("-" * 60)

        user_count = self.get_user_count()
        if user_count['success']:
            print(f"系统中共有 {user_count['count']} 个用户")

            if user_count['count'] > 0:
                users = self.get_user_list(0, min(10, user_count['count']))
                if users['success']:
                    print("用户列表:")
                    for i in range(len(users['addresses'])):
                        role_text = self.get_role_text(users['roles'][i])
                        print(
                            f"  [{i + 1}] {users['names'][i]} - {users['addresses'][i]} - {role_text} - {'活跃' if users['is_actives'][i] else '已停用'}")

        print("\n" + "=" * 80)
        print("用户注册测试完成")
        print("=" * 80)

    def get_role_text(self, role_id):
        """将角色ID转换为文本说明"""
        roles = {
            0: "未注册",
            1: "普通用户",
            2: "网络管理员",
            3: "系统管理员"
        }
        return roles.get(role_id, f"未知角色({role_id})")


if __name__ == "__main__":
    try:
        test = UserRegistrationTest()
        test.run_user_registration_tests()
    except Exception as e:
        print(f"测试过程中出错: {str(e)}")
        traceback.print_exc()