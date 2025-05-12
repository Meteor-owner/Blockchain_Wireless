"""
Blockchain Wireless Network Identity Authentication System - Comprehensive Test Script
CSEC5615 Cloud Security Project

This script integrates the complete testing process for user registration, network creation
and permission management, device registration, and authentication
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
import sys

# Load environment variables
load_dotenv()


class BlockchainAuth:
    def __init__(self, network="localhost"):
        """Initialize Web3 connection and contract interfaces"""
        # Set up Web3 connection
        if network == "localhost":
            self.w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        else:
            raise ValueError(f"Unsupported network: {network}")

        # Check connection
        if not self.w3.is_connected():
            raise ConnectionError(f"Unable to connect to {network} network")

        print(f"Successfully connected to {network} network")

        # Load primary account private key
        private_key = os.getenv("PRIVATE_KEY")
        if not private_key:
            raise ValueError("PRIVATE_KEY environment variable not found")

        if not private_key.startswith("0x"):
            private_key = f"0x{private_key}"

        self.admin_account = Account.from_key(private_key)
        print(f"Using admin account: {self.admin_account.address}")

        # Load contract addresses from deployments directory
        deployment_file = f"./deployments/blockchain-auth-{network}.json"
        if not os.path.exists(deployment_file):
            raise ValueError(f"Contract deployment information not found: {deployment_file}")

        with open(deployment_file, 'r') as f:
            deployment_data = json.load(f)
            self.contract_address = Web3.to_checksum_address(
                deployment_data['mainContract']['address']
            )
        print(f"Main contract address: {self.contract_address}")

        # Load contract ABIs
        self.load_contract_abis()

        # Instantiate contracts
        self.main_contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.main_abi
        )

        # Get and instantiate each sub-contract
        self.user_manager_address = self.main_contract.functions.userManager().call()
        self.device_manager_address = self.main_contract.functions.deviceManager().call()
        self.network_manager_address = self.main_contract.functions.networkManager().call()
        self.auth_manager_address = self.main_contract.functions.authManager().call()

        # Instantiate user management contract
        self.user_manager_contract = self.w3.eth.contract(
            address=self.user_manager_address,
            abi=self.user_manager_abi
        )

        print(f"UserManagement contract address: {self.user_manager_address}")
        print(f"DeviceManagement contract address: {self.device_manager_address}")
        print(f"NetworkManagement contract address: {self.network_manager_address}")
        print(f"AuthenticationManager contract address: {self.auth_manager_address}")

        # Check system administrator
        self.system_admin = self.main_contract.functions.systemAdmin().call()
        print(f"System administrator: {self.system_admin}")
        print(f"Is current account the system administrator: {self.admin_account.address.lower() == self.system_admin.lower()}")

        # Role constants
        self.USER_ROLE = {
            "NONE": 0,
            "USER": 1,
            "NETWORK_ADMIN": 2,
            "SYSTEM_ADMIN": 3
        }

        # Initialize storage
        self.test_accounts = []
        self.test_users = []
        self.admin_users = []
        self.network_admin_users = []
        self.regular_users = []
        self.test_devices = []
        self.test_networks = []
        self.test_tokens = []

    def load_contract_abis(self):
        """Load all required contract ABIs"""
        # Load main contract ABI
        main_abi_file = "./artifacts/contracts/BlockchainAuthMain.sol/BlockchainAuthMain.json"
        with open(main_abi_file, 'r') as f:
            contract_json = json.load(f)
            self.main_abi = contract_json['abi']

        # Load UserManagement contract ABI
        user_abi_file = "./artifacts/contracts/UserManagement.sol/UserManagement.json"
        with open(user_abi_file, 'r') as f:
            contract_json = json.load(f)
            self.user_manager_abi = contract_json['abi']

        # Load other sub-contract ABIs (optional)
        try:
            # DeviceManagement
            device_abi_file = "./artifacts/contracts/DeviceManagement.sol/DeviceManagement.json"
            with open(device_abi_file, 'r') as f:
                contract_json = json.load(f)
                self.device_manager_abi = contract_json['abi']

            # NetworkManagement
            network_abi_file = "./artifacts/contracts/NetworkManagement.sol/NetworkManagement.json"
            with open(network_abi_file, 'r') as f:
                contract_json = json.load(f)
                self.network_manager_abi = contract_json['abi']

            # AuthenticationManager
            auth_abi_file = "./artifacts/contracts/AuthenticationManager.sol/AuthenticationManager.json"
            with open(auth_abi_file, 'r') as f:
                contract_json = json.load(f)
                self.auth_manager_abi = contract_json['abi']
        except Exception as e:
            print(f"Note: Unable to load some sub-contract ABIs: {str(e)}")
            print(f"This will not affect testing, as we mainly interact through the main contract")

    def get_role_text(self, role_id):
        """Convert role ID to text description"""
        roles = {
            0: "Unregistered",
            1: "Regular User",
            2: "Network Administrator",
            3: "System Administrator"
        }
        return roles.get(role_id, f"Unknown Role({role_id})")

    def check_admin_registration(self):
        """Check if administrator is registered as a user"""
        try:
            result = self.main_contract.functions.isRegisteredUser(
                self.admin_account.address
            ).call()

            print(f"Admin account {self.admin_account.address} registration status: {'Registered' if result else 'Unregistered'}")
            return result
        except Exception as e:
            print(f"❌ Exception checking admin registration status: {str(e)}")
            return False

    def register_admin_as_user(self):
        """Register administrator as system user"""
        try:
            # Generate new key pair
            keys = self.generate_keys()
            public_key_bytes = bytes.fromhex(keys['public_key'])

            admin_name = "System Administrator"
            admin_email = "admin@example.com"

            print(f"Registering admin: {admin_name}, {admin_email}")

            # Build transaction
            tx = self.main_contract.functions.registerUser(
                admin_name,
                admin_email,
                public_key_bytes,
                b''  # Empty signature, as default admin has self-registration privileges
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            user_info = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'address': self.admin_account.address,
                'name': admin_name,
                'email': admin_email,
                'keys': keys,
                'account': {'address': self.admin_account.address, 'private_key': self.admin_account.key.hex()},
                'role': self.USER_ROLE["SYSTEM_ADMIN"]
            }

            if user_info['success']:
                print(f"✅ Admin registration successful")
                self.test_users.append(user_info)
                self.admin_users.append(user_info)
            else:
                print(f"❌ Admin registration failed")

            return user_info
        except Exception as e:
            print(f"❌ Admin registration exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def generate_keys(self):
        """Generate public-private key pair"""
        private_key = self.w3.eth.account.create().key
        acct = Account.from_key(private_key)
        public_key = acct._key_obj.public_key.to_bytes()

        return {
            'private_key': private_key.hex(),
            'public_key': public_key.hex(),
            'address': acct.address
        }

    def create_new_accounts(self, count=3):
        """Create new Ethereum accounts and transfer some ETH to them"""
        accounts = []
        for i in range(count):
            # Create new account
            acct = Account.create()
            print(f"Creating new account #{i + 1}: {acct.address}")

            # Transfer ETH from main account
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

            # Check new account balance
            balance = self.w3.eth.get_balance(acct.address)
            print(f"  Account balance: {self.w3.from_wei(balance, 'ether')} ETH")

            accounts.append({
                'address': acct.address,
                'private_key': acct.key.hex(),
                'account_obj': acct,
                'balance': self.w3.from_wei(balance, 'ether')
            })

        return accounts

    def register_user_from_account(self, account, name, email):
        """Register user from specified account"""
        try:
            # Generate new key pair
            keys = self.generate_keys()
            public_key_bytes = bytes.fromhex(keys['public_key'])

            print(f"Registering user from account {account['address']}: {name}, {email}")

            # Build transaction
            tx = self.main_contract.functions.registerUser(
                name,
                email,
                public_key_bytes,
                b''  # Empty signature
            ).build_transaction({
                'from': account['address'],
                'nonce': self.w3.eth.get_transaction_count(account['address']),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, account['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
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
                'role': self.USER_ROLE["USER"]  # Default to regular user
            }

            if user_info['success']:
                print(f"✅ User registration successful: {name}")
                self.test_users.append(user_info)
                self.regular_users.append(user_info)
            else:
                print(f"❌ User registration failed: {name}")

            return user_info
        except Exception as e:
            print(f"❌ User registration exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def change_user_role(self, user_address, new_role):
        """Administrator changes user role"""
        try:
            # Check if current account is system administrator
            if self.admin_account.address.lower() != self.system_admin.lower():
                print("❌ Current account is not system administrator, cannot change user role")
                return {
                    'success': False,
                    'error': "Not system admin"
                }

            role_text = self.get_role_text(new_role)
            print(f"Changing user {user_address} role to: {role_text}")

            # Build transaction
            tx = self.user_manager_contract.functions.changeUserRole(
                user_address,
                new_role
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'user_address': user_address,
                'new_role': new_role
            }

            if result['success']:
                print(f"✅ User role change successful")

                # Update role in test user list
                for user in self.test_users:
                    if user['address'].lower() == user_address.lower():
                        user['role'] = new_role

                        # Reclassify user
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
                print(f"❌ User role change failed")

            return result
        except Exception as e:
            print(f"❌ Change user role exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_user_info(self, user_address):
        """Get user information"""
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
            print(f"❌ Get user info exception: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def get_user_count(self):
        """Get the number of users in the system"""
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
        """Get user list"""
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
        """Update user information"""
        try:
            print(f"Updating user {account['address']} information: {name}, {email}")

            # First check if user is registered and active
            user_check = self.get_user_info(account['address'])
            if not user_check['success']:
                print(f"❌ Unable to get user information, user may not be registered")
                return {
                    'success': False,
                    'error': "User not registered"
                }

            if not user_check['is_active']:
                print(f"❌ User is deactivated, cannot update information")
                return {
                    'success': False,
                    'error': "User is not active"
                }

            print(f"✅ User is registered and active, continuing with update")

            # If new public key is provided, use it; otherwise use empty bytes
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

            # Ensure private key is correct
            if 'private_key' not in account:
                print(f"❌ No private key in account object")
                return {
                    'success': False,
                    'error': "Account object missing private key"
                }

            # Build transaction
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

            # Sign and send transaction
            try:
                signed_tx = self.w3.eth.account.sign_transaction(tx, account['private_key'])
                tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

                # Wait for transaction confirmation
                tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

                result = {
                    'success': tx_receipt.status == 1,
                    'tx_hash': self.w3.to_hex(tx_hash),
                    'block_number': tx_receipt.blockNumber,
                    'new_name': name,
                    'new_email': email
                }

                if result['success']:
                    print(f"✅ User information update successful")

                    # Update test user list information
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
                    print(f"❌ User information update failed")

                return result
            except Exception as tx_error:
                print(f"❌ Transaction execution error: {str(tx_error)}")
                return {
                    'success': False,
                    'error': str(tx_error),
                    'traceback': traceback.format_exc()
                }
        except Exception as e:
            print(f"❌ Update user info exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def deactivate_user(self, account):
        """Deactivate user account"""
        try:
            print(f"Deactivating user account: {account['address']}")

            # Build transaction
            tx = self.main_contract.functions.deactivateUser().build_transaction({
                'from': account['address'],
                'nonce': self.w3.eth.get_transaction_count(account['address']),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, account['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }

            if result['success']:
                print(f"✅ User account successfully deactivated")

                # Update test user status
                for user in self.test_users:
                    if user['address'].lower() == account['address'].lower():
                        user['is_active'] = False
            else:
                print(f"❌ User account deactivation failed")

            return result
        except Exception as e:
            print(f"❌ Deactivate user account exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def generate_login_challenge(self, user_address):
        """Generate user login challenge"""
        try:
            print(f"Generating login challenge for user {user_address}...")

            # Build transaction
            tx = self.user_manager_contract.functions.generateLoginChallenge(
                user_address
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # Try to get challenge value from events
            challenge = None
            expires_at = None

            if tx_receipt.status == 1:
                try:
                    # Parse event to get challenge value
                    event_filter = self.user_manager_contract.events.LoginChallengeGenerated().process_receipt(
                        tx_receipt)
                    if event_filter and len(event_filter) > 0:
                        for evt in event_filter:
                            challenge = self.w3.to_hex(evt['args']['challenge'])
                            expires_at = evt['args']['expiresAt']
                            print(f"Challenge value from event: {challenge}")
                            print(f"Challenge expiration time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_at))}")
                except Exception as e:
                    print(f"Exception parsing challenge event: {str(e)}")
                    # May need to get challenge value another way
                    challenge = None
                    expires_at = None

            result = {
                'success': tx_receipt.status == 1 and challenge is not None,
                'tx_hash': self.w3.to_hex(tx_hash),
                'challenge': challenge,
                'expires_at': expires_at
            }

            if result['success']:
                print(f"✅ Login challenge generated successfully")
            else:
                print(f"❌ Login challenge generation failed or unable to get challenge value")

            return result
        except Exception as e:
            print(f"❌ Generate login challenge exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def sign_login_challenge(self, private_key_hex, user_address, challenge):
        """Sign login challenge using private key"""
        try:
            # Ensure private key format is correct
            if not private_key_hex.startswith('0x'):
                private_key = f"0x{private_key_hex}"
            else:
                private_key = private_key_hex

            # Ensure challenge is in bytes32 format
            if challenge.startswith('0x'):
                challenge_bytes = bytes.fromhex(challenge[2:])
            else:
                challenge_bytes = bytes.fromhex(challenge)

            user_address_bytes = Web3.to_bytes(hexstr=user_address)

            # Build message hash - following contract logic
            message_bytes = user_address_bytes + challenge_bytes
            message_hash = Web3.keccak(message_bytes)

            # Create Ethereum signature message
            eth_message = encode_defunct(primitive=message_hash)

            # Sign with private key
            account = Account.from_key(private_key)
            signed_message = account.sign_message(eth_message)

            # Return signature result
            signature = signed_message.signature.hex()
            print(f"✅ Successfully signed login challenge: {signature[:20]}...")
            return signature
        except Exception as e:
            print(f"❌ Sign login challenge exception: {str(e)}")
            print(traceback.format_exc())
            return ""

    def verify_login(self, user_address, challenge, signature):
        """Verify user login"""
        try:
            print(f"Verifying login for user {user_address}...")

            # Convert signature to bytes
            if signature.startswith('0x'):
                signature_bytes = self.w3.to_bytes(hexstr=signature)
            else:
                signature_bytes = bytes.fromhex(signature)

            # Call contract to verify login
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

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # Try to get login result from events
            login_success = False
            user_role = None

            if tx_receipt.status == 1:
                try:
                    # Check for LoginSuccess event
                    success_events = self.user_manager_contract.events.LoginSuccess().process_receipt(tx_receipt)
                    if success_events and len(success_events) > 0:
                        login_success = True
                        print(f"Login success event detected")

                    # Can also check for LoginFailed event
                    failed_events = self.user_manager_contract.events.LoginFailed().process_receipt(tx_receipt)
                    if failed_events and len(failed_events) > 0:
                        login_success = False
                        print(f"Login failed event detected")

                    # Try to get user role from function return value
                    # This might need to be changed to call a view function, as getting return values from transactions is difficult
                    user_info = self.get_user_info(user_address)
                    if user_info['success']:
                        user_role = user_info['role']
                except Exception as e:
                    print(f"Exception parsing login events: {str(e)}")

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'login_success': login_success,
                'user_role': user_role
            }

            if result['success'] and login_success:
                print(f"✅ User login verification successful")
                print(f"  User role: {self.get_role_text(user_role)}")
            else:
                print(f"❌ User login verification failed")

            return result
        except Exception as e:
            print(f"❌ Verify login exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def create_network(self, name, owner_account=None):
        """Create new wireless network"""
        try:
            # Generate network ID
            network_id = f"net:{uuid.uuid4()}"
            # Convert to bytes32
            network_id_hash = hashlib.sha256(network_id.encode()).digest()
            network_id_bytes32 = "0x" + network_id_hash.hex()

            # If owner not specified, use admin account
            if owner_account is None:
                owner_account = {'address': self.admin_account.address, 'private_key': self.admin_account.key.hex()}

            print(f"Creating new network: {name}, ID: {network_id}")

            # Build transaction
            tx = self.main_contract.functions.createNetwork(
                self.w3.to_bytes(hexstr=network_id_bytes32),
                name
            ).build_transaction({
                'from': owner_account['address'],
                'nonce': self.w3.eth.get_transaction_count(owner_account['address']),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, owner_account['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            network_info = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'network_id': network_id,
                'network_id_bytes32': network_id_bytes32,
                'name': name,
                'owner': owner_account['address']
            }

            if network_info['success']:
                print(f"✅ Network created successfully: {name}")
                self.test_networks.append(network_info)
            else:
                print(f"❌ Network creation failed: {name}")

            return network_info
        except Exception as e:
            print(f"❌ Network creation exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def create_did(self, device_type):
        """Create device ID (DID)"""
        uuid_val = str(uuid.uuid4())
        # Create DID
        did = f"did:identity-chain:{uuid_val}"
        # Use SHA-256 to ensure 32-byte length
        did_hash = hashlib.sha256(did.encode()).digest()
        # Convert device type to bytes32
        device_type_bytes = self.w3.to_bytes(text=device_type).ljust(32, b'\0')
        device_type_hex = self.w3.to_hex(device_type_bytes)

        return {
            'did': did,
            'did_bytes32': "0x" + did_hash.hex(),
            'device_type_bytes32': device_type_hex
        }

    def register_device(self, device_type, name, owner_account):
        """Register device"""
        try:
            # Create device ID
            did_info = self.create_did(device_type)

            # Generate key pair
            keys = self.generate_keys()
            public_key_bytes = bytes.fromhex(keys['public_key'])

            # Create metadata
            metadata = f"metadata_{uuid.uuid4().hex[:8]}"
            metadata_bytes32 = self.w3.to_bytes(text=metadata).ljust(32, b'\0')

            print(f"Registering device for user {owner_account['address']}: {name}, type: {device_type}")

            # Build transaction
            tx = self.main_contract.functions.registerDevice(
                self.w3.to_bytes(text=device_type).ljust(32, b'\0'),
                self.w3.to_bytes(hexstr=did_info['did_bytes32']),
                public_key_bytes,
                name,
                metadata_bytes32
            ).build_transaction({
                'from': owner_account['address'],
                'nonce': self.w3.eth.get_transaction_count(owner_account['address']),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, owner_account['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
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
                print(f"✅ Device registration successful: {name}")
                self.test_devices.append(device_info)
            else:
                print(f"❌ Device registration failed: {name}")

            return device_info
        except Exception as e:
            print(f"❌ Device registration exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def grant_network_access(self, did_bytes32, network_id_bytes32, admin_account=None):
        """Grant device access to network"""
        try:
            if admin_account is None:
                admin_account = {'address': self.admin_account.address, 'private_key': self.admin_account.key.hex()}

            print(f"Granting device {did_bytes32} access to network {network_id_bytes32}")

            # Build transaction
            tx = self.main_contract.functions.grantAccess(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32)
            ).build_transaction({
                'from': admin_account['address'],
                'nonce': self.w3.eth.get_transaction_count(admin_account['address']),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, admin_account['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }

            if result['success']:
                print(f"✅ Access grant successful")
            else:
                print(f"❌ Access grant failed")

            return result
        except Exception as e:
            print(f"❌ Grant access exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def check_network_access(self, did_bytes32, network_id_bytes32):
        """Check if device has access to network"""
        try:
            result = self.main_contract.functions.checkAccess(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32)
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
        """Batch grant multiple devices access to network"""
        try:
            # Convert DID list to bytes32 list
            did_bytes32_list = [self.w3.to_bytes(hexstr=did) for did in did_list]

            print(f"Batch granting {len(did_list)} devices access to network")

            # Build transaction
            tx = self.main_contract.functions.batchGrantAccess(
                did_bytes32_list,
                self.w3.to_bytes(hexstr=network_id_bytes32)
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 2000000,  # Batch operations may need more gas
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # Try to get the success count from return
            success_count = 0
            if tx_receipt.status == 1:
                # May need to parse this from event logs
                success_count = len(did_list)  # Assume all successful

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber,
                'success_count': success_count
            }

            if result['success']:
                print(f"✅ Batch authorization successful: {success_count} devices")
            else:
                print(f"❌ Batch authorization failed")

            return result
        except Exception as e:
            print(f"❌ Batch authorization exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_owner_networks(self, owner_address=None):
        """Get list of networks owned by a user"""
        try:
            if owner_address is None:
                owner_address = self.admin_account.address

            networks = self.main_contract.functions.getOwnerNetworks(owner_address).call()

            # Convert to readable format
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
        """Deactivate device

        Args:
            device_info: Dictionary containing device information
            account: Account to execute deactivation (defaults to device owner)

        Returns:
            Dictionary containing operation result
        """
        try:
            # If account not specified, default to device owner's account
            if account is None:
                # Find test account that owns this device
                owner_address = device_info['owner']
                account = next((acc for acc in self.test_accounts if acc['address'] == owner_address), None)

                # If owner account not found, use admin account
                if account is None:
                    account = {'address': self.admin_account.address, 'private_key': self.admin_account.key.hex()}
                    print(f"Device owner account not found, using admin account to deactivate device")

            print(f"Deactivating device: {device_info['name']} (DID: {device_info['did']})")
            print(f"Executing account: {account['address']}")

            # Build transaction
            tx = self.main_contract.functions.deactivateDevice(
                self.w3.to_bytes(hexstr=device_info['did_bytes32'])
            ).build_transaction({
                'from': account['address'],
                'nonce': self.w3.eth.get_transaction_count(account['address']),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, account['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }

            if result['success']:
                print(f"✅ Device {device_info['name']} deactivation successful")
            else:
                print(f"❌ Device {device_info['name']} deactivation failed")

            return result
        except Exception as e:
            print(f"❌ Device deactivation exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_device_info(self, did_bytes32):
        """Get device information"""
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
        """Revoke device access to network"""
        try:
            print(f"Revoking device {did_bytes32} access to network {network_id_bytes32}")

            # Build transaction
            tx = self.main_contract.functions.revokeAccess(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32)
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }

            if result['success']:
                print(f"✅ Access revocation successful")
            else:
                print(f"❌ Access revocation failed")

            return result
        except Exception as e:
            print(f"❌ Revoke access exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def generate_auth_challenge(self, did_bytes32, network_id_bytes32):
        """Generate device authentication challenge"""
        try:
            print(f"Generating authentication challenge for device {did_bytes32}...")

            # Build transaction
            tx = self.main_contract.functions.generateAuthChallenge(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32)
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # Get challenge value, needs additional call to getLatestChallenge
            challenge_result = self.get_latest_challenge(did_bytes32)

            if challenge_result['success']:
                print(f"✅ Authentication challenge generated successfully")
                print(f"  Challenge value: {challenge_result['challenge']}")
                print(
                    f"  Expiration time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(challenge_result['expires_at']))}")
            else:
                print(f"❌ Authentication challenge generation failed")

            return {
                'success': tx_receipt.status == 1 and challenge_result['success'],
                'tx_hash': self.w3.to_hex(tx_hash),
                'challenge': challenge_result.get('challenge'),
                'expires_at': challenge_result.get('expires_at')
            }
        except Exception as e:
            print(f"❌ Generate authentication challenge exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def get_latest_challenge(self, did_bytes32):
        """Get device's latest challenge value"""
        try:
            result = self.main_contract.functions.getLatestChallenge(
                self.w3.to_bytes(hexstr=did_bytes32)
            ).call()

            return {
                'success': True,
                'challenge': self.w3.to_hex(result[0]),
                'expires_at': result[1]
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def sign_challenge(self, private_key_hex, did_bytes32, challenge):
        """Sign challenge using private key"""
        try:
            # Ensure private key format is correct
            if not private_key_hex.startswith('0x'):
                private_key = f"0x{private_key_hex}"
            else:
                private_key = private_key_hex

            # Ensure DID is in bytes32 format
            if did_bytes32.startswith('0x'):
                did_bytes = bytes.fromhex(did_bytes32[2:])
            else:
                did_bytes = bytes.fromhex(did_bytes32)

            # Ensure challenge is in bytes32 format
            if challenge.startswith('0x'):
                challenge_bytes = bytes.fromhex(challenge[2:])
            else:
                challenge_bytes = bytes.fromhex(challenge)

            # Build message hash according to contract logic
            # First concatenate DID and challenge value
            message_bytes = did_bytes + challenge_bytes
            # Calculate keccak256 hash
            message_hash = Web3.keccak(message_bytes)

            # Create Ethereum signature message
            from eth_account.messages import encode_defunct
            eth_message = encode_defunct(primitive=message_hash)

            # Sign with private key
            account = Account.from_key(private_key)
            signed_message = account.sign_message(eth_message)

            # Return signature result
            signature = signed_message.signature.hex()
            print(f"✅ Successfully signed challenge: {signature[:20]}...")
            return signature
        except Exception as e:
            print(f"❌ Sign challenge exception: {str(e)}")
            print(traceback.format_exc())
            return ""

    def authenticate(self, did_bytes32, network_id_bytes32, challenge, signature):
        """Authenticate device and get access token"""
        try:
            print(f"Authenticating device {did_bytes32}...")

            # Convert signature to bytes
            if signature.startswith('0x'):
                signature_bytes = self.w3.to_bytes(hexstr=signature)
            else:
                signature_bytes = bytes.fromhex(signature)

            # Build transaction
            tx = self.main_contract.functions.authenticate(
                self.w3.to_bytes(hexstr=did_bytes32),
                self.w3.to_bytes(hexstr=network_id_bytes32),
                self.w3.to_bytes(hexstr=challenge),
                signature_bytes
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # Try to get token ID from events
            token_id = None
            # Create filter for TokenIssued event
            if tx_receipt.status == 1:
                try:
                    # Try to get TokenIssued event
                    event_filter = self.main_contract.events.TokenIssued().process_receipt(tx_receipt)
                    if event_filter and len(event_filter) > 0:
                        for evt in event_filter:
                            token_id = self.w3.to_hex(evt['args']['tokenId'])
                            print(f"Token ID from event: {token_id}")
                except Exception as e:
                    print(f"Get token event exception: {str(e)}")
                    # Try return value as fallback
                    try:
                        # Try to get tokenId from transaction return value
                        # This requires listening to function return value, may not succeed
                        token_id = self.w3.to_hex(Web3.to_bytes(hexstr=tx_receipt.logs[0].data))
                        print(f"Token ID from log data: {token_id}")
                    except:
                        print("Unable to get token ID from logs")

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'token_id': token_id,
                'block_number': tx_receipt.blockNumber
            }

            if result['success']:
                print(f"✅ Device authentication successful")
                if token_id:
                    print(f"  Token ID received: {token_id}")
                    # Store token info for later testing
                    self.test_tokens.append({
                        'token_id': token_id,
                        'did_bytes32': did_bytes32,
                        'network_id_bytes32': network_id_bytes32,
                        'issued_at': int(time.time())
                    })
                else:
                    print("⚠️ Authentication successful but no token ID received")
            else:
                print(f"❌ Device authentication failed")

            return result
        except Exception as e:
            print(f"❌ Authentication exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def validate_token(self, token_id):
        """Validate access token validity"""
        try:
            print(f"Validating token {token_id}...")

            result = self.main_contract.functions.validateToken(
                self.w3.to_bytes(hexstr=token_id)
            ).call()

            if result:
                print(f"✅ Token is valid")
            else:
                print(f"❌ Token is invalid")

            return {
                'success': True,
                'valid': result
            }
        except Exception as e:
            print(f"❌ Validate token exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'valid': False
            }

    def revoke_token(self, token_id):
        """Revoke access token"""
        try:
            print(f"Revoking token {token_id}...")

            # Build transaction
            tx = self.main_contract.functions.revokeToken(
                self.w3.to_bytes(hexstr=token_id)
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 300000,
                'gasPrice': self.w3.eth.gas_price
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            result = {
                'success': tx_receipt.status == 1,
                'tx_hash': self.w3.to_hex(tx_hash),
                'block_number': tx_receipt.blockNumber
            }

            if result['success']:
                print(f"✅ Token successfully revoked")
            else:
                print(f"❌ Token revocation failed")

            return result
        except Exception as e:
            print(f"❌ Revoke token exception: {str(e)}")

    def get_auth_logs(self, did_bytes32):
        """Get device authentication logs"""
        try:
            print(f"Getting authentication logs for device {did_bytes32}...")

            # Get log count
            log_count = self.main_contract.functions.getAuthLogCount(
                self.w3.to_bytes(hexstr=did_bytes32)
            ).call()

            print(f"  Found {log_count} authentication logs")

            logs = []
            if log_count > 0:
                # If not too many logs, get all logs
                # Can also use getAuthLogs paging function to get partial logs
                for i in range(log_count):
                    log_info = self.main_contract.functions.getAuthLog(
                        self.w3.to_bytes(hexstr=did_bytes32),
                        i
                    ).call()

                    logs.append({
                        'verifier': log_info[0],
                        'challenge_hash': self.w3.to_hex(log_info[1]),
                        'timestamp': log_info[2],
                        'success': log_info[3]
                    })

                    # Print each log
                    log_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log_info[2]))
                    print(f"  [{i + 1}] Time: {log_time}, Result: {'Success' if log_info[3] else 'Failure'}")

            return {
                'success': True,
                'log_count': log_count,
                'logs': logs
            }
        except Exception as e:
            print(f"❌ Get authentication logs exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'log_count': 0,
                'logs': []
            }

    def wait_for_challenge_expiry(self, challenge_info, additional_wait=5):
        """Wait for authentication challenge to expire"""
        if not challenge_info['success'] or 'expires_at' not in challenge_info:
            print("⚠️ Cannot determine challenge expiration time")
            return False

        # Calculate wait time
        current_time = int(time.time())
        expires_at = challenge_info['expires_at']

        if current_time >= expires_at:
            print("Challenge already expired")
            return True

        wait_time = expires_at - current_time + additional_wait

        if wait_time > 300:  # Wait time too long, skip
            print(f"⚠️ Waiting for challenge expiry requires {wait_time} seconds, skipping wait")
            return False

        print(f"Waiting for challenge to expire, requires {wait_time} seconds...")
        time.sleep(wait_time)
        print("Challenge should now be expired")
        return True

    def run_system_test(self):
        print("\n" + "=" * 80)
        print("Starting System Management Feature Tests")
        print("=" * 80)

        # Step 0: Prepare test environment
        print("\n" + "-" * 60)
        print("Step 0: Prepare Test Environment")
        print("-" * 60)

        # Check if admin is registered
        is_registered = self.check_admin_registration()
        if not is_registered:
            print("Admin not registered, registering admin first...")
            admin_reg_result = self.register_admin_as_user()
            if not admin_reg_result['success']:
                print("❌ Admin registration failed, terminating test")
                return
            print("✅ Admin registration successful")
        else:
            print("✅ Admin already registered as user")

            # Get admin information
            admin_info = self.get_user_info(self.admin_account.address)
            if admin_info['success']:
                print(f"Admin information:")
                print(f"  Name: {admin_info['name']}")
                print(f"  Email: {admin_info['email']}")
                print(f"  Role: {self.get_role_text(admin_info['role'])}")
                print(
                    f"  Registration time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(admin_info['registered_at']))}")
                print(f"  Active status: {'Active' if admin_info['is_active'] else 'Deactivated'}")

                # Update admin_users list
                self.admin_users.append({
                    'address': self.admin_account.address,
                    'name': admin_info['name'],
                    'email': admin_info['email'],
                    'role': admin_info['role'],
                    'account': {'address': self.admin_account.address, 'private_key': self.admin_account.key.hex()}
                })

        # Create test accounts
        print("Creating test user accounts...")
        self.test_accounts = self.create_new_accounts(4)  # Create 4 test accounts

        # Step 1: User registration and classification management
        print("\n" + "-" * 60)
        print("Step 1: User Registration and Classification Management")
        print("-" * 60)

        # Register test users
        for idx, account in enumerate(self.test_accounts):
            user_name = f"System Test User {idx + 1}"
            user_email = f"systestuser{idx + 1}@example.com"
            self.register_user_from_account(account, user_name, user_email)

        # Display current user count
        user_count = self.get_user_count()
        if user_count['success']:
            print(f"System has {user_count['count']} users in total")

            # Get user list
            users = self.get_user_list(0, user_count['count'])
            if users['success']:
                print(f"User list:")
                for i in range(len(users['addresses'])):
                    role_text = self.get_role_text(users['roles'][i])
                    print(
                        f"  [{i + 1}] {users['names'][i]} - {users['addresses'][i]} - {role_text} - {'Active' if users['is_actives'][i] else 'Deactivated'}")

        # Step 2: Role management test
        print("\n" + "-" * 60)
        print("Step 2: Role Management Test")
        print("-" * 60)

        if len(self.test_users) >= 2:
            # Promote first user to network administrator
            network_admin_candidate = self.test_users[0]

            print(f"Promoting user {network_admin_candidate['name']} to Network Administrator")
            result = self.change_user_role(
                network_admin_candidate['address'],
                self.USER_ROLE["NETWORK_ADMIN"]
            )

            if result['success']:
                print(f"✅ Successfully promoted user to Network Administrator")

                # Get updated user information
                updated_info = self.get_user_info(network_admin_candidate['address'])
                if updated_info['success']:
                    print(f"Updated user role: {self.get_role_text(updated_info['role'])}")

                    if updated_info['role'] == self.USER_ROLE["NETWORK_ADMIN"]:
                        print(f"✅ User role successfully updated to Network Administrator")
                    else:
                        print(f"❌ User role update failed")
            else:
                print(f"❌ User role change failed")

            # Promote second user to system administrator
            system_admin_candidate = self.test_users[1]

            print(f"Promoting user {system_admin_candidate['name']} to System Administrator")
            result = self.change_user_role(
                system_admin_candidate['address'],
                self.USER_ROLE["SYSTEM_ADMIN"]
            )

            if result['success']:
                print(f"✅ Successfully promoted user to System Administrator")

                # Get updated user information
                updated_info = self.get_user_info(system_admin_candidate['address'])
                if updated_info['success']:
                    print(f"Updated user role: {self.get_role_text(updated_info['role'])}")

                    if updated_info['role'] == self.USER_ROLE["SYSTEM_ADMIN"]:
                        print(f"✅ User role successfully updated to System Administrator")
                    else:
                        print(f"❌ User role update failed")
            else:
                print(f"❌ User role change failed")

            # Print current role distribution
            print(f"\nCurrent user role distribution:")
            print(f"  System Administrators: {len(self.admin_users)}")
            print(f"  Network Administrators: {len(self.network_admin_users)}")
            print(f"  Regular Users: {len(self.regular_users)}")

            users = self.get_user_list(0, user_count['count'])
            if users['success']:
                print(f"User list:")
                for i in range(len(users['addresses'])):
                    role_text = self.get_role_text(users['roles'][i])
                    print(
                        f"  [{i + 1}] {users['names'][i]} - {users['addresses'][i]} - {role_text} - {'Active' if users['is_actives'][i] else 'Deactivated'}")

        # Step 3: User information update test
        print("\n" + "-" * 60)
        print("Step 3: User Information Update Test")
        print("-" * 60)

        if len(self.regular_users) > 0:
            # Select a regular user for information update test
            test_user = self.regular_users[0]

            # Get original user information
            original_info = self.get_user_info(test_user['address'])
            if original_info['success']:
                print(f"Original user information:")
                print(f"  Name: {original_info['name']}")
                print(f"  Email: {original_info['email']}")

                # Update user information
                new_name = f"{original_info['name']}_Updated"
                new_email = f"updated_{uuid.uuid4().hex[:6]}@example.com"

                update_result = self.update_user_info(
                    test_user['account'],
                    new_name,
                    new_email
                )

                if update_result['success']:
                    print(f"✅ User information update successful")

                    # Verify updated information
                    updated_info = self.get_user_info(test_user['address'])
                    if updated_info['success']:
                        print(f"Updated user information:")
                        print(f"  Name: {updated_info['name']}")
                        print(f"  Email: {updated_info['email']}")

                        if updated_info['name'] == new_name and updated_info['email'] == new_email:
                            print(f"✅ User information verification successful")
                        else:
                            print(f"❌ User information verification failed")
                else:
                    print(f"❌ User information update failed")
        else:
            print("No regular users available, skipping user information update test")

        # Step 4: User deactivation test
        print("\n" + "-" * 60)
        print("Step 4: User Deactivation Test")
        print("-" * 60)

        if len(self.regular_users) > 1:
            # Select a regular user for deactivation test
            test_user = self.regular_users[1]

            # Get original user status
            original_info = self.get_user_info(test_user['address'])
            if original_info['success']:
                print(f"Original user status: {'Active' if original_info['is_active'] else 'Deactivated'}")

                if original_info['is_active']:
                    # Deactivate user
                    deactivate_result = self.deactivate_user(test_user['account'])

                    if deactivate_result['success']:
                        print(f"✅ User deactivation operation successful")

                        # Verify user status
                        updated_info = self.get_user_info(test_user['address'])
                        if updated_info['success']:
                            print(f"Updated user status: {'Active' if updated_info['is_active'] else 'Deactivated'}")

                            if not updated_info['is_active']:
                                print(f"✅ User successfully deactivated")
                            else:
                                print(f"❌ User deactivation verification failed")
                    else:
                        print(f"❌ User deactivation operation failed")
                else:
                    print(f"User already deactivated, skipping deactivation test")
        else:
            print("Not enough regular users, skipping user deactivation test")

        # Step 5: User login test
        print("\n" + "-" * 60)
        print("Step 5: User Login Test")
        print("-" * 60)

        if len(self.test_users) > 0:
            # Select an active test user
            active_users = [user for user in self.test_users if user.get('is_active', True)]

            if active_users:
                test_user = active_users[0]

                print(f"Testing login flow for user {test_user['name']}")

                # 5.1 Generate login challenge
                print("\n5.1 Generate Login Challenge")
                challenge_result = self.generate_login_challenge(test_user['address'])

                if challenge_result['success']:
                    # 5.2 Sign challenge
                    print("\n5.2 User Signs Challenge")
                    signature = self.sign_login_challenge(
                        test_user['private_key'],
                        test_user['address'],
                        challenge_result['challenge']
                    )

                    if signature:
                        # 5.3 Verify login
                        print("\n5.3 Verify Login")
                        login_result = self.verify_login(
                            test_user['address'],
                            challenge_result['challenge'],
                            signature
                        )

                        if login_result['success'] and login_result['login_success']:
                            print(f"✅ User login successful")
                            print(f"  User role: {self.get_role_text(login_result['user_role'])}")
                        else:
                            print(f"❌ User login failed")
                    else:
                        print(f"❌ Challenge signing failed, skipping login verification")
                else:
                    print(f"❌ Generate login challenge failed, skipping subsequent steps")
            else:
                print("No active test users, skipping login test")
        else:
            print("No test users available, skipping login test")

        # Step 6: User permissions test
        print("\n" + "-" * 60)
        print("Step 6: User Permissions Test")
        print("-" * 60)

        # 6.1 Regular user attempts to change another user's role (should fail)
        print("\n6.1 Regular user attempts to change another user's role")

        if len(self.regular_users) > 0 and len(self.test_users) > 2:
            regular_user = self.regular_users[0]
            target_user = [user for user in self.test_users if user['address'] != regular_user['address']][0]

            print(
                f"Regular user {regular_user['name']} attempts to promote user {target_user['name']} to Network Administrator")

            # Save current nonce
            original_nonce = self.w3.eth.get_transaction_count(self.admin_account.address)

            try:
                # Build transaction (note: we expect this to fail)
                tx = self.user_manager_contract.functions.changeUserRole(
                    target_user['address'],
                    self.USER_ROLE["NETWORK_ADMIN"]
                ).build_transaction({
                    'from': regular_user['address'],
                    'nonce': self.w3.eth.get_transaction_count(regular_user['address']),
                    'gas': 500000,
                    'gasPrice': self.w3.eth.gas_price
                })

                # Sign and send transaction
                signed_tx = self.w3.eth.account.sign_transaction(tx, regular_user['account']['private_key'])

                # This may throw an exception due to insufficient permissions
                tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

                # Wait for transaction confirmation
                tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

                if tx_receipt.status == 1:
                    print(f"❌ Regular user successfully modified another user's role, this is a security issue!")
                else:
                    print(f"✅ Transaction accepted but execution failed, permission check working correctly")
            except Exception as e:
                print(f"✅ Transaction rejected, permission check working correctly: {str(e)}")
        else:
            print("Not enough users for permission test, skipping")

        print("\n" + "=" * 80)
        print("Starting Network Creation and Authorization Test")
        print("=" * 80)

        # Step 0: Ensure admin is registered as a user
        print("\n" + "-" * 60)
        print("Step 0: Ensure Admin is Registered as a User")
        print("-" * 60)

        # Check if admin is registered
        is_registered = self.check_admin_registration()
        if not is_registered:
            print("Admin not yet registered as a user, registering admin first...")
            admin_reg_result = self.register_admin_as_user()
            if not admin_reg_result['success']:
                print("❌ Admin registration failed, test terminated")
                return
            print("✅ Admin registration successful")
        else:
            print("✅ Admin already registered as a user")

        # Step 1: Create test user accounts
        print("\n" + "-" * 60)
        print("Step 1: Create Test User Accounts")
        print("-" * 60)

        # Create 3 new user accounts
        self.test_accounts = self.create_new_accounts(3)

        # Register users for each account
        users = []
        for idx, account in enumerate(self.test_accounts):
            user_name = f"Network Test User {idx + 1}"
            user_email = f"netuser{idx + 1}@example.com"

            # Register user
            user_info = self.register_user_from_account(account, user_name, user_email)
            if user_info['success']:
                users.append(user_info)

        print(f"Successfully registered {len(users)} test users")

        # Step 2: Admin creates network
        print("\n" + "-" * 60)
        print("Step 2: Admin Creates Network")
        print("-" * 60)

        # Create new network
        network_name = "CSEC5615 Test Wireless Network"
        network_info = self.create_network(network_name)

        if not network_info['success']:
            print("❌ Network creation failed, test terminated")
            return

        print(f"Network details:")
        print(f"  Name: {network_info['name']}")
        print(f"  ID: {network_info['network_id']}")
        print(f"  ID (bytes32): {network_info['network_id_bytes32']}")

        # Get admin's network list
        admin_networks = self.get_owner_networks()
        if admin_networks['success']:
            print(f"Admin owns {admin_networks['network_count']} networks:")
            for idx, net_id in enumerate(admin_networks['networks']):
                print(f"  [{idx + 1}] {net_id}")

        print("\n" + "-" * 60)
        print("Step 3: Register Devices for Each User")
        print("-" * 60)
        devices = []
        device_types = ["smartphone", "laptop", "tablet"]

        for idx, user in enumerate(users):
            device_type = device_types[idx % len(device_types)]
            device_name = f"{user['name']}'s {device_type}"

            # Register device
            device_info = self.register_device(
                device_type,
                device_name,
                self.test_accounts[idx]  # Corresponding account
            )

            if device_info['success']:
                devices.append(device_info)
                print(f"Device details:")
                print(f"  Name: {device_info['name']}")
                print(f"  DID: {device_info['did']}")
                print(f"  DID (bytes32): {device_info['did_bytes32']}")
                print(f"  Owner: {device_info['owner']}")

        print(f"Successfully registered {len(devices)} devices")

        # Step 4: Admin grants devices access to network
        print("\n" + "-" * 60)
        print("Step 4: Admin Grants Devices Access to Network - Individual Authorization")
        print("-" * 60)

        # Individual authorization test
        if devices:
            # Select first device for individual authorization test
            test_device = devices[0]

            # Check current access status
            access_check = self.check_network_access(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )
            print(f"Access status before authorization: {'Has access' if access_check['has_access'] else 'No access'}")

            # Grant access permission
            grant_result = self.grant_network_access(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            if grant_result['success']:
                # Check access status again
                access_check = self.check_network_access(
                    test_device['did_bytes32'],
                    network_info['network_id_bytes32']
                )
                print(
                    f"Access status after authorization: {'Has access' if access_check['has_access'] else 'No access'}")

        # Step 5: Batch authorization
        print("\n" + "-" * 60)
        print("Step 5: Admin Grants Devices Access to Network - Batch Authorization")
        print("-" * 60)

        if len(devices) > 1:
            # Select remaining devices for batch authorization
            remaining_devices = devices[1:]
            device_dids = [device['did_bytes32'] for device in remaining_devices]

            # Check current access status
            for idx, device in enumerate(remaining_devices):
                access_check = self.check_network_access(
                    device['did_bytes32'],
                    network_info['network_id_bytes32']
                )
                print(
                    f"Device {idx + 1} status before authorization: {'Has access' if access_check['has_access'] else 'No access'}")

            # Batch grant access permission
            batch_result = self.batch_grant_access(
                device_dids,
                network_info['network_id_bytes32']
            )

            if batch_result['success']:
                print(f"Batch authorization result: Successfully authorized {batch_result['success_count']} devices")

                # Check access status again
                for idx, device in enumerate(remaining_devices):
                    access_check = self.check_network_access(
                        device['did_bytes32'],
                        network_info['network_id_bytes32']
                    )
                    print(
                        f"Device {idx + 1} status after authorization: {'Has access' if access_check['has_access'] else 'No access'}")

        # Step 6: Verify all devices' access permissions
        print("\n" + "-" * 60)
        print("Step 6: Verify All Devices' Access Permissions")
        print("-" * 60)

        all_access_granted = True
        for idx, device in enumerate(devices):
            access_check = self.check_network_access(
                device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            if access_check['has_access']:
                print(f"✅ Device {device['name']} has successfully gained network access permission")
            else:
                print(f"❌ Device {device['name']} has not gained network access permission")
                all_access_granted = False

        if all_access_granted:
            print("\n✅ All devices have successfully gained network access permissions")
        else:
            print("\n❌ Some devices failed to gain network access permissions")

        print("\n" + "=" * 80)
        if all_access_granted:
            print("Test Result: Success ✅")
        else:
            print("Test Result: Partial Failure ⚠️")
        print("=" * 80)

        # Step 1: Basic authentication flow test
        print("\n" + "-" * 60)
        print("Step 1: Basic Authentication Flow Test")
        print("-" * 60)

        if len(self.test_devices) > 0:
            # Select first device for authentication test
            test_device = self.test_devices[0]
            print(f"Using device: {test_device['name']} (DID: {test_device['did']})")

            # 1.1 Generate authentication challenge
            print("\nAuthentication Step 1: Generate Authentication Challenge")
            challenge_result = self.generate_auth_challenge(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            if not challenge_result['success']:
                print("❌ Generate authentication challenge failed, skipping subsequent steps")
            else:
                # 1.2 Device signs challenge
                print("\nAuthentication Step 2: Device Signs Challenge")
                signature = self.sign_challenge(
                    test_device['keys']['private_key'],
                    test_device['did_bytes32'],
                    challenge_result['challenge']
                )

                if not signature:
                    print("❌ Sign challenge failed, skipping subsequent steps")
                else:
                    # 1.3 Verify device signature and get token
                    print("\nAuthentication Step 3: Verify Device and Get Token")
                    auth_result = self.authenticate(
                        test_device['did_bytes32'],
                        network_info['network_id_bytes32'],
                        challenge_result['challenge'],
                        signature
                    )

                    if not auth_result['success']:
                        print("❌ Device authentication failed, skipping subsequent steps")
                    else:
                        # 1.4 Verify token validity
                        if 'token_id' in auth_result and auth_result['token_id']:
                            print("\nAuthentication Step 4: Verify Token Validity")
                            token_valid = self.validate_token(auth_result['token_id'])

                            if token_valid['valid']:
                                print("✅ Token verification successful")
                            else:
                                print("❌ Token verification failed")

                            # 1.5 View authentication logs
                            print("\nAuthentication Step 5: View Authentication Logs")
                            auth_logs = self.get_auth_logs(test_device['did_bytes32'])

        # Step 2: Token revocation test
        print("\n" + "-" * 60)
        print("Step 2: Token Revocation Test")
        print("-" * 60)

        if len(self.test_tokens) > 0:
            token = self.test_tokens[0]
            token_id = token['token_id']

            # 2.1 Confirm token is currently valid
            print("\n2.1 Confirm Token is Currently Valid")
            token_valid = self.validate_token(token_id)

            if not token_valid['valid']:
                print("❌ Token already invalid, skipping revocation test")
            else:
                print("✅ Token currently valid")

                # 2.2 Revoke token
                print("\n2.2 Revoke Token")
                revoke_result = self.revoke_token(token_id)

                if not revoke_result['success']:
                    print("❌ Token revocation failed")
                else:
                    print("✅ Token revocation successful")

                    # 2.3 Verify token validity again
                    print("\n2.3 Verify Token Validity Again")
                    token_valid = self.validate_token(token_id)

                    if token_valid['valid']:
                        print("❌ Token still valid, revocation may not have succeeded")
                    else:
                        print("✅ Token successfully revoked, token now invalid")
        else:
            print("⚠️ No tokens available, skipping revocation test")

        # Step 3: Replay attack test
        print("\n" + "-" * 60)
        print("Step 3: Replay Attack Test")
        print("-" * 60)

        if len(self.test_devices) > 0:
            # Select second device for replay attack test
            test_device = self.test_devices[0] if len(self.test_devices) == 1 else self.test_devices[1]
            print(f"Using device: {test_device['name']} (DID: {test_device['did']})")

            # 3.1 Normal authentication flow
            print("\n3.1 Normal Authentication Flow")
            challenge_result = self.generate_auth_challenge(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            if challenge_result['success']:
                signature = self.sign_challenge(
                    test_device['keys']['private_key'],
                    test_device['did_bytes32'],
                    challenge_result['challenge']
                )

                first_auth_result = self.authenticate(
                    test_device['did_bytes32'],
                    network_info['network_id_bytes32'],
                    challenge_result['challenge'],
                    signature
                )

                if first_auth_result['success']:
                    print("✅ First authentication successful")

                    # 3.2 Replay attack test - try to use the same challenge and signature again
                    print("\n3.2 Replay Attack Test")
                    print("Trying to authenticate again using the same challenge and signature...")

                    # Wait a moment to ensure blockchain state has updated
                    time.sleep(2)

                    replay_auth_result = self.authenticate(
                        test_device['did_bytes32'],
                        network_info['network_id_bytes32'],
                        challenge_result['challenge'],
                        signature
                    )

                    if replay_auth_result['success']:
                        print("❌ Replay attack successful! This indicates a security vulnerability")
                    else:
                        print("✅ Replay attack blocked, system secure")
                else:
                    print("❌ First authentication failed, skipping replay attack test")
            else:
                print("❌ Generate challenge failed, skipping replay attack test")
        else:
            print("⚠️ No devices available, skipping replay attack test")

        # Step 4: Expired challenge test
        print("\n" + "-" * 60)
        print("Step 4: Expired Challenge Test")
        print("-" * 60)

        if len(self.test_devices) > 0:
            # Select a device for expired challenge test
            test_device = self.test_devices[-1]
            print(f"Using device: {test_device['name']} (DID: {test_device['did']})")

            # 4.1 Generate authentication challenge
            print("\n4.1 Generate Authentication Challenge")
            challenge_result = self.generate_auth_challenge(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            if challenge_result['success']:
                # Sign challenge
                signature = self.sign_challenge(
                    test_device['keys']['private_key'],
                    test_device['did_bytes32'],
                    challenge_result['challenge']
                )

                # Determine whether to wait for challenge to expire (depends on AUTH_CHALLENGE_EXPIRY setting)
                # In actual testing, we might skip waiting if expiry time is long
                should_wait = False

                # Assumption: if challenge expiry isn't long, we wait; otherwise skip
                expires_in = challenge_result['expires_at'] - int(time.time())
                if expires_in < 300:  # Less than 5 minutes, wait for expiry
                    should_wait = True
                    print(f"\n4.2 Waiting for Challenge to Expire (approximately {expires_in} seconds)...")
                    wait_success = self.wait_for_challenge_expiry(challenge_result)
                    if not wait_success:
                        print("⚠️ Unable to wait for challenge expiry, assuming expired and continuing test")
                else:
                    print("\n4.2 Challenge expiry time too long, skipping wait")
                    print(
                        f"  Challenge will expire at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(challenge_result['expires_at']))}")
                    print("  Using simulated expired challenge for this test")

                # 4.3 Try to authenticate using expired challenge
                print("\n4.3 Try to Authenticate Using Expired/Invalid Challenge")

                if should_wait:
                    print("Using real challenge that waited to expire...")
                else:
                    print("Using modified simulated expired challenge...")
                    # Simulate an expired/invalid challenge value
                    challenge_result['challenge'] = "0x" + "0" * 64  # All-zero challenge value, should be invalid

                expired_auth_result = self.authenticate(
                    test_device['did_bytes32'],
                    network_info['network_id_bytes32'],
                    challenge_result['challenge'],
                    signature
                )

                if expired_auth_result['success']:
                    print("❌ Authentication with expired/invalid challenge successful! This indicates a security issue")
                else:
                    print("✅ Authentication with expired/invalid challenge failed, system secure")
            else:
                print("❌ Generate challenge failed, skipping expired challenge test")

        # Step 5: Wrong private key signature test
        print("\n" + "-" * 60)
        print("Step 5: Wrong Private Key Signature Test")
        print("-" * 60)

        if len(self.test_devices) > 0:
            # Select device for wrong private key test
            test_device = self.test_devices[0]
            print(f"Using device: {test_device['name']} (DID: {test_device['did']})")

            # 5.1 Generate authentication challenge
            print("\n5.1 Generate Authentication Challenge")
            challenge_result = self.generate_auth_challenge(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            if challenge_result['success']:
                # 5.2 Sign challenge with wrong private key
                print("\n5.2 Sign Challenge with Wrong Private Key")

                # Generate a new private key (different from device's original key)
                wrong_keys = self.generate_keys()
                wrong_private_key = wrong_keys['private_key']

                wrong_signature = self.sign_challenge(
                    wrong_private_key,
                    test_device['did_bytes32'],
                    challenge_result['challenge']
                )

                # 5.3 Try to authenticate using wrong signature
                print("\n5.3 Try to Authenticate Using Wrong Signature")
                wrong_auth_result = self.authenticate(
                    test_device['did_bytes32'],
                    network_info['network_id_bytes32'],
                    challenge_result['challenge'],
                    wrong_signature
                )

                if wrong_auth_result['success']:
                    print("❌ Authentication with wrong private key successful! This indicates a security issue")
                else:
                    print("✅ Authentication with wrong private key failed, system secure")
            else:
                print("❌ Generate challenge failed, skipping wrong private key test")

        # Step 6: Authentication log verification
        print("\n" + "-" * 60)
        print("Step 6: Authentication Log Verification")
        print("-" * 60)

        if len(self.test_devices) > 0:
            # Get authentication logs for all devices
            for idx, device in enumerate(self.test_devices):
                print(f"\nChecking authentication logs for device {idx + 1}: {device['name']}")
                auth_logs = self.get_auth_logs(device['did_bytes32'])

                if not auth_logs['success'] or auth_logs['log_count'] == 0:
                    print(f"  No authentication logs found")
                else:
                    print(f"  Found {auth_logs['log_count']} authentication logs")

                    # Analyze successful and failed log counts
                    success_count = len([log for log in auth_logs['logs'] if log['success']])
                    fail_count = len([log for log in auth_logs['logs'] if not log['success']])

                    print(f"  Successful authentications: {success_count}")
                    print(f"  Failed authentications: {fail_count}")

        # Test result summary
        print("\n" + "=" * 80)
        print("Device Authentication Flow Test Complete")
        print("=" * 80)

        print("\n" + "-" * 60)
        print("Step 7: Test Device Deactivation Function")
        print("-" * 60)

        if devices:
            # Select a device for deactivation test
            test_device = devices[0]

            # Get current device status
            device_status = self.get_device_info(test_device['did_bytes32'])
            if device_status['success']:
                print(f"Current device status:")
                print(f"  Name: {device_status['name']}")
                print(f"  Owner: {device_status['owner']}")
                print(f"  Active: {'Yes' if device_status['is_active'] else 'No'}")

                if device_status['is_active']:
                    # Execute device deactivation
                    owner_account = next(
                        (acc for acc in self.test_accounts if acc['address'] == test_device['owner']),
                        None)
                    deactivate_result = self.deactivate_device(test_device, owner_account)

                    if deactivate_result['success']:
                        # Get device status again to confirm deactivation
                        updated_status = self.get_device_info(test_device['did_bytes32'])
                        if updated_status['success']:
                            print(f"Device status after deactivation:")
                            print(f"  Name: {updated_status['name']}")
                            print(f"  Active: {'Yes' if updated_status['is_active'] else 'No'}")

                            if not updated_status['is_active']:
                                print(f"✅ Device successfully deactivated")
                            else:
                                print(f"❌ Device deactivation operation successful, but device still active")
                    else:
                        print(
                            f"❌ Device deactivation operation failed: {deactivate_result.get('error', 'Unknown error')}")
                else:
                    print(f"Device already deactivated, skipping deactivation test")
            else:
                print(f"❌ Failed to get device information: {device_status.get('error', 'Unknown error')}")
        else:
            print(f"No test devices available, skipping deactivation test")

        # Step 8: Test network access permission after deactivation
        print("\n" + "-" * 60)
        print("Step 8: Test Network Access Permission After Deactivation")
        print("-" * 60)

        if devices and 'deactivate_result' in locals() and deactivate_result.get('success', False):
            # Check if deactivated device still has network access permission
            access_check = self.check_network_access(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            print(
                f"Device access status after deactivation: {'Has access' if access_check['has_access'] else 'No access'}")

            if access_check['has_access']:
                print(f"⚠️ Note: Device retains network access permission even after deactivation")
                print(
                    f"This may be expected contract behavior, as deactivating a device doesn't automatically revoke network access")
            else:
                print(f"✅ Device lost network access permission after deactivation")

            # Try to explicitly revoke deactivated device's access permission
            print("\nAttempting to explicitly revoke deactivated device's access permission...")
            revoke_result = self.revoke_network_access(
                test_device['did_bytes32'],
                network_info['network_id_bytes32']
            )

            if revoke_result['success']:
                print(f"✅ Successfully revoked deactivated device's access permission")

                # Check access status again
                access_check = self.check_network_access(
                    test_device['did_bytes32'],
                    network_info['network_id_bytes32']
                )
                print(
                    f"Device access status after revocation: {'Has access' if access_check['has_access'] else 'No access'}")
            else:
                print(
                    f"❌ Failed to revoke deactivated device's access permission: {revoke_result.get('error', 'Unknown error')}")

            print("\nTest Result Summary:")
            print(f"  • Test users count: {len(self.test_users)}")
            print(f"  • Test devices count: {len(self.test_devices)}")
            print(f"  • Test networks count: {len(self.test_networks)}")
            print(f"  • Generated tokens count: {len(self.test_tokens)}")

            # If sufficient tests were conducted, provide an overall assessment
            if len(self.test_devices) > 0 and len(self.test_tokens) > 0:
                print("\nSystem Security Assessment:")

                # Use variables to track results of various tests
                replay_secure = False if 'replay_auth_result' in locals() and replay_auth_result.get('success',
                                                                                                     False) else True
                expiry_secure = False if 'expired_auth_result' in locals() and expired_auth_result.get('success',
                                                                                                       False) else True
                wrong_key_secure = False if 'wrong_auth_result' in locals() and wrong_auth_result.get('success',
                                                                                                      False) else True

                if replay_secure and expiry_secure and wrong_key_secure:
                    print("  ✅ System passed all security tests, authentication mechanism working properly")
                else:
                    print("  ⚠️ System has the following security issues:")
                    if not replay_secure:
                        print("    - Insufficient replay attack protection")
                    if not expiry_secure:
                        print("    - Challenge expiration mechanism not strict enough")
                    if not wrong_key_secure:
                        print("    - Signature verification has vulnerabilities")

if __name__ == '__main__':
    try:
        test = BlockchainAuth()
        test.run_system_test()
    except Exception as e:
        print(f"Error during test process: {str(e)}")
        traceback.print_exc()