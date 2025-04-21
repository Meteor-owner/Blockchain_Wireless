"""
区块链无线网络身份验证系统演示脚本
CSEC5615 云安全项目
"""

import os
import sys
import time
from python.test_identity import IdentityChainClient

def print_header(text):
    """打印格式化的标题"""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80)

def print_section(text):
    """打印格式化的章节标题"""
    print("\n" + "-" * 60)
    print(f"  {text}")
    print("-" * 60)

def print_success(text):
    """打印成功信息"""
    print(f"✅ {text}")

def print_error(text):
    """打印错误信息"""
    print(f"❌ {text}")

def print_info(text):
    """打印信息"""
    print(f"ℹ️ {text}")

def check_environment():
    """检查环境设置"""
    print_section("环境检查")
    
    # 检查是否已编译合约
    artifacts_path = "./artifacts/contracts/IdentityManager.sol/IdentityManager.json"
    if not os.path.exists(artifacts_path):
        print_error(f"未找到合约构建文件: {artifacts_path}")
        print_info("请先运行 'npx hardhat compile' 编译合约")
        return False
    
    # 检查是否已设置环境变量
    if not os.getenv("PRIVATE_KEY"):
        print_error("未设置 PRIVATE_KEY 环境变量")
        print_info("请在 .env 文件中设置您的私钥")
        return False
    
    print_success("环境检查通过")
    return True

def run_demo():
    """运行完整的演示流程"""
    print_header("区块链无线网络身份验证系统演示")
    
    if not check_environment():
        return
    
    # 初始化连接
    print_section("初始化区块链连接")
    
    try:
        client = IdentityChainClient(network="localhost")
        print_success(f"已连接到区块链网络")
        print_info(f"使用账户: {client.account.address}")
    except Exception as e:
        print_error(f"连接失败: {str(e)}")
        print_info("请确保本地区块链节点正在运行 (npx hardhat node)")
        return

    # 步骤1: 创建网络
    print_section("步骤1: 创建无线网络")
    network_name = "CSEC5615-安全Wi-Fi网络"
    network_result = client.create_network(network_name)

    if not network_result.get('success', False):
        print_error(f"创建网络失败")
        error_msg = network_result.get('error', '未知错误')
        print(f"错误详情: {error_msg}")
        # 不要立即返回，尝试打印更多信息
        print(f"完整结果: {network_result}")
        # 如果有必要，这里仍然可以退出
        if 'traceback' in network_result:
            print(f"异常堆栈:\n{network_result['traceback']}")
        return

    network_id = network_result.get('network_id')
    network_id_bytes32 = network_result.get('network_id_bytes32')
    print_success(f"已创建网络: {network_name}")
    print_info(f"网络ID: {network_id}")
    
    # 步骤2: 注册设备
    print_section("步骤2: 注册设备")
    devices = []
    device_types = ["smartphone", "laptop", "smart_tv", "iot_device"]
    device_names = ["Alice的iPhone", "Bob的笔记本电脑", "客厅智能电视", "智能恒温器"]
    
    for i, (device_type, name) in enumerate(zip(device_types, device_names)):
        # 创建设备标识
        did_info = client.create_did(device_type)
        
        # 生成密钥对
        keys = client.generate_keys()
        
        # 注册设备
        register_result = client.register_device(device_type, did_info, keys)
        
        if register_result['success']:
            print_success(f"注册设备成功: {name}")
            print_info(f"DID: {did_info['did']}")
            devices.append({
                'name': name,
                'type': device_type,
                'did': did_info['did'],
                'did_bytes32': did_info['did_bytes32'],
                'keys': keys
            })
        else:
            print_error(f"注册设备失败: {name}")
            print_info(f"错误: {register_result.get('error', '未知错误')}")
    
    if not devices:
        print_error("没有设备注册成功，演示终止")
        return
    
    # 步骤3: 授予设备访问权限
    print_section("步骤3: 授予设备访问网络的权限")
    for device in devices:
        result = client.grant_access(device['did_bytes32'], network_id_bytes32)
        if result['success']:
            print_success(f"已授权设备访问网络: {device['name']}")
        else:
            print_error(f"授权失败: {device['name']}")
            print_info(f"错误: {result.get('error', '未知错误')}")
    
    # 步骤4: 模拟设备认证流程
    print_section("步骤4: 模拟设备认证流程")
    for device in devices:
        print(f"\n🔑 正在认证设备: {device['name']}")
        
        # 生成挑战
        import uuid
        challenge = f"auth_challenge_{uuid.uuid4()}"
        print_info(f"生成挑战: {challenge}")
        
        # 设备签名挑战
        signature = client.sign_challenge(device['keys']['private_key'], challenge)
        print_info(f"设备签名挑战: {signature[:20]}...")
        
        # 验证设备并获取令牌
        auth_result = client.authenticate(device['did_bytes32'], network_id_bytes32, challenge, signature)
        
        if auth_result['success']:
            token_id = auth_result['token_id']
            print_success(f"认证成功! 获得访问令牌")
            print_info(f"令牌ID: {token_id}")
            
            # 验证令牌有效性
            token_valid = client.validate_token(token_id)
            print_info(f"令牌有效性检查: {'有效' if token_valid['valid'] else '无效'}")
            
            # 记录令牌以便稍后撤销
            device['token_id'] = token_id
        else:
            print_error(f"认证失败")
            print_info(f"错误: {auth_result.get('error', '未知错误')}")
    
    # 模拟一个恶意认证尝试
    print_section("步骤5: 模拟恶意认证尝试")
    if len(devices) > 0:
        device = devices[0]
        print_info(f"尝试使用设备 {device['name']} 进行认证")
        
        # 生成挑战
        challenge = f"auth_challenge_{uuid.uuid4()}"
        print_info(f"生成挑战: {challenge}")
        
        # 伪造错误的签名
        fake_signature = "deadbeef" * 16  # 伪造的签名
        print_info(f"使用伪造的签名: {fake_signature[:20]}...")
        
        # 尝试验证
        try:
            auth_result = client.authenticate(device['did_bytes32'], network_id_bytes32, challenge, fake_signature)
            print_error(f"伪造签名居然通过了认证? 这不应该发生!")
        except Exception as e:
            print_success(f"预期的错误: 伪造签名被拒绝")
            print_info(f"错误信息: {str(e)}")
    
    # 步骤6: 查看认证日志
    print_section("步骤6: 查看设备认证日志")
    for device in devices:
        logs_result = client.get_auth_logs(device['did_bytes32'])
        if logs_result['success']:
            print_success(f"{device['name']} 的认证日志 (共 {logs_result['log_count']} 条):")
            
            for idx, log in enumerate(logs_result['logs']):
                log_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log['timestamp']))
                print(f"  [{idx+1}] 时间: {log_time}")
                print(f"      验证者: {log['verifier']}")
                print(f"      结果: {'成功' if log['success'] else '失败'}")
        else:
            print_error(f"获取认证日志失败: {device['name']}")
            print_info(f"错误: {logs_result.get('error', '未知错误')}")
    
    # 步骤7: 撤销一个设备的访问权限
    print_section("步骤7: 撤销设备访问权限")
    if len(devices) > 0:
        device = devices[-1]  # 选择最后一个设备
        print_info(f"选择设备: {device['name']}")
        
        # 查看当前权限状态
        access_check = client.check_access(device['did_bytes32'], network_id_bytes32)
        if access_check['success']:
            print_info(f"当前权限状态: {'有权限' if access_check['has_access'] else '无权限'}")
        
        # 撤销权限
        result = client.revoke_access(device['did_bytes32'], network_id_bytes32)
        if result['success']:
            print_success(f"已撤销设备访问权限: {device['name']}")
            
            # 验证权限已撤销
            access_check = client.check_access(device['did_bytes32'], network_id_bytes32)
            if access_check['success']:
                print_info(f"撤销后权限状态: {'有权限' if access_check['has_access'] else '无权限'}")
                
                if access_check['has_access']:
                    print_error("权限撤销失败，设备仍然有访问权限!")
                else:
                    print_success("权限撤销成功验证!")
        else:
            print_error(f"撤销访问权限失败: {device['name']}")
            print_info(f"错误: {result.get('error', '未知错误')}")
    
    # 步骤8: 撤销一个令牌
    print_section("步骤8: 撤销访问令牌")
    if len(devices) > 1 and 'token_id' in devices[0]:
        device = devices[0]  # 选择第一个设备
        print_info(f"选择设备: {device['name']}")
        print_info(f"令牌ID: {device['token_id']}")
        
        # 检查当前令牌状态
        token_valid = client.validate_token(device['token_id'])
        print_info(f"当前令牌状态: {'有效' if token_valid['valid'] else '无效'}")
        
        # 撤销令牌
        result = client.revoke_token(device['token_id'])
        if result['success']:
            print_success(f"已撤销访问令牌: {device['name']}")
            
            # 验证令牌已撤销
            token_valid = client.validate_token(device['token_id'])
            print_info(f"撤销后令牌状态: {'有效' if token_valid['valid'] else '无效'}")
            
            if token_valid['valid']:
                print_error("令牌撤销失败，令牌仍然有效!")
            else:
                print_success("令牌撤销成功验证!")
        else:
            print_error(f"撤销令牌失败: {device['name']}")
            print_info(f"错误: {result.get('error', '未知错误')}")
    
    print_header("演示完成!")
    print_info("区块链无线网络身份验证系统已成功演示")
    print_info("此演示展示了使用区块链技术实现无线网络身份验证的基本流程")
    print_info("包括设备注册、认证、令牌管理和访问控制等功能")

if __name__ == "__main__":
    run_demo()