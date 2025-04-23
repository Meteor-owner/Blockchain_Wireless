// 合约部署脚本
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("开始部署 IdentityManager 合约...");

  // 获取部署账户
  const [deployer] = await hre.ethers.getSigners();
  console.log(`使用部署账户: ${deployer.address}`);

  // 获取账户余额
  const balance = await deployer.getBalance();
  console.log(`部署账户余额: ${hre.ethers.utils.formatEther(balance)} ETH`);

  // 配置编译选项以解决 "Stack too deep" 错误
  try {
    console.log("编译合约，启用viaIR和优化...");
    await hre.run("compile", {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200
      }
    });
    console.log("合约编译成功");
  } catch (error) {
    console.error("编译失败:", error);
    process.exit(1);
  }

  // 获取合约工厂
  console.log("创建合约工厂...");
  const IdentityManager = await hre.ethers.getContractFactory("IdentityManager", {
    viaIR: true  // 确保合约工厂也使用viaIR
  });

  // 部署合约
  console.log("开始部署合约...");
  const identityManager = await IdentityManager.deploy();

  // 等待合约部署完成
  console.log("等待交易确认...");
  await identityManager.deployed();

  console.log(`IdentityManager 合约已部署至: ${identityManager.address}`);
  console.log(`部署者(系统管理员): ${deployer.address}`);

  // 创建 deployments 目录（如果不存在）
  const deploymentsDir = "./deployments";
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir);
  }

  // 保存部署信息
  const deploymentData = {
    network: hre.network.name,
    contract: {
      name: "IdentityManager",
      address: identityManager.address,
      deployer: deployer.address,
      deploymentTime: new Date().toISOString(),
      systemAdmin: deployer.address // 记录系统管理员地址
    },
    // 添加额外网络信息
    networkInfo: {
      chainId: hre.network.config.chainId,
      gasPrice: (await hre.ethers.provider.getGasPrice()).toString()
    }
  };

  const deploymentFilePath = path.join(deploymentsDir, `identity-manager-${hre.network.name}.json`);
  fs.writeFileSync(
    deploymentFilePath,
    JSON.stringify(deploymentData, null, 2)
  );

  console.log("部署信息已保存至:", deploymentFilePath);

  // 如果是测试网，生成Python接口调用示例
  if (["goerli", "sepolia", "localhost"].includes(hre.network.name)) {
    generatePythonExample(identityManager.address, hre.network.name);
  }

  // 如果是主网或测试网，验证合约
  if (["mainnet", "goerli", "sepolia"].includes(hre.network.name)) {
    console.log("等待块确认以进行合约验证...");
    // 等待几个块确认
    await identityManager.deployTransaction.wait(5);

    // 验证合约
    console.log("提交合约验证...");
    try {
      await hre.run("verify:verify", {
        address: identityManager.address,
        constructorArguments: [],
      });
      console.log("合约已成功验证");
    } catch (error) {
      console.error("合约验证失败:", error);
    }
  }
}

function generatePythonExample(contractAddress, network) {
  const exampleCode = `"""
区块链无线网络身份验证系统 - 部署测试脚本
CSEC5615 云安全项目
"""

import os
import json
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 连接到区块链网络
def connect_to_network():
    network = "${network}"
    if network == "localhost":
        w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    elif network == "goerli":
        infura_key = os.getenv("INFURA_KEY")
        w3 = Web3(Web3.HTTPProvider(f"https://goerli.infura.io/v3/{infura_key}"))
    elif network == "sepolia":
        infura_key = os.getenv("INFURA_KEY")
        w3 = Web3(Web3.HTTPProvider(f"https://sepolia.infura.io/v3/{infura_key}"))
    else:
        raise ValueError(f"不支持的网络: {network}")
        
    if not w3.is_connected():
        raise ConnectionError(f"无法连接到 {network} 网络")
    
    print(f"成功连接到 {network} 网络")
    return w3

# 加载合约
def load_contract(w3):
    contract_address = "${contractAddress}"
    
    # 加载ABI
    abi_file = "./artifacts/contracts/IdentityManager.sol/IdentityManager.json"
    with open(abi_file, 'r') as f:
        contract_json = json.load(f)
        contract_abi = contract_json['abi']
    
    # 实例化合约
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address),
        abi=contract_abi
    )
    
    return contract

# 主函数
def main():
    try:
        # 连接网络
        w3 = connect_to_network()
        
        # 加载账户
        private_key = os.getenv("PRIVATE_KEY")
        if not private_key:
            raise ValueError("未找到PRIVATE_KEY环境变量")
        
        if not private_key.startswith("0x"):
            private_key = f"0x{private_key}"
        
        account = Account.from_key(private_key)
        print(f"使用账户: {account.address}")
        
        # 加载合约
        contract = load_contract(w3)
        print(f"成功加载合约")
        
        # 检查系统管理员
        system_admin = contract.functions.systemAdmin().call()
        print(f"系统管理员: {system_admin}")
        
        # 检查当前账户是否为已注册用户
        is_registered = contract.functions.isRegisteredUser(account.address).call()
        print(f"当前账户是否已注册: {is_registered}")
        
        print("部署测试完成!")
        
    except Exception as e:
        print(f"错误: {str(e)}")

if __name__ == "__main__":
    main()
`;

  const exampleDir = "./scripts";
  if (!fs.existsSync(exampleDir)) {
    fs.mkdirSync(exampleDir);
  }

  const exampleFilePath = path.join(exampleDir, "test_deployment.py");
  fs.writeFileSync(exampleFilePath, exampleCode);

  console.log("生成Python测试脚本:", exampleFilePath);
}

// 执行部署脚本
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("部署失败:", error);
    process.exit(1);
  });