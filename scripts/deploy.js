// 合约部署脚本
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("开始部署 Blockchain_Auth 合约...");

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
  const BlockchainAuth = await hre.ethers.getContractFactory("Blockchain_Auth", {
    viaIR: true
  });

  // 部署合约
  console.log("开始部署合约...");
  const blockchainAuth = await BlockchainAuth.deploy();

  // 等待合约部署完成
  console.log("等待交易确认...");
  await blockchainAuth.deployed();

  console.log(`Blockchain_Auth 合约已部署至: ${blockchainAuth.address}`);
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
      name: "Blockchain_Auth",
      address: blockchainAuth.address,
      deployer: deployer.address,
      deploymentTime: new Date().toISOString(),
      systemAdmin: deployer.address
    },
    networkInfo: {
      chainId: hre.network.config.chainId,
      gasPrice: (await hre.ethers.provider.getGasPrice()).toString()
    }
  };

  const deploymentFilePath = path.join(deploymentsDir, `blockchain-auth-${hre.network.name}.json`);
  fs.writeFileSync(
    deploymentFilePath,
    JSON.stringify(deploymentData, null, 2)
  );

  console.log("部署信息已保存至:", deploymentFilePath);

  // 如果是测试网，生成Python接口调用示例（可自行取消注释）
  if (["goerli", "sepolia", "localhost"].includes(hre.network.name)) {
    // generatePythonExample(blockchainAuth.address, hre.network.name);
  }

  // 如果是主网或测试网，验证合约
  if (["mainnet", "goerli", "sepolia"].includes(hre.network.name)) {
    console.log("等待块确认以进行合约验证...");
    await blockchainAuth.deployTransaction.wait(5);

    console.log("提交合约验证...");
    try {
      await hre.run("verify:verify", {
        address: blockchainAuth.address,
        constructorArguments: [],
      });
      console.log("合约已成功验证");
    } catch (error) {
      console.error("合约验证失败:", error);
    }
  }
}

// 执行部署脚本
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("部署失败:", error);
    process.exit(1);
  });
