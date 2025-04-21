// const hre = require("hardhat");

// async function main() {
//     const add = await hre.ethers.deployContract("Add");
//     await add.waitForDeployment();
//     console.log( `Add deployed to ${add.target}`);
// }

// main().catch((error) => {
//     console.error(error);
//     process.exitCode = 1;
// });
// scripts/deploy.js
const hre = require("hardhat");

async function main() {
  console.log("开始部署 IdentityManager 合约...");

  // 获取部署者账户
  const [deployer] = await hre.ethers.getSigners();
  console.log(`使用账户 ${deployer.address} 部署合约`);

  // 获取合约工厂
  const IdentityManager = await hre.ethers.getContractFactory("IdentityManager");
  
  // 部署合约
  const identityManager = await IdentityManager.deploy();
  
  // 等待合约部署完成
  await identityManager.waitForDeployment();
  
  // 获取部署后的合约地址
  const identityManagerAddress = await identityManager.getAddress();

  console.log(`IdentityManager 合约已部署至: ${identityManagerAddress}`);
  
  // 保存合约地址到文件以便 Python 脚本使用
  const fs = require("fs");
  
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
      address: identityManagerAddress,
      deployer: deployer.address,
      deploymentTime: new Date().toISOString()
    }
  };
  
  fs.writeFileSync(
    `${deploymentsDir}/identity-manager-${hre.network.name}.json`,
    JSON.stringify(deploymentData, null, 2)
  );
  
  console.log("部署信息已保存至:", `${deploymentsDir}/identity-manager-${hre.network.name}.json`);
}

// 执行部署脚本
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("部署失败:", error);
    process.exit(1);
  });