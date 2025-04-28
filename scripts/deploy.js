// 合约部署脚本 - 模块化版本
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("开始部署区块链无线网络身份验证系统合约...");

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

  try {
    console.log("开始部署模块化合约...");

    // 1. 部署主合约 BlockchainAuthMain
    console.log("部署 BlockchainAuthMain 合约...");
    const BlockchainAuthMain = await hre.ethers.getContractFactory("BlockchainAuthMain");
    const blockchainAuthMain = await BlockchainAuthMain.deploy();
    await blockchainAuthMain.deployed();
    console.log(`BlockchainAuthMain 合约已部署至: ${blockchainAuthMain.address}`);

    // 2. 获取子合约地址
    console.log("获取子合约地址...");
    const userManagerAddress = await blockchainAuthMain.userManager();
    const deviceManagerAddress = await blockchainAuthMain.deviceManager();
    const networkManagerAddress = await blockchainAuthMain.networkManager();
    const authManagerAddress = await blockchainAuthMain.authManager();

    console.log(`UserManagement 合约地址: ${userManagerAddress}`);
    console.log(`DeviceManagement 合约地址: ${deviceManagerAddress}`);
    console.log(`NetworkManagement 合约地址: ${networkManagerAddress}`);
    console.log(`AuthenticationManager 合约地址: ${authManagerAddress}`);

    // 保存合约部署信息
    const deploymentData = {
      network: hre.network.name,
      mainContract: {
        name: "BlockchainAuthMain",
        address: blockchainAuthMain.address,
        deployer: deployer.address,
        deploymentTime: new Date().toISOString(),
        systemAdmin: deployer.address
      },
      subContracts: {
        userManagement: userManagerAddress,
        deviceManagement: deviceManagerAddress,
        networkManagement: networkManagerAddress,
        authenticationManager: authManagerAddress
      },
      networkInfo: {
        chainId: hre.network.config.chainId,
        gasPrice: (await hre.ethers.provider.getGasPrice()).toString()
      }
    };

    // 创建 deployments 目录（如果不存在）
    const deploymentsDir = "./deployments";
    if (!fs.existsSync(deploymentsDir)) {
      fs.mkdirSync(deploymentsDir);
    }

    // 保存部署信息
    const deploymentFilePath = path.join(deploymentsDir, `blockchain-auth-${hre.network.name}.json`);
    fs.writeFileSync(
      deploymentFilePath,
      JSON.stringify(deploymentData, null, 2)
    );

    console.log("部署信息已保存至:", deploymentFilePath);

    // 如果是主网或测试网，验证合约
    if (["mainnet", "goerli", "sepolia"].includes(hre.network.name)) {
      console.log("等待块确认以进行合约验证...");
      await blockchainAuthMain.deployTransaction.wait(5);

      console.log("提交主合约验证...");
      try {
        await hre.run("verify:verify", {
          address: blockchainAuthMain.address,
          constructorArguments: [],
        });
        console.log("主合约验证成功");

        // 验证子合约
        console.log("验证 UserManagement 合约...");
        await hre.run("verify:verify", { address: userManagerAddress });

        console.log("验证 DeviceManagement 合约...");
        await hre.run("verify:verify", {
          address: deviceManagerAddress,
          constructorArguments: [userManagerAddress]
        });

        console.log("验证 NetworkManagement 合约...");
        await hre.run("verify:verify", {
          address: networkManagerAddress,
          constructorArguments: [userManagerAddress]
        });

        console.log("验证 AuthenticationManager 合约...");
        await hre.run("verify:verify", {
          address: authManagerAddress,
          constructorArguments: [deviceManagerAddress, networkManagerAddress]
        });

        console.log("所有合约验证成功");
      } catch (error) {
        console.error("合约验证失败:", error);
      }
    }

    console.log("合约部署完成！");
  } catch (error) {
    console.error("部署过程中出错:", error);
    process.exit(1);
  }
}

// 执行部署脚本
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("部署失败:", error);
    process.exit(1);
  });