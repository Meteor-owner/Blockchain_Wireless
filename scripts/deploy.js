// Contract Deployment Script - Modular Version
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("Starting deployment of Blockchain Wireless Network Identity Authentication System contracts...");

  // Get deployment account
  const [deployer] = await hre.ethers.getSigners();
  console.log(`Using deployment account: ${deployer.address}`);

  // Get account balance
  const balance = await deployer.getBalance();
  console.log(`Deployment account balance: ${hre.ethers.utils.formatEther(balance)} ETH`);

  // Configure compilation options to solve "Stack too deep" error
  try {
    console.log("Compiling contracts, enabling viaIR and optimization...");
    await hre.run("compile", {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200
      }
    });
    console.log("Contract compilation successful");
  } catch (error) {
    console.error("Compilation failed:", error);
    process.exit(1);
  }

  try {
    console.log("Starting deployment of modular contracts...");

    // 1. Deploy main contract BlockchainAuthMain
    console.log("Deploying BlockchainAuthMain contract...");
    const BlockchainAuthMain = await hre.ethers.getContractFactory("BlockchainAuthMain");
    const blockchainAuthMain = await BlockchainAuthMain.deploy();
    await blockchainAuthMain.deployed();
    console.log(`BlockchainAuthMain contract deployed at: ${blockchainAuthMain.address}`);

    // 2. Get subcontract addresses
    console.log("Getting subcontract addresses...");
    const userManagerAddress = await blockchainAuthMain.userManager();
    const deviceManagerAddress = await blockchainAuthMain.deviceManager();
    const networkManagerAddress = await blockchainAuthMain.networkManager();
    const authManagerAddress = await blockchainAuthMain.authManager();

    console.log(`UserManagement contract address: ${userManagerAddress}`);
    console.log(`DeviceManagement contract address: ${deviceManagerAddress}`);
    console.log(`NetworkManagement contract address: ${networkManagerAddress}`);
    console.log(`AuthenticationManager contract address: ${authManagerAddress}`);

    // Save contract deployment information
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

    // Create deployments directory (if it doesn't exist)
    const deploymentsDir = "./deployments";
    if (!fs.existsSync(deploymentsDir)) {
      fs.mkdirSync(deploymentsDir);
    }

    // Save deployment information
    const deploymentFilePath = path.join(deploymentsDir, `blockchain-auth-${hre.network.name}.json`);
    fs.writeFileSync(
      deploymentFilePath,
      JSON.stringify(deploymentData, null, 2)
    );

    console.log("Deployment information saved to:", deploymentFilePath);

    // If main or test network, verify the contract
    if (["mainnet", "goerli", "sepolia"].includes(hre.network.name)) {
      console.log("Waiting for block confirmation to verify contracts...");
      await blockchainAuthMain.deployTransaction.wait(5);

      console.log("Submitting main contract for verification...");
      try {
        await hre.run("verify:verify", {
          address: blockchainAuthMain.address,
          constructorArguments: [],
        });
        console.log("Main contract verification successful");

        // Verify subcontracts
        console.log("Verifying UserManagement contract...");
        await hre.run("verify:verify", { address: userManagerAddress });

        console.log("Verifying DeviceManagement contract...");
        await hre.run("verify:verify", {
          address: deviceManagerAddress,
          constructorArguments: [userManagerAddress]
        });

        console.log("Verifying NetworkManagement contract...");
        await hre.run("verify:verify", {
          address: networkManagerAddress,
          constructorArguments: [userManagerAddress]
        });

        console.log("Verifying AuthenticationManager contract...");
        await hre.run("verify:verify", {
          address: authManagerAddress,
          constructorArguments: [deviceManagerAddress, networkManagerAddress]
        });

        console.log("All contracts verified successfully");
      } catch (error) {
        console.error("Contract verification failed:", error);
      }
    }

    console.log("Contract deployment complete!");
  } catch (error) {
    console.error("Error during deployment process:", error);
    process.exit(1);
  }
}

// Execute deployment script
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });