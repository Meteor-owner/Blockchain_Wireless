// 导入所需的模块
const { ethers, run } = require("hardhat");

// 定义一个异步函数来包装我们的代码逻辑
async function main() {
    // 获取默认的以太坊提供商
    const provider = ethers.provider;

    // 打印当前网络的区块高度
    const blockNumber = await provider.getBlockNumber();
    console.log("当前网络的区块高度：", blockNumber);

    // 部署一个简单的合约
    const MyContract = await ethers.getContractFactory("Lock");
    const contract = await MyContract.deploy();
    console.log("合约地址：", contract.address);
}

// 执行我们的代码逻辑
main()
.then(() => process.exit(0))
.catch(error => {
    console.error(error);
    process.exit(1);
});