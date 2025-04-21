# 区块链无线网络身份验证系统

**CSEC5615 云安全项目**

这个项目实现了一个基于区块链的无线网络身份验证系统，旨在解决传统WPA2认证机制中的安全问题。通过利用区块链技术的去中心化、防篡改和密码学特性，我们提供了一个更安全的无线网络身份验证方案。

## 项目结构

```
identity-chain/
├── contracts/                # Solidity智能合约
│   └── IdentityManager.sol   # 主要身份管理合约
├── scripts/                  # 部署脚本
│   └── deploy.js             # 合约部署脚本
├── python/                   # Python接口和测试
│   └── test_identity.py      # 与合约交互的Python接口
├── hardhat.config.js         # Hardhat配置
├── .env                      # 环境变量（不要提交到版本控制）
├── requirements.txt          # Python依赖
└── demo_wireless_auth.py     # 演示脚本
```

## 功能特性

- **设备注册**: 设备可以生成密钥对并在区块链上注册DID（分布式身份标识符）
- **网络创建**: 网络管理员可以创建无线网络并管理访问控制
- **访问控制**: 精确控制哪些设备可以访问哪些网络
- **安全认证**: 基于挑战-响应的认证机制，使用公私钥加密
- **令牌管理**: 颁发和验证访问令牌
- **审计日志**: 在区块链上记录所有认证尝试，提供不可篡改的审计跟踪

## 环境要求

### 区块链开发环境
- Node.js v16+
- npm v8+
- Hardhat
- Solidity v0.8.20

### Python环境
- Python 3.8+
- web3.py
- eth-account
- ecdsa

## 安装和设置

1. 克隆仓库:
```bash
git clone https://github.com/yourusername/identity-chain.git
cd identity-chain
```

2. 安装JavaScript依赖:
```bash
npm install
```

3. 安装Python依赖:
```bash
pip install -r requirements.txt
```

4. 配置环境变量:
```bash
cp .env.example .env
# 编辑.env文件，设置你的私钥和其他配置
```

5. 编译合约:
```bash
npx hardhat compile
```

## 运行本地区块链节点

```bash
npx hardhat node
```

## 部署合约

```bash
npx hardhat run scripts/deploy.js --network localhost
```

## 运行演示

```bash
python demo_wireless_auth.py
```

## 与WPA2的对比

| 特性 | WPA2 | 区块链身份验证 |
|------|------|----------------|
| 认证方式 | 预共享密钥(PSK)或802.1X | 非对称加密，挑战-响应 |
| 密钥管理 | 静态密钥或集中式服务器 | 分散式，设备持有私钥 |
| 审计能力 | 依赖于外部日志系统 | 区块链上不可篡改的记录 |
| 防篡改性 | 中等 | 高（区块链固有特性） |
| 抵抗字典攻击 | 弱（针对弱密码） | 强（基于公私钥加密） |
| 防止重放攻击 | 弱 | 强（基于唯一挑战） |
| 吊销机制 | 全网密钥更改 | 精细的权限控制 |

## 技术实现细节

### 设备注册流程

1. 设备生成ECDSA密钥对（私钥安全存储在设备上）
2. 设备创建DID（分布式身份标识符）
3. 设备将DID和公钥注册到区块链上
4. 区块链合约验证并存储设备身份信息

### 认证流程

1. 设备尝试连接到无线网络
2. 接入点（AP）生成随机挑战
3. 设备使用私钥对挑战进行签名
4. 接入点通过智能合约验证签名
5. 验证成功后，智能合约颁发访问令牌
6. 设备使用令牌获得网络访问权限
7. 认证过程记录在区块链上

### 安全优势

1. **无需共享密码**: 基于公私钥加密，消除了密码共享和管理问题
2. **动态认证**: 每次连接都使用新的挑战-响应，防止重放攻击
3. **防篡改日志**: 所有认证尝试都记录在区块链上，不可篡改
4. **精细权限控制**: 可以精确控制每个设备的网络访问权限
5. **透明审计**: 网络管理员可以查看完整的认证历史
6. **抵抗离线攻击**: 无法通过离线字典攻击破解公私钥

## 项目扩展方向

- **零知识证明集成**: 实现零知识证明以增强隐私保护
- **多因素认证**: 结合生物识别或其他认证因素
- **跨网络身份联合**: 实现不同网络间的身份互认
- **身份证明声明**: 支持可验证声明和身份属性证明
- **物联网设备管理**: 针对IoT设备的轻量级实现
- **移动客户端开发**: 开发用户友好的移动应用程序

## 演示截图

[此处可添加系统演示的截图]

## 贡献指南

1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开Pull Request

## 团队成员

- Ilham Radito (540451423)
- Senan Wang (540245855)
- Tancy Yang (530452135)

## 许可证

MIT

## 参考文献

1. Gürfidan, R., & Açıkgözoğlu, E. (2023). A New Blockchain-Based Authentication Infrastructure For Wireless Networks: BCAUTH.
2. Kumkar, V., Tiwari, A., Tiwari, P., Gupta, A., & Shrawne, S. (2012). Vulnerabilities of Wireless Security protocols (WEP and WPA2).