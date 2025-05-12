# Blockchain-based Wireless Network Identity Authentication System

**CSEC5615 Cloud Security Project**

This project implements a blockchain-based wireless network identity authentication system aimed at addressing security issues in traditional WPA2 authentication mechanisms. By leveraging the decentralization, tamper-proof, and cryptographic features of blockchain technology, we provide a more secure wireless network identity authentication solution.

## Project Structure

```
identity-chain/
├── contracts/                       # Solidity smart contracts
│   ├── AuthenticationManager.sol    # Authentication logic and token management
│   ├── BaseStructures.sol           # Base data structures and constants
│   ├── BlockchainAuthMain.sol       # Main contract integrating all modules
│   ├── CryptoUtils.sol              # Cryptographic utility functions
│   ├── DeviceManagement.sol         # Device registration and management
│   ├── NetworkManagement.sol        # Wireless network management
│   └── UserManagement.sol           # User registration and management
├── scripts/                         # Deployment scripts
│   └── deploy.js                    # Contract deployment script
├── python/                          # Python interface and tests
│   └── test_blockchain.py           # Python interface for contract interaction
├── deployments/                     # Deployment artifacts
│   └── blockchain-auth-localhost.json # Local deployment information
├── hardhat.config.js                # Hardhat configuration
├── .env                             # Environment variables (don't commit to version control)
├── requirements.txt                 # Python dependencies
└── Blockchain_auth.py               # Test script
```

## Features

- **Device Registration**: Devices can generate key pairs and register DIDs (Decentralized Identifiers) on the blockchain
- **Network Creation**: Network administrators can create wireless networks and manage access control
- **Access Control**: Precise control over which devices can access which networks
- **Secure Authentication**: Challenge-response based authentication mechanism using public-private key encryption
- **Token Management**: Issuance and verification of access tokens
- **Audit Logs**: Records all authentication attempts on the blockchain, providing tamper-proof audit trails
- **User Management**: Registration, authentication, and role-based access control for system users

## Requirements

### Blockchain Development Environment
- Node.js v16+
- npm v8+
- Hardhat
- Solidity v0.8.20

### Python Environment
- Python 3.8+
- web3.py
- eth-account
- ecdsa
- UI libraries (for the web interface)

## Installation and Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/identity-chain.git
cd identity-chain
```

2. Install JavaScript dependencies:
```bash
npm install
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
cp .env.example .env
# Edit the .env file to set your private key and other configurations
```

5. Compile contracts:
```bash
npx hardhat compile
```

## Running a Local Blockchain Node

```bash
npx hardhat node
```

## Deploying Contracts

```bash
npx hardhat run scripts/deploy.js --network localhost
```

## Running the Demo

Run the command-line demo:
```bash
python Blockchain_auth.py
```

[//]: # (Start the web interface:)

[//]: # (```bash)

[//]: # (python ui/app.py)

[//]: # (```)

## Comparison with WPA2

| Feature | WPA2 | Blockchain Authentication |
|---------|------|---------------------------|
| Authentication Method | Pre-shared key (PSK) or 802.1X | Asymmetric encryption, challenge-response |
| Key Management | Static keys or centralized server | Decentralized, devices hold private keys |
| Audit Capability | Depends on external logging systems | Tamper-proof records on blockchain |
| Tamper Resistance | Medium | High (inherent to blockchain) |
| Dictionary Attack Resistance | Weak (for weak passwords) | Strong (based on public-private key encryption) |
| Replay Attack Prevention | Weak | Strong (based on unique challenges) |
| Revocation Mechanism | Network-wide key change | Fine-grained permission control |

## Technical Implementation Details

### Device Registration Process

1. Device generates ECDSA key pair (private key securely stored on the device)
2. Device creates a DID (Decentralized Identifier)
3. Device registers its DID and public key on the blockchain
4. Blockchain contract verifies and stores device identity information

### Authentication Process

1. Device attempts to connect to a wireless network
2. Access Point (AP) generates a random challenge
3. Device signs the challenge with its private key
4. AP verifies the signature through the smart contract
5. Upon successful verification, the smart contract issues an access token
6. Device uses the token to gain network access
7. Authentication process is recorded on the blockchain

### Security Advantages

1. **No Shared Passwords**: Based on public-private key encryption, eliminating password sharing and management issues
2. **Dynamic Authentication**: Each connection uses a new challenge-response, preventing replay attacks
3. **Tamper-proof Logs**: All authentication attempts are recorded on the blockchain and cannot be tampered with
4. **Fine-grained Permission Control**: Precise control over each device's network access permissions
5. **Transparent Auditing**: Network administrators can view complete authentication history
6. **Offline Attack Resistance**: Cannot be broken through offline dictionary attacks against public-private keys

## Future Extensions

- **User Interface Development**: A comprehensive web-based UI interface is under development
- **Zero-Knowledge Proof Integration**: Implement zero-knowledge proofs to enhance privacy protection
- **Multi-factor Authentication**: Combine with biometrics or other authentication factors
- **Cross-Network Identity Federation**: Enable identity recognition between different networks
- **Verifiable Claims**: Support for verifiable claims and identity attribute proofs
- **IoT Device Management**: Lightweight implementation for IoT devices
- **Mobile Client Development**: Develop user-friendly mobile applications

## Demo Screenshots

[Screenshots of the system demonstration can be added here]

## Contribution Guidelines

1. Fork this repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## License

MIT
