# 🛡️ obSecure
**A Cross-Platform End-to-End Encrypted Messaging Application**

obSecure is a modern, security focused desktop messaging application that implements state of the art cryptographic protocols to ensure complete message privacy. Built with Qt6 and leveraging the Crypto++ library, obSecure provides a robust foundation for secure communication with phone number based authentication and zero knowledge server architecture.

## 🔬 Technical Overview

### Cryptographic Architecture
obSecure implements a **hybrid cryptographic system** combining multiple industry standard protocols:
- **X3DH (Extended Triple Diffie-Hellman)** for initial key agreement and perfect forward secrecy
- **Ed25519** for digital signatures and identity verification (512-bit security level)
- **X25519** for Elliptic Curve Diffie-Hellman key exchange (128-bit security level)
- **AES-256-GCM** for authenticated symmetric message encryption
- **HKDF** (HMAC based Key Derivation Function) for secure key derivation with SHA-256

### Key Management System
The application employs a sophisticated **prekey distribution model** similar to Signal Protocol:
- **Identity Keys**: Long term Ed25519 keys for user authentication and signing
- **Signed Prekeys**: Medium term X25519 keys, rotated periodically and signed by identity keys
- **One Time Prekeys**: Ephemeral X25519 keys consumed after single use to ensure forward secrecy
- **Session Keys**: Derived from X3DH handshake using HKDF for message encryption

### Server Architecture
The Flask-based server acts as a **key distribution center** with zero access to message content:
- **PostgreSQL** database with optimized indexing for key storage and retrieval
- **Redis** integration for distributed rate limiting and caching
- **HMAC SHA256** phone number hashing for privacy preservation
- **RESTful API** design with comprehensive input validation and error handling
- **Atomic transactions** for one time prekey consumption to prevent race conditions

### Network Protocol
- **Direct P2P Communication**: Messages sent directly between clients, server only for key exchange
- **Protocol Buffer like Serialization**: Custom binary protocol for efficient data transmission
- **TCP based Messaging**: Reliable delivery with connection state management
- **Automatic Reconnection**: Built in retry logic and connection recovery

### Security Properties
- **End-to-End Encryption**: Messages encrypted locally, server cannot decrypt
- **Forward Secrecy**: Past messages remain secure even if long term keys are compromised
- **Post Compromise Security**: Future messages are secure after key rotation
- **Deniable Authentication**: Messages are authenticated but sender cannot be proven to third parties
- **Minimal Metadata**: Server only stores necessary cryptographic material, not message metadata

## ✨ Features
🔒 **End-to-End Encryption** — Messages encrypted locally before transmission using AES-256-GCM  
📱 **Cross-Platform Support** — Native Qt6 application for Windows, macOS, and Linux  
🔑 **Advanced Key Management** — Automatic key rotation and perfect forward secrecy  
⚡ **Real Time Messaging** — Direct peer to peer communication with connection management  
🛡️ **Zero Knowledge Server** — Server cannot decrypt messages or access conversation content  
📊 **Cryptographic Verification** — Built in Ed25519 signature verification for all keys  
🔄 **Automatic Key Refresh** — Seamless one time prekey replenishment and signed prekey rotation  
🌐 **Phone Number Authentication** — E.164 format validation with HMAC-SHA256 hashing  
🎨 **Modern Dark UI** — Clean, responsive interface with real time connection status  
⚙️ **Configurable Server** — Environment based configuration with .env file support  

## 🛠️ Prerequisites
Ensure you have the following dependencies installed:

### For macOS (using Homebrew)
```bash
brew install qt6 cmake cryptopp python3 postgresql redis
````

### For Ubuntu/Debian

```bash
sudo apt update
sudo apt install qt6-base-dev qt6-tools-dev cmake libcrypto++-dev python3 python3-pip postgresql postgresql-contrib redis-server
```

### For Windows

  - Install [Qt6](https://www.qt.io/download) (6.0+ required)
  - Install [CMake](https://cmake.org/download/) (3.16+ required)
  - Install [vcpkg](https://vcpkg.io/) and use it to install Crypto++
  - Install [Python 3](https://www.python.org/downloads/) (3.8+ required)
  - Install [PostgreSQL](https://www.postgresql.org/download/windows/) (12+ required)
  - Install [Redis](https://github.com/microsoftarchive/redis/releases) for Windows

## 📦 Installation & Setup

### 1️⃣ Database Setup

**Start services**

```bash
# macOS
brew services start postgresql
brew services start redis

# Linux
sudo systemctl start postgresql redis
```

**Create database**

```bash
createdb keyserver
```

## 🔧 Configuration

### Client Configuration

Create a `.env` file in the client root:

```ini
SERVER_URL=
SERVER_PORT=
```

### Server Configuration

Create a `.env` file in the server root:

```ini
DATABASE_URL=
REDIS_URL=
PHONE_SALT=
SECRET_KEY=
JWT_SECRET_KEY=
FLASK_ENV=
CORS_ORIGINS=
RATELIMIT_DEFAULT=
```

### 2️⃣ Server Setup

```bash
cd server
python3 -m venv venv
source venv/bin/activate # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start server
python3 app.py
```

### 3️⃣ Client Build & Run

```bash
cd client
mkdir build && cd build

# Configure build
cmake ..

# Build (parallel compilation)
make -j$(nproc) # Linux
make -j$(sysctl -n hw.ncpu) # macOS

# Run application
./obSecure
```

## 🏗️ Project Structure

```
obSecure/
├── client/ # Qt6/C++ desktop application
│ ├── include/ # Header files
│ │ ├── MainWindow.h # Primary UI controller
│ │ ├── KeyManager.h # Cryptographic key management
│ │ ├── X3DHManager.h # X3DH protocol implementation
│ │ ├── CryptoManager.h # AES-GCM encryption/decryption
│ │ ├── NetworkManager.h # P2P networking and connection handling
│ │ ├── ServerAPI.h # REST API client for key server
│ │ ├── PhoneAuthManager.h # Phone number authentication
│ │ ├── UserManager.h # Contact and user management
│ │ ├── MessageProtocol.h # Message serialization protocol
│ │ └── ConfigManager.h # Configuration management
│ ├── src/ # Source files
│ │ ├── main.cpp # Application entry point
│ │ ├── MainWindow.cpp # UI implementation and event handling
│ │ ├── KeyManager.cpp # Ed25519/X25519 key operations
│ │ ├── X3DHManager.cpp # X3DH handshake and key derivation
│ │ ├── CryptoManager.cpp # Symmetric encryption operations
│ │ ├── NetworkManager.cpp # TCP networking and protocol handling
│ │ ├── ServerAPI.cpp # HTTP client for server communication
│ │ ├── PhoneAuthManager.cpp # Authentication workflow
│ │ ├── UserManager.cpp # Contact storage and management
│ │ ├── MessageProtocol.cpp # Binary message serialization
│ │ └── ConfigManager.cpp # Environment and config file handling
│ └── CMakeLists.txt # Build configuration
├── server/ # Flask key distribution server
│ ├── app.py # Main Flask application and middleware
│ ├── models.py # SQLAlchemy database models
│ ├── config.py # Configuration classes and environment handling
│ ├── init.sql # Database initialization and indexing
│ ├── routes/
│ │ ├── auth.py # User registration and phone verification
│ │ └── keys.py # Key bundle distribution and management
│ ├── utils/
│ │ ├── crypto_utils.py # Server-side cryptographic utilities
│ │ └── phone_utils.py # Phone number validation and normalization
│ ├── requirements.txt # Python dependencies
│ └── docker-compose.yml # Docker deployment configuration
├── .env.example # Environment variables template
├── .gitignore # Git ignore rules
├── LICENSE # MIT license
└── README.md # This file
```

## 🚀 Usage

### First Run

1.  **Launch the application**: `./obSecure` or run from your IDE
2.  **Enter phone number**: Provide your phone number in E.164 format (e.g., +1234567890)
3.  **Automatic registration**: The app will generate keys and register with the server
4.  **Add contacts**: Use "Add Contact" button to add friends by their phone numbers

### Adding Contacts

1.  Click **"Add Contact"** button
2.  Enter contact's **phone number** (must be registered)
3.  Provide **display name** (optional, defaults to phone number)
4.  Set **IP address** and **port** for direct connection
5.  App automatically fetches cryptographic keys from server

### Messaging

1.  **Select contact** from the contacts list
2.  Click **"Connect"** to establish P2P connection
3.  **Type message** and press Enter or click "Send"
4.  **First message** triggers X3DH handshake automatically
5.  **Subsequent messages** use established session keys

### Key Management

  - **Refresh Keys**: Generates and uploads new one time prekeys to server
  - **Share Identity Key**: Display your public identity key for verification
  - **Automatic Rotation**: Signed prekeys rotate automatically every 7 days

## 🛡️ Security Considerations

### Production Deployment

  - **Use HTTPS**: All server communication should use TLS in production
  - **Database Security**: Enable PostgreSQL SSL and use strong authentication
  - **Key Storage**: Private keys are stored locally with file system permissions
  - **Rate Limiting**: Built in protection against brute force and DoS attacks
  - **Input Validation**: Comprehensive validation for all user inputs and API endpoints

### Threat Model

  - **Server Compromise**: Messages remain secure; server cannot decrypt past or future messages
  - **Network Interception**: All communication is authenticated and encrypted
  - **Device Compromise**: Forward secrecy limits exposure to past messages
  - **Quantum Resistance**: Ed25519 and X25519 provide post-quantum security considerations

## 🤝 Contributing

We welcome contributions\! Please follow these guidelines:

### Development Setup

```bash
# Clone repository
git clone [https://github.com/i2mWasil/obSecure.git](https://github.com/i2mWasil/obSecure.git)
cd obSecure

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Install development dependencies
pip install pytest black flake8 mypy # Python tools
```

### Contribution Process

1.  **Fork the repository** and create a feature branch
2.  **Write tests** for new functionality
3.  **Update documentation** for API changes
4.  **Submit pull request** with detailed description

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

## 🔗 References & Standards

  - [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/) - Signal Foundation
  - [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) - Signal Foundation
  - [RFC 7748: Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748) - X25519 specification
  - [RFC 8032: EdDSA Signature Schemes](https://tools.ietf.org/html/rfc8032) - Ed25519 specification
  - [RFC 5869: HKDF](https://tools.ietf.org/html/rfc5869) - Key derivation function
  - [Crypto++ Documentation](https://www.cryptopp.com/docs/) - Cryptographic library reference
  - [Qt6 Documentation](https://doc.qt.io/qt-6/) - GUI framework reference

-----

**⚠️ Security Notice**: This is an educational/research project implementing real cryptographic protocols. While it follows security best practices and established standards, it has not undergone formal security auditing. For production use, conduct thorough security review and testing.

**🔐 Privacy**: Phone numbers are hashed using HMAC-SHA256 before server storage. The server never has access to plaintext messages, contact lists, or conversation metadata.

```
```