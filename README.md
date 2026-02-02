# 🔐 SwiftCrypto-Pro

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2015%2B%20%7C%20macOS%2012%2B-blue.svg)](https://developer.apple.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SPM](https://img.shields.io/badge/SPM-Compatible-brightgreen.svg)](https://swift.org/package-manager)

A comprehensive, production-ready cryptography toolkit for Swift. Built entirely on Apple CryptoKit and Security framework — no third-party dependencies.

## ✨ Features

| Module | Description |
|--------|-------------|
| **AES-256 GCM** | Symmetric encryption with authenticated data |
| **RSA** | Asymmetric encryption with OAEP padding |
| **SHA-256/512** | Secure hashing with multiple algorithms |
| **HMAC** | Hash-based message authentication codes |
| **ECDSA** | Elliptic curve digital signatures |
| **JWT** | Decode and validate JSON Web Tokens |
| **TOTP** | Time-based one-time passwords (RFC 6238) |
| **Keychain** | Secure storage with biometric protection |
| **Biometrics** | Face ID / Touch ID authentication |

## 📦 Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/SwiftCrypto-Pro.git", from: "1.0.0")
]
```

Or in Xcode: **File → Add Package Dependencies** and paste the repository URL.

## 🚀 Quick Start

### AES-256 Encryption

```swift
import SwiftCryptoPro

let encryptor = AESEncryptor()

// Encrypt
let key = AESEncryptor.generateKey()
let encrypted = try encryptor.encrypt("Secret message", using: key)

// Decrypt
let decrypted = try encryptor.decrypt(encrypted, using: key)
print(decrypted) // "Secret message"
```

### RSA Encryption

```swift
let rsa = RSAEncryptor()
let keyPair = try rsa.generateKeyPair(bits: 2048)

let encrypted = try rsa.encrypt("Hello RSA", publicKey: keyPair.publicKey)
let decrypted = try rsa.decrypt(encrypted, privateKey: keyPair.privateKey)
```

### Hashing

```swift
let hash = CryptoHasher.sha256("Hello, World!")
let hmac = HMACGenerator.generate(for: "message", key: "secret", algorithm: .sha256)
```

### String Extensions

```swift
let hash = "my secret text".sha256
let md5 = "hello".md5
let base64 = "encode me".base64Encoded
```

### JWT Decoding

```swift
let decoder = JWTDecoder()
let claims = try decoder.decode(token: jwtString)

print(claims.subject)
print(claims.expiresAt)
print(claims.isExpired)
```

### TOTP (Google Authenticator Compatible)

```swift
let generator = TOTPGenerator(secret: "JBSWY3DPEHPK3PXP")
let code = try generator.generateCode()
print(code) // "482193"

let timeRemaining = generator.timeRemaining
```

### Keychain Storage

```swift
let keychain = KeychainManager()

// Store
try keychain.save("api-token-value", forKey: "apiToken")

// Retrieve
let token: String? = try keychain.load(forKey: "apiToken")

// Delete
try keychain.delete(forKey: "apiToken")

// Store with biometric protection
try keychain.save("sensitive", forKey: "secret", biometric: true)
```

### Biometric Authentication

```swift
let auth = BiometricAuth()

if auth.isBiometricAvailable {
    let success = try await auth.authenticate(reason: "Access your wallet")
    if success {
        // Authenticated
    }
}
```

### ECDSA Signing

```swift
let signer = ECDSASigner()
let keyPair = signer.generateKeyPair()

let signature = try signer.sign("Important document", privateKey: keyPair.privateKey)
let isValid = signer.verify("Important document", signature: signature, publicKey: keyPair.publicKey)
```

## 🏗️ Architecture

```
SwiftCryptoPro/
├── Encryption/
│   ├── AESEncryptor.swift          # AES-256 GCM symmetric encryption
│   └── RSAEncryptor.swift          # RSA asymmetric encryption
├── Hashing/
│   ├── Hasher.swift                # SHA-256, SHA-384, SHA-512
│   └── HMAC.swift                  # HMAC authentication codes
├── Signing/
│   └── ECDSASigner.swift           # ECDSA digital signatures
├── JWT/
│   ├── JWTDecoder.swift            # JWT token decoder
│   └── JWTClaims.swift             # JWT claims model
├── TOTP/
│   └── TOTPGenerator.swift         # RFC 6238 TOTP generator
├── Keychain/
│   └── KeychainManager.swift       # Secure keychain wrapper
├── Biometric/
│   └── BiometricAuth.swift         # Face ID / Touch ID
└── Extensions/
    └── String+Crypto.swift         # Convenient string extensions
```

## 🔒 Security Considerations

- All encryption uses Apple CryptoKit (hardware-accelerated on Apple Silicon)
- AES uses GCM mode for authenticated encryption
- RSA uses OAEP with SHA-256 for padding
- Keychain items can require biometric authentication
- TOTP implementation follows RFC 6238 strictly
- No sensitive data is logged or stored in memory longer than needed

## 📋 Requirements

| Platform | Minimum Version |
|----------|----------------|
| iOS | 15.0+ |
| macOS | 12.0+ |
| tvOS | 15.0+ |
| watchOS | 8.0+ |
| Swift | 5.9+ |

## 🧪 Testing

```bash
swift test
```

Run specific test suites:

```bash
swift test --filter EncryptionTests
```

## 📖 Documentation

All public APIs include DocC-compatible documentation. Generate docs with:

```bash
swift package generate-documentation
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Apple CryptoKit team for the excellent framework
- RFC 6238 for TOTP specification
- RFC 7519 for JWT specification

---

Made with ❤️ by [Muhittin Camdali](https://github.com/muhittincamdali)
