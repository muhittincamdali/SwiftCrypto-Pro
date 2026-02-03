# SwiftCrypto-Pro

[![Swift](https://img.shields.io/badge/Swift-5.9+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2015+%20%7C%20macOS%2013+-blue.svg)](https://developer.apple.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SPM](https://img.shields.io/badge/SPM-Compatible-brightgreen.svg)](Package.swift)

**High-level cryptography toolkit for Swift.** AES/RSA encryption, SHA hashing, ECDSA signing, JWT encoding/decoding, TOTP generation, Keychain management, and biometric authentication — all in one package.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Encryption](#encryption)
  - [AES](#aes-encryption)
  - [RSA](#rsa-encryption)
- [Hashing](#hashing)
- [Signing](#signing)
- [JWT](#jwt)
- [TOTP](#totp)
- [Keychain](#keychain)
- [Biometric Authentication](#biometric-authentication)
- [Password Generation](#password-generation)
- [String Extensions](#string-extensions)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Feature | Description |
|---------|-------------|
| 🔐 **AES Encryption** | AES-GCM and AES-CBC with 128/256-bit keys |
| 🔑 **RSA Encryption** | RSA-OAEP with SHA-256 for asymmetric crypto |
| #️⃣ **Hashing** | SHA-256, SHA-384, SHA-512 with streaming support |
| 🔏 **HMAC** | HMAC-SHA256/SHA512 message authentication |
| 🧂 **PBKDF2** | Password-based key derivation |
| ✍️ **ECDSA Signing** | Elliptic curve digital signatures (P-256) |
| 🎫 **JWT** | Encode, decode, and validate JSON Web Tokens |
| 🔢 **TOTP** | Google Authenticator-compatible time-based OTP |
| 🗝️ **Keychain** | Secure storage with iCloud sync support |
| 👆 **Biometrics** | Face ID / Touch ID authentication |
| 🎲 **Passwords** | Configurable secure password generation |
| 📝 **Extensions** | `"text".sha256`, `"text".aesEncrypted(key:)` |

---

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/SwiftCrypto-Pro.git", from: "1.0.0")
]
```

Then add `"SwiftCryptoPro"` to your target dependencies.

---

## Quick Start

```swift
import SwiftCryptoPro

// Hash a string
let hash = "Hello, World!".sha256
print(hash) // "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"

// Encrypt with AES
let key = AESEncryptor.generateKey(size: .bits256)
let encrypted = try AESEncryptor.encrypt("Secret message", key: key)
let decrypted = try AESEncryptor.decrypt(encrypted, key: key)

// Generate TOTP
let totp = TOTPGenerator(secret: "JBSWY3DPEHPK3PXP")
let code = try totp.generate() // "482619"

// JWT
let token = try JWTEncoder.encode(claims: MyClaims(...), key: signingKey)
let decoded = try JWTDecoder.decode(MyClaims.self, from: token)
```

---

## Encryption

### AES Encryption

SwiftCrypto-Pro supports AES-GCM (recommended) and AES-CBC:

```swift
// AES-GCM (default, authenticated encryption)
let key = AESEncryptor.generateKey(size: .bits256)
let encrypted = try AESEncryptor.encrypt(plaintext, key: key)
let decrypted = try AESEncryptor.decrypt(encrypted, key: key)

// AES-CBC
let iv = AESEncryptor.generateIV()
let encrypted = try AESEncryptor.encrypt(plaintext, key: key, iv: iv, mode: .cbc)

// Encrypt raw Data
let encryptedData = try AESEncryptor.encrypt(data: imageData, key: key)
```

### RSA Encryption

```swift
// Generate key pair
let keyPair = try RSAEncryptor.generateKeyPair(size: .bits2048)

// Encrypt / Decrypt
let encrypted = try RSAEncryptor.encrypt("Secret", publicKey: keyPair.publicKey)
let decrypted = try RSAEncryptor.decrypt(encrypted, privateKey: keyPair.privateKey)

// Export keys
let publicPEM = try RSAEncryptor.exportPublicKey(keyPair.publicKey)
```

---

## Hashing

```swift
// SHA-256
let hash256 = Hasher.sha256("Hello")
let hash512 = Hasher.sha512(data)

// Streaming hash for large files
var context = Hasher.StreamingContext(algorithm: .sha256)
context.update(chunk1)
context.update(chunk2)
let finalHash = context.finalize()

// HMAC
let mac = HMAC.authenticate(message: "data", key: secretKey, algorithm: .sha256)
let valid = HMAC.verify(message: "data", mac: mac, key: secretKey, algorithm: .sha256)

// PBKDF2
let derivedKey = try PBKDF2.deriveKey(
    password: "mypassword",
    salt: salt,
    iterations: 100_000,
    keyLength: 32
)
```

---

## Signing

```swift
// ECDSA with P-256
let keyPair = try ECDSASigner.generateKeyPair()

let signature = try ECDSASigner.sign("Important document", privateKey: keyPair.privateKey)
let valid = try ECDSASigner.verify("Important document", signature: signature, publicKey: keyPair.publicKey)
```

---

## JWT

### Decoding

```swift
struct UserClaims: JWTClaims {
    let sub: String
    let name: String
    let exp: Date
    let iat: Date
}

let decoded = try JWTDecoder.decode(UserClaims.self, from: tokenString)
print(decoded.claims.name) // "John Doe"

// Validate expiration
try JWTDecoder.validate(decoded, leeway: 30)
```

### Encoding

```swift
let claims = UserClaims(sub: "123", name: "John", exp: expDate, iat: Date())
let token = try JWTEncoder.encode(claims: claims, algorithm: .hs256, key: secretKey)
```

---

## TOTP

Google Authenticator-compatible time-based one-time passwords:

```swift
let totp = TOTPGenerator(
    secret: "JBSWY3DPEHPK3PXP",
    digits: 6,
    period: 30,
    algorithm: .sha1
)

let code = try totp.generate()
let isValid = try totp.validate(code: "482619")

// Generate provisioning URI for QR codes
let uri = totp.provisioningURI(issuer: "MyApp", account: "user@example.com")
// otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp
```

---

## Keychain

```swift
let keychain = KeychainManager()

// Store and retrieve
try keychain.set("api-token-value", forKey: "apiToken")
let token = try keychain.getString(forKey: "apiToken")

// Store Codable objects
try keychain.set(userCredentials, forKey: "credentials")
let creds: Credentials = try keychain.get(forKey: "credentials")

// Delete
try keychain.delete(forKey: "apiToken")

// iCloud Keychain sync
try keychain.set("synced-value", forKey: "shared", accessibility: .afterFirstUnlock, synchronizable: true)
```

---

## Biometric Authentication

```swift
let bioAuth = BiometricAuth()

// Check availability
if bioAuth.isAvailable {
    print("Biometric type: \(bioAuth.biometricType)") // .faceID or .touchID
}

// Authenticate
let result = await bioAuth.authenticate(reason: "Access your wallet")
switch result {
case .success:
    print("Authenticated!")
case .failure(let error):
    print("Failed: \(error)")
}
```

---

## Password Generation

```swift
let password = PasswordGenerator.generate(
    length: 24,
    includeUppercase: true,
    includeLowercase: true,
    includeDigits: true,
    includeSymbols: true,
    excludeAmbiguous: true
)
// "Kf9$mWq2!xNp7#Rv4&Yz8*"

// Passphrase
let passphrase = PasswordGenerator.generatePassphrase(wordCount: 4, separator: "-")
// "correct-horse-battery-staple"

// Entropy calculation
let entropy = PasswordGenerator.entropy(of: password)
print("Entropy: \(entropy) bits")
```

---

## String Extensions

Convenience extensions for common crypto operations:

```swift
// Hashing
"Hello".sha256    // "185f8db3..."
"Hello".sha512    // "3615f80c..."
"Hello".md5       // "8b1a9953..." (not for security use)

// HMAC
"message".hmacSHA256(key: secretKey)

// Base64
"Hello".base64Encoded    // "SGVsbG8="
"SGVsbG8=".base64Decoded // "Hello"

// Hex
data.hexString           // "48656c6c6f"
Data(hexString: "48656c6c6f")
```

---

## Architecture

```
SwiftCryptoPro/
├── Encryption/
│   ├── AESEncryptor      # AES-GCM and AES-CBC
│   └── RSAEncryptor      # RSA-OAEP asymmetric
├── Hashing/
│   ├── Hasher            # SHA-256/384/512
│   ├── HMAC              # HMAC message auth
│   └── PBKDF2            # Key derivation
├── Signing/
│   └── ECDSASigner       # P-256 ECDSA
├── JWT/
│   ├── JWTDecoder        # Decode + validate
│   ├── JWTEncoder        # Create tokens
│   └── JWTClaims         # Claims protocol
├── TOTP/
│   └── TOTPGenerator     # RFC 6238 TOTP
├── Keychain/
│   └── KeychainManager   # Secure storage
├── Biometric/
│   └── BiometricAuth     # Face/Touch ID
├── Password/
│   └── PasswordGenerator # Secure passwords
└── Extensions/
    └── String+Crypto     # Convenience extensions
```

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Swift | 5.9+ |
| iOS | 15.0+ |
| macOS | 13.0+ |
| watchOS | 8.0+ |
| Xcode | 15.0+ |

> **Note:** Biometric authentication is only available on iOS and macOS.

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-algorithm`)
3. Write tests for new functionality
4. Ensure all tests pass (`swift test`)
5. Commit your changes
6. Push and open a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

Made with ❤️ for the Swift community.
