<h1 align="center">SwiftCrypto Pro</h1>

<p align="center">
  <strong>🔐 High-level cryptography for Swift - encryption, JWT, TOTP & biometrics</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Swift-6.0-orange.svg" alt="Swift"/>
  <img src="https://img.shields.io/badge/iOS-17.0+-blue.svg" alt="iOS"/>
</p>

---

## Features

| Feature | Description |
|---------|-------------|
| 🔒 **Encryption** | AES, ChaCha20, RSA |
| 🎫 **JWT** | Create & verify tokens |
| ⏰ **TOTP** | 2FA code generation |
| 🔑 **Keychain** | Secure key storage |
| 👆 **Biometrics** | Face ID / Touch ID |
| 🔐 **Hashing** | SHA, HMAC, Argon2 |

## Quick Start

```swift
import SwiftCryptoPro

// Encrypt data
let encrypted = try Crypto.encrypt(
    data: sensitiveData,
    key: encryptionKey,
    algorithm: .aes256gcm
)

// Decrypt data
let decrypted = try Crypto.decrypt(
    data: encrypted,
    key: encryptionKey
)

// Generate JWT
let jwt = try JWT.create(
    claims: ["userId": "123"],
    secret: jwtSecret,
    expiration: .hours(24)
)

// Verify JWT
let claims = try JWT.verify(jwt, secret: jwtSecret)

// TOTP
let totp = TOTP(secret: base32Secret)
let code = totp.generate() // "123456"

// Biometrics
let authenticated = try await Biometrics.authenticate(
    reason: "Unlock app"
)
```

## Encryption

```swift
// AES-256-GCM (recommended)
let encrypted = try Crypto.encrypt(data, key: key, algorithm: .aes256gcm)

// ChaCha20-Poly1305
let encrypted = try Crypto.encrypt(data, key: key, algorithm: .chacha20)

// RSA
let encrypted = try Crypto.encrypt(data, publicKey: rsaPublicKey)
```

## Key Management

```swift
// Generate secure key
let key = Crypto.generateKey(bits: 256)

// Store in Keychain
try Keychain.store(key, for: "encryption_key", biometric: true)

// Retrieve
let key = try Keychain.retrieve("encryption_key")
```

## Hashing

```swift
// SHA-256
let hash = Crypto.hash(data, algorithm: .sha256)

// HMAC
let hmac = Crypto.hmac(data, key: key, algorithm: .sha256)

// Password hashing (Argon2)
let hashedPassword = try Crypto.hashPassword(password)
let verified = try Crypto.verifyPassword(password, hash: hashedPassword)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License

---

## 📈 Star History

<a href="https://star-history.com/#muhittincamdali/SwiftCrypto-Pro&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=muhittincamdali/SwiftCrypto-Pro&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=muhittincamdali/SwiftCrypto-Pro&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=muhittincamdali/SwiftCrypto-Pro&type=Date" />
 </picture>
</a>
