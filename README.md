<div align="center">

# 🔐 SwiftCrypto-Pro

**High-level cryptography for Swift - encryption, JWT, TOTP & biometrics**

[![Swift](https://img.shields.io/badge/Swift-5.9+-F05138?style=for-the-badge&logo=swift&logoColor=white)](https://swift.org)
[![iOS](https://img.shields.io/badge/iOS-15.0+-000000?style=for-the-badge&logo=apple&logoColor=white)](https://developer.apple.com/ios/)
[![SPM](https://img.shields.io/badge/SPM-Compatible-FA7343?style=for-the-badge&logo=swift&logoColor=white)](https://swift.org/package-manager/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

</div>

---

## ✨ Features

- 🔒 **AES Encryption** — Secure data encryption
- 🎫 **JWT** — Token creation and validation
- 📱 **TOTP** — Time-based one-time passwords
- 👆 **Biometrics** — Face ID / Touch ID helpers
- 🔑 **Keychain** — Secure key storage

---

## 🚀 Quick Start

```swift
import SwiftCryptoPro

// Encrypt data
let encrypted = try Crypto.encrypt(data, key: secretKey)

// JWT
let token = try JWT.create(claims: ["userId": "123"], secret: key)
let valid = try JWT.verify(token, secret: key)

// TOTP
let code = TOTP.generate(secret: base32Secret)

// Biometrics
let success = await Biometrics.authenticate(reason: "Login")
```

---

## 📄 License

MIT • [@muhittincamdali](https://github.com/muhittincamdali)
