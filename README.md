<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/SwiftCrypto-Pro/main/.github/brand/banner-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/SwiftCrypto-Pro/main/.github/brand/banner-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/SwiftCrypto-Pro/main/.github/brand/banner-light.svg" alt="SwiftCrypto Pro has moved to iOSSecurityTools"></picture></p>

<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a></p>

# This project now lives in iOSSecurityTools

SwiftCrypto Pro is archived. Its cryptography code (symmetric encryption, X25519 key agreement and
the keychain with biometrics) now lives in
[iOSSecurityTools](https://github.com/muhittincamdali/iOSSecurityTools), a Swift package of
security building blocks for iOS, macOS, tvOS, watchOS and visionOS.

The code was not copied over. It was rebuilt on CryptoKit with tests, and the package also gained
public-key encryption (HPKE), Ed25519 and P-256 signatures, HMAC and signed tokens (JWT). This
repository's own code stays here, unchanged, as a record.

## Install iOSSecurityTools

```swift
.package(url: "https://github.com/muhittincamdali/iOSSecurityTools.git", from: "2.2.0")
```

Add the `iOSSecurityTools` product to your target. Version 2.2.0 needs Swift 6.2 and iOS 17,
macOS 14, tvOS 17, watchOS 10 or visionOS 1.

## Where each part went

| SwiftCrypto Pro                                                           | iOSSecurityTools                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CryptoSymmetric.encrypt(_:key:)` / `decrypt(_:key:)`                     | [`DataCipher`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Crypto/DataCipher.swift)                                                                                                                                                                                             |
| `ZeroKnowledgeEngine.generateKeyPair()`                                   | [`PublicKeyCipher.PrivateKey()`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Crypto/PublicKeyCipher.swift), or `Keychain.keyAgreementKey(forKey:)`                                                                                                                              |
| `ZeroKnowledgeEngine.deriveSharedSecret(privateKey:remotePublicKeyData:)` | [`KeyDerivation.sharedKey(privateKey:peerPublicKey:info:)`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Crypto/KeyDerivation%2BAgreement.swift), or `PublicKeyCipher.seal(_:to:)`                                                                                               |
| `BiometricKeychain`, `BiometricKeychainItem`                              | [`Keychain`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Keychain/Keychain.swift) with a biometric protection, and [`BiometricAuthenticator`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Biometrics/BiometricAuthenticator.swift) |

The error handler, circuit breaker, retry policy, event bus and metrics collector under
`KeyManagement/Enterprise` were not carried over: they were general-purpose helpers with no
cryptography in them. The earlier README also listed JWT, TOTP, RSA and Argon2, but the sources
never contained them. iOSSecurityTools has JWT
([`JWTVerifier`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Tokens/JWTVerifier.swift),
[`JWTSigner`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Tokens/JWTSigner.swift))
and one-time passwords
([`OneTimePassword`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/OneTimePassword/OneTimePassword.swift));
it has no RSA, and it uses only Apple's implementations, so there is no Argon2.

- [Documentation](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)
- [Moving from SwiftCrypto-Pro](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CHANGELOG.md#moving-from-swiftcrypto-pro)
- [iOSSecurityTools source](https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Sources/iOSSecurityTools)
- [Examples](https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples)

## License

MIT, see [LICENSE](LICENSE).
