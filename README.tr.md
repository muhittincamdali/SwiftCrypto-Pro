<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/muhittincamdali/SwiftCrypto-Pro/main/.github/brand/banner-tr-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/muhittincamdali/SwiftCrypto-Pro/main/.github/brand/banner-tr-light.svg"><img src="https://raw.githubusercontent.com/muhittincamdali/SwiftCrypto-Pro/main/.github/brand/banner-tr-light.svg" alt="SwiftCrypto Pro, iOSSecurityTools'a taşındı"></picture></p>

<p align="center"><a href="README.md">English</a> · <a href="README.tr.md">Türkçe</a></p>

# Bu proje artık iOSSecurityTools içinde

SwiftCrypto Pro arşivlendi. Şifreleme kodu (simetrik şifreleme, X25519 anahtar anlaşması ve
biyometrili keychain) artık
[iOSSecurityTools](https://github.com/muhittincamdali/iOSSecurityTools) içinde yaşıyor: iOS,
macOS, tvOS, watchOS ve visionOS için güvenlik yapı taşlarından oluşan bir Swift paketi.

Kod olduğu gibi taşınmadı. CryptoKit üzerinde testlerle yeniden yazıldı; paket ayrıca açık
anahtarlı şifreleme (HPKE), Ed25519 ve P-256 imzaları, HMAC ve imzalı token'lar (JWT) kazandı. Bu
deponun kendi kodu kayıt olarak burada değişmeden duruyor.

## iOSSecurityTools'u kurun

```swift
.package(url: "https://github.com/muhittincamdali/iOSSecurityTools.git", from: "2.2.0")
```

`iOSSecurityTools` ürününü hedefinize ekleyin. 2.2.0 sürümü için Swift 6.2 ve iOS 17, macOS 14,
tvOS 17, watchOS 10 ya da visionOS 1 gerekir.

## Her parça nereye gitti

| SwiftCrypto Pro                                                           | iOSSecurityTools                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `CryptoSymmetric.encrypt(_:key:)` / `decrypt(_:key:)`                     | [`DataCipher`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Crypto/DataCipher.swift)                                                                                                                                                                                   |
| `ZeroKnowledgeEngine.generateKeyPair()`                                   | [`PublicKeyCipher.PrivateKey()`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Crypto/PublicKeyCipher.swift) ya da `Keychain.keyAgreementKey(forKey:)`                                                                                                                  |
| `ZeroKnowledgeEngine.deriveSharedSecret(privateKey:remotePublicKeyData:)` | [`KeyDerivation.sharedKey(privateKey:peerPublicKey:info:)`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Crypto/KeyDerivation%2BAgreement.swift) ya da `PublicKeyCipher.seal(_:to:)`                                                                                   |
| `BiometricKeychain`, `BiometricKeychainItem`                              | Biyometrik korumalı [`Keychain`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Keychain/Keychain.swift) ve [`BiometricAuthenticator`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Biometrics/BiometricAuthenticator.swift) |

`KeyManagement/Enterprise` altındaki hata işleyici, circuit breaker, yeniden deneme politikası,
olay yolu ve metrik toplayıcı taşınmadı: bunlar içinde şifreleme bulunmayan genel amaçlı
yardımcılardı. Eski README JWT, TOTP, RSA ve Argon2'yi de sayıyordu, ancak kaynaklarda hiçbiri
yoktu. iOSSecurityTools'ta JWT
([`JWTVerifier`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Tokens/JWTVerifier.swift),
[`JWTSigner`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/Tokens/JWTSigner.swift))
ve tek kullanımlık parolalar
([`OneTimePassword`](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/Sources/iOSSecurityTools/OneTimePassword/OneTimePassword.swift))
var; RSA yok ve yalnızca Apple'ın kendi gerçeklemeleri kullanıldığı için Argon2 de yok.

- [Dokümantasyon](https://muhittincamdali.github.io/iOSSecurityTools/documentation/iossecuritytools/)
- [SwiftCrypto-Pro'dan geçiş](https://github.com/muhittincamdali/iOSSecurityTools/blob/master/CHANGELOG.md#moving-from-swiftcrypto-pro)
- [iOSSecurityTools kaynağı](https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Sources/iOSSecurityTools)
- [Örnekler](https://github.com/muhittincamdali/iOSSecurityTools/tree/master/Examples)

## Lisans

MIT, bkz. [LICENSE](LICENSE).
