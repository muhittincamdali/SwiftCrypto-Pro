import XCTest
import CryptoKit
@testable import SwiftCryptoPro

final class EncryptionTests: XCTestCase {

    // MARK: - AES Tests

    func testAESEncryptDecrypt() throws {
        let encryptor = AESEncryptor()
        let key = AESEncryptor.generateKey()
        let message = "Hello, SwiftCrypto-Pro!"

        let encrypted = try encryptor.encrypt(message, using: key)
        let decrypted = try encryptor.decrypt(encrypted, using: key)

        XCTAssertEqual(decrypted, message)
    }

    func testAESEncryptDecryptWithAAD() throws {
        let encryptor = AESEncryptor()
        let key = AESEncryptor.generateKey()
        let message = "Authenticated message"
        let aad = Data("additional-data".utf8)

        let encrypted = try encryptor.encrypt(message, using: key, authenticating: aad)
        let decrypted = try encryptor.decrypt(encrypted, using: key, authenticating: aad)

        XCTAssertEqual(decrypted, message)
    }

    func testAESDecryptWithWrongKeyFails() throws {
        let encryptor = AESEncryptor()
        let key1 = AESEncryptor.generateKey()
        let key2 = AESEncryptor.generateKey()

        let encrypted = try encryptor.encrypt("Secret", using: key1)

        XCTAssertThrowsError(try encryptor.decrypt(encrypted, using: key2))
    }

    func testAESDerivedKey() throws {
        let encryptor = AESEncryptor()
        let key = AESEncryptor.deriveKey(from: "my-passphrase", salt: Data("salt".utf8))
        let message = "Derived key encryption"

        let encrypted = try encryptor.encrypt(message, using: key)
        let decrypted = try encryptor.decrypt(encrypted, using: key)

        XCTAssertEqual(decrypted, message)
    }

    // MARK: - Hashing Tests

    func testSHA256() {
        let hash = CryptoHasher.sha256("hello")
        XCTAssertEqual(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }

    func testSHA512() {
        let hash = CryptoHasher.sha512("hello")
        XCTAssertFalse(hash.isEmpty)
        XCTAssertEqual(hash.count, 128) // 512 bits = 128 hex chars
    }

    // MARK: - HMAC Tests

    func testHMACGeneration() {
        let hmac = HMACGenerator.generate(for: "message", key: "secret")
        XCTAssertFalse(hmac.isEmpty)
    }

    func testHMACValidation() {
        let hmac = HMACGenerator.generate(for: "message", key: "secret")
        XCTAssertTrue(HMACGenerator.validate(message: "message", key: "secret", expectedMAC: hmac))
        XCTAssertFalse(HMACGenerator.validate(message: "tampered", key: "secret", expectedMAC: hmac))
    }

    // MARK: - ECDSA Tests

    func testECDSASignAndVerify() throws {
        let signer = ECDSASigner()
        let keyPair = signer.generateKeyPair()
        let message = "Sign this document"

        let signature = try signer.sign(message, privateKey: keyPair.privateKey)
        let isValid = signer.verify(message, signature: signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(isValid)
    }

    func testECDSAVerifyWithWrongKeyFails() throws {
        let signer = ECDSASigner()
        let keyPair1 = signer.generateKeyPair()
        let keyPair2 = signer.generateKeyPair()

        let signature = try signer.sign("message", privateKey: keyPair1.privateKey)
        let isValid = signer.verify("message", signature: signature, publicKey: keyPair2.publicKey)

        XCTAssertFalse(isValid)
    }

    // MARK: - String Extensions Tests

    func testStringExtensions() {
        XCTAssertEqual("hello".sha256, CryptoHasher.sha256("hello"))
        XCTAssertNotNil("encode me".base64Encoded)
        XCTAssertEqual("encode me".base64Encoded?.base64Decoded, "encode me")
    }
}
