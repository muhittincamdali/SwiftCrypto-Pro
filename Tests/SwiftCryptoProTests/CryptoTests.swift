import XCTest
import CryptoKit
@testable import SwiftCryptoPro

// MARK: - AES-GCM Tests

final class AESGCMTests: XCTestCase {
    
    var key: SymmetricKey!
    var encryptor: AESGCMEncryptor!
    
    override func setUp() {
        super.setUp()
        key = SymmetricKey(size: .bits256)
        encryptor = AESGCMEncryptor(key: key)
    }
    
    func testBasicEncryptionDecryption() throws {
        let plaintext = "Hello, World!"
        let encrypted = try encryptor.encrypt(plaintext)
        let decrypted = try encryptor.decryptToString(encrypted)
        
        XCTAssertEqual(plaintext, decrypted)
    }
    
    func testEmptyStringEncryption() throws {
        let plaintext = ""
        let encrypted = try encryptor.encrypt(plaintext)
        let decrypted = try encryptor.decryptToString(encrypted)
        
        XCTAssertEqual(plaintext, decrypted)
    }
    
    func testLargeDataEncryption() throws {
        let plaintext = String(repeating: "A", count: 1_000_000)
        let encrypted = try encryptor.encrypt(plaintext)
        let decrypted = try encryptor.decryptToString(encrypted)
        
        XCTAssertEqual(plaintext, decrypted)
    }
    
    func testBinaryDataEncryption() throws {
        let data = Data((0..<256).map { UInt8($0) })
        let encrypted = try encryptor.encrypt(data)
        let decrypted = try encryptor.decrypt(encrypted)
        
        XCTAssertEqual(data, decrypted)
    }
    
    func testDifferentKeysProduceDifferentCiphertext() throws {
        let key2 = SymmetricKey(size: .bits256)
        let encryptor2 = AESGCMEncryptor(key: key2)
        
        let plaintext = "Test message"
        let encrypted1 = try encryptor.encrypt(plaintext)
        let encrypted2 = try encryptor2.encrypt(plaintext)
        
        XCTAssertNotEqual(encrypted1, encrypted2)
    }
    
    func testDecryptionWithWrongKeyFails() throws {
        let plaintext = "Secret message"
        let encrypted = try encryptor.encrypt(plaintext)
        
        let wrongKey = SymmetricKey(size: .bits256)
        let wrongEncryptor = AESGCMEncryptor(key: wrongKey)
        
        XCTAssertThrowsError(try wrongEncryptor.decrypt(encrypted))
    }
    
    func testTamperedCiphertextFails() throws {
        let plaintext = "Original message"
        var encrypted = try encryptor.encrypt(plaintext)
        
        // Tamper with the ciphertext
        if encrypted.count > 20 {
            encrypted[20] ^= 0xFF
        }
        
        XCTAssertThrowsError(try encryptor.decrypt(encrypted))
    }
    
    func testUnicodeEncryption() throws {
        let plaintext = "こんにちは世界 🌍 مرحبا بالعالم"
        let encrypted = try encryptor.encrypt(plaintext)
        let decrypted = try encryptor.decryptToString(encrypted)
        
        XCTAssertEqual(plaintext, decrypted)
    }
}

// MARK: - ChaCha20-Poly1305 Tests

final class ChaCha20Poly1305Tests: XCTestCase {
    
    var key: SymmetricKey!
    var encryptor: ChaCha20Poly1305Encryptor!
    
    override func setUp() {
        super.setUp()
        key = SymmetricKey(size: .bits256)
        encryptor = ChaCha20Poly1305Encryptor(key: key)
    }
    
    func testBasicEncryptionDecryption() throws {
        let plaintext = "Hello, ChaCha20!"
        let encrypted = try encryptor.encrypt(plaintext)
        let decrypted = try encryptor.decryptToString(encrypted)
        
        XCTAssertEqual(plaintext, decrypted)
    }
    
    func testLargeDataEncryption() throws {
        let data = Data(repeating: 0xAB, count: 500_000)
        let encrypted = try encryptor.encrypt(data)
        let decrypted = try encryptor.decrypt(encrypted)
        
        XCTAssertEqual(data, decrypted)
    }
}

// MARK: - PBKDF2 Tests

final class PBKDF2Tests: XCTestCase {
    
    var pbkdf2: PBKDF2!
    
    override func setUp() {
        super.setUp()
        pbkdf2 = PBKDF2(configuration: .fast)
    }
    
    func testKeyDerivation() throws {
        let result = try pbkdf2.deriveKey(
            password: "password123",
            iterations: 1000,
            keyLength: 32
        )
        
        XCTAssertEqual(result.derivedKey.count, 32)
        XCTAssertEqual(result.iterations, 1000)
    }
    
    func testPasswordVerification() throws {
        let password = "SecurePassword!"
        let result = try pbkdf2.deriveKey(password: password, iterations: 1000)
        
        let isValid = try pbkdf2.verify(
            password: password,
            salt: result.salt,
            expectedKey: result.derivedKey,
            iterations: result.iterations,
            algorithm: result.algorithm
        )
        
        XCTAssertTrue(isValid)
    }
    
    func testWrongPasswordVerification() throws {
        let result = try pbkdf2.deriveKey(password: "CorrectPassword", iterations: 1000)
        
        let isValid = try pbkdf2.verify(
            password: "WrongPassword",
            salt: result.salt,
            expectedKey: result.derivedKey,
            iterations: result.iterations,
            algorithm: result.algorithm
        )
        
        XCTAssertFalse(isValid)
    }
    
    func testDifferentSaltsProduceDifferentKeys() throws {
        let password = "SamePassword"
        
        let result1 = try pbkdf2.deriveKey(password: password, iterations: 1000)
        let result2 = try pbkdf2.deriveKey(password: password, iterations: 1000)
        
        XCTAssertNotEqual(result1.derivedKey, result2.derivedKey)
        XCTAssertNotEqual(result1.salt, result2.salt)
    }
    
    func testStorableFormat() throws {
        let password = "TestPassword"
        let hash = try pbkdf2.hashPassword(password)
        
        // Verify format: algorithm$iterations$salt$key
        let components = hash.split(separator: "$")
        XCTAssertEqual(components.count, 4)
        
        // Verify password against storable
        let isValid = try pbkdf2.verifyPassword(password, against: hash)
        XCTAssertTrue(isValid)
    }
    
    func testSymmetricKeyDerivation() throws {
        let password = "EncryptionPassword"
        let salt = try SecureRandom.data(count: 32)
        
        let key = try pbkdf2.deriveSymmetricKey(
            password: password,
            salt: salt,
            iterations: 1000
        )
        
        // Use the key for encryption
        let message = "Test message"
        let messageData = message.data(using: .utf8)!
        let sealed = try AES.GCM.seal(messageData, using: key)
        let decrypted = try AES.GCM.open(sealed, using: key)
        
        XCTAssertEqual(messageData, decrypted)
    }
}

// MARK: - ECDSA Tests

final class ECDSASignerTests: XCTestCase {
    
    var signer: ECDSASigner!
    var keyPair: ECDSASigner.KeyPair!
    
    override func setUp() {
        super.setUp()
        signer = ECDSASigner()
        keyPair = signer.generateKeyPair()
    }
    
    func testSignAndVerify() throws {
        let message = "Test message for signing"
        let signature = try signer.sign(message, privateKey: keyPair.privateKey)
        
        let isValid = signer.verify(
            message,
            signature: signature,
            publicKey: keyPair.publicKey
        )
        
        XCTAssertTrue(isValid)
    }
    
    func testTamperedMessageVerificationFails() throws {
        let message = "Original message"
        let signature = try signer.sign(message, privateKey: keyPair.privateKey)
        
        let isValid = signer.verify(
            "Tampered message",
            signature: signature,
            publicKey: keyPair.publicKey
        )
        
        XCTAssertFalse(isValid)
    }
    
    func testDifferentKeyVerificationFails() throws {
        let message = "Test message"
        let signature = try signer.sign(message, privateKey: keyPair.privateKey)
        
        let differentKeyPair = signer.generateKeyPair()
        let isValid = signer.verify(
            message,
            signature: signature,
            publicKey: differentKeyPair.publicKey
        )
        
        XCTAssertFalse(isValid)
    }
    
    func testDataSigning() throws {
        let data = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let signature = try signer.sign(data, privateKey: keyPair.privateKey)
        
        let isValid = signer.verify(
            data,
            signature: signature,
            publicKey: keyPair.publicKey
        )
        
        XCTAssertTrue(isValid)
    }
}

// MARK: - Secure Random Tests

final class SecureRandomTests: XCTestCase {
    
    func testBytesGeneration() throws {
        let bytes = try SecureRandom.bytes(count: 32)
        XCTAssertEqual(bytes.count, 32)
        
        // Verify randomness (not all zeros or same value)
        let uniqueBytes = Set(bytes)
        XCTAssertGreaterThan(uniqueBytes.count, 1)
    }
    
    func testIntInRange() {
        for _ in 0..<100 {
            let value = SecureRandom.int(in: 10...20)
            XCTAssertGreaterThanOrEqual(value, 10)
            XCTAssertLessThanOrEqual(value, 20)
        }
    }
    
    func testDoubleInRange() {
        for _ in 0..<100 {
            let value = SecureRandom.double(in: 0.0...1.0)
            XCTAssertGreaterThanOrEqual(value, 0.0)
            XCTAssertLessThanOrEqual(value, 1.0)
        }
    }
    
    func testStringGeneration() throws {
        let alphanumeric = SecureRandom.alphanumeric(length: 20)
        XCTAssertEqual(alphanumeric.count, 20)
        
        // All characters should be alphanumeric
        let validChars = CharacterSet.alphanumerics
        for char in alphanumeric.unicodeScalars {
            XCTAssertTrue(validChars.contains(char))
        }
    }
    
    func testHexGeneration() throws {
        let hex = SecureRandom.hex(length: 32)
        XCTAssertEqual(hex.count, 32)
        
        // All characters should be hex
        let validChars = CharacterSet(charactersIn: "0123456789abcdef")
        for char in hex.unicodeScalars {
            XCTAssertTrue(validChars.contains(char))
        }
    }
    
    func testPasswordGeneration() {
        let password = SecureRandom.password(length: 16, includeSymbols: true)
        XCTAssertEqual(password.count, 16)
    }
    
    func testPassphraseGeneration() {
        let passphrase = SecureRandom.passphrase(wordCount: 4, separator: "-")
        let words = passphrase.split(separator: "-")
        XCTAssertEqual(words.count, 4)
    }
    
    func testShuffle() {
        let original = Array(1...10)
        var shuffled = SecureRandom.shuffle(original)
        
        // Same elements
        XCTAssertEqual(Set(shuffled), Set(original))
        
        // Should be shuffled (extremely unlikely to be the same order)
        var allSame = true
        for _ in 0..<10 {
            shuffled = SecureRandom.shuffle(original)
            if shuffled != original {
                allSame = false
                break
            }
        }
        XCTAssertFalse(allSame)
    }
    
    func testElementSelection() {
        let array = ["a", "b", "c", "d", "e"]
        
        for _ in 0..<10 {
            let element = SecureRandom.element(from: array)
            XCTAssertNotNil(element)
            XCTAssertTrue(array.contains(element!))
        }
    }
    
    func testMultipleElementSelection() {
        let array = Array(1...100)
        let selected = SecureRandom.elements(5, from: array)
        
        XCTAssertEqual(selected.count, 5)
        XCTAssertEqual(Set(selected).count, 5) // All unique
    }
}

// MARK: - HMAC Tests

final class HMACGeneratorTests: XCTestCase {
    
    func testHMACGeneration() {
        let message = "Hello, World!"
        let key = "SecretKey123"
        
        let hmac = HMACGenerator.generate(for: message, key: key, algorithm: .sha256)
        
        XCTAssertFalse(hmac.isEmpty)
        XCTAssertEqual(hmac.count, 64) // SHA-256 produces 32 bytes = 64 hex chars
    }
    
    func testHMACValidation() {
        let message = "Test message"
        let key = "MyKey"
        
        let hmac = HMACGenerator.generate(for: message, key: key)
        let isValid = HMACGenerator.validate(
            message: message,
            key: key,
            expectedMAC: hmac
        )
        
        XCTAssertTrue(isValid)
    }
    
    func testHMACInvalidation() {
        let message = "Test message"
        let key = "MyKey"
        
        let hmac = HMACGenerator.generate(for: message, key: key)
        let isValid = HMACGenerator.validate(
            message: "Different message",
            key: key,
            expectedMAC: hmac
        )
        
        XCTAssertFalse(isValid)
    }
    
    func testDifferentAlgorithms() {
        let message = "Test"
        let key = "Key"
        
        let sha256 = HMACGenerator.generate(for: message, key: key, algorithm: .sha256)
        let sha384 = HMACGenerator.generate(for: message, key: key, algorithm: .sha384)
        let sha512 = HMACGenerator.generate(for: message, key: key, algorithm: .sha512)
        
        // Different lengths
        XCTAssertEqual(sha256.count, 64)  // 32 bytes
        XCTAssertEqual(sha384.count, 96)  // 48 bytes
        XCTAssertEqual(sha512.count, 128) // 64 bytes
        
        // Different values
        XCTAssertNotEqual(sha256, sha384)
        XCTAssertNotEqual(sha384, sha512)
    }
}

// MARK: - Keychain Wrapper Tests

final class KeychainWrapperTests: XCTestCase {
    
    var keychain: KeychainWrapper!
    let testService = "com.test.keychain.unit"
    
    override func setUp() {
        super.setUp()
        keychain = KeychainWrapper(service: testService)
        try? keychain.deleteAll()
    }
    
    override func tearDown() {
        try? keychain.deleteAll()
        super.tearDown()
    }
    
    func testSetAndGetString() throws {
        let key = "test_string"
        let value = "Hello, Keychain!"
        
        try keychain.set(value, forKey: key)
        let retrieved = try keychain.getString(forKey: key)
        
        XCTAssertEqual(retrieved, value)
    }
    
    func testSetAndGetData() throws {
        let key = "test_data"
        let value = Data([0x01, 0x02, 0x03, 0x04])
        
        try keychain.set(value, forKey: key)
        let retrieved = try keychain.getData(forKey: key)
        
        XCTAssertEqual(retrieved, value)
    }
    
    func testSetAndGetCodable() throws {
        struct TestObject: Codable, Equatable {
            let name: String
            let count: Int
        }
        
        let key = "test_codable"
        let value = TestObject(name: "Test", count: 42)
        
        try keychain.set(value, forKey: key)
        let retrieved = try keychain.get(key, as: TestObject.self)
        
        XCTAssertEqual(retrieved, value)
    }
    
    func testSetAndGetBool() throws {
        let key = "test_bool"
        
        try keychain.set(true, forKey: key)
        XCTAssertEqual(try keychain.getBool(forKey: key), true)
        
        try keychain.set(false, forKey: key)
        XCTAssertEqual(try keychain.getBool(forKey: key), false)
    }
    
    func testSetAndGetInt() throws {
        let key = "test_int"
        let value = 42
        
        try keychain.set(value, forKey: key)
        let retrieved = try keychain.getInt(forKey: key)
        
        XCTAssertEqual(retrieved, value)
    }
    
    func testDelete() throws {
        let key = "test_delete"
        try keychain.set("value", forKey: key)
        
        XCTAssertTrue(keychain.contains(key: key))
        
        try keychain.delete(key: key)
        
        XCTAssertFalse(keychain.contains(key: key))
    }
    
    func testContains() throws {
        let key = "test_contains"
        
        XCTAssertFalse(keychain.contains(key: key))
        
        try keychain.set("value", forKey: key)
        
        XCTAssertTrue(keychain.contains(key: key))
    }
    
    func testAllKeys() throws {
        try keychain.set("value1", forKey: "key1")
        try keychain.set("value2", forKey: "key2")
        try keychain.set("value3", forKey: "key3")
        
        let keys = keychain.allKeys()
        
        XCTAssertTrue(keys.contains("key1"))
        XCTAssertTrue(keys.contains("key2"))
        XCTAssertTrue(keys.contains("key3"))
    }
    
    func testSubscript() throws {
        keychain["subscript_key"] = "subscript_value"
        
        XCTAssertEqual(keychain["subscript_key"], "subscript_value")
        
        keychain["subscript_key"] = nil
        
        XCTAssertNil(keychain["subscript_key"])
    }
    
    func testOverwrite() throws {
        let key = "test_overwrite"
        
        try keychain.set("original", forKey: key)
        XCTAssertEqual(try keychain.getString(forKey: key), "original")
        
        try keychain.set("updated", forKey: key)
        XCTAssertEqual(try keychain.getString(forKey: key), "updated")
    }
    
    func testNonExistentKey() throws {
        let result = try keychain.getString(forKey: "nonexistent")
        XCTAssertNil(result)
    }
}

// MARK: - Blowfish Tests

final class BlowfishTests: XCTestCase {
    
    func testBasicEncryptionDecryption() throws {
        let blowfish = try Blowfish(key: "TestKey12345678")
        
        let plaintext = "Hello, Blowfish!"
        let encrypted = try blowfish.encryptString(plaintext, mode: .cbc)
        let decrypted = try blowfish.decryptString(encrypted, mode: .cbc)
        
        XCTAssertEqual(plaintext, decrypted)
    }
    
    func testECBMode() throws {
        let blowfish = try Blowfish(key: "MySecretKey")
        
        let data = "TestData".data(using: .utf8)!
        let encrypted = try blowfish.encrypt(data, mode: .ecb)
        let decrypted = try blowfish.decrypt(encrypted, mode: .ecb)
        
        XCTAssertEqual(data, decrypted)
    }
    
    func testCTRMode() throws {
        let blowfish = try Blowfish(key: "CounterModeKey")
        
        let plaintext = "Counter mode encryption test"
        let encrypted = try blowfish.encryptString(plaintext, mode: .ctr)
        let decrypted = try blowfish.decryptString(encrypted, mode: .ctr)
        
        XCTAssertEqual(plaintext, decrypted)
    }
    
    func testInvalidKeyLength() {
        XCTAssertThrowsError(try Blowfish(key: "abc")) // Too short
    }
    
    func testLongKey() throws {
        let longKey = String(repeating: "A", count: 56)
        let blowfish = try Blowfish(key: longKey)
        
        let plaintext = "Test with maximum key length"
        let encrypted = try blowfish.encryptString(plaintext)
        let decrypted = try blowfish.decryptString(encrypted)
        
        XCTAssertEqual(plaintext, decrypted)
    }
}
