//
//  AES-GCM.swift
//  SwiftCryptoPro
//
//  Created by Muhittin Camdali on 2025.
//  Copyright © 2025 Muhittin Camdali. All rights reserved.
//

import Foundation
import CryptoKit
import Security
import CommonCrypto

// MARK: - AES-GCM Error Types

/// Errors that can occur during AES-GCM operations
public enum AESGCMError: Error, LocalizedError, Equatable {
    case invalidKeySize
    case invalidNonceSize
    case encryptionFailed
    case decryptionFailed
    case authenticationFailed
    case invalidCiphertext
    case invalidPlaintext
    case keyGenerationFailed
    case nonceGenerationFailed
    case invalidData
    case serializationFailed
    case deserializationFailed
    case unsupportedKeySize
    case streamClosed
    case bufferOverflow
    case tagMismatch
    case invalidTagSize
    case fileOperationFailed
    
    public var errorDescription: String? {
        switch self {
        case .invalidKeySize:
            return "Invalid key size. AES-GCM supports 128, 192, or 256-bit keys."
        case .invalidNonceSize:
            return "Invalid nonce size. AES-GCM requires a 96-bit (12-byte) nonce."
        case .encryptionFailed:
            return "Encryption operation failed."
        case .decryptionFailed:
            return "Decryption operation failed."
        case .authenticationFailed:
            return "Authentication failed. The ciphertext may have been tampered with."
        case .invalidCiphertext:
            return "Invalid ciphertext format."
        case .invalidPlaintext:
            return "Invalid plaintext data."
        case .keyGenerationFailed:
            return "Failed to generate cryptographic key."
        case .nonceGenerationFailed:
            return "Failed to generate nonce."
        case .invalidData:
            return "Invalid data provided."
        case .serializationFailed:
            return "Failed to serialize data."
        case .deserializationFailed:
            return "Failed to deserialize data."
        case .unsupportedKeySize:
            return "Unsupported key size specified."
        case .streamClosed:
            return "Stream has been closed."
        case .bufferOverflow:
            return "Buffer overflow detected."
        case .tagMismatch:
            return "Authentication tag does not match."
        case .invalidTagSize:
            return "Invalid authentication tag size."
        case .fileOperationFailed:
            return "File operation failed."
        }
    }
}

// MARK: - AES Key Size

/// Supported AES key sizes
public enum AESKeySize: Int, Codable, CaseIterable {
    case bits128 = 16
    case bits192 = 24
    case bits256 = 32
    
    /// Key size in bits
    public var bitCount: Int {
        return rawValue * 8
    }
    
    /// Key size in bytes
    public var byteCount: Int {
        return rawValue
    }
    
    /// Human-readable description
    public var description: String {
        return "AES-\(bitCount)"
    }
}

// MARK: - AES-GCM Key

/// A symmetric key for AES-GCM encryption
public struct AESGCMKey: Equatable, Hashable {
    
    /// The key size
    public let keySize: AESKeySize
    
    /// The underlying key data
    private var keyData: Data
    
    /// Initialize with raw key data
    /// - Parameter data: The key data (16, 24, or 32 bytes)
    /// - Throws: AESGCMError.invalidKeySize if data size is invalid
    public init(data: Data) throws {
        guard let size = AESKeySize(rawValue: data.count) else {
            throw AESGCMError.invalidKeySize
        }
        self.keySize = size
        self.keyData = data
    }
    
    /// Initialize with specific key size
    /// - Parameters:
    ///   - data: The key data
    ///   - keySize: The expected key size
    /// - Throws: AESGCMError.invalidKeySize if data doesn't match size
    public init(data: Data, keySize: AESKeySize) throws {
        guard data.count == keySize.byteCount else {
            throw AESGCMError.invalidKeySize
        }
        self.keySize = keySize
        self.keyData = data
    }
    
    /// Generate a new random key
    /// - Parameter keySize: The key size to generate
    /// - Returns: A newly generated random key
    /// - Throws: AESGCMError.keyGenerationFailed if generation fails
    public static func generate(size: AESKeySize = .bits256) throws -> AESGCMKey {
        var keyData = Data(count: size.byteCount)
        let result = keyData.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, size.byteCount, buffer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw AESGCMError.keyGenerationFailed
        }
        return try AESGCMKey(data: keyData, keySize: size)
    }
    
    /// Generate key from password using PBKDF2
    /// - Parameters:
    ///   - password: The password to derive the key from
    ///   - salt: The salt for key derivation
    ///   - keySize: The desired key size
    ///   - iterations: Number of PBKDF2 iterations (default: 100000)
    /// - Returns: A derived key
    /// - Throws: AESGCMError.keyGenerationFailed if derivation fails
    public static func deriveFromPassword(
        _ password: String,
        salt: Data,
        keySize: AESKeySize = .bits256,
        iterations: Int = 100000
    ) throws -> AESGCMKey {
        guard let passwordData = password.data(using: .utf8) else {
            throw AESGCMError.keyGenerationFailed
        }
        
        var derivedKey = Data(count: keySize.byteCount)
        let result = derivedKey.withUnsafeMutableBytes { derivedBuffer in
            passwordData.withUnsafeBytes { passwordBuffer in
                salt.withUnsafeBytes { saltBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.baseAddress?.assumingMemoryBound(to: Int8.self),
                        passwordData.count,
                        saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keySize.byteCount
                    )
                }
            }
        }
        
        guard result == kCCSuccess else {
            throw AESGCMError.keyGenerationFailed
        }
        
        return try AESGCMKey(data: derivedKey, keySize: keySize)
    }
    
    /// Derive key using HKDF
    /// - Parameters:
    ///   - inputKey: The input keying material
    ///   - salt: The salt
    ///   - info: The context info
    ///   - keySize: The output key size
    /// - Returns: A derived key
    public static func deriveWithHKDF(
        inputKey: Data,
        salt: Data,
        info: Data,
        keySize: AESKeySize = .bits256
    ) throws -> AESGCMKey {
        let symmetricKey = SymmetricKey(data: inputKey)
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: symmetricKey,
            salt: salt,
            info: info,
            outputByteCount: keySize.byteCount
        )
        return try AESGCMKey(data: derivedKey.withUnsafeBytes { Data($0) }, keySize: keySize)
    }
    
    /// Access the raw key data
    public var rawData: Data {
        return keyData
    }
    
    /// Convert to CryptoKit symmetric key
    public var symmetricKey: SymmetricKey {
        return SymmetricKey(data: keyData)
    }
    
    /// Zero out the key data for secure cleanup
    public mutating func zeroize() {
        keyData.withUnsafeMutableBytes { buffer in
            memset(buffer.baseAddress, 0, buffer.count)
        }
    }
    
    /// Export key as base64
    public var base64Encoded: String {
        return keyData.base64EncodedString()
    }
    
    /// Import key from base64
    /// - Parameter base64String: The base64 encoded key
    /// - Returns: An AESGCMKey
    public static func fromBase64(_ base64String: String) throws -> AESGCMKey {
        guard let data = Data(base64Encoded: base64String) else {
            throw AESGCMError.invalidData
        }
        return try AESGCMKey(data: data)
    }
}

// MARK: - AES-GCM Nonce

/// A nonce for AES-GCM encryption
public struct AESGCMNonce: Equatable, Hashable {
    
    /// The nonce size in bytes (12 bytes = 96 bits)
    public static let nonceSize = 12
    
    /// The underlying nonce data
    private let nonceData: Data
    
    /// Initialize with raw nonce data
    /// - Parameter data: The 12-byte nonce data
    /// - Throws: AESGCMError.invalidNonceSize if data is not 12 bytes
    public init(data: Data) throws {
        guard data.count == Self.nonceSize else {
            throw AESGCMError.invalidNonceSize
        }
        self.nonceData = data
    }
    
    /// Generate a new random nonce
    /// - Returns: A newly generated random nonce
    /// - Throws: AESGCMError.nonceGenerationFailed if generation fails
    public static func generate() throws -> AESGCMNonce {
        var nonceData = Data(count: nonceSize)
        let result = nonceData.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, nonceSize, buffer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw AESGCMError.nonceGenerationFailed
        }
        return try AESGCMNonce(data: nonceData)
    }
    
    /// Create a counter-based nonce
    /// - Parameters:
    ///   - prefix: A 4-byte prefix (e.g., sender ID)
    ///   - counter: An 8-byte counter
    /// - Returns: A nonce combining prefix and counter
    public static func fromPrefixAndCounter(prefix: UInt32, counter: UInt64) throws -> AESGCMNonce {
        var data = Data()
        var prefixBytes = prefix.bigEndian
        var counterBytes = counter.bigEndian
        data.append(Data(bytes: &prefixBytes, count: 4))
        data.append(Data(bytes: &counterBytes, count: 8))
        return try AESGCMNonce(data: data)
    }
    
    /// Create from counter only
    /// - Parameter counter: The counter value
    /// - Returns: A nonce based on the counter
    public static func fromCounter(_ counter: UInt64) throws -> AESGCMNonce {
        var data = Data(count: 4) // 4 zero bytes
        var counterBytes = counter.bigEndian
        data.append(Data(bytes: &counterBytes, count: 8))
        return try AESGCMNonce(data: data)
    }
    
    /// Access the raw nonce data
    public var rawData: Data {
        return nonceData
    }
    
    /// Convert to CryptoKit nonce
    public var cryptoKitNonce: AES.GCM.Nonce {
        return try! AES.GCM.Nonce(data: nonceData)
    }
    
    /// Increment the nonce (for counter mode)
    public func incremented() throws -> AESGCMNonce {
        var mutableData = nonceData
        for i in (0..<nonceData.count).reversed() {
            mutableData[i] = mutableData[i] &+ 1
            if mutableData[i] != 0 {
                break
            }
        }
        return try AESGCMNonce(data: mutableData)
    }
}

// MARK: - AES-GCM Sealed Box

/// A sealed box containing the encrypted data, nonce, and authentication tag
public struct AESGCMSealedBox: Equatable {
    
    /// The default authentication tag size in bytes
    public static let defaultTagSize = 16
    
    /// The nonce used for encryption
    public let nonce: AESGCMNonce
    
    /// The encrypted ciphertext
    public let ciphertext: Data
    
    /// The authentication tag
    public let tag: Data
    
    /// Additional authenticated data (not encrypted, but authenticated)
    public let aad: Data?
    
    /// Initialize a sealed box with components
    public init(nonce: AESGCMNonce, ciphertext: Data, tag: Data, aad: Data? = nil) throws {
        guard tag.count >= 12 && tag.count <= 16 else {
            throw AESGCMError.invalidTagSize
        }
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
        self.aad = aad
    }
    
    /// Initialize from CryptoKit sealed box
    internal init(cryptoKitBox: AES.GCM.SealedBox, aad: Data? = nil) throws {
        self.nonce = try AESGCMNonce(data: Data(cryptoKitBox.nonce))
        self.ciphertext = cryptoKitBox.ciphertext
        self.tag = cryptoKitBox.tag
        self.aad = aad
    }
    
    /// Combined representation (nonce + ciphertext + tag)
    public var combined: Data {
        var result = Data()
        result.append(nonce.rawData)
        result.append(ciphertext)
        result.append(tag)
        return result
    }
    
    /// Initialize from combined data
    /// - Parameter data: Combined nonce + ciphertext + tag
    /// - Parameter tagSize: The size of the authentication tag
    /// - Throws: AESGCMError if data is invalid
    public static func fromCombined(_ data: Data, tagSize: Int = defaultTagSize) throws -> AESGCMSealedBox {
        let minSize = AESGCMNonce.nonceSize + tagSize
        guard data.count >= minSize else {
            throw AESGCMError.invalidCiphertext
        }
        
        let nonceData = data.prefix(AESGCMNonce.nonceSize)
        let tagData = data.suffix(tagSize)
        let ciphertextData = data.dropFirst(AESGCMNonce.nonceSize).dropLast(tagSize)
        
        let nonce = try AESGCMNonce(data: nonceData)
        return try AESGCMSealedBox(
            nonce: nonce,
            ciphertext: Data(ciphertextData),
            tag: Data(tagData)
        )
    }
    
    /// Serialize to a portable format with metadata
    public func serialize() throws -> Data {
        var data = Data()
        
        // Magic bytes "AGCM"
        data.append(contentsOf: [0x41, 0x47, 0x43, 0x4D])
        
        // Version (2 bytes)
        data.append(contentsOf: [0x00, 0x01])
        
        // Nonce length (1 byte) + nonce
        data.append(UInt8(nonce.rawData.count))
        data.append(nonce.rawData)
        
        // Tag length (1 byte) + tag
        data.append(UInt8(tag.count))
        data.append(tag)
        
        // Ciphertext length (4 bytes, big endian) + ciphertext
        var ciphertextLength = UInt32(ciphertext.count).bigEndian
        data.append(Data(bytes: &ciphertextLength, count: 4))
        data.append(ciphertext)
        
        // AAD length (4 bytes) + AAD (if present)
        if let aadData = aad {
            var aadLength = UInt32(aadData.count).bigEndian
            data.append(Data(bytes: &aadLength, count: 4))
            data.append(aadData)
        } else {
            var aadLength = UInt32(0).bigEndian
            data.append(Data(bytes: &aadLength, count: 4))
        }
        
        return data
    }
    
    /// Deserialize from portable format
    public static func deserialize(_ data: Data) throws -> AESGCMSealedBox {
        guard data.count >= 6 else {
            throw AESGCMError.deserializationFailed
        }
        
        var offset = 0
        
        // Magic bytes
        guard data[0] == 0x41, data[1] == 0x47, data[2] == 0x43, data[3] == 0x4D else {
            throw AESGCMError.deserializationFailed
        }
        offset = 4
        
        // Version
        guard data[4] == 0x00, data[5] == 0x01 else {
            throw AESGCMError.deserializationFailed
        }
        offset = 6
        
        // Nonce
        guard offset < data.count else { throw AESGCMError.deserializationFailed }
        let nonceLength = Int(data[offset])
        offset += 1
        
        guard offset + nonceLength <= data.count else {
            throw AESGCMError.deserializationFailed
        }
        let nonceData = data[offset..<(offset + nonceLength)]
        let nonce = try AESGCMNonce(data: Data(nonceData))
        offset += nonceLength
        
        // Tag
        guard offset < data.count else { throw AESGCMError.deserializationFailed }
        let tagLength = Int(data[offset])
        offset += 1
        
        guard offset + tagLength <= data.count else {
            throw AESGCMError.deserializationFailed
        }
        let tag = data[offset..<(offset + tagLength)]
        offset += tagLength
        
        // Ciphertext length
        guard offset + 4 <= data.count else {
            throw AESGCMError.deserializationFailed
        }
        let ciphertextLength = data[offset..<(offset + 4)].withUnsafeBytes {
            UInt32(bigEndian: $0.load(as: UInt32.self))
        }
        offset += 4
        
        // Ciphertext
        guard offset + Int(ciphertextLength) <= data.count else {
            throw AESGCMError.deserializationFailed
        }
        let ciphertext = data[offset..<(offset + Int(ciphertextLength))]
        offset += Int(ciphertextLength)
        
        // AAD length
        guard offset + 4 <= data.count else {
            throw AESGCMError.deserializationFailed
        }
        let aadLength = data[offset..<(offset + 4)].withUnsafeBytes {
            UInt32(bigEndian: $0.load(as: UInt32.self))
        }
        offset += 4
        
        // AAD
        var aad: Data? = nil
        if aadLength > 0 {
            guard offset + Int(aadLength) <= data.count else {
                throw AESGCMError.deserializationFailed
            }
            aad = Data(data[offset..<(offset + Int(aadLength))])
        }
        
        return try AESGCMSealedBox(
            nonce: nonce,
            ciphertext: Data(ciphertext),
            tag: Data(tag),
            aad: aad
        )
    }
    
    /// Convert to base64 string
    public var base64Encoded: String {
        return combined.base64EncodedString()
    }
    
    /// Create from base64 string
    public static func fromBase64(_ string: String, tagSize: Int = defaultTagSize) throws -> AESGCMSealedBox {
        guard let data = Data(base64Encoded: string) else {
            throw AESGCMError.invalidData
        }
        return try fromCombined(data, tagSize: tagSize)
    }
}

// MARK: - AES-GCM Cipher

/// Main AES-GCM encryption/decryption implementation
public final class AESGCMCipher {
    
    /// The encryption key
    private var key: AESGCMKey
    
    /// Counter for automatic nonce generation
    private var nonceCounter: UInt64 = 0
    
    /// Lock for thread-safe nonce counter increment
    private let counterLock = NSLock()
    
    /// Sender ID prefix for nonce generation
    public var senderPrefix: UInt32 = 0
    
    /// Initialize with a key
    /// - Parameter key: The encryption key
    public init(key: AESGCMKey) {
        self.key = key
    }
    
    /// Generate a new cipher with a random key
    /// - Parameter keySize: The key size to use
    /// - Returns: A new cipher instance
    /// - Throws: AESGCMError.keyGenerationFailed if key generation fails
    public static func generateCipher(keySize: AESKeySize = .bits256) throws -> AESGCMCipher {
        let key = try AESGCMKey.generate(size: keySize)
        return AESGCMCipher(key: key)
    }
    
    /// Create cipher from password
    /// - Parameters:
    ///   - password: The password
    ///   - salt: The salt for key derivation
    ///   - keySize: The desired key size
    ///   - iterations: PBKDF2 iterations
    /// - Returns: A new cipher instance
    public static func fromPassword(
        _ password: String,
        salt: Data,
        keySize: AESKeySize = .bits256,
        iterations: Int = 100000
    ) throws -> AESGCMCipher {
        let key = try AESGCMKey.deriveFromPassword(password, salt: salt, keySize: keySize, iterations: iterations)
        return AESGCMCipher(key: key)
    }
    
    // MARK: - Encryption
    
    /// Encrypt data
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - aad: Optional additional authenticated data
    /// - Returns: A sealed box containing the ciphertext
    /// - Throws: AESGCMError if encryption fails
    public func encrypt(_ plaintext: Data, authenticating aad: Data? = nil) throws -> AESGCMSealedBox {
        let nonce = try AESGCMNonce.generate()
        return try encrypt(plaintext, nonce: nonce, authenticating: aad)
    }
    
    /// Encrypt data with a specific nonce
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - nonce: The nonce to use
    ///   - aad: Optional additional authenticated data
    /// - Returns: A sealed box containing the ciphertext
    /// - Throws: AESGCMError if encryption fails
    public func encrypt(
        _ plaintext: Data,
        nonce: AESGCMNonce,
        authenticating aad: Data? = nil
    ) throws -> AESGCMSealedBox {
        do {
            let sealedBox: AES.GCM.SealedBox
            if let aadData = aad {
                sealedBox = try AES.GCM.seal(
                    plaintext,
                    using: key.symmetricKey,
                    nonce: nonce.cryptoKitNonce,
                    authenticating: aadData
                )
            } else {
                sealedBox = try AES.GCM.seal(
                    plaintext,
                    using: key.symmetricKey,
                    nonce: nonce.cryptoKitNonce
                )
            }
            return try AESGCMSealedBox(cryptoKitBox: sealedBox, aad: aad)
        } catch {
            throw AESGCMError.encryptionFailed
        }
    }
    
    /// Encrypt data with automatic counter-based nonce
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - aad: Optional additional authenticated data
    /// - Returns: A sealed box containing the ciphertext
    /// - Throws: AESGCMError if encryption fails
    public func encryptWithCounter(_ plaintext: Data, authenticating aad: Data? = nil) throws -> AESGCMSealedBox {
        counterLock.lock()
        let currentCounter = nonceCounter
        nonceCounter += 1
        counterLock.unlock()
        
        let nonce = try AESGCMNonce.fromPrefixAndCounter(prefix: senderPrefix, counter: currentCounter)
        return try encrypt(plaintext, nonce: nonce, authenticating: aad)
    }
    
    /// Encrypt a string
    /// - Parameters:
    ///   - string: The string to encrypt
    ///   - aad: Optional additional authenticated data
    /// - Returns: A sealed box containing the ciphertext
    /// - Throws: AESGCMError if encryption fails
    public func encryptString(_ string: String, authenticating aad: Data? = nil) throws -> AESGCMSealedBox {
        guard let data = string.data(using: .utf8) else {
            throw AESGCMError.invalidPlaintext
        }
        return try encrypt(data, authenticating: aad)
    }
    
    /// Encrypt with combined output
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - aad: Optional additional authenticated data
    /// - Returns: Combined nonce + ciphertext + tag
    public func encryptCombined(_ plaintext: Data, authenticating aad: Data? = nil) throws -> Data {
        let sealedBox = try encrypt(plaintext, authenticating: aad)
        return sealedBox.combined
    }
    
    // MARK: - Decryption
    
    /// Decrypt a sealed box
    /// - Parameters:
    ///   - sealedBox: The sealed box to decrypt
    ///   - aad: Optional additional authenticated data (must match encryption AAD)
    /// - Returns: The decrypted plaintext
    /// - Throws: AESGCMError if decryption fails
    public func decrypt(_ sealedBox: AESGCMSealedBox, authenticating aad: Data? = nil) throws -> Data {
        do {
            let combined = sealedBox.nonce.rawData + sealedBox.ciphertext + sealedBox.tag
            let cryptoKitBox = try AES.GCM.SealedBox(combined: combined)
            
            if let aadData = aad {
                return try AES.GCM.open(cryptoKitBox, using: key.symmetricKey, authenticating: aadData)
            } else {
                return try AES.GCM.open(cryptoKitBox, using: key.symmetricKey)
            }
        } catch {
            throw AESGCMError.decryptionFailed
        }
    }
    
    /// Decrypt combined data (nonce + ciphertext + tag)
    /// - Parameters:
    ///   - combined: The combined encrypted data
    ///   - aad: Optional additional authenticated data
    /// - Returns: The decrypted plaintext
    /// - Throws: AESGCMError if decryption fails
    public func decryptCombined(_ combined: Data, authenticating aad: Data? = nil) throws -> Data {
        let sealedBox = try AESGCMSealedBox.fromCombined(combined)
        return try decrypt(sealedBox, authenticating: aad)
    }
    
    /// Decrypt to string
    /// - Parameters:
    ///   - sealedBox: The sealed box to decrypt
    ///   - aad: Optional additional authenticated data
    /// - Returns: The decrypted string
    /// - Throws: AESGCMError if decryption fails
    public func decryptToString(_ sealedBox: AESGCMSealedBox, authenticating aad: Data? = nil) throws -> String {
        let data = try decrypt(sealedBox, authenticating: aad)
        guard let string = String(data: data, encoding: .utf8) else {
            throw AESGCMError.decryptionFailed
        }
        return string
    }
    
    /// Decrypt from base64
    /// - Parameters:
    ///   - base64String: The base64 encoded combined data
    ///   - aad: Optional additional authenticated data
    /// - Returns: The decrypted data
    public func decryptBase64(_ base64String: String, authenticating aad: Data? = nil) throws -> Data {
        let sealedBox = try AESGCMSealedBox.fromBase64(base64String)
        return try decrypt(sealedBox, authenticating: aad)
    }
    
    // MARK: - Key Management
    
    /// Get the current key
    public var currentKey: AESGCMKey {
        return key
    }
    
    /// Get the key size
    public var keySize: AESKeySize {
        return key.keySize
    }
    
    /// Update the encryption key
    /// - Parameter newKey: The new key to use
    public func updateKey(_ newKey: AESGCMKey) {
        key = newKey
        resetCounter()
    }
    
    /// Rotate to a new random key
    /// - Returns: The new key
    @discardableResult
    public func rotateKey() throws -> AESGCMKey {
        let newKey = try AESGCMKey.generate(size: key.keySize)
        updateKey(newKey)
        return newKey
    }
    
    /// Reset the nonce counter
    public func resetCounter() {
        counterLock.lock()
        defer { counterLock.unlock() }
        nonceCounter = 0
    }
    
    /// Set the sender prefix for nonce generation
    public func setSenderPrefix(_ prefix: UInt32) {
        senderPrefix = prefix
    }
    
    /// Securely destroy the cipher (zeroize key)
    public func destroy() {
        key.zeroize()
    }
}

// MARK: - Streaming AES-GCM

/// Configuration for streaming encryption
public struct AESGCMStreamConfig {
    public let blockSize: Int
    public let cipher: AESGCMCipher
    
    public init(cipher: AESGCMCipher, blockSize: Int = 65536) {
        self.cipher = cipher
        self.blockSize = blockSize
    }
}

/// Streaming encryptor for large data
public final class AESGCMStreamEncryptor {
    
    private let config: AESGCMStreamConfig
    private var buffer: Data = Data()
    private var isFinalized = false
    private var encryptedBlocks: [AESGCMSealedBox] = []
    
    public init(config: AESGCMStreamConfig) {
        self.config = config
    }
    
    public convenience init(cipher: AESGCMCipher, blockSize: Int = 65536) {
        self.init(config: AESGCMStreamConfig(cipher: cipher, blockSize: blockSize))
    }
    
    /// Write data to the stream
    public func write(_ data: Data) throws -> [AESGCMSealedBox] {
        guard !isFinalized else {
            throw AESGCMError.streamClosed
        }
        
        buffer.append(data)
        var blocks: [AESGCMSealedBox] = []
        
        while buffer.count >= config.blockSize {
            let block = buffer.prefix(config.blockSize)
            buffer.removeFirst(config.blockSize)
            
            let sealedBox = try config.cipher.encryptWithCounter(Data(block))
            blocks.append(sealedBox)
            encryptedBlocks.append(sealedBox)
        }
        
        return blocks
    }
    
    /// Finalize the stream
    public func finalize() throws -> AESGCMSealedBox? {
        guard !isFinalized else {
            throw AESGCMError.streamClosed
        }
        
        isFinalized = true
        
        guard !buffer.isEmpty else {
            return nil
        }
        
        let sealedBox = try config.cipher.encryptWithCounter(buffer)
        encryptedBlocks.append(sealedBox)
        buffer = Data()
        
        return sealedBox
    }
    
    public var allBlocks: [AESGCMSealedBox] {
        return encryptedBlocks
    }
}

/// Streaming decryptor for large data
public final class AESGCMStreamDecryptor {
    
    private let cipher: AESGCMCipher
    private var decryptedData: Data = Data()
    private var isFinalized = false
    
    public init(cipher: AESGCMCipher) {
        self.cipher = cipher
    }
    
    public func decrypt(_ sealedBox: AESGCMSealedBox) throws -> Data {
        guard !isFinalized else {
            throw AESGCMError.streamClosed
        }
        
        let data = try cipher.decrypt(sealedBox)
        decryptedData.append(data)
        return data
    }
    
    public func decryptAll(_ boxes: [AESGCMSealedBox]) throws -> Data {
        var result = Data()
        for box in boxes {
            let data = try decrypt(box)
            result.append(data)
        }
        return result
    }
    
    public func finalize() -> Data {
        isFinalized = true
        return decryptedData
    }
}

// MARK: - File Encryption

/// File encryptor using AES-GCM
public final class AESGCMFileEncryptor {
    
    private let cipher: AESGCMCipher
    
    public init(cipher: AESGCMCipher) {
        self.cipher = cipher
    }
    
    /// Encrypt a file
    public func encryptFile(at inputURL: URL, to outputURL: URL, chunkSize: Int = 1024 * 1024) throws {
        let inputStream = try FileHandle(forReadingFrom: inputURL)
        defer { try? inputStream.close() }
        
        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let outputStream = try FileHandle(forWritingTo: outputURL)
        defer { try? outputStream.close() }
        
        // Write header
        var header = Data()
        header.append(contentsOf: [0x41, 0x45, 0x53, 0x47]) // "AESG" magic bytes
        header.append(contentsOf: [0x00, 0x01]) // Version 1
        header.append(UInt8(cipher.keySize.byteCount)) // Key size byte
        try outputStream.write(contentsOf: header)
        
        // Encrypt in chunks
        while true {
            let chunk = inputStream.readData(ofLength: chunkSize)
            if chunk.isEmpty { break }
            
            let sealedBox = try cipher.encrypt(chunk)
            let combined = sealedBox.combined
            
            var length = UInt32(combined.count).bigEndian
            try outputStream.write(contentsOf: Data(bytes: &length, count: 4))
            try outputStream.write(contentsOf: combined)
        }
        
        // Write end marker
        var endMarker = UInt32(0).bigEndian
        try outputStream.write(contentsOf: Data(bytes: &endMarker, count: 4))
    }
    
    /// Decrypt a file
    public func decryptFile(at inputURL: URL, to outputURL: URL) throws {
        let inputStream = try FileHandle(forReadingFrom: inputURL)
        defer { try? inputStream.close() }
        
        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let outputStream = try FileHandle(forWritingTo: outputURL)
        defer { try? outputStream.close() }
        
        // Read and verify header
        let header = inputStream.readData(ofLength: 7)
        guard header.count == 7,
              header[0] == 0x41, header[1] == 0x45,
              header[2] == 0x53, header[3] == 0x47,
              header[4] == 0x00, header[5] == 0x01 else {
            throw AESGCMError.invalidCiphertext
        }
        
        // Decrypt blocks
        while true {
            let lengthData = inputStream.readData(ofLength: 4)
            guard lengthData.count == 4 else {
                throw AESGCMError.invalidCiphertext
            }
            
            let length = lengthData.withUnsafeBytes {
                UInt32(bigEndian: $0.load(as: UInt32.self))
            }
            
            if length == 0 { break }
            
            let combined = inputStream.readData(ofLength: Int(length))
            guard combined.count == Int(length) else {
                throw AESGCMError.invalidCiphertext
            }
            
            let plaintext = try cipher.decryptCombined(combined)
            try outputStream.write(contentsOf: plaintext)
        }
    }
    
    /// Calculate encrypted file size
    public func calculateEncryptedSize(originalSize: Int, chunkSize: Int = 1024 * 1024) -> Int {
        let headerSize = 7
        let chunkCount = (originalSize + chunkSize - 1) / chunkSize
        let perChunkOverhead = AESGCMNonce.nonceSize + AESGCMSealedBox.defaultTagSize + 4 // nonce + tag + length
        let endMarkerSize = 4
        
        return headerSize + (chunkCount * (chunkSize + perChunkOverhead)) + endMarkerSize
    }
}

// MARK: - Convenience Extensions

extension Data {
    
    /// Encrypt data using AES-GCM
    public func aesGCMEncrypt(with key: AESGCMKey) throws -> AESGCMSealedBox {
        let cipher = AESGCMCipher(key: key)
        return try cipher.encrypt(self)
    }
    
    /// Encrypt data using AES-GCM with password
    public func aesGCMEncrypt(password: String, salt: Data, keySize: AESKeySize = .bits256) throws -> AESGCMSealedBox {
        let key = try AESGCMKey.deriveFromPassword(password, salt: salt, keySize: keySize)
        return try aesGCMEncrypt(with: key)
    }
    
    /// Quick AES-256-GCM encryption with random key
    public func aesGCMEncryptWithRandomKey() throws -> (sealedBox: AESGCMSealedBox, key: AESGCMKey) {
        let key = try AESGCMKey.generate(size: .bits256)
        let sealedBox = try aesGCMEncrypt(with: key)
        return (sealedBox, key)
    }
}

extension String {
    
    /// Encrypt string using AES-GCM
    public func aesGCMEncrypt(with key: AESGCMKey) throws -> AESGCMSealedBox {
        guard let data = self.data(using: .utf8) else {
            throw AESGCMError.invalidPlaintext
        }
        return try data.aesGCMEncrypt(with: key)
    }
    
    /// Decrypt base64 AES-GCM string
    public func aesGCMDecrypt(with key: AESGCMKey) throws -> Data {
        let cipher = AESGCMCipher(key: key)
        return try cipher.decryptBase64(self)
    }
}

// MARK: - AES-GCM SIV (Synthetic IV)

/// AES-GCM-SIV implementation for nonce-misuse resistance
public final class AESGCMSIVCipher {
    
    private let key: AESGCMKey
    private let hashKey: SymmetricKey
    
    public init(key: AESGCMKey) throws {
        self.key = key
        // Derive hash key from main key
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: key.symmetricKey,
            salt: Data("AES-GCM-SIV-HASH".utf8),
            info: Data(),
            outputByteCount: 32
        )
        self.hashKey = derivedKey
    }
    
    /// Encrypt with synthetic IV
    public func encrypt(_ plaintext: Data, authenticating aad: Data? = nil) throws -> AESGCMSealedBox {
        // Generate synthetic nonce from plaintext and AAD
        var hashInput = Data()
        hashInput.append(plaintext)
        if let aadData = aad {
            hashInput.append(aadData)
        }
        
        let hash = HMAC<SHA256>.authenticationCode(for: hashInput, using: hashKey)
        let syntheticNonce = try AESGCMNonce(data: Data(hash.prefix(12)))
        
        let cipher = AESGCMCipher(key: key)
        return try cipher.encrypt(plaintext, nonce: syntheticNonce, authenticating: aad)
    }
    
    /// Decrypt with verification
    public func decrypt(_ sealedBox: AESGCMSealedBox, authenticating aad: Data? = nil) throws -> Data {
        let cipher = AESGCMCipher(key: key)
        return try cipher.decrypt(sealedBox, authenticating: aad)
    }
}
