//
//  ChaCha20Poly1305.swift
//  SwiftCryptoPro
//
//  Created by Muhittin Camdali on 2025.
//  Copyright © 2025 Muhittin Camdali. All rights reserved.
//

import Foundation
import CryptoKit
import Security

// MARK: - ChaCha20Poly1305 Error Types

/// Errors that can occur during ChaCha20-Poly1305 operations
public enum ChaCha20Poly1305Error: Error, LocalizedError, Equatable {
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
    case streamClosed
    case bufferOverflow
    case insufficientData
    case invalidAAD
    case tagMismatch
    
    public var errorDescription: String? {
        switch self {
        case .invalidKeySize:
            return "Invalid key size. ChaCha20-Poly1305 requires a 256-bit (32-byte) key."
        case .invalidNonceSize:
            return "Invalid nonce size. ChaCha20-Poly1305 requires a 96-bit (12-byte) nonce."
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
        case .streamClosed:
            return "Stream has been closed."
        case .bufferOverflow:
            return "Buffer overflow detected."
        case .insufficientData:
            return "Insufficient data for operation."
        case .invalidAAD:
            return "Invalid additional authenticated data."
        case .tagMismatch:
            return "Authentication tag mismatch."
        }
    }
}

// MARK: - ChaCha20Poly1305 Key

/// A symmetric key for ChaCha20-Poly1305 encryption
public struct ChaCha20Poly1305Key: Equatable, Hashable {
    
    /// The key size in bytes (32 bytes = 256 bits)
    public static let keySize = 32
    
    /// The underlying key data
    private let keyData: Data
    
    /// Initialize with raw key data
    /// - Parameter data: The 32-byte key data
    /// - Throws: ChaCha20Poly1305Error.invalidKeySize if data is not 32 bytes
    public init(data: Data) throws {
        guard data.count == Self.keySize else {
            throw ChaCha20Poly1305Error.invalidKeySize
        }
        self.keyData = data
    }
    
    /// Generate a new random key
    /// - Returns: A newly generated random key
    /// - Throws: ChaCha20Poly1305Error.keyGenerationFailed if generation fails
    public static func generate() throws -> ChaCha20Poly1305Key {
        var keyData = Data(count: keySize)
        let result = keyData.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, keySize, buffer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw ChaCha20Poly1305Error.keyGenerationFailed
        }
        return try ChaCha20Poly1305Key(data: keyData)
    }
    
    /// Generate key from password using PBKDF2
    /// - Parameters:
    ///   - password: The password to derive the key from
    ///   - salt: The salt for key derivation
    ///   - iterations: Number of PBKDF2 iterations (default: 100000)
    /// - Returns: A derived key
    /// - Throws: ChaCha20Poly1305Error.keyGenerationFailed if derivation fails
    public static func deriveFromPassword(
        _ password: String,
        salt: Data,
        iterations: Int = 100000
    ) throws -> ChaCha20Poly1305Key {
        guard let passwordData = password.data(using: .utf8) else {
            throw ChaCha20Poly1305Error.keyGenerationFailed
        }
        
        var derivedKey = Data(count: keySize)
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
                        keySize
                    )
                }
            }
        }
        
        guard result == kCCSuccess else {
            throw ChaCha20Poly1305Error.keyGenerationFailed
        }
        
        return try ChaCha20Poly1305Key(data: derivedKey)
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
        var mutableData = keyData
        mutableData.withUnsafeMutableBytes { buffer in
            memset(buffer.baseAddress, 0, buffer.count)
        }
    }
}

// Required for CCKeyDerivationPBKDF
import CommonCrypto

// MARK: - ChaCha20Poly1305 Nonce

/// A nonce for ChaCha20-Poly1305 encryption
public struct ChaCha20Poly1305Nonce: Equatable, Hashable {
    
    /// The nonce size in bytes (12 bytes = 96 bits)
    public static let nonceSize = 12
    
    /// The underlying nonce data
    private let nonceData: Data
    
    /// Initialize with raw nonce data
    /// - Parameter data: The 12-byte nonce data
    /// - Throws: ChaCha20Poly1305Error.invalidNonceSize if data is not 12 bytes
    public init(data: Data) throws {
        guard data.count == Self.nonceSize else {
            throw ChaCha20Poly1305Error.invalidNonceSize
        }
        self.nonceData = data
    }
    
    /// Generate a new random nonce
    /// - Returns: A newly generated random nonce
    /// - Throws: ChaCha20Poly1305Error.nonceGenerationFailed if generation fails
    public static func generate() throws -> ChaCha20Poly1305Nonce {
        var nonceData = Data(count: nonceSize)
        let result = nonceData.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, nonceSize, buffer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw ChaCha20Poly1305Error.nonceGenerationFailed
        }
        return try ChaCha20Poly1305Nonce(data: nonceData)
    }
    
    /// Create a counter-based nonce
    /// - Parameter counter: The counter value (will be zero-padded to 12 bytes)
    /// - Returns: A nonce based on the counter
    public static func fromCounter(_ counter: UInt64) throws -> ChaCha20Poly1305Nonce {
        var data = Data(count: nonceSize)
        data.replaceSubrange(4..<12, with: withUnsafeBytes(of: counter.bigEndian) { Data($0) })
        return try ChaCha20Poly1305Nonce(data: data)
    }
    
    /// Access the raw nonce data
    public var rawData: Data {
        return nonceData
    }
    
    /// Convert to CryptoKit nonce
    public var cryptoKitNonce: ChaChaPoly.Nonce {
        return try! ChaChaPoly.Nonce(data: nonceData)
    }
}

// MARK: - ChaCha20Poly1305 Sealed Box

/// A sealed box containing the encrypted data, nonce, and authentication tag
public struct ChaCha20Poly1305SealedBox: Equatable {
    
    /// The authentication tag size in bytes
    public static let tagSize = 16
    
    /// The nonce used for encryption
    public let nonce: ChaCha20Poly1305Nonce
    
    /// The encrypted ciphertext
    public let ciphertext: Data
    
    /// The authentication tag
    public let tag: Data
    
    /// Additional authenticated data (not encrypted, but authenticated)
    public let aad: Data?
    
    /// Initialize a sealed box with components
    /// - Parameters:
    ///   - nonce: The nonce used for encryption
    ///   - ciphertext: The encrypted data
    ///   - tag: The authentication tag
    ///   - aad: Optional additional authenticated data
    public init(nonce: ChaCha20Poly1305Nonce, ciphertext: Data, tag: Data, aad: Data? = nil) throws {
        guard tag.count == Self.tagSize else {
            throw ChaCha20Poly1305Error.authenticationFailed
        }
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
        self.aad = aad
    }
    
    /// Initialize from CryptoKit sealed box
    internal init(cryptoKitBox: ChaChaPoly.SealedBox, aad: Data? = nil) throws {
        self.nonce = try ChaCha20Poly1305Nonce(data: Data(cryptoKitBox.nonce))
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
    /// - Throws: ChaCha20Poly1305Error if data is invalid
    public static func fromCombined(_ data: Data) throws -> ChaCha20Poly1305SealedBox {
        let minSize = ChaCha20Poly1305Nonce.nonceSize + tagSize
        guard data.count >= minSize else {
            throw ChaCha20Poly1305Error.invalidCiphertext
        }
        
        let nonceData = data.prefix(ChaCha20Poly1305Nonce.nonceSize)
        let tagData = data.suffix(tagSize)
        let ciphertextData = data.dropFirst(ChaCha20Poly1305Nonce.nonceSize).dropLast(tagSize)
        
        let nonce = try ChaCha20Poly1305Nonce(data: nonceData)
        return try ChaCha20Poly1305SealedBox(
            nonce: nonce,
            ciphertext: Data(ciphertextData),
            tag: Data(tagData)
        )
    }
    
    /// Serialize to a portable format
    public func serialize() throws -> Data {
        var data = Data()
        
        // Version byte
        data.append(0x01)
        
        // Nonce length (1 byte) + nonce
        data.append(UInt8(nonce.rawData.count))
        data.append(nonce.rawData)
        
        // Ciphertext length (4 bytes, big endian) + ciphertext
        var ciphertextLength = UInt32(ciphertext.count).bigEndian
        data.append(Data(bytes: &ciphertextLength, count: 4))
        data.append(ciphertext)
        
        // Tag
        data.append(tag)
        
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
    public static func deserialize(_ data: Data) throws -> ChaCha20Poly1305SealedBox {
        guard data.count > 0 else {
            throw ChaCha20Poly1305Error.deserializationFailed
        }
        
        var offset = 0
        
        // Version byte
        let version = data[offset]
        guard version == 0x01 else {
            throw ChaCha20Poly1305Error.deserializationFailed
        }
        offset += 1
        
        // Nonce
        guard offset < data.count else { throw ChaCha20Poly1305Error.deserializationFailed }
        let nonceLength = Int(data[offset])
        offset += 1
        
        guard offset + nonceLength <= data.count else {
            throw ChaCha20Poly1305Error.deserializationFailed
        }
        let nonceData = data[offset..<(offset + nonceLength)]
        let nonce = try ChaCha20Poly1305Nonce(data: Data(nonceData))
        offset += nonceLength
        
        // Ciphertext length
        guard offset + 4 <= data.count else {
            throw ChaCha20Poly1305Error.deserializationFailed
        }
        let ciphertextLength = data[offset..<(offset + 4)].withUnsafeBytes {
            UInt32(bigEndian: $0.load(as: UInt32.self))
        }
        offset += 4
        
        // Ciphertext
        guard offset + Int(ciphertextLength) <= data.count else {
            throw ChaCha20Poly1305Error.deserializationFailed
        }
        let ciphertext = data[offset..<(offset + Int(ciphertextLength))]
        offset += Int(ciphertextLength)
        
        // Tag
        guard offset + tagSize <= data.count else {
            throw ChaCha20Poly1305Error.deserializationFailed
        }
        let tag = data[offset..<(offset + tagSize)]
        offset += tagSize
        
        // AAD length
        guard offset + 4 <= data.count else {
            throw ChaCha20Poly1305Error.deserializationFailed
        }
        let aadLength = data[offset..<(offset + 4)].withUnsafeBytes {
            UInt32(bigEndian: $0.load(as: UInt32.self))
        }
        offset += 4
        
        // AAD
        var aad: Data? = nil
        if aadLength > 0 {
            guard offset + Int(aadLength) <= data.count else {
                throw ChaCha20Poly1305Error.deserializationFailed
            }
            aad = Data(data[offset..<(offset + Int(aadLength))])
        }
        
        return try ChaCha20Poly1305SealedBox(
            nonce: nonce,
            ciphertext: Data(ciphertext),
            tag: Data(tag),
            aad: aad
        )
    }
}

// MARK: - ChaCha20Poly1305 Cipher

/// Main ChaCha20-Poly1305 encryption/decryption implementation
public final class ChaCha20Poly1305Cipher {
    
    /// The encryption key
    private var key: ChaCha20Poly1305Key
    
    /// Counter for automatic nonce generation
    private var nonceCounter: UInt64 = 0
    
    /// Lock for thread-safe nonce counter increment
    private let counterLock = NSLock()
    
    /// Initialize with a key
    /// - Parameter key: The encryption key
    public init(key: ChaCha20Poly1305Key) {
        self.key = key
    }
    
    /// Generate a new cipher with a random key
    /// - Returns: A new cipher instance
    /// - Throws: ChaCha20Poly1305Error.keyGenerationFailed if key generation fails
    public static func generateCipher() throws -> ChaCha20Poly1305Cipher {
        let key = try ChaCha20Poly1305Key.generate()
        return ChaCha20Poly1305Cipher(key: key)
    }
    
    /// Create cipher from password
    /// - Parameters:
    ///   - password: The password
    ///   - salt: The salt for key derivation
    ///   - iterations: PBKDF2 iterations
    /// - Returns: A new cipher instance
    public static func fromPassword(
        _ password: String,
        salt: Data,
        iterations: Int = 100000
    ) throws -> ChaCha20Poly1305Cipher {
        let key = try ChaCha20Poly1305Key.deriveFromPassword(password, salt: salt, iterations: iterations)
        return ChaCha20Poly1305Cipher(key: key)
    }
    
    // MARK: - Encryption
    
    /// Encrypt data
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - aad: Optional additional authenticated data
    /// - Returns: A sealed box containing the ciphertext
    /// - Throws: ChaCha20Poly1305Error if encryption fails
    public func encrypt(_ plaintext: Data, authenticating aad: Data? = nil) throws -> ChaCha20Poly1305SealedBox {
        let nonce = try ChaCha20Poly1305Nonce.generate()
        return try encrypt(plaintext, nonce: nonce, authenticating: aad)
    }
    
    /// Encrypt data with a specific nonce
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - nonce: The nonce to use
    ///   - aad: Optional additional authenticated data
    /// - Returns: A sealed box containing the ciphertext
    /// - Throws: ChaCha20Poly1305Error if encryption fails
    public func encrypt(
        _ plaintext: Data,
        nonce: ChaCha20Poly1305Nonce,
        authenticating aad: Data? = nil
    ) throws -> ChaCha20Poly1305SealedBox {
        do {
            let sealedBox: ChaChaPoly.SealedBox
            if let aadData = aad {
                sealedBox = try ChaChaPoly.seal(
                    plaintext,
                    using: key.symmetricKey,
                    nonce: nonce.cryptoKitNonce,
                    authenticating: aadData
                )
            } else {
                sealedBox = try ChaChaPoly.seal(
                    plaintext,
                    using: key.symmetricKey,
                    nonce: nonce.cryptoKitNonce
                )
            }
            return try ChaCha20Poly1305SealedBox(cryptoKitBox: sealedBox, aad: aad)
        } catch {
            throw ChaCha20Poly1305Error.encryptionFailed
        }
    }
    
    /// Encrypt data with automatic counter-based nonce
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - aad: Optional additional authenticated data
    /// - Returns: A sealed box containing the ciphertext
    /// - Throws: ChaCha20Poly1305Error if encryption fails
    public func encryptWithCounter(_ plaintext: Data, authenticating aad: Data? = nil) throws -> ChaCha20Poly1305SealedBox {
        counterLock.lock()
        defer { counterLock.unlock() }
        
        let nonce = try ChaCha20Poly1305Nonce.fromCounter(nonceCounter)
        nonceCounter += 1
        
        return try encrypt(plaintext, nonce: nonce, authenticating: aad)
    }
    
    /// Encrypt a string
    /// - Parameters:
    ///   - string: The string to encrypt
    ///   - aad: Optional additional authenticated data
    /// - Returns: A sealed box containing the ciphertext
    /// - Throws: ChaCha20Poly1305Error if encryption fails
    public func encryptString(_ string: String, authenticating aad: Data? = nil) throws -> ChaCha20Poly1305SealedBox {
        guard let data = string.data(using: .utf8) else {
            throw ChaCha20Poly1305Error.invalidPlaintext
        }
        return try encrypt(data, authenticating: aad)
    }
    
    // MARK: - Decryption
    
    /// Decrypt a sealed box
    /// - Parameters:
    ///   - sealedBox: The sealed box to decrypt
    ///   - aad: Optional additional authenticated data (must match encryption AAD)
    /// - Returns: The decrypted plaintext
    /// - Throws: ChaCha20Poly1305Error if decryption fails
    public func decrypt(_ sealedBox: ChaCha20Poly1305SealedBox, authenticating aad: Data? = nil) throws -> Data {
        do {
            let combined = sealedBox.nonce.rawData + sealedBox.ciphertext + sealedBox.tag
            let cryptoKitBox = try ChaChaPoly.SealedBox(combined: combined)
            
            if let aadData = aad {
                return try ChaChaPoly.open(cryptoKitBox, using: key.symmetricKey, authenticating: aadData)
            } else {
                return try ChaChaPoly.open(cryptoKitBox, using: key.symmetricKey)
            }
        } catch {
            throw ChaCha20Poly1305Error.decryptionFailed
        }
    }
    
    /// Decrypt combined data (nonce + ciphertext + tag)
    /// - Parameters:
    ///   - combined: The combined encrypted data
    ///   - aad: Optional additional authenticated data
    /// - Returns: The decrypted plaintext
    /// - Throws: ChaCha20Poly1305Error if decryption fails
    public func decryptCombined(_ combined: Data, authenticating aad: Data? = nil) throws -> Data {
        let sealedBox = try ChaCha20Poly1305SealedBox.fromCombined(combined)
        return try decrypt(sealedBox, authenticating: aad)
    }
    
    /// Decrypt to string
    /// - Parameters:
    ///   - sealedBox: The sealed box to decrypt
    ///   - aad: Optional additional authenticated data
    /// - Returns: The decrypted string
    /// - Throws: ChaCha20Poly1305Error if decryption fails
    public func decryptToString(_ sealedBox: ChaCha20Poly1305SealedBox, authenticating aad: Data? = nil) throws -> String {
        let data = try decrypt(sealedBox, authenticating: aad)
        guard let string = String(data: data, encoding: .utf8) else {
            throw ChaCha20Poly1305Error.decryptionFailed
        }
        return string
    }
    
    // MARK: - Key Management
    
    /// Get the current key
    public var currentKey: ChaCha20Poly1305Key {
        return key
    }
    
    /// Update the encryption key
    /// - Parameter newKey: The new key to use
    public func updateKey(_ newKey: ChaCha20Poly1305Key) {
        key = newKey
        resetCounter()
    }
    
    /// Reset the nonce counter
    public func resetCounter() {
        counterLock.lock()
        defer { counterLock.unlock() }
        nonceCounter = 0
    }
    
    /// Securely destroy the cipher (zeroize key)
    public func destroy() {
        key.zeroize()
    }
}

// MARK: - Streaming Encryption

/// Streaming encryptor for large data
public final class ChaCha20Poly1305StreamEncryptor {
    
    /// The cipher instance
    private let cipher: ChaCha20Poly1305Cipher
    
    /// Buffer for accumulating data
    private var buffer: Data = Data()
    
    /// Block size for streaming
    public let blockSize: Int
    
    /// Whether the stream is finalized
    private var isFinalized = false
    
    /// All encrypted blocks
    private var encryptedBlocks: [ChaCha20Poly1305SealedBox] = []
    
    /// Initialize a stream encryptor
    /// - Parameters:
    ///   - cipher: The cipher to use
    ///   - blockSize: The block size for streaming (default: 64KB)
    public init(cipher: ChaCha20Poly1305Cipher, blockSize: Int = 65536) {
        self.cipher = cipher
        self.blockSize = blockSize
    }
    
    /// Write data to the stream
    /// - Parameter data: The data to write
    /// - Returns: Any encrypted blocks produced
    /// - Throws: ChaCha20Poly1305Error if encryption fails
    public func write(_ data: Data) throws -> [ChaCha20Poly1305SealedBox] {
        guard !isFinalized else {
            throw ChaCha20Poly1305Error.streamClosed
        }
        
        buffer.append(data)
        var blocks: [ChaCha20Poly1305SealedBox] = []
        
        while buffer.count >= blockSize {
            let block = buffer.prefix(blockSize)
            buffer.removeFirst(blockSize)
            
            let sealedBox = try cipher.encryptWithCounter(Data(block))
            blocks.append(sealedBox)
            encryptedBlocks.append(sealedBox)
        }
        
        return blocks
    }
    
    /// Finalize the stream and encrypt any remaining data
    /// - Returns: The final encrypted block (if any)
    /// - Throws: ChaCha20Poly1305Error if encryption fails
    public func finalize() throws -> ChaCha20Poly1305SealedBox? {
        guard !isFinalized else {
            throw ChaCha20Poly1305Error.streamClosed
        }
        
        isFinalized = true
        
        guard !buffer.isEmpty else {
            return nil
        }
        
        let sealedBox = try cipher.encryptWithCounter(buffer)
        encryptedBlocks.append(sealedBox)
        buffer = Data()
        
        return sealedBox
    }
    
    /// Get all encrypted blocks
    public var allBlocks: [ChaCha20Poly1305SealedBox] {
        return encryptedBlocks
    }
}

// MARK: - Streaming Decryption

/// Streaming decryptor for large data
public final class ChaCha20Poly1305StreamDecryptor {
    
    /// The cipher instance
    private let cipher: ChaCha20Poly1305Cipher
    
    /// Decrypted data
    private var decryptedData: Data = Data()
    
    /// Whether the stream is finalized
    private var isFinalized = false
    
    /// Initialize a stream decryptor
    /// - Parameter cipher: The cipher to use
    public init(cipher: ChaCha20Poly1305Cipher) {
        self.cipher = cipher
    }
    
    /// Decrypt a sealed box and append to stream
    /// - Parameter sealedBox: The sealed box to decrypt
    /// - Returns: The decrypted data for this block
    /// - Throws: ChaCha20Poly1305Error if decryption fails
    public func decrypt(_ sealedBox: ChaCha20Poly1305SealedBox) throws -> Data {
        guard !isFinalized else {
            throw ChaCha20Poly1305Error.streamClosed
        }
        
        let data = try cipher.decrypt(sealedBox)
        decryptedData.append(data)
        return data
    }
    
    /// Decrypt multiple sealed boxes
    /// - Parameter boxes: The sealed boxes to decrypt
    /// - Returns: The decrypted data for all blocks
    /// - Throws: ChaCha20Poly1305Error if decryption fails
    public func decryptAll(_ boxes: [ChaCha20Poly1305SealedBox]) throws -> Data {
        var result = Data()
        for box in boxes {
            let data = try decrypt(box)
            result.append(data)
        }
        return result
    }
    
    /// Finalize the stream
    /// - Returns: All decrypted data
    public func finalize() -> Data {
        isFinalized = true
        return decryptedData
    }
}

// MARK: - File Encryption

/// File encryptor using ChaCha20-Poly1305
public final class ChaCha20Poly1305FileEncryptor {
    
    /// The cipher instance
    private let cipher: ChaCha20Poly1305Cipher
    
    /// Initialize with a cipher
    /// - Parameter cipher: The cipher to use
    public init(cipher: ChaCha20Poly1305Cipher) {
        self.cipher = cipher
    }
    
    /// Encrypt a file
    /// - Parameters:
    ///   - inputURL: The input file URL
    ///   - outputURL: The output file URL
    ///   - chunkSize: The chunk size for streaming (default: 1MB)
    /// - Throws: ChaCha20Poly1305Error if encryption fails
    public func encryptFile(at inputURL: URL, to outputURL: URL, chunkSize: Int = 1024 * 1024) throws {
        let inputStream = try FileHandle(forReadingFrom: inputURL)
        defer { try? inputStream.close() }
        
        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let outputStream = try FileHandle(forWritingTo: outputURL)
        defer { try? outputStream.close() }
        
        // Write header
        var header = Data()
        header.append(contentsOf: [0x43, 0x43, 0x50, 0x31]) // "CCP1" magic bytes
        header.append(contentsOf: [0x00, 0x01]) // Version 1
        try outputStream.write(contentsOf: header)
        
        // Encrypt in chunks
        var blockIndex: UInt32 = 0
        while true {
            let chunk = inputStream.readData(ofLength: chunkSize)
            if chunk.isEmpty { break }
            
            let sealedBox = try cipher.encrypt(chunk)
            
            // Write block: length (4 bytes) + sealed box combined
            let combined = sealedBox.combined
            var length = UInt32(combined.count).bigEndian
            try outputStream.write(contentsOf: Data(bytes: &length, count: 4))
            try outputStream.write(contentsOf: combined)
            
            blockIndex += 1
        }
        
        // Write end marker
        var endMarker = UInt32(0).bigEndian
        try outputStream.write(contentsOf: Data(bytes: &endMarker, count: 4))
    }
    
    /// Decrypt a file
    /// - Parameters:
    ///   - inputURL: The input encrypted file URL
    ///   - outputURL: The output decrypted file URL
    /// - Throws: ChaCha20Poly1305Error if decryption fails
    public func decryptFile(at inputURL: URL, to outputURL: URL) throws {
        let inputStream = try FileHandle(forReadingFrom: inputURL)
        defer { try? inputStream.close() }
        
        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let outputStream = try FileHandle(forWritingTo: outputURL)
        defer { try? outputStream.close() }
        
        // Read and verify header
        let header = inputStream.readData(ofLength: 6)
        guard header.count == 6,
              header[0] == 0x43, header[1] == 0x43,
              header[2] == 0x50, header[3] == 0x31,
              header[4] == 0x00, header[5] == 0x01 else {
            throw ChaCha20Poly1305Error.invalidCiphertext
        }
        
        // Decrypt blocks
        while true {
            let lengthData = inputStream.readData(ofLength: 4)
            guard lengthData.count == 4 else {
                throw ChaCha20Poly1305Error.invalidCiphertext
            }
            
            let length = lengthData.withUnsafeBytes {
                UInt32(bigEndian: $0.load(as: UInt32.self))
            }
            
            // End marker
            if length == 0 { break }
            
            let combined = inputStream.readData(ofLength: Int(length))
            guard combined.count == Int(length) else {
                throw ChaCha20Poly1305Error.invalidCiphertext
            }
            
            let plaintext = try cipher.decryptCombined(combined)
            try outputStream.write(contentsOf: plaintext)
        }
    }
}

// MARK: - Convenience Extensions

extension Data {
    
    /// Encrypt data using ChaCha20-Poly1305
    /// - Parameter key: The encryption key
    /// - Returns: The encrypted sealed box
    public func chacha20Poly1305Encrypt(with key: ChaCha20Poly1305Key) throws -> ChaCha20Poly1305SealedBox {
        let cipher = ChaCha20Poly1305Cipher(key: key)
        return try cipher.encrypt(self)
    }
    
    /// Encrypt data using ChaCha20-Poly1305 with password
    /// - Parameters:
    ///   - password: The encryption password
    ///   - salt: The salt for key derivation
    /// - Returns: The encrypted sealed box
    public func chacha20Poly1305Encrypt(password: String, salt: Data) throws -> ChaCha20Poly1305SealedBox {
        let key = try ChaCha20Poly1305Key.deriveFromPassword(password, salt: salt)
        return try chacha20Poly1305Encrypt(with: key)
    }
}

extension String {
    
    /// Encrypt string using ChaCha20-Poly1305
    /// - Parameter key: The encryption key
    /// - Returns: The encrypted sealed box
    public func chacha20Poly1305Encrypt(with key: ChaCha20Poly1305Key) throws -> ChaCha20Poly1305SealedBox {
        guard let data = self.data(using: .utf8) else {
            throw ChaCha20Poly1305Error.invalidPlaintext
        }
        return try data.chacha20Poly1305Encrypt(with: key)
    }
}
