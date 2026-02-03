//
//  RSA-OAEP.swift
//  SwiftCryptoPro
//
//  Created by Muhittin Camdali on 2025.
//  Copyright © 2025 Muhittin Camdali. All rights reserved.
//

import Foundation
import Security
import CryptoKit
import CommonCrypto

// MARK: - RSA-OAEP Error Types

/// Errors that can occur during RSA-OAEP operations
public enum RSAOAEPError: Error, LocalizedError, Equatable {
    case invalidKeySize
    case keyGenerationFailed
    case encryptionFailed
    case decryptionFailed
    case invalidPublicKey
    case invalidPrivateKey
    case invalidPEM
    case invalidDER
    case keyExportFailed
    case keyImportFailed
    case invalidCiphertext
    case invalidPlaintext
    case plaintextTooLong
    case paddingFailed
    case hashMismatch
    case invalidOAEPLabel
    case keychainError(OSStatus)
    case unsupportedAlgorithm
    case invalidKeyFormat
    case serializationFailed
    case deserializationFailed
    case signatureFailed
    case verificationFailed
    
    public var errorDescription: String? {
        switch self {
        case .invalidKeySize:
            return "Invalid RSA key size. Supported sizes: 2048, 3072, 4096 bits."
        case .keyGenerationFailed:
            return "Failed to generate RSA key pair."
        case .encryptionFailed:
            return "RSA-OAEP encryption failed."
        case .decryptionFailed:
            return "RSA-OAEP decryption failed."
        case .invalidPublicKey:
            return "Invalid RSA public key."
        case .invalidPrivateKey:
            return "Invalid RSA private key."
        case .invalidPEM:
            return "Invalid PEM format."
        case .invalidDER:
            return "Invalid DER format."
        case .keyExportFailed:
            return "Failed to export key."
        case .keyImportFailed:
            return "Failed to import key."
        case .invalidCiphertext:
            return "Invalid ciphertext format."
        case .invalidPlaintext:
            return "Invalid plaintext data."
        case .plaintextTooLong:
            return "Plaintext is too long for the key size."
        case .paddingFailed:
            return "OAEP padding operation failed."
        case .hashMismatch:
            return "Hash verification failed."
        case .invalidOAEPLabel:
            return "Invalid OAEP label."
        case .keychainError(let status):
            return "Keychain error: \(status)"
        case .unsupportedAlgorithm:
            return "Unsupported algorithm."
        case .invalidKeyFormat:
            return "Invalid key format."
        case .serializationFailed:
            return "Failed to serialize data."
        case .deserializationFailed:
            return "Failed to deserialize data."
        case .signatureFailed:
            return "Failed to create signature."
        case .verificationFailed:
            return "Signature verification failed."
        }
    }
}

// MARK: - RSA Key Size

/// Supported RSA key sizes
public enum RSAKeySize: Int, Codable, CaseIterable {
    case bits2048 = 2048
    case bits3072 = 3072
    case bits4096 = 4096
    
    /// Key size in bits
    public var bitCount: Int {
        return rawValue
    }
    
    /// Key size in bytes
    public var byteCount: Int {
        return rawValue / 8
    }
    
    /// Maximum plaintext size for OAEP with SHA-256
    public var maxPlaintextSize: Int {
        // OAEP overhead: 2 * hash_length + 2 = 2 * 32 + 2 = 66 bytes for SHA-256
        return byteCount - 66
    }
    
    /// Human-readable description
    public var description: String {
        return "RSA-\(rawValue)"
    }
}

// MARK: - OAEP Hash Algorithm

/// Hash algorithms supported for OAEP
public enum OAEPHashAlgorithm: String, Codable, CaseIterable {
    case sha1 = "SHA-1"
    case sha256 = "SHA-256"
    case sha384 = "SHA-384"
    case sha512 = "SHA-512"
    
    /// The Security framework algorithm
    internal var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .sha1:
            return .rsaEncryptionOAEPSHA1
        case .sha256:
            return .rsaEncryptionOAEPSHA256
        case .sha384:
            return .rsaEncryptionOAEPSHA384
        case .sha512:
            return .rsaEncryptionOAEPSHA512
        }
    }
    
    /// Hash output size in bytes
    public var hashSize: Int {
        switch self {
        case .sha1: return 20
        case .sha256: return 32
        case .sha384: return 48
        case .sha512: return 64
        }
    }
    
    /// OAEP overhead for this hash
    public var oaepOverhead: Int {
        return 2 * hashSize + 2
    }
}

// MARK: - RSA Public Key

/// RSA public key for encryption
public final class RSAPublicKey {
    
    /// The underlying SecKey
    private let secKey: SecKey
    
    /// The key size
    public let keySize: RSAKeySize
    
    /// Initialize with a SecKey
    internal init(secKey: SecKey) throws {
        self.secKey = secKey
        
        // Determine key size
        guard let attributes = SecKeyCopyAttributes(secKey) as? [String: Any],
              let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int,
              let rsaKeySize = RSAKeySize(rawValue: keySize) else {
            throw RSAOAEPError.invalidPublicKey
        }
        self.keySize = rsaKeySize
    }
    
    /// Import from DER format
    /// - Parameter derData: The DER encoded public key
    /// - Returns: An RSAPublicKey
    public static func fromDER(_ derData: Data) throws -> RSAPublicKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ]
        
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(derData as CFData, attributes as CFDictionary, &error) else {
            throw RSAOAEPError.keyImportFailed
        }
        
        return try RSAPublicKey(secKey: secKey)
    }
    
    /// Import from PEM format
    /// - Parameter pemString: The PEM encoded public key
    /// - Returns: An RSAPublicKey
    public static func fromPEM(_ pemString: String) throws -> RSAPublicKey {
        let derData = try extractDERFromPEM(pemString, type: "PUBLIC KEY")
        return try fromDER(derData)
    }
    
    /// Export to DER format
    /// - Returns: The DER encoded public key
    public func toDER() throws -> Data {
        var error: Unmanaged<CFError>?
        guard let derData = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw RSAOAEPError.keyExportFailed
        }
        return derData
    }
    
    /// Export to PEM format
    /// - Returns: The PEM encoded public key
    public func toPEM() throws -> String {
        let derData = try toDER()
        return wrapInPEM(derData, type: "PUBLIC KEY")
    }
    
    /// Get the underlying SecKey
    internal var underlyingKey: SecKey {
        return secKey
    }
    
    /// Maximum plaintext size for given hash algorithm
    public func maxPlaintextSize(hashAlgorithm: OAEPHashAlgorithm) -> Int {
        return keySize.byteCount - hashAlgorithm.oaepOverhead
    }
    
    /// Get key modulus and exponent (for interoperability)
    public func getComponents() throws -> (modulus: Data, exponent: Data) {
        let derData = try toDER()
        return try parseRSAPublicKeyComponents(derData)
    }
}

// MARK: - RSA Private Key

/// RSA private key for decryption
public final class RSAPrivateKey {
    
    /// The underlying SecKey
    private let secKey: SecKey
    
    /// The key size
    public let keySize: RSAKeySize
    
    /// Initialize with a SecKey
    internal init(secKey: SecKey) throws {
        self.secKey = secKey
        
        // Determine key size
        guard let attributes = SecKeyCopyAttributes(secKey) as? [String: Any],
              let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int,
              let rsaKeySize = RSAKeySize(rawValue: keySize) else {
            throw RSAOAEPError.invalidPrivateKey
        }
        self.keySize = rsaKeySize
    }
    
    /// Import from DER format
    /// - Parameter derData: The DER encoded private key (PKCS#1 or PKCS#8)
    /// - Returns: An RSAPrivateKey
    public static func fromDER(_ derData: Data) throws -> RSAPrivateKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]
        
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(derData as CFData, attributes as CFDictionary, &error) else {
            throw RSAOAEPError.keyImportFailed
        }
        
        return try RSAPrivateKey(secKey: secKey)
    }
    
    /// Import from PEM format
    /// - Parameter pemString: The PEM encoded private key
    /// - Returns: An RSAPrivateKey
    public static func fromPEM(_ pemString: String) throws -> RSAPrivateKey {
        // Try RSA PRIVATE KEY first (PKCS#1)
        if pemString.contains("RSA PRIVATE KEY") {
            let derData = try extractDERFromPEM(pemString, type: "RSA PRIVATE KEY")
            return try fromDER(derData)
        }
        // Try PRIVATE KEY (PKCS#8)
        let derData = try extractDERFromPEM(pemString, type: "PRIVATE KEY")
        return try fromDER(derData)
    }
    
    /// Export to DER format
    /// - Returns: The DER encoded private key
    public func toDER() throws -> Data {
        var error: Unmanaged<CFError>?
        guard let derData = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw RSAOAEPError.keyExportFailed
        }
        return derData
    }
    
    /// Export to PEM format
    /// - Returns: The PEM encoded private key
    public func toPEM() throws -> String {
        let derData = try toDER()
        return wrapInPEM(derData, type: "RSA PRIVATE KEY")
    }
    
    /// Get the corresponding public key
    /// - Returns: The public key
    public func publicKey() throws -> RSAPublicKey {
        guard let publicSecKey = SecKeyCopyPublicKey(secKey) else {
            throw RSAOAEPError.invalidPrivateKey
        }
        return try RSAPublicKey(secKey: publicSecKey)
    }
    
    /// Get the underlying SecKey
    internal var underlyingKey: SecKey {
        return secKey
    }
}

// MARK: - RSA Key Pair

/// An RSA key pair containing public and private keys
public struct RSAKeyPair {
    
    /// The public key
    public let publicKey: RSAPublicKey
    
    /// The private key
    public let privateKey: RSAPrivateKey
    
    /// The key size
    public var keySize: RSAKeySize {
        return publicKey.keySize
    }
    
    /// Generate a new RSA key pair
    /// - Parameter keySize: The key size to generate
    /// - Returns: A new key pair
    public static func generate(keySize: RSAKeySize = .bits2048) throws -> RSAKeyPair {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize.bitCount,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateSecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw RSAOAEPError.keyGenerationFailed
        }
        
        guard let publicSecKey = SecKeyCopyPublicKey(privateSecKey) else {
            throw RSAOAEPError.keyGenerationFailed
        }
        
        let publicKey = try RSAPublicKey(secKey: publicSecKey)
        let privateKey = try RSAPrivateKey(secKey: privateSecKey)
        
        return RSAKeyPair(publicKey: publicKey, privateKey: privateKey)
    }
    
    /// Generate a key pair and store in keychain
    /// - Parameters:
    ///   - keySize: The key size to generate
    ///   - tag: The keychain tag for the key
    /// - Returns: A new key pair
    public static func generateAndStore(
        keySize: RSAKeySize = .bits2048,
        tag: String
    ) throws -> RSAKeyPair {
        guard let tagData = tag.data(using: .utf8) else {
            throw RSAOAEPError.keyGenerationFailed
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize.bitCount,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateSecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw RSAOAEPError.keyGenerationFailed
        }
        
        guard let publicSecKey = SecKeyCopyPublicKey(privateSecKey) else {
            throw RSAOAEPError.keyGenerationFailed
        }
        
        let publicKey = try RSAPublicKey(secKey: publicSecKey)
        let privateKey = try RSAPrivateKey(secKey: privateSecKey)
        
        return RSAKeyPair(publicKey: publicKey, privateKey: privateKey)
    }
    
    /// Load key pair from keychain
    /// - Parameter tag: The keychain tag
    /// - Returns: The key pair if found
    public static func loadFromKeychain(tag: String) throws -> RSAKeyPair {
        guard let tagData = tag.data(using: .utf8) else {
            throw RSAOAEPError.keyImportFailed
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess, let privateSecKey = item as! SecKey? else {
            throw RSAOAEPError.keychainError(status)
        }
        
        guard let publicSecKey = SecKeyCopyPublicKey(privateSecKey) else {
            throw RSAOAEPError.invalidPrivateKey
        }
        
        let publicKey = try RSAPublicKey(secKey: publicSecKey)
        let privateKey = try RSAPrivateKey(secKey: privateSecKey)
        
        return RSAKeyPair(publicKey: publicKey, privateKey: privateKey)
    }
    
    /// Delete key pair from keychain
    /// - Parameter tag: The keychain tag
    public static func deleteFromKeychain(tag: String) throws {
        guard let tagData = tag.data(using: .utf8) else {
            throw RSAOAEPError.keychainError(errSecParam)
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw RSAOAEPError.keychainError(status)
        }
    }
}

// MARK: - RSA-OAEP Cipher

/// Main RSA-OAEP encryption/decryption implementation
public final class RSAOAEPCipher {
    
    /// The hash algorithm to use for OAEP
    public let hashAlgorithm: OAEPHashAlgorithm
    
    /// Initialize with hash algorithm
    /// - Parameter hashAlgorithm: The hash algorithm for OAEP (default: SHA-256)
    public init(hashAlgorithm: OAEPHashAlgorithm = .sha256) {
        self.hashAlgorithm = hashAlgorithm
    }
    
    // MARK: - Encryption
    
    /// Encrypt data with a public key
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - publicKey: The public key to use
    /// - Returns: The encrypted ciphertext
    /// - Throws: RSAOAEPError if encryption fails
    public func encrypt(_ plaintext: Data, with publicKey: RSAPublicKey) throws -> Data {
        // Check plaintext size
        let maxSize = publicKey.maxPlaintextSize(hashAlgorithm: hashAlgorithm)
        guard plaintext.count <= maxSize else {
            throw RSAOAEPError.plaintextTooLong
        }
        
        var error: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            publicKey.underlyingKey,
            hashAlgorithm.secKeyAlgorithm,
            plaintext as CFData,
            &error
        ) as Data? else {
            throw RSAOAEPError.encryptionFailed
        }
        
        return ciphertext
    }
    
    /// Encrypt a string with a public key
    /// - Parameters:
    ///   - string: The string to encrypt
    ///   - publicKey: The public key to use
    /// - Returns: The encrypted ciphertext
    public func encryptString(_ string: String, with publicKey: RSAPublicKey) throws -> Data {
        guard let data = string.data(using: .utf8) else {
            throw RSAOAEPError.invalidPlaintext
        }
        return try encrypt(data, with: publicKey)
    }
    
    /// Encrypt and return base64 encoded ciphertext
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - publicKey: The public key to use
    /// - Returns: Base64 encoded ciphertext
    public func encryptToBase64(_ plaintext: Data, with publicKey: RSAPublicKey) throws -> String {
        let ciphertext = try encrypt(plaintext, with: publicKey)
        return ciphertext.base64EncodedString()
    }
    
    // MARK: - Decryption
    
    /// Decrypt ciphertext with a private key
    /// - Parameters:
    ///   - ciphertext: The data to decrypt
    ///   - privateKey: The private key to use
    /// - Returns: The decrypted plaintext
    /// - Throws: RSAOAEPError if decryption fails
    public func decrypt(_ ciphertext: Data, with privateKey: RSAPrivateKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            privateKey.underlyingKey,
            hashAlgorithm.secKeyAlgorithm,
            ciphertext as CFData,
            &error
        ) as Data? else {
            throw RSAOAEPError.decryptionFailed
        }
        
        return plaintext
    }
    
    /// Decrypt to string
    /// - Parameters:
    ///   - ciphertext: The data to decrypt
    ///   - privateKey: The private key to use
    /// - Returns: The decrypted string
    public func decryptToString(_ ciphertext: Data, with privateKey: RSAPrivateKey) throws -> String {
        let plaintext = try decrypt(ciphertext, with: privateKey)
        guard let string = String(data: plaintext, encoding: .utf8) else {
            throw RSAOAEPError.decryptionFailed
        }
        return string
    }
    
    /// Decrypt from base64
    /// - Parameters:
    ///   - base64String: The base64 encoded ciphertext
    ///   - privateKey: The private key to use
    /// - Returns: The decrypted plaintext
    public func decryptFromBase64(_ base64String: String, with privateKey: RSAPrivateKey) throws -> Data {
        guard let ciphertext = Data(base64Encoded: base64String) else {
            throw RSAOAEPError.invalidCiphertext
        }
        return try decrypt(ciphertext, with: privateKey)
    }
}

// MARK: - RSA Signing (PSS)

/// RSA-PSS signing and verification
public final class RSAPSSSigner {
    
    /// The hash algorithm to use
    public let hashAlgorithm: OAEPHashAlgorithm
    
    /// Initialize with hash algorithm
    /// - Parameter hashAlgorithm: The hash algorithm for PSS (default: SHA-256)
    public init(hashAlgorithm: OAEPHashAlgorithm = .sha256) {
        self.hashAlgorithm = hashAlgorithm
    }
    
    private var signatureAlgorithm: SecKeyAlgorithm {
        switch hashAlgorithm {
        case .sha1:
            return .rsaSignatureMessagePSSSHA1
        case .sha256:
            return .rsaSignatureMessagePSSSHA256
        case .sha384:
            return .rsaSignatureMessagePSSSHA384
        case .sha512:
            return .rsaSignatureMessagePSSSHA512
        }
    }
    
    /// Sign data with a private key
    /// - Parameters:
    ///   - data: The data to sign
    ///   - privateKey: The private key to use
    /// - Returns: The signature
    public func sign(_ data: Data, with privateKey: RSAPrivateKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey.underlyingKey,
            signatureAlgorithm,
            data as CFData,
            &error
        ) as Data? else {
            throw RSAOAEPError.signatureFailed
        }
        
        return signature
    }
    
    /// Verify a signature
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The original data
    ///   - publicKey: The public key to use
    /// - Returns: True if the signature is valid
    public func verify(_ signature: Data, for data: Data, with publicKey: RSAPublicKey) throws -> Bool {
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            publicKey.underlyingKey,
            signatureAlgorithm,
            data as CFData,
            signature as CFData,
            &error
        )
        
        return result
    }
    
    /// Sign and return base64 encoded signature
    public func signToBase64(_ data: Data, with privateKey: RSAPrivateKey) throws -> String {
        let signature = try sign(data, with: privateKey)
        return signature.base64EncodedString()
    }
    
    /// Verify base64 encoded signature
    public func verifyBase64(_ base64Signature: String, for data: Data, with publicKey: RSAPublicKey) throws -> Bool {
        guard let signature = Data(base64Encoded: base64Signature) else {
            throw RSAOAEPError.invalidCiphertext
        }
        return try verify(signature, for: data, with: publicKey)
    }
}

// MARK: - RSA PKCS#1 v1.5 Signing

/// RSA PKCS#1 v1.5 signing (for compatibility)
public final class RSAPKCS1Signer {
    
    public let hashAlgorithm: OAEPHashAlgorithm
    
    public init(hashAlgorithm: OAEPHashAlgorithm = .sha256) {
        self.hashAlgorithm = hashAlgorithm
    }
    
    private var signatureAlgorithm: SecKeyAlgorithm {
        switch hashAlgorithm {
        case .sha1:
            return .rsaSignatureMessagePKCS1v15SHA1
        case .sha256:
            return .rsaSignatureMessagePKCS1v15SHA256
        case .sha384:
            return .rsaSignatureMessagePKCS1v15SHA384
        case .sha512:
            return .rsaSignatureMessagePKCS1v15SHA512
        }
    }
    
    /// Sign data with a private key
    public func sign(_ data: Data, with privateKey: RSAPrivateKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey.underlyingKey,
            signatureAlgorithm,
            data as CFData,
            &error
        ) as Data? else {
            throw RSAOAEPError.signatureFailed
        }
        
        return signature
    }
    
    /// Verify a signature
    public func verify(_ signature: Data, for data: Data, with publicKey: RSAPublicKey) throws -> Bool {
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            publicKey.underlyingKey,
            signatureAlgorithm,
            data as CFData,
            signature as CFData,
            &error
        )
        
        return result
    }
}

// MARK: - Hybrid Encryption

/// Hybrid encryption combining RSA-OAEP with AES-GCM
public final class RSAHybridCipher {
    
    /// The RSA cipher for key encryption
    private let rsaCipher: RSAOAEPCipher
    
    /// Initialize with hash algorithm
    public init(hashAlgorithm: OAEPHashAlgorithm = .sha256) {
        self.rsaCipher = RSAOAEPCipher(hashAlgorithm: hashAlgorithm)
    }
    
    /// Encrypt large data using hybrid encryption
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - publicKey: The RSA public key
    /// - Returns: Combined encrypted key and encrypted data
    public func encrypt(_ plaintext: Data, with publicKey: RSAPublicKey) throws -> Data {
        // Generate random AES key
        let aesKey = SymmetricKey(size: .bits256)
        let aesKeyData = aesKey.withUnsafeBytes { Data($0) }
        
        // Encrypt AES key with RSA
        let encryptedKey = try rsaCipher.encrypt(aesKeyData, with: publicKey)
        
        // Encrypt data with AES-GCM
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(plaintext, using: aesKey, nonce: nonce)
        
        // Combine: key_length (2 bytes) + encrypted_key + nonce + ciphertext + tag
        var result = Data()
        var keyLength = UInt16(encryptedKey.count).bigEndian
        result.append(Data(bytes: &keyLength, count: 2))
        result.append(encryptedKey)
        result.append(contentsOf: nonce)
        result.append(sealedBox.ciphertext)
        result.append(sealedBox.tag)
        
        return result
    }
    
    /// Decrypt hybrid encrypted data
    /// - Parameters:
    ///   - ciphertext: The encrypted data
    ///   - privateKey: The RSA private key
    /// - Returns: The decrypted plaintext
    public func decrypt(_ ciphertext: Data, with privateKey: RSAPrivateKey) throws -> Data {
        guard ciphertext.count >= 2 else {
            throw RSAOAEPError.invalidCiphertext
        }
        
        var offset = 0
        
        // Read encrypted key length
        let keyLength = ciphertext[offset..<(offset + 2)].withUnsafeBytes {
            UInt16(bigEndian: $0.load(as: UInt16.self))
        }
        offset += 2
        
        // Read encrypted key
        guard offset + Int(keyLength) <= ciphertext.count else {
            throw RSAOAEPError.invalidCiphertext
        }
        let encryptedKey = ciphertext[offset..<(offset + Int(keyLength))]
        offset += Int(keyLength)
        
        // Decrypt AES key
        let aesKeyData = try rsaCipher.decrypt(Data(encryptedKey), with: privateKey)
        let aesKey = SymmetricKey(data: aesKeyData)
        
        // Read nonce (12 bytes)
        guard offset + 12 <= ciphertext.count else {
            throw RSAOAEPError.invalidCiphertext
        }
        let nonceData = ciphertext[offset..<(offset + 12)]
        let nonce = try AES.GCM.Nonce(data: Data(nonceData))
        offset += 12
        
        // Read ciphertext and tag
        guard offset + 16 <= ciphertext.count else {
            throw RSAOAEPError.invalidCiphertext
        }
        let encryptedData = ciphertext[offset..<(ciphertext.count - 16)]
        let tag = ciphertext.suffix(16)
        
        // Decrypt
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encryptedData, tag: tag)
        return try AES.GCM.open(sealedBox, using: aesKey)
    }
}

// MARK: - PEM Utilities

/// Extract DER data from PEM string
private func extractDERFromPEM(_ pem: String, type: String) throws -> Data {
    let beginMarker = "-----BEGIN \(type)-----"
    let endMarker = "-----END \(type)-----"
    
    guard let beginRange = pem.range(of: beginMarker),
          let endRange = pem.range(of: endMarker) else {
        throw RSAOAEPError.invalidPEM
    }
    
    let base64String = pem[beginRange.upperBound..<endRange.lowerBound]
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .replacingOccurrences(of: "\n", with: "")
        .replacingOccurrences(of: "\r", with: "")
    
    guard let data = Data(base64Encoded: base64String) else {
        throw RSAOAEPError.invalidPEM
    }
    
    return data
}

/// Wrap DER data in PEM format
private func wrapInPEM(_ derData: Data, type: String) -> String {
    let base64 = derData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    return "-----BEGIN \(type)-----\n\(base64)\n-----END \(type)-----"
}

/// Parse RSA public key components from DER
private func parseRSAPublicKeyComponents(_ derData: Data) throws -> (modulus: Data, exponent: Data) {
    // This is a simplified parser - in production use ASN.1 library
    // RSA public key in PKCS#1 format: SEQUENCE { INTEGER modulus, INTEGER exponent }
    
    guard derData.count > 10 else {
        throw RSAOAEPError.invalidDER
    }
    
    var index = 0
    
    // Skip SEQUENCE header
    if derData[index] == 0x30 {
        index += 1
        if derData[index] & 0x80 != 0 {
            let lengthBytes = Int(derData[index] & 0x7F)
            index += 1 + lengthBytes
        } else {
            index += 1
        }
    }
    
    // Read modulus INTEGER
    guard derData[index] == 0x02 else {
        throw RSAOAEPError.invalidDER
    }
    index += 1
    
    var modulusLength: Int
    if derData[index] & 0x80 != 0 {
        let lengthBytes = Int(derData[index] & 0x7F)
        index += 1
        modulusLength = 0
        for _ in 0..<lengthBytes {
            modulusLength = (modulusLength << 8) | Int(derData[index])
            index += 1
        }
    } else {
        modulusLength = Int(derData[index])
        index += 1
    }
    
    // Skip leading zero if present
    if derData[index] == 0x00 {
        index += 1
        modulusLength -= 1
    }
    
    let modulus = derData[index..<(index + modulusLength)]
    index += modulusLength
    
    // Read exponent INTEGER
    guard derData[index] == 0x02 else {
        throw RSAOAEPError.invalidDER
    }
    index += 1
    
    var exponentLength: Int
    if derData[index] & 0x80 != 0 {
        let lengthBytes = Int(derData[index] & 0x7F)
        index += 1
        exponentLength = 0
        for _ in 0..<lengthBytes {
            exponentLength = (exponentLength << 8) | Int(derData[index])
            index += 1
        }
    } else {
        exponentLength = Int(derData[index])
        index += 1
    }
    
    let exponent = derData[index..<(index + exponentLength)]
    
    return (Data(modulus), Data(exponent))
}

// MARK: - Convenience Extensions

extension Data {
    
    /// Encrypt data using RSA-OAEP
    public func rsaOAEPEncrypt(with publicKey: RSAPublicKey, hashAlgorithm: OAEPHashAlgorithm = .sha256) throws -> Data {
        let cipher = RSAOAEPCipher(hashAlgorithm: hashAlgorithm)
        return try cipher.encrypt(self, with: publicKey)
    }
    
    /// Decrypt data using RSA-OAEP
    public func rsaOAEPDecrypt(with privateKey: RSAPrivateKey, hashAlgorithm: OAEPHashAlgorithm = .sha256) throws -> Data {
        let cipher = RSAOAEPCipher(hashAlgorithm: hashAlgorithm)
        return try cipher.decrypt(self, with: privateKey)
    }
    
    /// Encrypt with hybrid RSA+AES
    public func rsaHybridEncrypt(with publicKey: RSAPublicKey) throws -> Data {
        let cipher = RSAHybridCipher()
        return try cipher.encrypt(self, with: publicKey)
    }
    
    /// Decrypt with hybrid RSA+AES
    public func rsaHybridDecrypt(with privateKey: RSAPrivateKey) throws -> Data {
        let cipher = RSAHybridCipher()
        return try cipher.decrypt(self, with: privateKey)
    }
}

extension String {
    
    /// Encrypt string using RSA-OAEP
    public func rsaOAEPEncrypt(with publicKey: RSAPublicKey) throws -> Data {
        let cipher = RSAOAEPCipher()
        return try cipher.encryptString(self, with: publicKey)
    }
}

// MARK: - Key Wrap

/// RSA-OAEP key wrapping
public final class RSAKeyWrapper {
    
    private let cipher: RSAOAEPCipher
    
    public init(hashAlgorithm: OAEPHashAlgorithm = .sha256) {
        self.cipher = RSAOAEPCipher(hashAlgorithm: hashAlgorithm)
    }
    
    /// Wrap a symmetric key
    /// - Parameters:
    ///   - symmetricKey: The key to wrap
    ///   - publicKey: The wrapping key
    /// - Returns: The wrapped key
    public func wrap(_ symmetricKey: SymmetricKey, with publicKey: RSAPublicKey) throws -> Data {
        let keyData = symmetricKey.withUnsafeBytes { Data($0) }
        return try cipher.encrypt(keyData, with: publicKey)
    }
    
    /// Unwrap a symmetric key
    /// - Parameters:
    ///   - wrappedKey: The wrapped key
    ///   - privateKey: The unwrapping key
    ///   - keySize: The size of the unwrapped key
    /// - Returns: The unwrapped symmetric key
    public func unwrap(_ wrappedKey: Data, with privateKey: RSAPrivateKey) throws -> SymmetricKey {
        let keyData = try cipher.decrypt(wrappedKey, with: privateKey)
        return SymmetricKey(data: keyData)
    }
}
