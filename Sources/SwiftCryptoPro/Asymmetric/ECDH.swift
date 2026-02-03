//
//  ECDH.swift
//  SwiftCryptoPro
//
//  Created by Muhittin Camdali on 2025.
//  Copyright © 2025 Muhittin Camdali. All rights reserved.
//

import Foundation
import CryptoKit
import Security

// MARK: - ECDH Error Types

/// Errors that can occur during ECDH operations
public enum ECDHError: Error, LocalizedError, Equatable {
    case keyGenerationFailed
    case invalidPublicKey
    case invalidPrivateKey
    case keyDerivationFailed
    case invalidCurve
    case invalidKeyData
    case keyExportFailed
    case keyImportFailed
    case invalidPEM
    case invalidDER
    case encryptionFailed
    case decryptionFailed
    case authenticationFailed
    case keychainError(OSStatus)
    case unsupportedCurve
    case serializationFailed
    case deserializationFailed
    
    public var errorDescription: String? {
        switch self {
        case .keyGenerationFailed:
            return "Failed to generate ECDH key pair."
        case .invalidPublicKey:
            return "Invalid ECDH public key."
        case .invalidPrivateKey:
            return "Invalid ECDH private key."
        case .keyDerivationFailed:
            return "Key derivation failed."
        case .invalidCurve:
            return "Invalid elliptic curve."
        case .invalidKeyData:
            return "Invalid key data format."
        case .keyExportFailed:
            return "Failed to export key."
        case .keyImportFailed:
            return "Failed to import key."
        case .invalidPEM:
            return "Invalid PEM format."
        case .invalidDER:
            return "Invalid DER format."
        case .encryptionFailed:
            return "ECIES encryption failed."
        case .decryptionFailed:
            return "ECIES decryption failed."
        case .authenticationFailed:
            return "Authentication failed."
        case .keychainError(let status):
            return "Keychain error: \(status)"
        case .unsupportedCurve:
            return "Unsupported elliptic curve."
        case .serializationFailed:
            return "Failed to serialize data."
        case .deserializationFailed:
            return "Failed to deserialize data."
        }
    }
}

// MARK: - Elliptic Curve Type

/// Supported elliptic curves for ECDH
public enum ECDHCurve: String, Codable, CaseIterable {
    case p256 = "P-256"
    case p384 = "P-384"
    case p521 = "P-521"
    case x25519 = "X25519"
    
    /// Key size in bits
    public var keyBits: Int {
        switch self {
        case .p256: return 256
        case .p384: return 384
        case .p521: return 521
        case .x25519: return 255
        }
    }
    
    /// Shared secret size in bytes
    public var sharedSecretSize: Int {
        switch self {
        case .p256: return 32
        case .p384: return 48
        case .p521: return 66
        case .x25519: return 32
        }
    }
    
    /// Description
    public var description: String {
        return rawValue
    }
}

// MARK: - P256 ECDH

/// P-256 ECDH key pair wrapper
public struct P256ECDHKeyPair {
    
    /// The private key
    public let privateKey: P256.KeyAgreement.PrivateKey
    
    /// The public key
    public var publicKey: P256.KeyAgreement.PublicKey {
        return privateKey.publicKey
    }
    
    /// Generate a new key pair
    public init() {
        self.privateKey = P256.KeyAgreement.PrivateKey()
    }
    
    /// Initialize with existing private key
    public init(privateKey: P256.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
    }
    
    /// Import private key from raw data
    /// - Parameter rawRepresentation: The raw private key bytes
    public static func fromRaw(_ rawRepresentation: Data) throws -> P256ECDHKeyPair {
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
        return P256ECDHKeyPair(privateKey: privateKey)
    }
    
    /// Import from X9.63 representation
    /// - Parameter x963Representation: The X9.63 encoded private key
    public static func fromX963(_ x963Representation: Data) throws -> P256ECDHKeyPair {
        let privateKey = try P256.KeyAgreement.PrivateKey(x963Representation: x963Representation)
        return P256ECDHKeyPair(privateKey: privateKey)
    }
    
    /// Import from PEM format
    /// - Parameter pemRepresentation: The PEM encoded private key
    public static func fromPEM(_ pemRepresentation: String) throws -> P256ECDHKeyPair {
        let privateKey = try P256.KeyAgreement.PrivateKey(pemRepresentation: pemRepresentation)
        return P256ECDHKeyPair(privateKey: privateKey)
    }
    
    /// Export private key to raw bytes
    public var rawRepresentation: Data {
        return privateKey.rawRepresentation
    }
    
    /// Export to X9.63 format
    public var x963Representation: Data {
        return privateKey.x963Representation
    }
    
    /// Export to PEM format
    public var pemRepresentation: String {
        return privateKey.pemRepresentation
    }
    
    /// Perform key agreement
    /// - Parameter peerPublicKey: The peer's public key
    /// - Returns: The shared secret
    public func sharedSecret(with peerPublicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        return try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
    }
    
    /// Derive a symmetric key using HKDF
    /// - Parameters:
    ///   - peerPublicKey: The peer's public key
    ///   - salt: The salt for HKDF
    ///   - info: The info for HKDF
    ///   - outputByteCount: The number of bytes to derive
    /// - Returns: A symmetric key
    public func deriveKey(
        with peerPublicKey: P256.KeyAgreement.PublicKey,
        salt: Data = Data(),
        info: Data = Data(),
        outputByteCount: Int = 32
    ) throws -> SymmetricKey {
        let sharedSecret = try self.sharedSecret(with: peerPublicKey)
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: outputByteCount
        )
    }
}

/// P-256 public key wrapper
public struct P256ECDHPublicKey {
    
    /// The underlying public key
    public let publicKey: P256.KeyAgreement.PublicKey
    
    /// Initialize with CryptoKit public key
    public init(publicKey: P256.KeyAgreement.PublicKey) {
        self.publicKey = publicKey
    }
    
    /// Import from raw data (compressed or uncompressed)
    public static func fromRaw(_ rawRepresentation: Data) throws -> P256ECDHPublicKey {
        let publicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: rawRepresentation)
        return P256ECDHPublicKey(publicKey: publicKey)
    }
    
    /// Import from X9.63 representation
    public static func fromX963(_ x963Representation: Data) throws -> P256ECDHPublicKey {
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: x963Representation)
        return P256ECDHPublicKey(publicKey: publicKey)
    }
    
    /// Import from compact representation
    public static func fromCompact(_ compactRepresentation: Data) throws -> P256ECDHPublicKey {
        let publicKey = try P256.KeyAgreement.PublicKey(compactRepresentation: compactRepresentation)
        return P256ECDHPublicKey(publicKey: publicKey)
    }
    
    /// Import from PEM format
    public static func fromPEM(_ pemRepresentation: String) throws -> P256ECDHPublicKey {
        let publicKey = try P256.KeyAgreement.PublicKey(pemRepresentation: pemRepresentation)
        return P256ECDHPublicKey(publicKey: publicKey)
    }
    
    /// Export to raw representation
    public var rawRepresentation: Data {
        return publicKey.rawRepresentation
    }
    
    /// Export to X9.63 representation
    public var x963Representation: Data {
        return publicKey.x963Representation
    }
    
    /// Export to compact representation
    public var compactRepresentation: Data? {
        return publicKey.compactRepresentation
    }
    
    /// Export to PEM format
    public var pemRepresentation: String {
        return publicKey.pemRepresentation
    }
}

// MARK: - P384 ECDH

/// P-384 ECDH key pair wrapper
public struct P384ECDHKeyPair {
    
    public let privateKey: P384.KeyAgreement.PrivateKey
    
    public var publicKey: P384.KeyAgreement.PublicKey {
        return privateKey.publicKey
    }
    
    public init() {
        self.privateKey = P384.KeyAgreement.PrivateKey()
    }
    
    public init(privateKey: P384.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
    }
    
    public static func fromRaw(_ rawRepresentation: Data) throws -> P384ECDHKeyPair {
        let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
        return P384ECDHKeyPair(privateKey: privateKey)
    }
    
    public static func fromX963(_ x963Representation: Data) throws -> P384ECDHKeyPair {
        let privateKey = try P384.KeyAgreement.PrivateKey(x963Representation: x963Representation)
        return P384ECDHKeyPair(privateKey: privateKey)
    }
    
    public static func fromPEM(_ pemRepresentation: String) throws -> P384ECDHKeyPair {
        let privateKey = try P384.KeyAgreement.PrivateKey(pemRepresentation: pemRepresentation)
        return P384ECDHKeyPair(privateKey: privateKey)
    }
    
    public var rawRepresentation: Data {
        return privateKey.rawRepresentation
    }
    
    public var x963Representation: Data {
        return privateKey.x963Representation
    }
    
    public var pemRepresentation: String {
        return privateKey.pemRepresentation
    }
    
    public func sharedSecret(with peerPublicKey: P384.KeyAgreement.PublicKey) throws -> SharedSecret {
        return try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
    }
    
    public func deriveKey(
        with peerPublicKey: P384.KeyAgreement.PublicKey,
        salt: Data = Data(),
        info: Data = Data(),
        outputByteCount: Int = 32
    ) throws -> SymmetricKey {
        let sharedSecret = try self.sharedSecret(with: peerPublicKey)
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA384.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: outputByteCount
        )
    }
}

/// P-384 public key wrapper
public struct P384ECDHPublicKey {
    
    public let publicKey: P384.KeyAgreement.PublicKey
    
    public init(publicKey: P384.KeyAgreement.PublicKey) {
        self.publicKey = publicKey
    }
    
    public static func fromRaw(_ rawRepresentation: Data) throws -> P384ECDHPublicKey {
        let publicKey = try P384.KeyAgreement.PublicKey(rawRepresentation: rawRepresentation)
        return P384ECDHPublicKey(publicKey: publicKey)
    }
    
    public static func fromX963(_ x963Representation: Data) throws -> P384ECDHPublicKey {
        let publicKey = try P384.KeyAgreement.PublicKey(x963Representation: x963Representation)
        return P384ECDHPublicKey(publicKey: publicKey)
    }
    
    public static func fromPEM(_ pemRepresentation: String) throws -> P384ECDHPublicKey {
        let publicKey = try P384.KeyAgreement.PublicKey(pemRepresentation: pemRepresentation)
        return P384ECDHPublicKey(publicKey: publicKey)
    }
    
    public var rawRepresentation: Data {
        return publicKey.rawRepresentation
    }
    
    public var x963Representation: Data {
        return publicKey.x963Representation
    }
    
    public var pemRepresentation: String {
        return publicKey.pemRepresentation
    }
}

// MARK: - P521 ECDH

/// P-521 ECDH key pair wrapper
public struct P521ECDHKeyPair {
    
    public let privateKey: P521.KeyAgreement.PrivateKey
    
    public var publicKey: P521.KeyAgreement.PublicKey {
        return privateKey.publicKey
    }
    
    public init() {
        self.privateKey = P521.KeyAgreement.PrivateKey()
    }
    
    public init(privateKey: P521.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
    }
    
    public static func fromRaw(_ rawRepresentation: Data) throws -> P521ECDHKeyPair {
        let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
        return P521ECDHKeyPair(privateKey: privateKey)
    }
    
    public static func fromX963(_ x963Representation: Data) throws -> P521ECDHKeyPair {
        let privateKey = try P521.KeyAgreement.PrivateKey(x963Representation: x963Representation)
        return P521ECDHKeyPair(privateKey: privateKey)
    }
    
    public static func fromPEM(_ pemRepresentation: String) throws -> P521ECDHKeyPair {
        let privateKey = try P521.KeyAgreement.PrivateKey(pemRepresentation: pemRepresentation)
        return P521ECDHKeyPair(privateKey: privateKey)
    }
    
    public var rawRepresentation: Data {
        return privateKey.rawRepresentation
    }
    
    public var x963Representation: Data {
        return privateKey.x963Representation
    }
    
    public var pemRepresentation: String {
        return privateKey.pemRepresentation
    }
    
    public func sharedSecret(with peerPublicKey: P521.KeyAgreement.PublicKey) throws -> SharedSecret {
        return try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
    }
    
    public func deriveKey(
        with peerPublicKey: P521.KeyAgreement.PublicKey,
        salt: Data = Data(),
        info: Data = Data(),
        outputByteCount: Int = 32
    ) throws -> SymmetricKey {
        let sharedSecret = try self.sharedSecret(with: peerPublicKey)
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA512.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: outputByteCount
        )
    }
}

/// P-521 public key wrapper
public struct P521ECDHPublicKey {
    
    public let publicKey: P521.KeyAgreement.PublicKey
    
    public init(publicKey: P521.KeyAgreement.PublicKey) {
        self.publicKey = publicKey
    }
    
    public static func fromRaw(_ rawRepresentation: Data) throws -> P521ECDHPublicKey {
        let publicKey = try P521.KeyAgreement.PublicKey(rawRepresentation: rawRepresentation)
        return P521ECDHPublicKey(publicKey: publicKey)
    }
    
    public static func fromX963(_ x963Representation: Data) throws -> P521ECDHPublicKey {
        let publicKey = try P521.KeyAgreement.PublicKey(x963Representation: x963Representation)
        return P521ECDHPublicKey(publicKey: publicKey)
    }
    
    public static func fromPEM(_ pemRepresentation: String) throws -> P521ECDHPublicKey {
        let publicKey = try P521.KeyAgreement.PublicKey(pemRepresentation: pemRepresentation)
        return P521ECDHPublicKey(publicKey: publicKey)
    }
    
    public var rawRepresentation: Data {
        return publicKey.rawRepresentation
    }
    
    public var x963Representation: Data {
        return publicKey.x963Representation
    }
    
    public var pemRepresentation: String {
        return publicKey.pemRepresentation
    }
}

// MARK: - Curve25519 ECDH

/// Curve25519 ECDH key pair wrapper
public struct X25519KeyPair {
    
    public let privateKey: Curve25519.KeyAgreement.PrivateKey
    
    public var publicKey: Curve25519.KeyAgreement.PublicKey {
        return privateKey.publicKey
    }
    
    public init() {
        self.privateKey = Curve25519.KeyAgreement.PrivateKey()
    }
    
    public init(privateKey: Curve25519.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
    }
    
    public static func fromRaw(_ rawRepresentation: Data) throws -> X25519KeyPair {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
        return X25519KeyPair(privateKey: privateKey)
    }
    
    public var rawRepresentation: Data {
        return privateKey.rawRepresentation
    }
    
    public func sharedSecret(with peerPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> SharedSecret {
        return try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
    }
    
    public func deriveKey(
        with peerPublicKey: Curve25519.KeyAgreement.PublicKey,
        salt: Data = Data(),
        info: Data = Data(),
        outputByteCount: Int = 32
    ) throws -> SymmetricKey {
        let sharedSecret = try self.sharedSecret(with: peerPublicKey)
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: outputByteCount
        )
    }
}

/// Curve25519 public key wrapper
public struct X25519PublicKey {
    
    public let publicKey: Curve25519.KeyAgreement.PublicKey
    
    public init(publicKey: Curve25519.KeyAgreement.PublicKey) {
        self.publicKey = publicKey
    }
    
    public static func fromRaw(_ rawRepresentation: Data) throws -> X25519PublicKey {
        let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rawRepresentation)
        return X25519PublicKey(publicKey: publicKey)
    }
    
    public var rawRepresentation: Data {
        return publicKey.rawRepresentation
    }
}

// MARK: - ECIES (Elliptic Curve Integrated Encryption Scheme)

/// ECIES encryption using P-256 ECDH + AES-GCM
public final class ECIES_P256 {
    
    /// The receiver's public key
    private let recipientPublicKey: P256.KeyAgreement.PublicKey
    
    /// Initialize with recipient's public key
    public init(recipientPublicKey: P256.KeyAgreement.PublicKey) {
        self.recipientPublicKey = recipientPublicKey
    }
    
    /// Initialize with wrapped public key
    public init(recipientPublicKey: P256ECDHPublicKey) {
        self.recipientPublicKey = recipientPublicKey.publicKey
    }
    
    /// Encrypt data
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - additionalData: Optional additional authenticated data
    /// - Returns: The encrypted message (ephemeral public key + ciphertext + tag)
    public func encrypt(_ plaintext: Data, additionalData: Data = Data()) throws -> Data {
        // Generate ephemeral key pair
        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey
        
        // Derive shared secret
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
        
        // Derive symmetric key using HKDF
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: ephemeralPublicKey.x963Representation,
            outputByteCount: 32
        )
        
        // Encrypt with AES-GCM
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: additionalData)
        
        // Combine: ephemeral public key (65 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
        var result = Data()
        result.append(ephemeralPublicKey.x963Representation) // 65 bytes for uncompressed P-256
        result.append(contentsOf: nonce)
        result.append(sealedBox.ciphertext)
        result.append(sealedBox.tag)
        
        return result
    }
    
    /// Decrypt data
    /// - Parameters:
    ///   - ciphertext: The encrypted message
    ///   - privateKey: The recipient's private key
    ///   - additionalData: Optional additional authenticated data
    /// - Returns: The decrypted plaintext
    public static func decrypt(
        _ ciphertext: Data,
        with privateKey: P256.KeyAgreement.PrivateKey,
        additionalData: Data = Data()
    ) throws -> Data {
        // Parse components
        guard ciphertext.count >= 65 + 12 + 16 else { // ephemeral key + nonce + tag
            throw ECDHError.decryptionFailed
        }
        
        let ephemeralPublicKeyData = ciphertext.prefix(65)
        let nonceData = ciphertext[65..<77]
        let encryptedData = ciphertext[77..<(ciphertext.count - 16)]
        let tag = ciphertext.suffix(16)
        
        // Import ephemeral public key
        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKeyData)
        
        // Derive shared secret
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        
        // Derive symmetric key
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: ephemeralPublicKeyData,
            outputByteCount: 32
        )
        
        // Decrypt
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encryptedData, tag: tag)
        
        return try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: additionalData)
    }
    
    /// Decrypt with key pair wrapper
    public static func decrypt(
        _ ciphertext: Data,
        with keyPair: P256ECDHKeyPair,
        additionalData: Data = Data()
    ) throws -> Data {
        return try decrypt(ciphertext, with: keyPair.privateKey, additionalData: additionalData)
    }
}

// MARK: - ECIES with X25519

/// ECIES encryption using X25519 + ChaCha20-Poly1305
public final class ECIES_X25519 {
    
    private let recipientPublicKey: Curve25519.KeyAgreement.PublicKey
    
    public init(recipientPublicKey: Curve25519.KeyAgreement.PublicKey) {
        self.recipientPublicKey = recipientPublicKey
    }
    
    public init(recipientPublicKey: X25519PublicKey) {
        self.recipientPublicKey = recipientPublicKey.publicKey
    }
    
    /// Encrypt data
    public func encrypt(_ plaintext: Data, additionalData: Data = Data()) throws -> Data {
        // Generate ephemeral key pair
        let ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey
        
        // Derive shared secret
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
        
        // Derive symmetric key
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: ephemeralPublicKey.rawRepresentation,
            outputByteCount: 32
        )
        
        // Encrypt with ChaCha20-Poly1305
        let nonce = ChaChaPoly.Nonce()
        let sealedBox = try ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: additionalData)
        
        // Combine: ephemeral public key (32 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
        var result = Data()
        result.append(ephemeralPublicKey.rawRepresentation)
        result.append(contentsOf: nonce)
        result.append(sealedBox.ciphertext)
        result.append(sealedBox.tag)
        
        return result
    }
    
    /// Decrypt data
    public static func decrypt(
        _ ciphertext: Data,
        with privateKey: Curve25519.KeyAgreement.PrivateKey,
        additionalData: Data = Data()
    ) throws -> Data {
        guard ciphertext.count >= 32 + 12 + 16 else {
            throw ECDHError.decryptionFailed
        }
        
        let ephemeralPublicKeyData = ciphertext.prefix(32)
        let nonceData = ciphertext[32..<44]
        let encryptedData = ciphertext[44..<(ciphertext.count - 16)]
        let tag = ciphertext.suffix(16)
        
        let ephemeralPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicKeyData)
        
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: ephemeralPublicKeyData,
            outputByteCount: 32
        )
        
        let nonce = try ChaChaPoly.Nonce(data: nonceData)
        let sealedBox = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: encryptedData, tag: tag)
        
        return try ChaChaPoly.open(sealedBox, using: symmetricKey, authenticating: additionalData)
    }
    
    public static func decrypt(
        _ ciphertext: Data,
        with keyPair: X25519KeyPair,
        additionalData: Data = Data()
    ) throws -> Data {
        return try decrypt(ciphertext, with: keyPair.privateKey, additionalData: additionalData)
    }
}

// MARK: - Key Exchange Protocol

/// A complete key exchange protocol session
public final class ECDHKeyExchange {
    
    /// The curve to use
    public let curve: ECDHCurve
    
    /// The local key pair (type-erased)
    private let localPrivateKeyData: Data
    private let localPublicKeyData: Data
    
    /// Initialize with curve
    public init(curve: ECDHCurve = .p256) throws {
        self.curve = curve
        
        switch curve {
        case .p256:
            let keyPair = P256ECDHKeyPair()
            self.localPrivateKeyData = keyPair.rawRepresentation
            self.localPublicKeyData = keyPair.publicKey.x963Representation
        case .p384:
            let keyPair = P384ECDHKeyPair()
            self.localPrivateKeyData = keyPair.rawRepresentation
            self.localPublicKeyData = keyPair.publicKey.x963Representation
        case .p521:
            let keyPair = P521ECDHKeyPair()
            self.localPrivateKeyData = keyPair.rawRepresentation
            self.localPublicKeyData = keyPair.publicKey.x963Representation
        case .x25519:
            let keyPair = X25519KeyPair()
            self.localPrivateKeyData = keyPair.rawRepresentation
            self.localPublicKeyData = keyPair.publicKey.rawRepresentation
        }
    }
    
    /// Get the local public key to send to peer
    public var publicKeyForExchange: Data {
        return localPublicKeyData
    }
    
    /// Derive shared key from peer's public key
    /// - Parameters:
    ///   - peerPublicKeyData: The peer's public key
    ///   - salt: Optional salt for HKDF
    ///   - info: Optional info for HKDF
    ///   - outputByteCount: The number of bytes to derive
    /// - Returns: A symmetric key
    public func deriveKey(
        from peerPublicKeyData: Data,
        salt: Data = Data(),
        info: Data = Data(),
        outputByteCount: Int = 32
    ) throws -> SymmetricKey {
        switch curve {
        case .p256:
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: localPrivateKeyData)
            let peerPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: peerPublicKeyData)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
            return sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: salt,
                sharedInfo: info,
                outputByteCount: outputByteCount
            )
        case .p384:
            let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: localPrivateKeyData)
            let peerPublicKey = try P384.KeyAgreement.PublicKey(x963Representation: peerPublicKeyData)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
            return sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA384.self,
                salt: salt,
                sharedInfo: info,
                outputByteCount: outputByteCount
            )
        case .p521:
            let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: localPrivateKeyData)
            let peerPublicKey = try P521.KeyAgreement.PublicKey(x963Representation: peerPublicKeyData)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
            return sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA512.self,
                salt: salt,
                sharedInfo: info,
                outputByteCount: outputByteCount
            )
        case .x25519:
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localPrivateKeyData)
            let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKeyData)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
            return sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: salt,
                sharedInfo: info,
                outputByteCount: outputByteCount
            )
        }
    }
}

// MARK: - Ephemeral Key Exchange

/// Ephemeral-ephemeral key exchange for perfect forward secrecy
public struct EphemeralKeyExchange {
    
    /// The curve used
    public let curve: ECDHCurve
    
    /// The ephemeral public key to send
    public let ephemeralPublicKey: Data
    
    /// The derived shared secret
    public let sharedSecret: Data
    
    /// Perform ephemeral key exchange
    /// - Parameters:
    ///   - peerPublicKey: The peer's ephemeral public key
    ///   - curve: The curve to use
    /// - Returns: An exchange result
    public static func perform(
        with peerPublicKey: Data,
        curve: ECDHCurve = .x25519
    ) throws -> EphemeralKeyExchange {
        switch curve {
        case .x25519:
            let localKeyPair = X25519KeyPair()
            let peerKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            let sharedSecret = try localKeyPair.privateKey.sharedSecretFromKeyAgreement(with: peerKey)
            
            return EphemeralKeyExchange(
                curve: curve,
                ephemeralPublicKey: localKeyPair.publicKey.rawRepresentation,
                sharedSecret: sharedSecret.withUnsafeBytes { Data($0) }
            )
        case .p256:
            let localKeyPair = P256ECDHKeyPair()
            let peerKey = try P256.KeyAgreement.PublicKey(x963Representation: peerPublicKey)
            let sharedSecret = try localKeyPair.privateKey.sharedSecretFromKeyAgreement(with: peerKey)
            
            return EphemeralKeyExchange(
                curve: curve,
                ephemeralPublicKey: localKeyPair.publicKey.x963Representation,
                sharedSecret: sharedSecret.withUnsafeBytes { Data($0) }
            )
        case .p384:
            let localKeyPair = P384ECDHKeyPair()
            let peerKey = try P384.KeyAgreement.PublicKey(x963Representation: peerPublicKey)
            let sharedSecret = try localKeyPair.privateKey.sharedSecretFromKeyAgreement(with: peerKey)
            
            return EphemeralKeyExchange(
                curve: curve,
                ephemeralPublicKey: localKeyPair.publicKey.x963Representation,
                sharedSecret: sharedSecret.withUnsafeBytes { Data($0) }
            )
        case .p521:
            let localKeyPair = P521ECDHKeyPair()
            let peerKey = try P521.KeyAgreement.PublicKey(x963Representation: peerPublicKey)
            let sharedSecret = try localKeyPair.privateKey.sharedSecretFromKeyAgreement(with: peerKey)
            
            return EphemeralKeyExchange(
                curve: curve,
                ephemeralPublicKey: localKeyPair.publicKey.x963Representation,
                sharedSecret: sharedSecret.withUnsafeBytes { Data($0) }
            )
        }
    }
    
    /// Derive a symmetric key from the shared secret
    public func deriveSymmetricKey(
        salt: Data = Data(),
        info: Data = Data(),
        outputByteCount: Int = 32
    ) -> SymmetricKey {
        let inputKey = SymmetricKey(data: sharedSecret)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            info: info,
            outputByteCount: outputByteCount
        )
    }
}

// MARK: - Convenience Extensions

extension Data {
    
    /// Encrypt using ECIES with P-256
    public func eciesEncrypt(with publicKey: P256.KeyAgreement.PublicKey) throws -> Data {
        let ecies = ECIES_P256(recipientPublicKey: publicKey)
        return try ecies.encrypt(self)
    }
    
    /// Decrypt using ECIES with P-256
    public func eciesDecrypt(with privateKey: P256.KeyAgreement.PrivateKey) throws -> Data {
        return try ECIES_P256.decrypt(self, with: privateKey)
    }
    
    /// Encrypt using ECIES with X25519
    public func eciesX25519Encrypt(with publicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let ecies = ECIES_X25519(recipientPublicKey: publicKey)
        return try ecies.encrypt(self)
    }
    
    /// Decrypt using ECIES with X25519
    public func eciesX25519Decrypt(with privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        return try ECIES_X25519.decrypt(self, with: privateKey)
    }
}
