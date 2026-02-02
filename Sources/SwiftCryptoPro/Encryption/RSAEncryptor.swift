import Foundation
import Security

/// RSA asymmetric encryption using the Security framework.
///
/// Supports key pair generation, encryption with OAEP padding, and decryption.
public struct RSAEncryptor {

    // MARK: - Types

    /// An RSA key pair containing both public and private keys.
    public struct KeyPair {
        /// The public key used for encryption
        public let publicKey: SecKey
        /// The private key used for decryption
        public let privateKey: SecKey
    }

    /// Errors that can occur during RSA operations.
    public enum RSAError: LocalizedError {
        case keyGenerationFailed(String)
        case encryptionFailed(String)
        case decryptionFailed(String)
        case invalidKey
        case dataConversionFailed
        case messageTooLong

        public var errorDescription: String? {
            switch self {
            case .keyGenerationFailed(let reason):
                return "RSA key generation failed: \(reason)"
            case .encryptionFailed(let reason):
                return "RSA encryption failed: \(reason)"
            case .decryptionFailed(let reason):
                return "RSA decryption failed: \(reason)"
            case .invalidKey:
                return "Invalid RSA key provided."
            case .dataConversionFailed:
                return "Failed to convert data."
            case .messageTooLong:
                return "Message exceeds maximum RSA block size."
            }
        }
    }

    // MARK: - Initialization

    public init() {}

    // MARK: - Key Generation

    /// Generates an RSA key pair with the specified bit size.
    /// - Parameter bits: Key size in bits (2048, 3072, or 4096 recommended).
    /// - Returns: A `KeyPair` containing public and private keys.
    public func generateKeyPair(bits: Int = 2048) throws -> KeyPair {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: bits,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let message = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw RSAError.keyGenerationFailed(message)
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw RSAError.keyGenerationFailed("Could not extract public key.")
        }

        return KeyPair(publicKey: publicKey, privateKey: privateKey)
    }

    // MARK: - Encryption

    /// Encrypts a string using RSA-OAEP with SHA-256.
    /// - Parameters:
    ///   - plaintext: The string to encrypt.
    ///   - publicKey: The RSA public key.
    /// - Returns: The encrypted data.
    public func encrypt(_ plaintext: String, publicKey: SecKey) throws -> Data {
        guard let data = plaintext.data(using: .utf8) else {
            throw RSAError.dataConversionFailed
        }
        return try encrypt(data, publicKey: publicKey)
    }

    /// Encrypts raw data using RSA-OAEP with SHA-256.
    /// - Parameters:
    ///   - data: The data to encrypt.
    ///   - publicKey: The RSA public key.
    /// - Returns: The encrypted data.
    public func encrypt(_ data: Data, publicKey: SecKey) throws -> Data {
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256

        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw RSAError.invalidKey
        }

        var error: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) else {
            let message = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw RSAError.encryptionFailed(message)
        }

        return ciphertext as Data
    }

    // MARK: - Decryption

    /// Decrypts RSA-encrypted data back to a string.
    /// - Parameters:
    ///   - data: The encrypted data.
    ///   - privateKey: The RSA private key.
    /// - Returns: The decrypted string.
    public func decrypt(_ data: Data, privateKey: SecKey) throws -> String {
        let decryptedData = try decryptToData(data, privateKey: privateKey)
        guard let string = String(data: decryptedData, encoding: .utf8) else {
            throw RSAError.dataConversionFailed
        }
        return string
    }

    /// Decrypts RSA-encrypted data back to raw data.
    /// - Parameters:
    ///   - data: The encrypted data.
    ///   - privateKey: The RSA private key.
    /// - Returns: The decrypted data.
    public func decryptToData(_ data: Data, privateKey: SecKey) throws -> Data {
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256

        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw RSAError.invalidKey
        }

        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(privateKey, algorithm, data as CFData, &error) else {
            let message = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw RSAError.decryptionFailed(message)
        }

        return plaintext as Data
    }
}
