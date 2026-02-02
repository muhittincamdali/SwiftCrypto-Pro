import Foundation
import CryptoKit

/// AES-256 GCM encryption engine providing authenticated symmetric encryption.
///
/// Uses Apple CryptoKit for hardware-accelerated operations on Apple Silicon.
public struct AESEncryptor {

    // MARK: - Types

    /// Represents an AES-encrypted payload with all components needed for decryption.
    public struct EncryptedPayload: Codable {
        /// The encrypted ciphertext bytes
        public let ciphertext: Data
        /// The GCM nonce (IV) used during encryption
        public let nonce: Data
        /// The GCM authentication tag
        public let tag: Data

        public init(ciphertext: Data, nonce: Data, tag: Data) {
            self.ciphertext = ciphertext
            self.nonce = nonce
            self.tag = tag
        }

        /// Returns a combined representation: nonce + ciphertext + tag
        public var combined: Data {
            var data = Data()
            data.append(nonce)
            data.append(ciphertext)
            data.append(tag)
            return data
        }
    }

    /// Errors that can occur during AES operations.
    public enum AESError: LocalizedError {
        case encryptionFailed(String)
        case decryptionFailed(String)
        case invalidKeySize
        case invalidPayload

        public var errorDescription: String? {
            switch self {
            case .encryptionFailed(let reason):
                return "Encryption failed: \(reason)"
            case .decryptionFailed(let reason):
                return "Decryption failed: \(reason)"
            case .invalidKeySize:
                return "Invalid key size. Expected 256-bit (32 bytes) key."
            case .invalidPayload:
                return "Invalid encrypted payload structure."
            }
        }
    }

    // MARK: - Initialization

    public init() {}

    // MARK: - Key Generation

    /// Generates a cryptographically secure 256-bit symmetric key.
    /// - Returns: A 32-byte symmetric key as `Data`.
    public static func generateKey() -> SymmetricKey {
        return SymmetricKey(size: .bits256)
    }

    /// Generates a symmetric key from a passphrase using HKDF.
    /// - Parameters:
    ///   - passphrase: The passphrase to derive the key from.
    ///   - salt: Optional salt for key derivation.
    /// - Returns: A derived 256-bit symmetric key.
    public static func deriveKey(from passphrase: String, salt: Data? = nil) -> SymmetricKey {
        let passphraseData = Data(passphrase.utf8)
        let saltData = salt ?? Data("SwiftCryptoPro.AES.Salt".utf8)
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: passphraseData),
            salt: saltData,
            outputByteCount: 32
        )
        return derivedKey
    }

    // MARK: - Encryption

    /// Encrypts a string using AES-256 GCM.
    /// - Parameters:
    ///   - plaintext: The string to encrypt.
    ///   - key: The 256-bit symmetric key.
    ///   - authenticatingData: Optional additional authenticated data.
    /// - Returns: An `EncryptedPayload` containing the ciphertext and metadata.
    public func encrypt(
        _ plaintext: String,
        using key: SymmetricKey,
        authenticating authenticatingData: Data? = nil
    ) throws -> EncryptedPayload {
        guard let data = plaintext.data(using: .utf8) else {
            throw AESError.encryptionFailed("Could not encode string to UTF-8.")
        }
        return try encrypt(data, using: key, authenticating: authenticatingData)
    }

    /// Encrypts raw data using AES-256 GCM.
    /// - Parameters:
    ///   - data: The data to encrypt.
    ///   - key: The 256-bit symmetric key.
    ///   - authenticatingData: Optional additional authenticated data.
    /// - Returns: An `EncryptedPayload` containing the ciphertext and metadata.
    public func encrypt(
        _ data: Data,
        using key: SymmetricKey,
        authenticating authenticatingData: Data? = nil
    ) throws -> EncryptedPayload {
        do {
            let sealedBox: AES.GCM.SealedBox
            if let aad = authenticatingData {
                sealedBox = try AES.GCM.seal(data, using: key, authenticating: aad)
            } else {
                sealedBox = try AES.GCM.seal(data, using: key)
            }

            return EncryptedPayload(
                ciphertext: sealedBox.ciphertext,
                nonce: Data(sealedBox.nonce),
                tag: sealedBox.tag
            )
        } catch {
            throw AESError.encryptionFailed(error.localizedDescription)
        }
    }

    // MARK: - Decryption

    /// Decrypts an encrypted payload back to a string.
    /// - Parameters:
    ///   - payload: The encrypted payload to decrypt.
    ///   - key: The 256-bit symmetric key used during encryption.
    ///   - authenticatingData: Optional additional authenticated data (must match encryption).
    /// - Returns: The decrypted string.
    public func decrypt(
        _ payload: EncryptedPayload,
        using key: SymmetricKey,
        authenticating authenticatingData: Data? = nil
    ) throws -> String {
        let data = try decryptToData(payload, using: key, authenticating: authenticatingData)
        guard let string = String(data: data, encoding: .utf8) else {
            throw AESError.decryptionFailed("Could not decode decrypted data to UTF-8 string.")
        }
        return string
    }

    /// Decrypts an encrypted payload back to raw data.
    /// - Parameters:
    ///   - payload: The encrypted payload to decrypt.
    ///   - key: The 256-bit symmetric key used during encryption.
    ///   - authenticatingData: Optional additional authenticated data (must match encryption).
    /// - Returns: The decrypted data.
    public func decryptToData(
        _ payload: EncryptedPayload,
        using key: SymmetricKey,
        authenticating authenticatingData: Data? = nil
    ) throws -> Data {
        do {
            let nonce = try AES.GCM.Nonce(data: payload.nonce)
            let sealedBox = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: payload.ciphertext,
                tag: payload.tag
            )

            if let aad = authenticatingData {
                return try AES.GCM.open(sealedBox, using: key, authenticating: aad)
            } else {
                return try AES.GCM.open(sealedBox, using: key)
            }
        } catch let error as AESError {
            throw error
        } catch {
            throw AESError.decryptionFailed(error.localizedDescription)
        }
    }
}
