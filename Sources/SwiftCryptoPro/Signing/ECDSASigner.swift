import Foundation
import CryptoKit

/// ECDSA (Elliptic Curve Digital Signature Algorithm) signing and verification.
///
/// Uses P-256 curve via Apple CryptoKit for high-performance operations.
public struct ECDSASigner {

    // MARK: - Types

    /// An ECDSA key pair for signing and verification.
    public struct KeyPair {
        /// The private key used for signing
        public let privateKey: P256.Signing.PrivateKey
        /// The public key used for verification
        public let publicKey: P256.Signing.PublicKey
    }

    /// Errors that can occur during ECDSA operations.
    public enum ECDSAError: LocalizedError {
        case signingFailed(String)
        case verificationFailed
        case invalidSignature
        case dataConversionFailed

        public var errorDescription: String? {
            switch self {
            case .signingFailed(let reason):
                return "ECDSA signing failed: \(reason)"
            case .verificationFailed:
                return "ECDSA signature verification failed."
            case .invalidSignature:
                return "Invalid ECDSA signature format."
            case .dataConversionFailed:
                return "Failed to convert data for signing."
            }
        }
    }

    // MARK: - Initialization

    public init() {}

    // MARK: - Key Generation

    /// Generates a new ECDSA P-256 key pair.
    /// - Returns: A `KeyPair` with private and public keys.
    public func generateKeyPair() -> KeyPair {
        let privateKey = P256.Signing.PrivateKey()
        return KeyPair(privateKey: privateKey, publicKey: privateKey.publicKey)
    }

    // MARK: - Signing

    /// Signs a string message using the private key.
    /// - Parameters:
    ///   - message: The message to sign.
    ///   - privateKey: The ECDSA private key.
    /// - Returns: The signature as `Data`.
    public func sign(_ message: String, privateKey: P256.Signing.PrivateKey) throws -> Data {
        guard let data = message.data(using: .utf8) else {
            throw ECDSAError.dataConversionFailed
        }
        return try sign(data, privateKey: privateKey)
    }

    /// Signs raw data using the private key.
    /// - Parameters:
    ///   - data: The data to sign.
    ///   - privateKey: The ECDSA private key.
    /// - Returns: The DER-encoded signature as `Data`.
    public func sign(_ data: Data, privateKey: P256.Signing.PrivateKey) throws -> Data {
        do {
            let signature = try privateKey.signature(for: data)
            return signature.derRepresentation
        } catch {
            throw ECDSAError.signingFailed(error.localizedDescription)
        }
    }

    // MARK: - Verification

    /// Verifies a signature against a string message.
    /// - Parameters:
    ///   - message: The original message.
    ///   - signature: The DER-encoded signature data.
    ///   - publicKey: The ECDSA public key.
    /// - Returns: `true` if the signature is valid.
    public func verify(
        _ message: String,
        signature: Data,
        publicKey: P256.Signing.PublicKey
    ) -> Bool {
        guard let data = message.data(using: .utf8) else { return false }
        return verify(data, signature: signature, publicKey: publicKey)
    }

    /// Verifies a signature against raw data.
    /// - Parameters:
    ///   - data: The original data.
    ///   - signature: The DER-encoded signature data.
    ///   - publicKey: The ECDSA public key.
    /// - Returns: `true` if the signature is valid.
    public func verify(
        _ data: Data,
        signature: Data,
        publicKey: P256.Signing.PublicKey
    ) -> Bool {
        guard let ecdsaSignature = try? P256.Signing.ECDSASignature(derRepresentation: signature) else {
            return false
        }
        return publicKey.isValidSignature(ecdsaSignature, for: data)
    }
}
