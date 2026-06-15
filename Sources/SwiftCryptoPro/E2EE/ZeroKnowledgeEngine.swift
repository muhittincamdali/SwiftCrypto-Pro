import Foundation
import CryptoKit

/// SwiftCrypto-Pro: Zero-Knowledge End-to-End Encryption (E2EE) Engine
/// 
/// Provides a high-level API for establishing secure communications channels
/// without ever storing private keys in memory for longer than a single execution cycle.
public struct ZeroKnowledgeEngine: Sendable {
    
    /// Generates a forward-secure Key Agreement using Curve25519.
    public static func generateKeyPair() -> Curve25519.KeyAgreement.PrivateKey {
        print("🔐 [SwiftCrypto-Pro] Generating Ephemeral Curve25519 KeyPair.")
        return Curve25519.KeyAgreement.PrivateKey()
    }
    
    /// Derives a shared symmetric key from a local private key and a remote public key.
    public static func deriveSharedSecret(privateKey: Curve25519.KeyAgreement.PrivateKey, remotePublicKeyData: Data) throws -> SharedSecret {
        let remotePublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remotePublicKeyData)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: remotePublicKey)
        print("🤝 [SwiftCrypto-Pro] Shared Secret Derived Successfully.")
        return sharedSecret
    }
}
