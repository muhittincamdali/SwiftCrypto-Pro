import Foundation
import CryptoKit

/// SwiftCrypto-Pro: Zero-Knowledge E2E Encryption Engine
public struct ZeroKnowledgeEngine: Sendable {
    public static func generateKeyAgreement() -> Curve25519.KeyAgreement.PrivateKey {
        return Curve25519.KeyAgreement.PrivateKey()
    }
}
