import Foundation
import CryptoKit

/// Generates HMAC (Hash-based Message Authentication Code) values.
///
/// Supports SHA-256, SHA-384, and SHA-512 as underlying hash functions.
public struct HMACGenerator {

    // MARK: - Initialization

    public init() {}

    // MARK: - HMAC Generation

    /// Generates an HMAC for the given message and key.
    /// - Parameters:
    ///   - message: The message to authenticate.
    ///   - key: The secret key as a string.
    ///   - algorithm: The hash algorithm to use (default: SHA-256).
    /// - Returns: Hexadecimal string of the HMAC.
    public static func generate(
        for message: String,
        key: String,
        algorithm: CryptoHasher.Algorithm = .sha256
    ) -> String {
        let keyData = Data(key.utf8)
        let messageData = Data(message.utf8)
        let symmetricKey = SymmetricKey(data: keyData)

        switch algorithm {
        case .sha256:
            let mac = HMAC<SHA256>.authenticationCode(for: messageData, using: symmetricKey)
            return Data(mac).map { String(format: "%02x", $0) }.joined()
        case .sha384:
            let mac = HMAC<SHA384>.authenticationCode(for: messageData, using: symmetricKey)
            return Data(mac).map { String(format: "%02x", $0) }.joined()
        case .sha512:
            let mac = HMAC<SHA512>.authenticationCode(for: messageData, using: symmetricKey)
            return Data(mac).map { String(format: "%02x", $0) }.joined()
        }
    }

    /// Validates an HMAC against an expected value.
    /// - Parameters:
    ///   - message: The original message.
    ///   - key: The secret key.
    ///   - expectedMAC: The expected HMAC hex string.
    ///   - algorithm: The hash algorithm used.
    /// - Returns: `true` if the HMAC matches.
    public static func validate(
        message: String,
        key: String,
        expectedMAC: String,
        algorithm: CryptoHasher.Algorithm = .sha256
    ) -> Bool {
        let computed = generate(for: message, key: key, algorithm: algorithm)
        return computed == expectedMAC.lowercased()
    }
}
