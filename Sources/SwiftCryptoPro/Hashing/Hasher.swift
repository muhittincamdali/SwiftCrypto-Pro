import Foundation
import CryptoKit

/// Provides cryptographic hashing using SHA-256, SHA-384, and SHA-512.
///
/// All operations use Apple CryptoKit for hardware-accelerated performance.
public struct CryptoHasher {

    // MARK: - Algorithm

    /// Supported hash algorithms.
    public enum Algorithm {
        case sha256
        case sha384
        case sha512
    }

    // MARK: - Initialization

    public init() {}

    // MARK: - String Hashing

    /// Hashes a string using the specified algorithm.
    /// - Parameters:
    ///   - input: The string to hash.
    ///   - algorithm: The hash algorithm to use.
    /// - Returns: Hexadecimal string representation of the hash.
    public static func hash(_ input: String, algorithm: Algorithm = .sha256) -> String {
        let data = Data(input.utf8)
        return hash(data, algorithm: algorithm)
    }

    /// Hashes raw data using the specified algorithm.
    /// - Parameters:
    ///   - data: The data to hash.
    ///   - algorithm: The hash algorithm to use.
    /// - Returns: Hexadecimal string representation of the hash.
    public static func hash(_ data: Data, algorithm: Algorithm = .sha256) -> String {
        switch algorithm {
        case .sha256:
            return sha256(data)
        case .sha384:
            return sha384(data)
        case .sha512:
            return sha512(data)
        }
    }

    // MARK: - SHA-256

    /// Computes the SHA-256 hash of a string.
    /// - Parameter input: The string to hash.
    /// - Returns: Hexadecimal string of the SHA-256 digest.
    public static func sha256(_ input: String) -> String {
        let data = Data(input.utf8)
        return sha256(data)
    }

    /// Computes the SHA-256 hash of data.
    /// - Parameter data: The data to hash.
    /// - Returns: Hexadecimal string of the SHA-256 digest.
    public static func sha256(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - SHA-384

    /// Computes the SHA-384 hash of a string.
    /// - Parameter input: The string to hash.
    /// - Returns: Hexadecimal string of the SHA-384 digest.
    public static func sha384(_ input: String) -> String {
        let data = Data(input.utf8)
        let digest = SHA384.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - SHA-512

    /// Computes the SHA-512 hash of a string.
    /// - Parameter input: The string to hash.
    /// - Returns: Hexadecimal string of the SHA-512 digest.
    public static func sha512(_ input: String) -> String {
        let data = Data(input.utf8)
        return sha512(data)
    }

    /// Computes the SHA-512 hash of data.
    /// - Parameter data: The data to hash.
    /// - Returns: Hexadecimal string of the SHA-512 digest.
    public static func sha512(_ data: Data) -> String {
        let digest = SHA512.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Raw Digest

    /// Returns the raw SHA-256 digest bytes.
    /// - Parameter data: The data to hash.
    /// - Returns: The digest as `Data`.
    public static func sha256Digest(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    /// Returns the raw SHA-512 digest bytes.
    /// - Parameter data: The data to hash.
    /// - Returns: The digest as `Data`.
    public static func sha512Digest(_ data: Data) -> Data {
        let digest = SHA512.hash(data: data)
        return Data(digest)
    }
}
