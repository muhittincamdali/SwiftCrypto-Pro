import Foundation
import CryptoKit

/// Convenient cryptographic extensions on `String`.
///
/// Provides quick access to common hash functions and encoding operations.
public extension String {

    /// Returns the SHA-256 hash of this string as a hex string.
    var sha256: String {
        CryptoHasher.sha256(self)
    }

    /// Returns the SHA-384 hash of this string as a hex string.
    var sha384: String {
        CryptoHasher.sha384(self)
    }

    /// Returns the SHA-512 hash of this string as a hex string.
    var sha512: String {
        CryptoHasher.sha512(self)
    }

    /// Returns the MD5 hash of this string as a hex string.
    ///
    /// - Warning: MD5 is cryptographically broken. Use only for non-security purposes
    ///   such as checksums and cache keys.
    var md5: String {
        let data = Data(self.utf8)
        let digest = Insecure.MD5.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Returns the Base64-encoded version of this string.
    var base64Encoded: String? {
        data(using: .utf8)?.base64EncodedString()
    }

    /// Decodes this string from Base64.
    var base64Decoded: String? {
        guard let data = Data(base64Encoded: self) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Returns the HMAC-SHA256 of this string using the given key.
    /// - Parameter key: The secret key.
    /// - Returns: Hex-encoded HMAC string.
    func hmacSHA256(key: String) -> String {
        HMACGenerator.generate(for: self, key: key, algorithm: .sha256)
    }

    /// Returns the HMAC-SHA512 of this string using the given key.
    /// - Parameter key: The secret key.
    /// - Returns: Hex-encoded HMAC string.
    func hmacSHA512(key: String) -> String {
        HMACGenerator.generate(for: self, key: key, algorithm: .sha512)
    }

    /// Returns the hex-encoded representation of this string's UTF-8 bytes.
    var hexEncoded: String {
        Data(self.utf8).map { String(format: "%02x", $0) }.joined()
    }

    /// Decodes this hex string to a regular string.
    var hexDecoded: String? {
        var bytes = [UInt8]()
        var index = startIndex
        while index < endIndex {
            let nextIndex = self.index(index, offsetBy: 2, limitedBy: endIndex) ?? endIndex
            guard nextIndex != index else { return nil }
            let byteString = self[index..<nextIndex]
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            bytes.append(byte)
            index = nextIndex
        }
        return String(bytes: bytes, encoding: .utf8)
    }
}
