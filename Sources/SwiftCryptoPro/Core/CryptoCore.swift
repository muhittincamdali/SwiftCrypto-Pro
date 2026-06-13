import Foundation
import CryptoKit

/// Main entry point for the SwiftCryptoPro toolkit.
public enum SwiftCryptoPro {
    public static let version = "2.0.0"
}

/// A high-integrity symmetric encryption utility using AES-GCM.
public struct CryptoSymmetric: Sendable {
    public static func encrypt(_ data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined!
    }
    
    public static func decrypt(_ combinedData: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: combinedData)
        return try AES.GCM.open(sealedBox, using: key)
    }
}
