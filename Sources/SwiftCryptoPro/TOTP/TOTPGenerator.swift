import Foundation
import CryptoKit

/// Generates Time-based One-Time Passwords following RFC 6238.
///
/// Compatible with Google Authenticator and other TOTP apps.
public struct TOTPGenerator {

    // MARK: - Properties

    /// The shared secret key (Base32 encoded)
    public let secret: String

    /// Time step in seconds (default: 30)
    public let period: TimeInterval

    /// Number of digits in the generated code (default: 6)
    public let digits: Int

    // MARK: - Errors

    public enum TOTPError: LocalizedError {
        case invalidSecret
        case generationFailed

        public var errorDescription: String? {
            switch self {
            case .invalidSecret:
                return "Invalid Base32-encoded secret."
            case .generationFailed:
                return "Failed to generate TOTP code."
            }
        }
    }

    // MARK: - Initialization

    /// Creates a TOTP generator.
    /// - Parameters:
    ///   - secret: The Base32-encoded shared secret.
    ///   - period: Time step in seconds (default: 30).
    ///   - digits: Number of digits in the code (default: 6).
    public init(secret: String, period: TimeInterval = 30, digits: Int = 6) {
        self.secret = secret
        self.period = period
        self.digits = digits
    }

    // MARK: - Code Generation

    /// Generates a TOTP code for the current time.
    /// - Returns: The TOTP code as a zero-padded string.
    public func generateCode() throws -> String {
        return try generateCode(for: Date())
    }

    /// Generates a TOTP code for a specific date.
    /// - Parameter date: The date to generate the code for.
    /// - Returns: The TOTP code as a zero-padded string.
    public func generateCode(for date: Date) throws -> String {
        guard let secretData = base32Decode(secret) else {
            throw TOTPError.invalidSecret
        }

        let counter = UInt64(date.timeIntervalSince1970 / period)
        var bigEndianCounter = counter.bigEndian
        let counterData = Data(bytes: &bigEndianCounter, count: MemoryLayout<UInt64>.size)

        let key = SymmetricKey(data: secretData)
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key)
        let macBytes = Array(mac)

        let offset = Int(macBytes[macBytes.count - 1] & 0x0f)
        let truncatedHash = macBytes[offset..<offset + 4]

        var number = truncatedHash.reduce(0) { ($0 << 8) | UInt32($1) }
        number &= 0x7fffffff

        let otp = number % UInt32(pow(10, Float(digits)))
        return String(format: "%0\(digits)d", otp)
    }

    /// Returns the number of seconds remaining in the current period.
    public var timeRemaining: TimeInterval {
        let elapsed = Date().timeIntervalSince1970.truncatingRemainder(dividingBy: period)
        return period - elapsed
    }

    /// Returns the current time step counter value.
    public var currentCounter: UInt64 {
        return UInt64(Date().timeIntervalSince1970 / period)
    }

    // MARK: - Base32 Decoding

    private func base32Decode(_ input: String) -> Data? {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        let cleanInput = input.uppercased().replacingOccurrences(of: "=", with: "")

        var bits = ""
        for char in cleanInput {
            guard let index = alphabet.firstIndex(of: char) else { return nil }
            let value = alphabet.distance(from: alphabet.startIndex, to: index)
            bits += String(value, radix: 2).leftPadded(toLength: 5, with: "0")
        }

        var bytes = [UInt8]()
        var index = bits.startIndex
        while bits.distance(from: index, to: bits.endIndex) >= 8 {
            let nextIndex = bits.index(index, offsetBy: 8)
            let byteString = String(bits[index..<nextIndex])
            if let byte = UInt8(byteString, radix: 2) {
                bytes.append(byte)
            }
            index = nextIndex
        }

        return Data(bytes)
    }
}

// MARK: - String Extension

private extension String {
    func leftPadded(toLength length: Int, with character: Character) -> String {
        let padding = length - count
        if padding <= 0 { return self }
        return String(repeating: character, count: padding) + self
    }
}
