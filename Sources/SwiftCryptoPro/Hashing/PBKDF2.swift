import Foundation
import CommonCrypto
import CryptoKit

// MARK: - PBKDF2 Key Derivation

/// Password-Based Key Derivation Function 2 (PBKDF2) implementation.
///
/// PBKDF2 is a key derivation function that applies a pseudorandom function
/// (such as HMAC-SHA256) to the input password along with a salt value and
/// repeats the process many times to produce a derived key.
///
/// ## Features
/// - Configurable iteration count for adjustable security
/// - Multiple hash algorithm support (SHA-1, SHA-256, SHA-384, SHA-512)
/// - Automatic salt generation
/// - Timing-safe comparison for password verification
///
/// ## Usage
/// ```swift
/// let pbkdf2 = PBKDF2()
///
/// // Derive a key from password
/// let result = try pbkdf2.deriveKey(
///     password: "MySecretPassword",
///     iterations: 100_000,
///     keyLength: 32
/// )
///
/// // Store result.salt and result.derivedKey
/// // Later, verify with the same salt
/// let isValid = try pbkdf2.verify(
///     password: "MySecretPassword",
///     salt: storedSalt,
///     expectedKey: storedKey,
///     iterations: 100_000
/// )
/// ```
///
/// ## Security Considerations
/// - Use at least 100,000 iterations for password storage (2024 recommendation)
/// - Use unique, random salts for each password
/// - Consider Argon2 for new applications requiring memory-hard KDF
public struct PBKDF2 {
    
    // MARK: - Types
    
    /// Hash algorithms supported by PBKDF2.
    public enum Algorithm: CaseIterable {
        /// SHA-1 (160-bit output) - Legacy, not recommended for new applications
        case sha1
        
        /// SHA-256 (256-bit output) - Recommended for most use cases
        case sha256
        
        /// SHA-384 (384-bit output) - Higher security margin
        case sha384
        
        /// SHA-512 (512-bit output) - Maximum security
        case sha512
        
        /// The output length in bytes for this algorithm.
        public var digestLength: Int {
            switch self {
            case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
            case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
            case .sha384: return Int(CC_SHA384_DIGEST_LENGTH)
            case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
            }
        }
        
        /// CommonCrypto algorithm identifier.
        fileprivate var ccAlgorithm: CCPseudoRandomAlgorithm {
            switch self {
            case .sha1: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
            case .sha256: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
            case .sha384: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
            case .sha512: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
            }
        }
        
        /// Human-readable name for the algorithm.
        public var name: String {
            switch self {
            case .sha1: return "SHA-1"
            case .sha256: return "SHA-256"
            case .sha384: return "SHA-384"
            case .sha512: return "SHA-512"
            }
        }
    }
    
    /// Result of key derivation containing the derived key and salt.
    public struct DerivedKeyResult {
        /// The derived cryptographic key.
        public let derivedKey: Data
        
        /// The salt used during derivation.
        public let salt: Data
        
        /// The number of iterations used.
        public let iterations: Int
        
        /// The algorithm used for derivation.
        public let algorithm: Algorithm
        
        /// Returns the derived key as a hexadecimal string.
        public var hexKey: String {
            derivedKey.map { String(format: "%02x", $0) }.joined()
        }
        
        /// Returns the salt as a hexadecimal string.
        public var hexSalt: String {
            salt.map { String(format: "%02x", $0) }.joined()
        }
        
        /// Returns a combined string suitable for storage (format: algorithm$iterations$salt$key).
        public var storable: String {
            let algName = algorithm.name.replacingOccurrences(of: "-", with: "")
            return "\(algName)$\(iterations)$\(hexSalt)$\(hexKey)"
        }
    }
    
    /// Errors that can occur during PBKDF2 operations.
    public enum PBKDF2Error: LocalizedError {
        case derivationFailed(status: Int32)
        case invalidIterationCount
        case invalidKeyLength
        case invalidSaltLength
        case passwordEncodingFailed
        case verificationFailed
        case invalidStorableFormat
        
        public var errorDescription: String? {
            switch self {
            case .derivationFailed(let status):
                return "Key derivation failed with status: \(status)"
            case .invalidIterationCount:
                return "Iteration count must be at least 1000."
            case .invalidKeyLength:
                return "Key length must be between 1 and 512 bytes."
            case .invalidSaltLength:
                return "Salt must be at least 8 bytes."
            case .passwordEncodingFailed:
                return "Failed to encode password as UTF-8."
            case .verificationFailed:
                return "Password verification failed."
            case .invalidStorableFormat:
                return "Invalid storable format. Expected: algorithm$iterations$salt$key"
            }
        }
    }
    
    // MARK: - Configuration
    
    /// Configuration options for PBKDF2.
    public struct Configuration {
        /// Default salt length in bytes.
        public var saltLength: Int
        
        /// Default number of iterations.
        public var iterations: Int
        
        /// Default derived key length in bytes.
        public var keyLength: Int
        
        /// Default hash algorithm.
        public var algorithm: Algorithm
        
        /// Creates a configuration with default values.
        public init(
            saltLength: Int = 32,
            iterations: Int = 100_000,
            keyLength: Int = 32,
            algorithm: Algorithm = .sha256
        ) {
            self.saltLength = saltLength
            self.iterations = iterations
            self.keyLength = keyLength
            self.algorithm = algorithm
        }
        
        /// High-security configuration (slower but more secure).
        public static let highSecurity = Configuration(
            saltLength: 32,
            iterations: 600_000,
            keyLength: 64,
            algorithm: .sha512
        )
        
        /// Standard configuration (balanced security and performance).
        public static let standard = Configuration(
            saltLength: 32,
            iterations: 100_000,
            keyLength: 32,
            algorithm: .sha256
        )
        
        /// Fast configuration (for testing only - not for production).
        public static let fast = Configuration(
            saltLength: 16,
            iterations: 1000,
            keyLength: 32,
            algorithm: .sha256
        )
    }
    
    // MARK: - Properties
    
    /// The configuration for this instance.
    public let configuration: Configuration
    
    // MARK: - Initialization
    
    /// Creates a PBKDF2 instance with default configuration.
    public init() {
        self.configuration = Configuration()
    }
    
    /// Creates a PBKDF2 instance with custom configuration.
    ///
    /// - Parameter configuration: The configuration to use.
    public init(configuration: Configuration) {
        self.configuration = configuration
    }
    
    // MARK: - Key Derivation
    
    /// Derives a cryptographic key from a password.
    ///
    /// - Parameters:
    ///   - password: The password to derive the key from.
    ///   - salt: Optional salt (generated automatically if nil).
    ///   - iterations: Number of iterations (uses configuration default if nil).
    ///   - keyLength: Desired key length in bytes (uses configuration default if nil).
    ///   - algorithm: Hash algorithm (uses configuration default if nil).
    /// - Returns: A `DerivedKeyResult` containing the key and parameters.
    /// - Throws: `PBKDF2Error` if derivation fails.
    public func deriveKey(
        password: String,
        salt: Data? = nil,
        iterations: Int? = nil,
        keyLength: Int? = nil,
        algorithm: Algorithm? = nil
    ) throws -> DerivedKeyResult {
        let actualIterations = iterations ?? configuration.iterations
        let actualKeyLength = keyLength ?? configuration.keyLength
        let actualAlgorithm = algorithm ?? configuration.algorithm
        let actualSalt = salt ?? generateSalt(length: configuration.saltLength)
        
        // Validate parameters
        guard actualIterations >= 1000 else {
            throw PBKDF2Error.invalidIterationCount
        }
        guard actualKeyLength >= 1 && actualKeyLength <= 512 else {
            throw PBKDF2Error.invalidKeyLength
        }
        guard actualSalt.count >= 8 else {
            throw PBKDF2Error.invalidSaltLength
        }
        
        let derivedKey = try deriveKeyInternal(
            password: password,
            salt: actualSalt,
            iterations: actualIterations,
            keyLength: actualKeyLength,
            algorithm: actualAlgorithm
        )
        
        return DerivedKeyResult(
            derivedKey: derivedKey,
            salt: actualSalt,
            iterations: actualIterations,
            algorithm: actualAlgorithm
        )
    }
    
    /// Derives a key from raw password data.
    ///
    /// - Parameters:
    ///   - passwordData: The password as raw data.
    ///   - salt: The salt data.
    ///   - iterations: Number of iterations.
    ///   - keyLength: Desired key length.
    ///   - algorithm: Hash algorithm.
    /// - Returns: The derived key.
    public func deriveKey(
        passwordData: Data,
        salt: Data,
        iterations: Int,
        keyLength: Int,
        algorithm: Algorithm = .sha256
    ) throws -> Data {
        guard iterations >= 1000 else {
            throw PBKDF2Error.invalidIterationCount
        }
        guard keyLength >= 1 && keyLength <= 512 else {
            throw PBKDF2Error.invalidKeyLength
        }
        guard salt.count >= 8 else {
            throw PBKDF2Error.invalidSaltLength
        }
        
        var derivedKey = [UInt8](repeating: 0, count: keyLength)
        
        let status = passwordData.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                    passwordData.count,
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    salt.count,
                    algorithm.ccAlgorithm,
                    UInt32(iterations),
                    &derivedKey,
                    keyLength
                )
            }
        }
        
        guard status == kCCSuccess else {
            throw PBKDF2Error.derivationFailed(status: status)
        }
        
        return Data(derivedKey)
    }
    
    // MARK: - Verification
    
    /// Verifies a password against a previously derived key.
    ///
    /// - Parameters:
    ///   - password: The password to verify.
    ///   - salt: The original salt used during derivation.
    ///   - expectedKey: The expected derived key.
    ///   - iterations: The number of iterations used originally.
    ///   - algorithm: The hash algorithm used originally.
    /// - Returns: `true` if the password matches.
    public func verify(
        password: String,
        salt: Data,
        expectedKey: Data,
        iterations: Int,
        algorithm: Algorithm = .sha256
    ) throws -> Bool {
        let derivedKey = try deriveKeyInternal(
            password: password,
            salt: salt,
            iterations: iterations,
            keyLength: expectedKey.count,
            algorithm: algorithm
        )
        
        return constantTimeCompare(derivedKey, expectedKey)
    }
    
    /// Verifies a password against a storable string.
    ///
    /// - Parameters:
    ///   - password: The password to verify.
    ///   - storable: The storable string (format: algorithm$iterations$salt$key).
    /// - Returns: `true` if the password matches.
    public func verify(password: String, storable: String) throws -> Bool {
        let parsed = try parseStorable(storable)
        return try verify(
            password: password,
            salt: parsed.salt,
            expectedKey: parsed.key,
            iterations: parsed.iterations,
            algorithm: parsed.algorithm
        )
    }
    
    // MARK: - Salt Generation
    
    /// Generates a cryptographically secure random salt.
    ///
    /// - Parameter length: The salt length in bytes.
    /// - Returns: Random salt data.
    public func generateSalt(length: Int = 32) -> Data {
        var bytes = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        return Data(bytes)
    }
    
    // MARK: - Utility Methods
    
    /// Calculates the recommended iteration count based on target time.
    ///
    /// - Parameters:
    ///   - targetMilliseconds: Target derivation time in milliseconds.
    ///   - algorithm: The hash algorithm to test.
    ///   - keyLength: The key length to derive.
    /// - Returns: Recommended iteration count.
    public func calibrateIterations(
        targetMilliseconds: Int = 100,
        algorithm: Algorithm = .sha256,
        keyLength: Int = 32
    ) -> Int {
        let testIterations = 10_000
        let testPassword = "calibration_password"
        let testSalt = generateSalt(length: 16)
        
        let startTime = CFAbsoluteTimeGetCurrent()
        
        _ = try? deriveKeyInternal(
            password: testPassword,
            salt: testSalt,
            iterations: testIterations,
            keyLength: keyLength,
            algorithm: algorithm
        )
        
        let elapsedMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
        
        guard elapsedMs > 0 else { return 100_000 }
        
        let iterationsPerMs = Double(testIterations) / elapsedMs
        let recommendedIterations = Int(iterationsPerMs * Double(targetMilliseconds))
        
        // Ensure minimum security
        return max(recommendedIterations, 10_000)
    }
    
    /// Estimates the time required for key derivation.
    ///
    /// - Parameters:
    ///   - iterations: The number of iterations.
    ///   - algorithm: The hash algorithm.
    /// - Returns: Estimated time in milliseconds.
    public func estimateTime(iterations: Int, algorithm: Algorithm = .sha256) -> Double {
        let testIterations = 10_000
        let testPassword = "estimate_password"
        let testSalt = generateSalt(length: 16)
        
        let startTime = CFAbsoluteTimeGetCurrent()
        
        _ = try? deriveKeyInternal(
            password: testPassword,
            salt: testSalt,
            iterations: testIterations,
            keyLength: 32,
            algorithm: algorithm
        )
        
        let elapsedMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
        
        return (elapsedMs / Double(testIterations)) * Double(iterations)
    }
    
    // MARK: - Private Methods
    
    /// Internal key derivation using CommonCrypto.
    private func deriveKeyInternal(
        password: String,
        salt: Data,
        iterations: Int,
        keyLength: Int,
        algorithm: Algorithm
    ) throws -> Data {
        guard let passwordData = password.data(using: .utf8) else {
            throw PBKDF2Error.passwordEncodingFailed
        }
        
        var derivedKey = [UInt8](repeating: 0, count: keyLength)
        
        let status = passwordData.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                    passwordData.count,
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    salt.count,
                    algorithm.ccAlgorithm,
                    UInt32(iterations),
                    &derivedKey,
                    keyLength
                )
            }
        }
        
        guard status == kCCSuccess else {
            throw PBKDF2Error.derivationFailed(status: status)
        }
        
        return Data(derivedKey)
    }
    
    /// Timing-safe comparison of two data values.
    private func constantTimeCompare(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[i] ^ b[i]
        }
        return result == 0
    }
    
    /// Parses a storable string into components.
    private func parseStorable(_ storable: String) throws -> (
        algorithm: Algorithm,
        iterations: Int,
        salt: Data,
        key: Data
    ) {
        let components = storable.split(separator: "$")
        guard components.count == 4 else {
            throw PBKDF2Error.invalidStorableFormat
        }
        
        let algString = String(components[0]).uppercased()
        let algorithm: Algorithm
        switch algString {
        case "SHA1": algorithm = .sha1
        case "SHA256": algorithm = .sha256
        case "SHA384": algorithm = .sha384
        case "SHA512": algorithm = .sha512
        default: throw PBKDF2Error.invalidStorableFormat
        }
        
        guard let iterations = Int(components[1]) else {
            throw PBKDF2Error.invalidStorableFormat
        }
        
        guard let salt = Data(hexString: String(components[2])) else {
            throw PBKDF2Error.invalidStorableFormat
        }
        
        guard let key = Data(hexString: String(components[3])) else {
            throw PBKDF2Error.invalidStorableFormat
        }
        
        return (algorithm, iterations, salt, key)
    }
}

// MARK: - Data Hex Extension

private extension Data {
    /// Initializes Data from a hexadecimal string.
    init?(hexString: String) {
        let hex = hexString.dropFirst(hexString.hasPrefix("0x") ? 2 : 0)
        guard hex.count % 2 == 0 else { return nil }
        
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }
        
        self = data
    }
}

// MARK: - Convenience Extensions

extension PBKDF2 {
    
    /// Hashes a password for storage using default parameters.
    ///
    /// - Parameter password: The password to hash.
    /// - Returns: A storable string containing all derivation parameters.
    public func hashPassword(_ password: String) throws -> String {
        let result = try deriveKey(password: password)
        return result.storable
    }
    
    /// Verifies a password against a stored hash.
    ///
    /// - Parameters:
    ///   - password: The password to verify.
    ///   - hash: The stored hash string.
    /// - Returns: `true` if the password matches.
    public func verifyPassword(_ password: String, against hash: String) throws -> Bool {
        return try verify(password: password, storable: hash)
    }
    
    /// Derives a symmetric key suitable for use with CryptoKit.
    ///
    /// - Parameters:
    ///   - password: The password to derive from.
    ///   - salt: The salt data.
    ///   - iterations: Number of iterations.
    /// - Returns: A CryptoKit SymmetricKey.
    public func deriveSymmetricKey(
        password: String,
        salt: Data,
        iterations: Int = 100_000
    ) throws -> SymmetricKey {
        let result = try deriveKey(
            password: password,
            salt: salt,
            iterations: iterations,
            keyLength: 32,
            algorithm: .sha256
        )
        return SymmetricKey(data: result.derivedKey)
    }
}
