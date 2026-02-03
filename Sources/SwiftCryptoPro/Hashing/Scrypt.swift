//
//  Scrypt.swift
//  SwiftCryptoPro
//
//  Created by Muhittin Camdali on 2025.
//  Copyright © 2025 Muhittin Camdali. All rights reserved.
//

import Foundation
import CryptoKit
import Security
import CommonCrypto

// MARK: - Scrypt Error Types

/// Errors that can occur during Scrypt operations
public enum ScryptError: Error, LocalizedError, Equatable {
    case invalidSaltLength
    case invalidPasswordLength
    case invalidOutputLength
    case invalidCostFactor
    case invalidBlockSize
    case invalidParallelization
    case hashingFailed
    case verificationFailed
    case invalidEncodedHash
    case outOfMemory
    case internalError
    case parameterOverflow
    
    public var errorDescription: String? {
        switch self {
        case .invalidSaltLength:
            return "Salt must be at least 8 bytes (16 bytes recommended)."
        case .invalidPasswordLength:
            return "Password cannot be empty."
        case .invalidOutputLength:
            return "Output length must be between 1 and (2^32 - 1) * 32 bytes."
        case .invalidCostFactor:
            return "Cost factor N must be a power of 2 greater than 1."
        case .invalidBlockSize:
            return "Block size r must be greater than 0."
        case .invalidParallelization:
            return "Parallelization factor p must be greater than 0."
        case .hashingFailed:
            return "Scrypt hashing operation failed."
        case .verificationFailed:
            return "Password verification failed."
        case .invalidEncodedHash:
            return "Invalid encoded Scrypt hash format."
        case .outOfMemory:
            return "Out of memory during Scrypt operation."
        case .internalError:
            return "Internal Scrypt error occurred."
        case .parameterOverflow:
            return "Parameters would cause memory overflow."
        }
    }
}

// MARK: - Scrypt Parameters

/// Configuration parameters for Scrypt
public struct ScryptParameters: Equatable, Codable {
    
    /// CPU/memory cost factor (N) - must be power of 2
    public let costFactor: UInt64
    
    /// Block size factor (r)
    public let blockSize: UInt32
    
    /// Parallelization factor (p)
    public let parallelization: UInt32
    
    /// Output hash length in bytes
    public let hashLength: UInt32
    
    /// Log2 of cost factor (for encoding)
    public var log2N: Int {
        return Int(log2(Double(costFactor)))
    }
    
    // MARK: - Preset Parameters
    
    /// Interactive logins (fast, ~100ms)
    public static let interactive = ScryptParameters(
        costFactor: 16384,      // N = 2^14
        blockSize: 8,           // r
        parallelization: 1,     // p
        hashLength: 32
    )
    
    /// Standard password hashing (~500ms)
    public static let standard = ScryptParameters(
        costFactor: 32768,      // N = 2^15
        blockSize: 8,           // r
        parallelization: 1,     // p
        hashLength: 32
    )
    
    /// Sensitive storage (slower, more secure)
    public static let sensitive = ScryptParameters(
        costFactor: 65536,      // N = 2^16
        blockSize: 8,           // r
        parallelization: 1,     // p
        hashLength: 32
    )
    
    /// Strong security (~2-3 seconds)
    public static let strong = ScryptParameters(
        costFactor: 131072,     // N = 2^17
        blockSize: 8,           // r
        parallelization: 2,     // p
        hashLength: 32
    )
    
    /// Maximum security (very slow)
    public static let maximum = ScryptParameters(
        costFactor: 262144,     // N = 2^18
        blockSize: 8,           // r
        parallelization: 4,     // p
        hashLength: 64
    )
    
    /// Lightweight (for mobile devices)
    public static let mobile = ScryptParameters(
        costFactor: 8192,       // N = 2^13
        blockSize: 8,           // r
        parallelization: 1,     // p
        hashLength: 32
    )
    
    /// Initialize with custom parameters
    /// - Parameters:
    ///   - costFactor: CPU/memory cost (N), must be power of 2 > 1
    ///   - blockSize: Block size factor (r)
    ///   - parallelization: Parallelization factor (p)
    ///   - hashLength: Output hash length in bytes
    public init(
        costFactor: UInt64,
        blockSize: UInt32,
        parallelization: UInt32,
        hashLength: UInt32 = 32
    ) {
        self.costFactor = costFactor
        self.blockSize = blockSize
        self.parallelization = parallelization
        self.hashLength = hashLength
    }
    
    /// Initialize with log2 of cost factor
    /// - Parameters:
    ///   - log2N: Log2 of the cost factor (e.g., 14 for N=16384)
    ///   - blockSize: Block size factor (r)
    ///   - parallelization: Parallelization factor (p)
    ///   - hashLength: Output hash length in bytes
    public init(
        log2N: Int,
        blockSize: UInt32,
        parallelization: UInt32,
        hashLength: UInt32 = 32
    ) {
        self.costFactor = UInt64(1) << log2N
        self.blockSize = blockSize
        self.parallelization = parallelization
        self.hashLength = hashLength
    }
    
    /// Validate parameters
    public func validate() throws {
        // N must be power of 2 > 1
        guard costFactor > 1 && (costFactor & (costFactor - 1)) == 0 else {
            throw ScryptError.invalidCostFactor
        }
        
        guard blockSize > 0 else {
            throw ScryptError.invalidBlockSize
        }
        
        guard parallelization > 0 else {
            throw ScryptError.invalidParallelization
        }
        
        guard hashLength >= 1 else {
            throw ScryptError.invalidOutputLength
        }
        
        // Check for parameter overflow
        // p * r <= 2^30
        let maxPR: UInt64 = 1 << 30
        guard UInt64(parallelization) * UInt64(blockSize) <= maxPR else {
            throw ScryptError.parameterOverflow
        }
    }
    
    /// Calculate memory usage in bytes
    public var memoryUsageBytes: UInt64 {
        return costFactor * UInt64(blockSize) * 128
    }
    
    /// Calculate memory usage in MB
    public var memoryUsageMB: Double {
        return Double(memoryUsageBytes) / (1024 * 1024)
    }
    
    /// Human-readable description
    public var description: String {
        return "Scrypt(N=\(costFactor), r=\(blockSize), p=\(parallelization), dkLen=\(hashLength))"
    }
}

// MARK: - Scrypt Hash Result

/// The result of a Scrypt hash operation
public struct ScryptHashResult: Equatable {
    
    /// The raw hash bytes
    public let hash: Data
    
    /// The salt used
    public let salt: Data
    
    /// The parameters used
    public let parameters: ScryptParameters
    
    /// Encode to string format
    /// Format: $scrypt$ln=14,r=8,p=1$salt$hash
    public func encodedString() -> String {
        let saltBase64 = salt.base64EncodedString()
            .replacingOccurrences(of: "+", with: ".")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        
        let hashBase64 = hash.base64EncodedString()
            .replacingOccurrences(of: "+", with: ".")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        
        return "$scrypt$ln=\(parameters.log2N),r=\(parameters.blockSize),p=\(parameters.parallelization)$\(saltBase64)$\(hashBase64)"
    }
    
    /// Parse from encoded string format
    public static func fromEncodedString(_ encoded: String) throws -> ScryptHashResult {
        let parts = encoded.split(separator: "$", omittingEmptySubsequences: true).map { String($0) }
        
        guard parts.count == 4, parts[0] == "scrypt" else {
            throw ScryptError.invalidEncodedHash
        }
        
        // Parse parameters
        var log2N: Int = 0
        var blockSize: UInt32 = 0
        var parallelization: UInt32 = 0
        
        let paramParts = parts[1].split(separator: ",")
        for param in paramParts {
            if param.starts(with: "ln=") {
                log2N = Int(param.dropFirst(3)) ?? 0
            } else if param.starts(with: "r=") {
                blockSize = UInt32(param.dropFirst(2)) ?? 0
            } else if param.starts(with: "p=") {
                parallelization = UInt32(param.dropFirst(2)) ?? 0
            }
        }
        
        guard log2N > 0, blockSize > 0, parallelization > 0 else {
            throw ScryptError.invalidEncodedHash
        }
        
        // Parse salt
        let saltBase64 = parts[2]
            .replacingOccurrences(of: ".", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddedSalt = saltBase64.padding(toLength: ((saltBase64.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        guard let salt = Data(base64Encoded: paddedSalt) else {
            throw ScryptError.invalidEncodedHash
        }
        
        // Parse hash
        let hashBase64 = parts[3]
            .replacingOccurrences(of: ".", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddedHash = hashBase64.padding(toLength: ((hashBase64.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        guard let hash = Data(base64Encoded: paddedHash) else {
            throw ScryptError.invalidEncodedHash
        }
        
        let parameters = ScryptParameters(
            log2N: log2N,
            blockSize: blockSize,
            parallelization: parallelization,
            hashLength: UInt32(hash.count)
        )
        
        return ScryptHashResult(hash: hash, salt: salt, parameters: parameters)
    }
    
    /// Compare two hashes in constant time
    public func constantTimeEquals(_ other: ScryptHashResult) -> Bool {
        guard hash.count == other.hash.count else { return false }
        
        var result: UInt8 = 0
        for (a, b) in zip(hash, other.hash) {
            result |= a ^ b
        }
        return result == 0
    }
    
    /// Export as MCF (Modular Crypt Format)
    public func toMCF() -> String {
        return encodedString()
    }
}

// MARK: - Scrypt Hasher

/// Scrypt password hasher
public final class ScryptHasher {
    
    /// The parameters to use
    public let parameters: ScryptParameters
    
    /// Initialize with parameters
    public init(parameters: ScryptParameters = .standard) throws {
        try parameters.validate()
        self.parameters = parameters
    }
    
    /// Generate a random salt
    /// - Parameter length: The salt length in bytes (default: 16)
    /// - Returns: Random salt data
    public static func generateSalt(length: Int = 16) throws -> Data {
        var salt = Data(count: length)
        let result = salt.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, length, buffer.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw ScryptError.hashingFailed
        }
        return salt
    }
    
    // MARK: - Hashing
    
    /// Hash a password
    /// - Parameters:
    ///   - password: The password to hash
    ///   - salt: The salt to use (must be at least 8 bytes)
    /// - Returns: The hash result
    public func hash(password: String, salt: Data) throws -> ScryptHashResult {
        guard let passwordData = password.data(using: .utf8), !passwordData.isEmpty else {
            throw ScryptError.invalidPasswordLength
        }
        return try hash(data: passwordData, salt: salt)
    }
    
    /// Hash arbitrary data
    /// - Parameters:
    ///   - data: The data to hash
    ///   - salt: The salt to use
    /// - Returns: The hash result
    public func hash(data: Data, salt: Data) throws -> ScryptHashResult {
        guard salt.count >= 8 else {
            throw ScryptError.invalidSaltLength
        }
        
        guard !data.isEmpty else {
            throw ScryptError.invalidPasswordLength
        }
        
        // Perform Scrypt computation
        let hash = try computeScrypt(
            password: data,
            salt: salt,
            parameters: parameters
        )
        
        return ScryptHashResult(hash: hash, salt: salt, parameters: parameters)
    }
    
    /// Hash a password with automatic salt generation
    /// - Parameter password: The password to hash
    /// - Returns: The hash result with generated salt
    public func hash(password: String) throws -> ScryptHashResult {
        let salt = try Self.generateSalt()
        return try hash(password: password, salt: salt)
    }
    
    // MARK: - Verification
    
    /// Verify a password against a hash
    /// - Parameters:
    ///   - password: The password to verify
    ///   - expectedResult: The expected hash result
    /// - Returns: True if the password matches
    public func verify(password: String, against expectedResult: ScryptHashResult) throws -> Bool {
        let computedResult = try hash(password: password, salt: expectedResult.salt)
        return computedResult.constantTimeEquals(expectedResult)
    }
    
    /// Verify a password against an encoded hash string
    /// - Parameters:
    ///   - password: The password to verify
    ///   - encodedHash: The encoded hash string
    /// - Returns: True if the password matches
    public func verify(password: String, encodedHash: String) throws -> Bool {
        let expectedResult = try ScryptHashResult.fromEncodedString(encodedHash)
        
        // Create a new hasher with the parsed parameters
        let hasher = try ScryptHasher(parameters: expectedResult.parameters)
        let computedResult = try hasher.hash(password: password, salt: expectedResult.salt)
        
        return computedResult.constantTimeEquals(expectedResult)
    }
    
    // MARK: - Key Derivation
    
    /// Derive a key from a password
    /// - Parameters:
    ///   - password: The password
    ///   - salt: The salt
    ///   - keyLength: The desired key length
    /// - Returns: The derived key
    public func deriveKey(
        from password: String,
        salt: Data,
        keyLength: Int = 32
    ) throws -> Data {
        let params = ScryptParameters(
            costFactor: parameters.costFactor,
            blockSize: parameters.blockSize,
            parallelization: parameters.parallelization,
            hashLength: UInt32(keyLength)
        )
        
        guard let passwordData = password.data(using: .utf8) else {
            throw ScryptError.invalidPasswordLength
        }
        
        return try computeScrypt(
            password: passwordData,
            salt: salt,
            parameters: params
        )
    }
    
    // MARK: - Scrypt Core Algorithm
    
    /// Core Scrypt computation
    private func computeScrypt(
        password: Data,
        salt: Data,
        parameters: ScryptParameters
    ) throws -> Data {
        let N = Int(parameters.costFactor)
        let r = Int(parameters.blockSize)
        let p = Int(parameters.parallelization)
        let dkLen = Int(parameters.hashLength)
        
        // Step 1: Generate initial B using PBKDF2-HMAC-SHA256
        let blockSize = 128 * r
        let bLen = blockSize * p
        
        var b = try pbkdf2HMACSHA256(
            password: password,
            salt: salt,
            iterations: 1,
            keyLength: bLen
        )
        
        // Step 2: Process each block with SMix
        for i in 0..<p {
            let startIndex = i * blockSize
            let endIndex = startIndex + blockSize
            
            var block = Array(b[startIndex..<endIndex])
            smix(&block, N: N, r: r)
            
            for (j, byte) in block.enumerated() {
                b[startIndex + j] = byte
            }
        }
        
        // Step 3: Final PBKDF2 to generate output
        return try pbkdf2HMACSHA256(
            password: password,
            salt: Data(b),
            iterations: 1,
            keyLength: dkLen
        )
    }
    
    /// SMix function
    private func smix(_ b: inout [UInt8], N: Int, r: Int) {
        let blockSize = 128 * r
        
        // Convert to 32-bit words
        var x = [UInt32](repeating: 0, count: blockSize / 4)
        for i in 0..<x.count {
            let offset = i * 4
            x[i] = UInt32(b[offset]) |
                   (UInt32(b[offset + 1]) << 8) |
                   (UInt32(b[offset + 2]) << 16) |
                   (UInt32(b[offset + 3]) << 24)
        }
        
        // Allocate V for memory-hard part
        var v = [[UInt32]](repeating: [UInt32](repeating: 0, count: blockSize / 4), count: N)
        
        // Step 1: Fill V with sequential BlockMix results
        for i in 0..<N {
            v[i] = x
            blockMix(&x, r: r)
        }
        
        // Step 2: Mix using V
        for _ in 0..<N {
            let j = Int(x[blockSize / 4 - 16] & UInt32(N - 1))
            
            // XOR with V[j]
            for k in 0..<x.count {
                x[k] ^= v[j][k]
            }
            
            blockMix(&x, r: r)
        }
        
        // Convert back to bytes
        for i in 0..<x.count {
            let offset = i * 4
            b[offset] = UInt8(x[i] & 0xFF)
            b[offset + 1] = UInt8((x[i] >> 8) & 0xFF)
            b[offset + 2] = UInt8((x[i] >> 16) & 0xFF)
            b[offset + 3] = UInt8((x[i] >> 24) & 0xFF)
        }
    }
    
    /// BlockMix function using Salsa20/8
    private func blockMix(_ b: inout [UInt32], r: Int) {
        let wordCount = 2 * r * 16
        
        // X = B[2r-1]
        var x = Array(b[(wordCount - 16)..<wordCount])
        
        var y = [UInt32](repeating: 0, count: wordCount)
        
        // Process each block
        for i in 0..<(2 * r) {
            let blockStart = i * 16
            
            // T = X XOR B[i]
            for j in 0..<16 {
                x[j] ^= b[blockStart + j]
            }
            
            // X = Salsa20/8(T)
            salsa20_8(&x)
            
            // Y[i] = X (interleaved)
            let destIndex = (i / 2) + (i % 2) * r
            for j in 0..<16 {
                y[destIndex * 16 + j] = x[j]
            }
        }
        
        b = y
    }
    
    /// Salsa20/8 core function
    private func salsa20_8(_ b: inout [UInt32]) {
        var x = b
        
        // 8 rounds (4 double-rounds)
        for _ in 0..<4 {
            // Column round
            x[ 4] ^= rotl(x[ 0] &+ x[12],  7)
            x[ 8] ^= rotl(x[ 4] &+ x[ 0],  9)
            x[12] ^= rotl(x[ 8] &+ x[ 4], 13)
            x[ 0] ^= rotl(x[12] &+ x[ 8], 18)
            
            x[ 9] ^= rotl(x[ 5] &+ x[ 1],  7)
            x[13] ^= rotl(x[ 9] &+ x[ 5],  9)
            x[ 1] ^= rotl(x[13] &+ x[ 9], 13)
            x[ 5] ^= rotl(x[ 1] &+ x[13], 18)
            
            x[14] ^= rotl(x[10] &+ x[ 6],  7)
            x[ 2] ^= rotl(x[14] &+ x[10],  9)
            x[ 6] ^= rotl(x[ 2] &+ x[14], 13)
            x[10] ^= rotl(x[ 6] &+ x[ 2], 18)
            
            x[ 3] ^= rotl(x[15] &+ x[11],  7)
            x[ 7] ^= rotl(x[ 3] &+ x[15],  9)
            x[11] ^= rotl(x[ 7] &+ x[ 3], 13)
            x[15] ^= rotl(x[11] &+ x[ 7], 18)
            
            // Row round
            x[ 1] ^= rotl(x[ 0] &+ x[ 3],  7)
            x[ 2] ^= rotl(x[ 1] &+ x[ 0],  9)
            x[ 3] ^= rotl(x[ 2] &+ x[ 1], 13)
            x[ 0] ^= rotl(x[ 3] &+ x[ 2], 18)
            
            x[ 6] ^= rotl(x[ 5] &+ x[ 4],  7)
            x[ 7] ^= rotl(x[ 6] &+ x[ 5],  9)
            x[ 4] ^= rotl(x[ 7] &+ x[ 6], 13)
            x[ 5] ^= rotl(x[ 4] &+ x[ 7], 18)
            
            x[11] ^= rotl(x[10] &+ x[ 9],  7)
            x[ 8] ^= rotl(x[11] &+ x[10],  9)
            x[ 9] ^= rotl(x[ 8] &+ x[11], 13)
            x[10] ^= rotl(x[ 9] &+ x[ 8], 18)
            
            x[12] ^= rotl(x[15] &+ x[14],  7)
            x[13] ^= rotl(x[12] &+ x[15],  9)
            x[14] ^= rotl(x[13] &+ x[12], 13)
            x[15] ^= rotl(x[14] &+ x[13], 18)
        }
        
        // Add original values
        for i in 0..<16 {
            b[i] = b[i] &+ x[i]
        }
    }
    
    /// Left rotation for 32-bit values
    private func rotl(_ value: UInt32, _ bits: Int) -> UInt32 {
        return (value << bits) | (value >> (32 - bits))
    }
    
    /// PBKDF2-HMAC-SHA256 implementation
    private func pbkdf2HMACSHA256(
        password: Data,
        salt: Data,
        iterations: Int,
        keyLength: Int
    ) throws -> Data {
        var derivedKey = Data(count: keyLength)
        let result = derivedKey.withUnsafeMutableBytes { derivedBuffer in
            password.withUnsafeBytes { passwordBuffer in
                salt.withUnsafeBytes { saltBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.baseAddress?.assumingMemoryBound(to: Int8.self),
                        password.count,
                        saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }
        
        guard result == kCCSuccess else {
            throw ScryptError.hashingFailed
        }
        
        return derivedKey
    }
}

// MARK: - Benchmarking

/// Scrypt benchmark utilities
public struct ScryptBenchmark {
    
    /// Benchmark Scrypt with given parameters
    /// - Parameters:
    ///   - parameters: The parameters to benchmark
    ///   - iterations: Number of iterations for averaging
    /// - Returns: Average time in milliseconds
    public static func benchmark(
        parameters: ScryptParameters,
        iterations: Int = 3
    ) -> Double {
        let password = "benchmark_password_123"
        let salt = Data(repeating: 0x42, count: 16)
        
        var totalTime: Double = 0
        
        for _ in 0..<iterations {
            let start = CFAbsoluteTimeGetCurrent()
            
            do {
                let hasher = try ScryptHasher(parameters: parameters)
                _ = try hasher.hash(password: password, salt: salt)
            } catch {
                continue
            }
            
            let end = CFAbsoluteTimeGetCurrent()
            totalTime += (end - start) * 1000
        }
        
        return totalTime / Double(iterations)
    }
    
    /// Find optimal parameters for target time
    /// - Parameters:
    ///   - targetMs: Target hashing time in milliseconds
    ///   - maxMemoryMB: Maximum memory usage in MB
    /// - Returns: Optimal parameters
    public static func findOptimalParameters(
        targetMs: Double,
        maxMemoryMB: Double = 64
    ) -> ScryptParameters {
        let blockSize: UInt32 = 8
        let parallelization: UInt32 = 1
        
        // Start with low cost and increase
        var log2N = 10 // N = 1024
        
        while log2N <= 20 {
            let params = ScryptParameters(
                log2N: log2N,
                blockSize: blockSize,
                parallelization: parallelization,
                hashLength: 32
            )
            
            // Check memory constraint
            if params.memoryUsageMB > maxMemoryMB {
                break
            }
            
            let time = benchmark(parameters: params, iterations: 1)
            
            if time >= targetMs {
                return params
            }
            
            log2N += 1
        }
        
        return ScryptParameters(
            log2N: log2N - 1,
            blockSize: blockSize,
            parallelization: parallelization,
            hashLength: 32
        )
    }
    
    /// Print parameter comparison
    public static func printComparison() {
        let presets: [(String, ScryptParameters)] = [
            ("Mobile", .mobile),
            ("Interactive", .interactive),
            ("Standard", .standard),
            ("Sensitive", .sensitive),
            ("Strong", .strong)
        ]
        
        print("Scrypt Parameter Comparison:")
        print("----------------------------")
        
        for (name, params) in presets {
            let time = benchmark(parameters: params)
            print("\(name): N=\(params.costFactor), r=\(params.blockSize), p=\(params.parallelization)")
            print("  Memory: \(String(format: "%.1f", params.memoryUsageMB)) MB")
            print("  Time: \(String(format: "%.0f", time)) ms")
            print()
        }
    }
}

// MARK: - Convenience Functions

/// Quick password hashing with default parameters
public func scryptHash(password: String, salt: Data? = nil) throws -> String {
    let hasher = try ScryptHasher(parameters: .standard)
    let result: ScryptHashResult
    if let salt = salt {
        result = try hasher.hash(password: password, salt: salt)
    } else {
        result = try hasher.hash(password: password)
    }
    return result.encodedString()
}

/// Quick password verification
public func scryptVerify(password: String, encodedHash: String) throws -> Bool {
    let hasher = try ScryptHasher(parameters: .standard)
    return try hasher.verify(password: password, encodedHash: encodedHash)
}

// MARK: - Extensions

extension String {
    
    /// Hash this string using Scrypt
    public func scryptHash(parameters: ScryptParameters = .standard) throws -> String {
        let hasher = try ScryptHasher(parameters: parameters)
        let result = try hasher.hash(password: self)
        return result.encodedString()
    }
    
    /// Verify this string against a Scrypt hash
    public func scryptVerify(against encodedHash: String) throws -> Bool {
        let hasher = try ScryptHasher(parameters: .standard)
        return try hasher.verify(password: self, encodedHash: encodedHash)
    }
}

extension Data {
    
    /// Derive key from this data using Scrypt
    public func scryptDeriveKey(
        salt: Data,
        parameters: ScryptParameters = .standard,
        keyLength: Int = 32
    ) throws -> Data {
        let hasher = try ScryptHasher(parameters: parameters)
        let result = try hasher.hash(data: self, salt: salt)
        return result.hash
    }
}
