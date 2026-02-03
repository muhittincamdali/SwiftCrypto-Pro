//
//  Argon2.swift
//  SwiftCryptoPro
//
//  Created by Muhittin Camdali on 2025.
//  Copyright © 2025 Muhittin Camdali. All rights reserved.
//

import Foundation
import CryptoKit
import Security

// MARK: - Argon2 Error Types

/// Errors that can occur during Argon2 operations
public enum Argon2Error: Error, LocalizedError, Equatable {
    case invalidSaltLength
    case invalidPasswordLength
    case invalidOutputLength
    case invalidMemoryCost
    case invalidTimeCost
    case invalidParallelism
    case hashingFailed
    case verificationFailed
    case invalidEncodedHash
    case outOfMemory
    case internalError
    case invalidSecretKey
    case invalidAssociatedData
    
    public var errorDescription: String? {
        switch self {
        case .invalidSaltLength:
            return "Salt must be at least 8 bytes (16 bytes recommended)."
        case .invalidPasswordLength:
            return "Password cannot be empty."
        case .invalidOutputLength:
            return "Output length must be between 4 and 2^32 - 1 bytes."
        case .invalidMemoryCost:
            return "Memory cost must be at least 8 * parallelism KB."
        case .invalidTimeCost:
            return "Time cost (iterations) must be at least 1."
        case .invalidParallelism:
            return "Parallelism must be between 1 and 2^24 - 1."
        case .hashingFailed:
            return "Argon2 hashing operation failed."
        case .verificationFailed:
            return "Password verification failed."
        case .invalidEncodedHash:
            return "Invalid encoded Argon2 hash format."
        case .outOfMemory:
            return "Out of memory during Argon2 operation."
        case .internalError:
            return "Internal Argon2 error occurred."
        case .invalidSecretKey:
            return "Invalid secret key provided."
        case .invalidAssociatedData:
            return "Invalid associated data provided."
        }
    }
}

// MARK: - Argon2 Variant

/// Argon2 algorithm variants
public enum Argon2Variant: String, Codable, CaseIterable {
    /// Argon2d - Data-dependent, faster, vulnerable to side-channel attacks
    case argon2d = "argon2d"
    
    /// Argon2i - Data-independent, resistant to side-channel attacks
    case argon2i = "argon2i"
    
    /// Argon2id - Hybrid, recommended for password hashing
    case argon2id = "argon2id"
    
    /// The algorithm identifier for encoding
    public var identifier: String {
        return rawValue
    }
    
    /// Description
    public var description: String {
        switch self {
        case .argon2d:
            return "Argon2d (data-dependent)"
        case .argon2i:
            return "Argon2i (data-independent)"
        case .argon2id:
            return "Argon2id (hybrid)"
        }
    }
}

// MARK: - Argon2 Version

/// Argon2 version
public enum Argon2Version: Int, Codable, CaseIterable {
    case v10 = 0x10  // Version 1.0
    case v13 = 0x13  // Version 1.3 (recommended)
    
    /// String representation
    public var versionString: String {
        switch self {
        case .v10: return "v=16"
        case .v13: return "v=19"
        }
    }
}

// MARK: - Argon2 Parameters

/// Configuration parameters for Argon2
public struct Argon2Parameters: Equatable, Codable {
    
    /// The Argon2 variant to use
    public let variant: Argon2Variant
    
    /// The version of Argon2
    public let version: Argon2Version
    
    /// Memory cost in KB (m parameter)
    public let memoryCostKB: UInt32
    
    /// Time cost / iterations (t parameter)
    public let timeCost: UInt32
    
    /// Degree of parallelism (p parameter)
    public let parallelism: UInt32
    
    /// Output hash length in bytes
    public let hashLength: UInt32
    
    /// Default parameters for password hashing (OWASP 2023 recommendations)
    public static let passwordHashingDefault = Argon2Parameters(
        variant: .argon2id,
        version: .v13,
        memoryCostKB: 46 * 1024,  // 46 MB (OWASP minimum for argon2id)
        timeCost: 1,
        parallelism: 1,
        hashLength: 32
    )
    
    /// Light parameters for resource-constrained environments
    public static let light = Argon2Parameters(
        variant: .argon2id,
        version: .v13,
        memoryCostKB: 16 * 1024,  // 16 MB
        timeCost: 2,
        parallelism: 1,
        hashLength: 32
    )
    
    /// Moderate parameters (balanced security/performance)
    public static let moderate = Argon2Parameters(
        variant: .argon2id,
        version: .v13,
        memoryCostKB: 65536,  // 64 MB
        timeCost: 3,
        parallelism: 4,
        hashLength: 32
    )
    
    /// Strong parameters for high security
    public static let strong = Argon2Parameters(
        variant: .argon2id,
        version: .v13,
        memoryCostKB: 131072,  // 128 MB
        timeCost: 4,
        parallelism: 4,
        hashLength: 32
    )
    
    /// Maximum security parameters
    public static let maximum = Argon2Parameters(
        variant: .argon2id,
        version: .v13,
        memoryCostKB: 262144,  // 256 MB
        timeCost: 6,
        parallelism: 8,
        hashLength: 64
    )
    
    /// Initialize with custom parameters
    /// - Parameters:
    ///   - variant: The Argon2 variant
    ///   - version: The Argon2 version
    ///   - memoryCostKB: Memory cost in KB
    ///   - timeCost: Number of iterations
    ///   - parallelism: Degree of parallelism
    ///   - hashLength: Output hash length
    public init(
        variant: Argon2Variant = .argon2id,
        version: Argon2Version = .v13,
        memoryCostKB: UInt32,
        timeCost: UInt32,
        parallelism: UInt32,
        hashLength: UInt32 = 32
    ) {
        self.variant = variant
        self.version = version
        self.memoryCostKB = memoryCostKB
        self.timeCost = timeCost
        self.parallelism = parallelism
        self.hashLength = hashLength
    }
    
    /// Validate parameters
    public func validate() throws {
        guard timeCost >= 1 else {
            throw Argon2Error.invalidTimeCost
        }
        
        guard parallelism >= 1 && parallelism <= 0xFFFFFF else {
            throw Argon2Error.invalidParallelism
        }
        
        guard memoryCostKB >= 8 * parallelism else {
            throw Argon2Error.invalidMemoryCost
        }
        
        guard hashLength >= 4 else {
            throw Argon2Error.invalidOutputLength
        }
    }
    
    /// Calculate memory usage in bytes
    public var memoryUsageBytes: UInt64 {
        return UInt64(memoryCostKB) * 1024
    }
    
    /// Estimated hashing time (rough estimate)
    public var estimatedTimeMs: UInt32 {
        // Very rough estimate based on typical hardware
        return timeCost * (memoryCostKB / 1024) * 10
    }
}

// MARK: - Argon2 Hash Result

/// The result of an Argon2 hash operation
public struct Argon2HashResult: Equatable {
    
    /// The raw hash bytes
    public let hash: Data
    
    /// The salt used
    public let salt: Data
    
    /// The parameters used
    public let parameters: Argon2Parameters
    
    /// Encode to PHC string format
    /// Format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
    public func encodedString() -> String {
        let saltBase64 = salt.base64EncodedString()
            .replacingOccurrences(of: "+", with: ".")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        
        let hashBase64 = hash.base64EncodedString()
            .replacingOccurrences(of: "+", with: ".")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        
        return "$\(parameters.variant.identifier)$\(parameters.version.versionString)$m=\(parameters.memoryCostKB),t=\(parameters.timeCost),p=\(parameters.parallelism)$\(saltBase64)$\(hashBase64)"
    }
    
    /// Parse from PHC string format
    public static func fromEncodedString(_ encoded: String) throws -> Argon2HashResult {
        let parts = encoded.split(separator: "$", omittingEmptySubsequences: true).map { String($0) }
        
        guard parts.count == 5 else {
            throw Argon2Error.invalidEncodedHash
        }
        
        // Parse variant
        guard let variant = Argon2Variant(rawValue: parts[0]) else {
            throw Argon2Error.invalidEncodedHash
        }
        
        // Parse version
        guard parts[1].starts(with: "v="),
              let versionInt = Int(parts[1].dropFirst(2)),
              let version = Argon2Version(rawValue: versionInt) else {
            throw Argon2Error.invalidEncodedHash
        }
        
        // Parse parameters
        var memoryCost: UInt32 = 0
        var timeCost: UInt32 = 0
        var parallelism: UInt32 = 0
        
        let paramParts = parts[2].split(separator: ",")
        for param in paramParts {
            if param.starts(with: "m=") {
                memoryCost = UInt32(param.dropFirst(2)) ?? 0
            } else if param.starts(with: "t=") {
                timeCost = UInt32(param.dropFirst(2)) ?? 0
            } else if param.starts(with: "p=") {
                parallelism = UInt32(param.dropFirst(2)) ?? 0
            }
        }
        
        guard memoryCost > 0, timeCost > 0, parallelism > 0 else {
            throw Argon2Error.invalidEncodedHash
        }
        
        // Parse salt
        let saltBase64 = parts[3]
            .replacingOccurrences(of: ".", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddedSalt = saltBase64.padding(toLength: ((saltBase64.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        guard let salt = Data(base64Encoded: paddedSalt) else {
            throw Argon2Error.invalidEncodedHash
        }
        
        // Parse hash
        let hashBase64 = parts[4]
            .replacingOccurrences(of: ".", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddedHash = hashBase64.padding(toLength: ((hashBase64.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        guard let hash = Data(base64Encoded: paddedHash) else {
            throw Argon2Error.invalidEncodedHash
        }
        
        let parameters = Argon2Parameters(
            variant: variant,
            version: version,
            memoryCostKB: memoryCost,
            timeCost: timeCost,
            parallelism: parallelism,
            hashLength: UInt32(hash.count)
        )
        
        return Argon2HashResult(hash: hash, salt: salt, parameters: parameters)
    }
    
    /// Compare two hashes in constant time
    public func constantTimeEquals(_ other: Argon2HashResult) -> Bool {
        guard hash.count == other.hash.count else { return false }
        
        var result: UInt8 = 0
        for (a, b) in zip(hash, other.hash) {
            result |= a ^ b
        }
        return result == 0
    }
}

// MARK: - Argon2 Pure Swift Implementation

/// Argon2 hasher (pure Swift implementation)
public final class Argon2Hasher {
    
    /// The parameters to use
    public let parameters: Argon2Parameters
    
    /// Optional secret key
    private let secretKey: Data?
    
    /// Optional associated data
    private let associatedData: Data?
    
    /// Initialize with parameters
    public init(
        parameters: Argon2Parameters = .passwordHashingDefault,
        secretKey: Data? = nil,
        associatedData: Data? = nil
    ) throws {
        try parameters.validate()
        self.parameters = parameters
        self.secretKey = secretKey
        self.associatedData = associatedData
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
            throw Argon2Error.hashingFailed
        }
        return salt
    }
    
    // MARK: - Hashing
    
    /// Hash a password
    /// - Parameters:
    ///   - password: The password to hash
    ///   - salt: The salt to use (must be at least 8 bytes)
    /// - Returns: The hash result
    public func hash(password: String, salt: Data) throws -> Argon2HashResult {
        guard let passwordData = password.data(using: .utf8), !passwordData.isEmpty else {
            throw Argon2Error.invalidPasswordLength
        }
        return try hash(data: passwordData, salt: salt)
    }
    
    /// Hash arbitrary data
    /// - Parameters:
    ///   - data: The data to hash
    ///   - salt: The salt to use
    /// - Returns: The hash result
    public func hash(data: Data, salt: Data) throws -> Argon2HashResult {
        guard salt.count >= 8 else {
            throw Argon2Error.invalidSaltLength
        }
        
        guard !data.isEmpty else {
            throw Argon2Error.invalidPasswordLength
        }
        
        // Perform Argon2 computation
        let hash = try computeArgon2(
            password: data,
            salt: salt,
            parameters: parameters
        )
        
        return Argon2HashResult(hash: hash, salt: salt, parameters: parameters)
    }
    
    /// Hash a password with automatic salt generation
    /// - Parameter password: The password to hash
    /// - Returns: The hash result with generated salt
    public func hash(password: String) throws -> Argon2HashResult {
        let salt = try Self.generateSalt()
        return try hash(password: password, salt: salt)
    }
    
    // MARK: - Verification
    
    /// Verify a password against a hash
    /// - Parameters:
    ///   - password: The password to verify
    ///   - expectedResult: The expected hash result
    /// - Returns: True if the password matches
    public func verify(password: String, against expectedResult: Argon2HashResult) throws -> Bool {
        let computedResult = try hash(password: password, salt: expectedResult.salt)
        return computedResult.constantTimeEquals(expectedResult)
    }
    
    /// Verify a password against an encoded hash string
    /// - Parameters:
    ///   - password: The password to verify
    ///   - encodedHash: The encoded hash string
    /// - Returns: True if the password matches
    public func verify(password: String, encodedHash: String) throws -> Bool {
        let expectedResult = try Argon2HashResult.fromEncodedString(encodedHash)
        
        // Create a new hasher with the parsed parameters
        let hasher = try Argon2Hasher(parameters: expectedResult.parameters)
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
        let params = Argon2Parameters(
            variant: parameters.variant,
            version: parameters.version,
            memoryCostKB: parameters.memoryCostKB,
            timeCost: parameters.timeCost,
            parallelism: parameters.parallelism,
            hashLength: UInt32(keyLength)
        )
        
        guard let passwordData = password.data(using: .utf8) else {
            throw Argon2Error.invalidPasswordLength
        }
        
        return try computeArgon2(
            password: passwordData,
            salt: salt,
            parameters: params
        )
    }
    
    // MARK: - Argon2 Core Algorithm
    
    /// Core Argon2 computation
    private func computeArgon2(
        password: Data,
        salt: Data,
        parameters: Argon2Parameters
    ) throws -> Data {
        // Block size is 1024 bytes
        let blockSize = 1024
        
        // Calculate number of blocks
        let memoryBlocks = Int(parameters.memoryCostKB) * 1024 / blockSize
        let lanes = Int(parameters.parallelism)
        let segmentLength = memoryBlocks / (4 * lanes)
        let laneLengthBlocks = segmentLength * 4
        
        // Initialize memory
        var memory = [[UInt64]](repeating: [UInt64](repeating: 0, count: blockSize / 8), count: memoryBlocks)
        
        // Compute H0 (initial hash)
        let h0 = computeH0(
            password: password,
            salt: salt,
            parameters: parameters
        )
        
        // Initialize first two blocks of each lane
        for lane in 0..<lanes {
            let blockIndex0 = lane * laneLengthBlocks
            let blockIndex1 = lane * laneLengthBlocks + 1
            
            // Block 0: H'(H0 || 0 || lane)
            var input0 = h0
            input0.append(contentsOf: withUnsafeBytes(of: UInt32(0).littleEndian) { Data($0) })
            input0.append(contentsOf: withUnsafeBytes(of: UInt32(lane).littleEndian) { Data($0) })
            memory[blockIndex0] = hPrime(input0, outputLength: blockSize)
            
            // Block 1: H'(H0 || 1 || lane)
            var input1 = h0
            input1.append(contentsOf: withUnsafeBytes(of: UInt32(1).littleEndian) { Data($0) })
            input1.append(contentsOf: withUnsafeBytes(of: UInt32(lane).littleEndian) { Data($0) })
            memory[blockIndex1] = hPrime(input1, outputLength: blockSize)
        }
        
        // Main computation passes
        for pass in 0..<Int(parameters.timeCost) {
            for slice in 0..<4 {
                for lane in 0..<lanes {
                    fillSegment(
                        memory: &memory,
                        pass: pass,
                        lane: lane,
                        slice: slice,
                        segmentLength: segmentLength,
                        lanes: lanes,
                        laneLengthBlocks: laneLengthBlocks,
                        variant: parameters.variant
                    )
                }
            }
        }
        
        // Finalize: XOR last blocks of all lanes
        var finalBlock = memory[(lanes - 1) * laneLengthBlocks + laneLengthBlocks - 1]
        for lane in 0..<(lanes - 1) {
            let lastBlockIndex = lane * laneLengthBlocks + laneLengthBlocks - 1
            for i in 0..<finalBlock.count {
                finalBlock[i] ^= memory[lastBlockIndex][i]
            }
        }
        
        // Final hash
        var finalBlockData = Data()
        for value in finalBlock {
            finalBlockData.append(contentsOf: withUnsafeBytes(of: value.littleEndian) { Data($0) })
        }
        
        let result = hPrimeBytes(finalBlockData, outputLength: Int(parameters.hashLength))
        return result
    }
    
    /// Compute initial hash H0
    private func computeH0(password: Data, salt: Data, parameters: Argon2Parameters) -> Data {
        var input = Data()
        
        // p (parallelism)
        input.append(contentsOf: withUnsafeBytes(of: parameters.parallelism.littleEndian) { Data($0) })
        
        // T (tag length)
        input.append(contentsOf: withUnsafeBytes(of: parameters.hashLength.littleEndian) { Data($0) })
        
        // m (memory cost)
        input.append(contentsOf: withUnsafeBytes(of: parameters.memoryCostKB.littleEndian) { Data($0) })
        
        // t (time cost)
        input.append(contentsOf: withUnsafeBytes(of: parameters.timeCost.littleEndian) { Data($0) })
        
        // v (version)
        input.append(contentsOf: withUnsafeBytes(of: UInt32(parameters.version.rawValue).littleEndian) { Data($0) })
        
        // y (type: 0=argon2d, 1=argon2i, 2=argon2id)
        let typeValue: UInt32
        switch parameters.variant {
        case .argon2d: typeValue = 0
        case .argon2i: typeValue = 1
        case .argon2id: typeValue = 2
        }
        input.append(contentsOf: withUnsafeBytes(of: typeValue.littleEndian) { Data($0) })
        
        // Password length + password
        input.append(contentsOf: withUnsafeBytes(of: UInt32(password.count).littleEndian) { Data($0) })
        input.append(password)
        
        // Salt length + salt
        input.append(contentsOf: withUnsafeBytes(of: UInt32(salt.count).littleEndian) { Data($0) })
        input.append(salt)
        
        // Secret key length + secret key
        let secretLen = secretKey?.count ?? 0
        input.append(contentsOf: withUnsafeBytes(of: UInt32(secretLen).littleEndian) { Data($0) })
        if let secret = secretKey {
            input.append(secret)
        }
        
        // Associated data length + associated data
        let adLen = associatedData?.count ?? 0
        input.append(contentsOf: withUnsafeBytes(of: UInt32(adLen).littleEndian) { Data($0) })
        if let ad = associatedData {
            input.append(ad)
        }
        
        // Hash with BLAKE2b (64-byte output)
        return blake2b(input, outputLength: 64)
    }
    
    /// Fill a segment of memory
    private func fillSegment(
        memory: inout [[UInt64]],
        pass: Int,
        lane: Int,
        slice: Int,
        segmentLength: Int,
        lanes: Int,
        laneLengthBlocks: Int,
        variant: Argon2Variant
    ) {
        let startIndex = (pass == 0 && slice == 0) ? 2 : 0
        
        for index in startIndex..<segmentLength {
            let blockIndex = lane * laneLengthBlocks + slice * segmentLength + index
            
            // Previous block
            let prevIndex = (blockIndex == lane * laneLengthBlocks) ?
                lane * laneLengthBlocks + laneLengthBlocks - 1 :
                blockIndex - 1
            
            // Reference block (simplified index selection)
            let refLane: Int
            let refIndex: Int
            
            if variant == .argon2i || (variant == .argon2id && pass == 0 && slice < 2) {
                // Data-independent addressing
                let pseudoRand = generatePseudoRandom(pass: pass, lane: lane, slice: slice, index: index)
                refLane = Int(pseudoRand % UInt64(lanes))
                refIndex = Int(pseudoRand % UInt64(laneLengthBlocks))
            } else {
                // Data-dependent addressing
                let j1 = memory[prevIndex][0]
                refLane = Int(j1 >> 32) % lanes
                refIndex = Int(j1 & 0xFFFFFFFF) % laneLengthBlocks
            }
            
            // Compute new block using compression function G
            let newBlock = compressG(
                memory[prevIndex],
                memory[refLane * laneLengthBlocks + refIndex]
            )
            
            if pass == 0 {
                memory[blockIndex] = newBlock
            } else {
                // XOR with previous value
                for i in 0..<newBlock.count {
                    memory[blockIndex][i] ^= newBlock[i]
                }
            }
        }
    }
    
    /// Generate pseudo-random value for data-independent addressing
    private func generatePseudoRandom(pass: Int, lane: Int, slice: Int, index: Int) -> UInt64 {
        var input = Data()
        input.append(contentsOf: withUnsafeBytes(of: UInt64(pass).littleEndian) { Data($0) })
        input.append(contentsOf: withUnsafeBytes(of: UInt64(lane).littleEndian) { Data($0) })
        input.append(contentsOf: withUnsafeBytes(of: UInt64(slice).littleEndian) { Data($0) })
        input.append(contentsOf: withUnsafeBytes(of: UInt64(index).littleEndian) { Data($0) })
        
        let hash = blake2b(input, outputLength: 8)
        return hash.withUnsafeBytes { $0.load(as: UInt64.self) }
    }
    
    /// Compression function G (simplified)
    private func compressG(_ x: [UInt64], _ y: [UInt64]) -> [UInt64] {
        var r = [UInt64](repeating: 0, count: x.count)
        
        // XOR inputs
        for i in 0..<r.count {
            r[i] = x[i] ^ y[i]
        }
        
        // Apply permutation rounds (simplified Blake2 rounds)
        for _ in 0..<2 {
            // Row-wise mixing
            for row in 0..<8 {
                let base = row * 16
                mixG(&r, base, base + 4, base + 8, base + 12)
                mixG(&r, base + 1, base + 5, base + 9, base + 13)
                mixG(&r, base + 2, base + 6, base + 10, base + 14)
                mixG(&r, base + 3, base + 7, base + 11, base + 15)
            }
            
            // Column-wise mixing
            for col in 0..<8 {
                mixG(&r, col, col + 32, col + 64, col + 96)
                mixG(&r, col + 1, col + 33, col + 65, col + 97)
            }
        }
        
        // XOR with original
        for i in 0..<r.count {
            r[i] ^= x[i] ^ y[i]
        }
        
        return r
    }
    
    /// G mixing function
    private func mixG(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        guard a < v.count && b < v.count && c < v.count && d < v.count else { return }
        
        v[a] = v[a] &+ v[b] &+ 2 &* (v[a] & 0xFFFFFFFF) &* (v[b] & 0xFFFFFFFF)
        v[d] = rotateRight(v[d] ^ v[a], 32)
        v[c] = v[c] &+ v[d] &+ 2 &* (v[c] & 0xFFFFFFFF) &* (v[d] & 0xFFFFFFFF)
        v[b] = rotateRight(v[b] ^ v[c], 24)
        
        v[a] = v[a] &+ v[b] &+ 2 &* (v[a] & 0xFFFFFFFF) &* (v[b] & 0xFFFFFFFF)
        v[d] = rotateRight(v[d] ^ v[a], 16)
        v[c] = v[c] &+ v[d] &+ 2 &* (v[c] & 0xFFFFFFFF) &* (v[d] & 0xFFFFFFFF)
        v[b] = rotateRight(v[b] ^ v[c], 63)
    }
    
    /// Right rotation
    private func rotateRight(_ value: UInt64, _ bits: Int) -> UInt64 {
        return (value >> bits) | (value << (64 - bits))
    }
    
    /// H' function (variable-length hash)
    private func hPrime(_ input: Data, outputLength: Int) -> [UInt64] {
        let bytes = hPrimeBytes(input, outputLength: outputLength)
        var result = [UInt64]()
        for i in stride(from: 0, to: bytes.count, by: 8) {
            let end = min(i + 8, bytes.count)
            var value: UInt64 = 0
            for j in i..<end {
                value |= UInt64(bytes[j]) << (8 * (j - i))
            }
            result.append(value)
        }
        return result
    }
    
    /// H' function returning bytes
    private func hPrimeBytes(_ input: Data, outputLength: Int) -> Data {
        if outputLength <= 64 {
            var lengthBytes = Data()
            lengthBytes.append(contentsOf: withUnsafeBytes(of: UInt32(outputLength).littleEndian) { Data($0) })
            return blake2b(lengthBytes + input, outputLength: outputLength)
        }
        
        var result = Data()
        var v = blake2b(withUnsafeBytes(of: UInt32(outputLength).littleEndian) { Data($0) } + input, outputLength: 64)
        result.append(v.prefix(32))
        
        var remaining = outputLength - 32
        while remaining > 64 {
            v = blake2b(v, outputLength: 64)
            result.append(v.prefix(32))
            remaining -= 32
        }
        
        v = blake2b(v, outputLength: remaining)
        result.append(v)
        
        return result
    }
    
    /// BLAKE2b hash (using CryptoKit's SHA512 as fallback since BLAKE2b isn't in CryptoKit)
    private func blake2b(_ input: Data, outputLength: Int) -> Data {
        // Use SHA512 as a substitute since CryptoKit doesn't have BLAKE2b
        // In production, you'd want to use a proper BLAKE2b implementation
        let hash = SHA512.hash(data: input)
        var result = Data(hash)
        
        if outputLength < result.count {
            result = Data(result.prefix(outputLength))
        } else if outputLength > result.count {
            // Extend with additional hashing
            while result.count < outputLength {
                let additional = SHA512.hash(data: result)
                result.append(contentsOf: additional.prefix(min(64, outputLength - result.count)))
            }
        }
        
        return result
    }
}

// MARK: - Convenience Functions

/// Quick password hashing with default parameters
public func argon2Hash(password: String, salt: Data? = nil) throws -> String {
    let hasher = try Argon2Hasher(parameters: .passwordHashingDefault)
    let result: Argon2HashResult
    if let salt = salt {
        result = try hasher.hash(password: password, salt: salt)
    } else {
        result = try hasher.hash(password: password)
    }
    return result.encodedString()
}

/// Quick password verification
public func argon2Verify(password: String, encodedHash: String) throws -> Bool {
    let hasher = try Argon2Hasher(parameters: .passwordHashingDefault)
    return try hasher.verify(password: password, encodedHash: encodedHash)
}

// MARK: - Extensions

extension String {
    
    /// Hash this string using Argon2
    public func argon2Hash(parameters: Argon2Parameters = .passwordHashingDefault) throws -> String {
        let hasher = try Argon2Hasher(parameters: parameters)
        let result = try hasher.hash(password: self)
        return result.encodedString()
    }
    
    /// Verify this string against an Argon2 hash
    public func argon2Verify(against encodedHash: String) throws -> Bool {
        let hasher = try Argon2Hasher(parameters: .passwordHashingDefault)
        return try hasher.verify(password: self, encodedHash: encodedHash)
    }
}
