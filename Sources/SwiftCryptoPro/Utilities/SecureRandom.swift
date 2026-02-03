import Foundation
import Security
import CryptoKit

// MARK: - Secure Random Number Generator

/// A cryptographically secure random number generator.
///
/// This class provides various methods for generating cryptographically secure
/// random data, numbers, and strings using Apple's Security framework.
///
/// ## Features
/// - Cryptographically secure random bytes generation
/// - Type-safe random number generation for all numeric types
/// - Secure string generation with customizable character sets
/// - UUID and token generation
/// - Shuffling and random selection
///
/// ## Usage
/// ```swift
/// // Generate random bytes
/// let bytes = SecureRandom.bytes(count: 32)
///
/// // Generate random integer in range
/// let number = SecureRandom.int(in: 1...100)
///
/// // Generate random password
/// let password = SecureRandom.password(length: 16)
///
/// // Generate cryptographic key
/// let key = SecureRandom.symmetricKey(bits: 256)
/// ```
///
/// ## Security Notes
/// - Uses `SecRandomCopyBytes` from the Security framework
/// - Suitable for cryptographic purposes (keys, IVs, nonces)
/// - Thread-safe for concurrent access
public struct SecureRandom {
    
    // MARK: - Character Sets
    
    /// Predefined character sets for random string generation.
    public enum CharacterSet {
        /// Lowercase letters (a-z)
        case lowercase
        
        /// Uppercase letters (A-Z)
        case uppercase
        
        /// All letters (a-z, A-Z)
        case letters
        
        /// Decimal digits (0-9)
        case digits
        
        /// Alphanumeric characters (a-z, A-Z, 0-9)
        case alphanumeric
        
        /// URL-safe base64 characters (a-z, A-Z, 0-9, -, _)
        case urlSafe
        
        /// Hexadecimal characters (0-9, a-f)
        case hex
        
        /// All printable ASCII characters
        case printable
        
        /// Custom character set
        case custom(String)
        
        /// The string of characters in this set.
        public var characters: String {
            switch self {
            case .lowercase:
                return "abcdefghijklmnopqrstuvwxyz"
            case .uppercase:
                return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            case .letters:
                return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            case .digits:
                return "0123456789"
            case .alphanumeric:
                return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            case .urlSafe:
                return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            case .hex:
                return "0123456789abcdef"
            case .printable:
                return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
            case .custom(let chars):
                return chars
            }
        }
    }
    
    /// Errors that can occur during random generation.
    public enum SecureRandomError: LocalizedError {
        case generationFailed(OSStatus)
        case invalidLength
        case emptyCharacterSet
        case invalidRange
        
        public var errorDescription: String? {
            switch self {
            case .generationFailed(let status):
                return "Random generation failed with status: \(status)"
            case .invalidLength:
                return "Invalid length specified."
            case .emptyCharacterSet:
                return "Character set cannot be empty."
            case .invalidRange:
                return "Invalid range specified."
            }
        }
    }
    
    // MARK: - Initialization
    
    /// Private initializer - all methods are static.
    private init() {}
    
    // MARK: - Raw Bytes Generation
    
    /// Generates cryptographically secure random bytes.
    ///
    /// - Parameter count: The number of bytes to generate.
    /// - Returns: An array of random bytes.
    /// - Throws: `SecureRandomError.generationFailed` if generation fails.
    public static func bytes(count: Int) throws -> [UInt8] {
        guard count > 0 else {
            throw SecureRandomError.invalidLength
        }
        
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        
        guard status == errSecSuccess else {
            throw SecureRandomError.generationFailed(status)
        }
        
        return bytes
    }
    
    /// Generates cryptographically secure random data.
    ///
    /// - Parameter count: The number of bytes to generate.
    /// - Returns: Random data of the specified length.
    public static func data(count: Int) throws -> Data {
        let randomBytes = try bytes(count: count)
        return Data(randomBytes)
    }
    
    /// Generates random bytes without throwing (returns empty on error).
    ///
    /// - Parameter count: The number of bytes to generate.
    /// - Returns: Random bytes or empty array on failure.
    public static func bytesOrEmpty(count: Int) -> [UInt8] {
        return (try? bytes(count: count)) ?? []
    }
    
    /// Fills a buffer with random bytes.
    ///
    /// - Parameter buffer: The buffer to fill.
    /// - Returns: `true` if successful.
    @discardableResult
    public static func fill(_ buffer: inout [UInt8]) -> Bool {
        guard !buffer.isEmpty else { return true }
        let status = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
        return status == errSecSuccess
    }
    
    // MARK: - Integer Generation
    
    /// Generates a random UInt8.
    ///
    /// - Returns: A random value in the full UInt8 range.
    public static func uint8() -> UInt8 {
        var value: UInt8 = 0
        _ = SecRandomCopyBytes(kSecRandomDefault, 1, &value)
        return value
    }
    
    /// Generates a random UInt16.
    ///
    /// - Returns: A random value in the full UInt16 range.
    public static func uint16() -> UInt16 {
        var value: UInt16 = 0
        withUnsafeMutableBytes(of: &value) { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 2, ptr.baseAddress!)
        }
        return value
    }
    
    /// Generates a random UInt32.
    ///
    /// - Returns: A random value in the full UInt32 range.
    public static func uint32() -> UInt32 {
        var value: UInt32 = 0
        withUnsafeMutableBytes(of: &value) { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 4, ptr.baseAddress!)
        }
        return value
    }
    
    /// Generates a random UInt64.
    ///
    /// - Returns: A random value in the full UInt64 range.
    public static func uint64() -> UInt64 {
        var value: UInt64 = 0
        withUnsafeMutableBytes(of: &value) { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 8, ptr.baseAddress!)
        }
        return value
    }
    
    /// Generates a random Int in a closed range.
    ///
    /// - Parameter range: The closed range.
    /// - Returns: A random value within the range.
    public static func int(in range: ClosedRange<Int>) -> Int {
        guard range.lowerBound < range.upperBound else {
            return range.lowerBound
        }
        
        let span = UInt64(bitPattern: Int64(range.upperBound) - Int64(range.lowerBound))
        let random = uniformRandom(upperBound: span + 1)
        return range.lowerBound + Int(random)
    }
    
    /// Generates a random Int in a half-open range.
    ///
    /// - Parameter range: The half-open range.
    /// - Returns: A random value within the range.
    public static func int(in range: Range<Int>) -> Int {
        guard !range.isEmpty else { return range.lowerBound }
        return int(in: range.lowerBound...(range.upperBound - 1))
    }
    
    /// Generates a random UInt32 in a closed range.
    ///
    /// - Parameter range: The closed range.
    /// - Returns: A random value within the range.
    public static func uint32(in range: ClosedRange<UInt32>) -> UInt32 {
        guard range.lowerBound < range.upperBound else {
            return range.lowerBound
        }
        
        let span = UInt64(range.upperBound - range.lowerBound)
        let random = uniformRandom(upperBound: span + 1)
        return range.lowerBound + UInt32(random)
    }
    
    /// Generates a uniformly distributed random UInt64 less than upperBound.
    ///
    /// This uses rejection sampling to avoid modulo bias.
    private static func uniformRandom(upperBound: UInt64) -> UInt64 {
        guard upperBound > 0 else { return 0 }
        guard upperBound > 1 else { return 0 }
        
        // Calculate the largest multiple of upperBound that fits in UInt64
        let limit = UInt64.max - (UInt64.max % upperBound)
        
        var random: UInt64
        repeat {
            random = uint64()
        } while random >= limit
        
        return random % upperBound
    }
    
    // MARK: - Floating Point Generation
    
    /// Generates a random Double in [0, 1).
    ///
    /// - Returns: A random double between 0 (inclusive) and 1 (exclusive).
    public static func double() -> Double {
        let value = uint64()
        // Use 53 bits for full double mantissa precision
        return Double(value >> 11) * (1.0 / Double(1 << 53))
    }
    
    /// Generates a random Double in a range.
    ///
    /// - Parameter range: The closed range.
    /// - Returns: A random double within the range.
    public static func double(in range: ClosedRange<Double>) -> Double {
        return range.lowerBound + double() * (range.upperBound - range.lowerBound)
    }
    
    /// Generates a random Float in [0, 1).
    ///
    /// - Returns: A random float between 0 (inclusive) and 1 (exclusive).
    public static func float() -> Float {
        let value = uint32()
        // Use 24 bits for full float mantissa precision
        return Float(value >> 8) * (1.0 / Float(1 << 24))
    }
    
    // MARK: - Boolean Generation
    
    /// Generates a random boolean.
    ///
    /// - Returns: `true` or `false` with equal probability.
    public static func bool() -> Bool {
        return uint8() & 1 == 1
    }
    
    /// Generates a random boolean with specified true probability.
    ///
    /// - Parameter probability: The probability of returning `true` (0.0 to 1.0).
    /// - Returns: A random boolean.
    public static func bool(trueProbability probability: Double) -> Bool {
        return double() < probability
    }
    
    // MARK: - String Generation
    
    /// Generates a random string from a character set.
    ///
    /// - Parameters:
    ///   - length: The length of the string to generate.
    ///   - characterSet: The character set to use.
    /// - Returns: A random string.
    /// - Throws: `SecureRandomError` if generation fails.
    public static func string(
        length: Int,
        characterSet: CharacterSet = .alphanumeric
    ) throws -> String {
        guard length > 0 else {
            throw SecureRandomError.invalidLength
        }
        
        let chars = characterSet.characters
        guard !chars.isEmpty else {
            throw SecureRandomError.emptyCharacterSet
        }
        
        let charArray = Array(chars)
        var result = ""
        result.reserveCapacity(length)
        
        for _ in 0..<length {
            let index = int(in: 0..<charArray.count)
            result.append(charArray[index])
        }
        
        return result
    }
    
    /// Generates a random alphanumeric string.
    ///
    /// - Parameter length: The length of the string.
    /// - Returns: A random alphanumeric string.
    public static func alphanumeric(length: Int) -> String {
        return (try? string(length: length, characterSet: .alphanumeric)) ?? ""
    }
    
    /// Generates a random hexadecimal string.
    ///
    /// - Parameter length: The length of the string.
    /// - Returns: A random hex string.
    public static func hex(length: Int) -> String {
        return (try? string(length: length, characterSet: .hex)) ?? ""
    }
    
    /// Generates a secure password with mixed character types.
    ///
    /// - Parameters:
    ///   - length: The length of the password.
    ///   - includeSymbols: Whether to include special characters.
    /// - Returns: A random password.
    public static func password(length: Int, includeSymbols: Bool = true) -> String {
        let charset: CharacterSet = includeSymbols ? .printable : .alphanumeric
        
        guard length >= 8 else {
            return (try? string(length: length, characterSet: charset)) ?? ""
        }
        
        // Ensure at least one of each required character type
        var password = [Character]()
        password.reserveCapacity(length)
        
        // Add required characters
        let lowercase = "abcdefghijklmnopqrstuvwxyz"
        let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        let digits = "0123456789"
        let symbols = "!@#$%^&*()-_=+[]{}|;:',.<>?/"
        
        password.append(lowercase.randomElement(using: &SystemRandomNumberGenerator())!)
        password.append(uppercase.randomElement(using: &SystemRandomNumberGenerator())!)
        password.append(digits.randomElement(using: &SystemRandomNumberGenerator())!)
        
        if includeSymbols {
            password.append(symbols.randomElement(using: &SystemRandomNumberGenerator())!)
        }
        
        // Fill remaining with random characters
        let allChars = charset.characters
        while password.count < length {
            let index = int(in: 0..<allChars.count)
            password.append(Array(allChars)[index])
        }
        
        // Shuffle the password
        return String(shuffle(password))
    }
    
    /// Generates a passphrase of random words.
    ///
    /// - Parameters:
    ///   - wordCount: The number of words.
    ///   - separator: The separator between words.
    ///   - wordList: The word list to use (defaults to common words).
    /// - Returns: A random passphrase.
    public static func passphrase(
        wordCount: Int = 4,
        separator: String = "-",
        wordList: [String]? = nil
    ) -> String {
        let words = wordList ?? defaultWordList
        guard !words.isEmpty, wordCount > 0 else { return "" }
        
        var selected = [String]()
        for _ in 0..<wordCount {
            let index = int(in: 0..<words.count)
            selected.append(words[index])
        }
        
        return selected.joined(separator: separator)
    }
    
    // MARK: - Token Generation
    
    /// Generates a URL-safe random token.
    ///
    /// - Parameter length: The length of the token.
    /// - Returns: A URL-safe token string.
    public static func token(length: Int = 32) -> String {
        return (try? string(length: length, characterSet: .urlSafe)) ?? ""
    }
    
    /// Generates a random UUID.
    ///
    /// - Returns: A new UUID.
    public static func uuid() -> UUID {
        return UUID()
    }
    
    /// Generates a random UUID string.
    ///
    /// - Returns: A UUID string in standard format.
    public static func uuidString() -> String {
        return uuid().uuidString
    }
    
    // MARK: - Cryptographic Keys
    
    /// Generates a CryptoKit symmetric key.
    ///
    /// - Parameter bits: The key size in bits (128, 192, or 256).
    /// - Returns: A symmetric key.
    public static func symmetricKey(bits: Int = 256) -> SymmetricKey {
        return SymmetricKey(size: SymmetricKeySize(bitCount: bits))
    }
    
    /// Generates an initialization vector (IV).
    ///
    /// - Parameter bytes: The IV length in bytes (default: 12 for AES-GCM).
    /// - Returns: Random IV data.
    public static func iv(bytes: Int = 12) -> Data {
        return (try? data(count: bytes)) ?? Data()
    }
    
    /// Generates a nonce for authenticated encryption.
    ///
    /// - Parameter bytes: The nonce length in bytes.
    /// - Returns: Random nonce data.
    public static func nonce(bytes: Int = 12) -> Data {
        return iv(bytes: bytes)
    }
    
    /// Generates a salt for password hashing.
    ///
    /// - Parameter bytes: The salt length in bytes (default: 32).
    /// - Returns: Random salt data.
    public static func salt(bytes: Int = 32) -> Data {
        return (try? data(count: bytes)) ?? Data()
    }
    
    // MARK: - Collection Operations
    
    /// Shuffles an array using secure random numbers.
    ///
    /// - Parameter array: The array to shuffle.
    /// - Returns: A shuffled copy of the array.
    public static func shuffle<T>(_ array: [T]) -> [T] {
        var result = array
        shuffleInPlace(&result)
        return result
    }
    
    /// Shuffles an array in place using secure random numbers.
    ///
    /// - Parameter array: The array to shuffle.
    public static func shuffleInPlace<T>(_ array: inout [T]) {
        guard array.count > 1 else { return }
        
        for i in stride(from: array.count - 1, through: 1, by: -1) {
            let j = int(in: 0...i)
            if i != j {
                array.swapAt(i, j)
            }
        }
    }
    
    /// Selects a random element from an array.
    ///
    /// - Parameter array: The array to select from.
    /// - Returns: A random element, or nil if empty.
    public static func element<T>(from array: [T]) -> T? {
        guard !array.isEmpty else { return nil }
        let index = int(in: 0..<array.count)
        return array[index]
    }
    
    /// Selects multiple unique random elements from an array.
    ///
    /// - Parameters:
    ///   - count: The number of elements to select.
    ///   - array: The array to select from.
    /// - Returns: An array of randomly selected unique elements.
    public static func elements<T>(_ count: Int, from array: [T]) -> [T] {
        guard count > 0, !array.isEmpty else { return [] }
        
        if count >= array.count {
            return shuffle(array)
        }
        
        var result = [T]()
        var available = array
        
        for _ in 0..<count {
            let index = int(in: 0..<available.count)
            result.append(available.remove(at: index))
        }
        
        return result
    }
    
    // MARK: - Default Word List
    
    /// Default word list for passphrase generation.
    private static let defaultWordList = [
        "apple", "arrow", "badge", "beach", "berry", "bloom", "brave", "brick",
        "brush", "cabin", "candy", "cargo", "charm", "chase", "chess", "chill",
        "climb", "cloud", "coral", "couch", "craft", "crane", "crisp", "crown",
        "dance", "depth", "diary", "dream", "drift", "eagle", "earth", "ember",
        "fable", "fairy", "feast", "field", "flame", "flash", "float", "flora",
        "flute", "focus", "forge", "frost", "fruit", "giant", "glass", "gleam",
        "globe", "grace", "grain", "grape", "grass", "grove", "guard", "guest",
        "heart", "honey", "horizon", "house", "ivory", "jewel", "judge", "juice",
        "karma", "kayak", "kiosk", "knife", "knock", "label", "lance", "latch",
        "laugh", "layer", "lemon", "light", "lilac", "linen", "locus", "logic",
        "lotus", "lucky", "lunar", "magic", "maple", "march", "marsh", "medal",
        "melon", "mercy", "merit", "metal", "metro", "mirth", "model", "money",
        "month", "moose", "mount", "music", "noble", "noise", "north", "novel",
        "ocean", "olive", "onion", "opera", "orbit", "otter", "ozone", "paint",
        "panic", "paper", "party", "patch", "peace", "pearl", "penny", "piano",
        "pilot", "pixel", "pizza", "place", "plain", "plant", "plaza", "plumb",
        "point", "polar", "porch", "power", "press", "pride", "prime", "print",
        "prize", "proof", "pulse", "punch", "queen", "quest", "quick", "quiet"
    ]
}

// MARK: - Secure Random Generator (for RandomNumberGenerator protocol)

/// A RandomNumberGenerator using SecRandomCopyBytes.
public struct SecureRandomGenerator: RandomNumberGenerator {
    
    public init() {}
    
    public mutating func next() -> UInt64 {
        return SecureRandom.uint64()
    }
}

// MARK: - Collection Extensions

extension Array {
    
    /// Returns a securely shuffled copy of the array.
    public func securelyShuffled() -> [Element] {
        return SecureRandom.shuffle(self)
    }
    
    /// Shuffles the array in place using secure random numbers.
    public mutating func securelyShuffle() {
        SecureRandom.shuffleInPlace(&self)
    }
    
    /// Returns a random element using secure random.
    public func secureRandomElement() -> Element? {
        return SecureRandom.element(from: self)
    }
}
