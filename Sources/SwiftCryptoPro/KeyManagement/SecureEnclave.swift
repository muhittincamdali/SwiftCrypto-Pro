import Foundation
import Security
import CryptoKit
import LocalAuthentication

// MARK: - Secure Enclave Manager

/// Provides secure key management using the Apple Secure Enclave.
///
/// The Secure Enclave is a hardware-based security processor that provides
/// an additional layer of security for cryptographic operations. Private keys
/// created in the Secure Enclave never leave the hardware.
///
/// ## Features
/// - Hardware-backed key generation (P-256 elliptic curve)
/// - Biometric-protected key access
/// - Secure signing and key agreement operations
/// - Key persistence across app launches
///
/// ## Usage
/// ```swift
/// let secureEnclave = SecureEnclaveManager()
///
/// // Generate a new key pair
/// let keyPair = try secureEnclave.generateKeyPair(
///     tag: "com.app.signing-key",
///     biometricProtection: true
/// )
///
/// // Sign data
/// let signature = try secureEnclave.sign(
///     data: messageData,
///     keyTag: "com.app.signing-key"
/// )
///
/// // Verify signature (can be done without Secure Enclave)
/// let isValid = secureEnclave.verify(
///     data: messageData,
///     signature: signature,
///     publicKey: keyPair.publicKey
/// )
/// ```
///
/// ## Requirements
/// - Device with Secure Enclave (iPhone 5s+, iPad Air+, Mac with T1/T2/Apple Silicon)
/// - iOS 11+ / macOS 10.13+
///
/// - Important: Keys stored in the Secure Enclave cannot be exported or backed up.
///   If the device is reset, all Secure Enclave keys are permanently lost.
@available(iOS 11.0, macOS 10.13, *)
public final class SecureEnclaveManager {
    
    // MARK: - Types
    
    /// A key pair with the public key accessible for verification.
    public struct KeyPair {
        /// The tag identifying the key in the keychain
        public let tag: String
        
        /// The public key (exportable)
        public let publicKey: SecKey
        
        /// The public key as raw data (X9.63 format)
        public var publicKeyData: Data? {
            var error: Unmanaged<CFError>?
            guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
                return nil
            }
            return data
        }
        
        /// The public key as a base64 string
        public var publicKeyBase64: String? {
            publicKeyData?.base64EncodedString()
        }
    }
    
    /// Access control options for key protection.
    public struct AccessControl {
        /// Require biometric authentication (Face ID / Touch ID)
        public var biometricOnly: Bool
        
        /// Require device passcode as fallback
        public var passcodeAsBackup: Bool
        
        /// Require authentication for each use
        public var requireAuthenticationPerUse: Bool
        
        /// Authentication validity duration in seconds (0 = always require)
        public var authenticationValidityDuration: TimeInterval
        
        /// Creates default access control with biometric protection.
        public static let biometric = AccessControl(
            biometricOnly: true,
            passcodeAsBackup: false,
            requireAuthenticationPerUse: true,
            authenticationValidityDuration: 0
        )
        
        /// Creates access control with biometric + passcode fallback.
        public static let biometricOrPasscode = AccessControl(
            biometricOnly: false,
            passcodeAsBackup: true,
            requireAuthenticationPerUse: true,
            authenticationValidityDuration: 0
        )
        
        /// Creates access control without biometric (device presence only).
        public static let devicePresence = AccessControl(
            biometricOnly: false,
            passcodeAsBackup: false,
            requireAuthenticationPerUse: false,
            authenticationValidityDuration: 0
        )
        
        public init(
            biometricOnly: Bool = true,
            passcodeAsBackup: Bool = false,
            requireAuthenticationPerUse: Bool = true,
            authenticationValidityDuration: TimeInterval = 0
        ) {
            self.biometricOnly = biometricOnly
            self.passcodeAsBackup = passcodeAsBackup
            self.requireAuthenticationPerUse = requireAuthenticationPerUse
            self.authenticationValidityDuration = authenticationValidityDuration
        }
    }
    
    /// Errors that can occur during Secure Enclave operations.
    public enum SecureEnclaveError: LocalizedError {
        case notAvailable
        case keyGenerationFailed(OSStatus)
        case keyNotFound
        case signingFailed(Error)
        case verificationFailed
        case encryptionFailed(Error)
        case decryptionFailed(Error)
        case keyAgreementFailed(Error)
        case invalidPublicKey
        case accessControlCreationFailed
        case authenticationFailed(Error)
        case keyDeletionFailed(OSStatus)
        case duplicateKeyTag
        case invalidKeyData
        
        public var errorDescription: String? {
            switch self {
            case .notAvailable:
                return "Secure Enclave is not available on this device."
            case .keyGenerationFailed(let status):
                return "Key generation failed with status: \(status)"
            case .keyNotFound:
                return "The requested key was not found."
            case .signingFailed(let error):
                return "Signing operation failed: \(error.localizedDescription)"
            case .verificationFailed:
                return "Signature verification failed."
            case .encryptionFailed(let error):
                return "Encryption failed: \(error.localizedDescription)"
            case .decryptionFailed(let error):
                return "Decryption failed: \(error.localizedDescription)"
            case .keyAgreementFailed(let error):
                return "Key agreement failed: \(error.localizedDescription)"
            case .invalidPublicKey:
                return "The provided public key is invalid."
            case .accessControlCreationFailed:
                return "Failed to create access control for key."
            case .authenticationFailed(let error):
                return "User authentication failed: \(error.localizedDescription)"
            case .keyDeletionFailed(let status):
                return "Key deletion failed with status: \(status)"
            case .duplicateKeyTag:
                return "A key with this tag already exists."
            case .invalidKeyData:
                return "The key data is invalid or corrupted."
            }
        }
    }
    
    // MARK: - Properties
    
    /// Shared instance for convenience.
    public static let shared = SecureEnclaveManager()
    
    /// The LAContext for biometric authentication.
    private var authContext: LAContext?
    
    // MARK: - Initialization
    
    /// Creates a new Secure Enclave manager.
    public init() {}
    
    // MARK: - Availability Check
    
    /// Checks if the Secure Enclave is available on this device.
    ///
    /// - Returns: `true` if Secure Enclave is available.
    public var isAvailable: Bool {
        // Check if we can create a test access control for SE
        var error: Unmanaged<CFError>?
        guard let _ = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else {
            return false
        }
        
        #if targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
    }
    
    /// Checks if biometric authentication is available.
    ///
    /// - Returns: `true` if biometrics (Face ID or Touch ID) are available.
    public var isBiometricAvailable: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    /// Returns the type of biometric authentication available.
    ///
    /// - Returns: The biometry type (.faceID, .touchID, or .none).
    public var biometryType: LABiometryType {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType
    }
    
    // MARK: - Key Generation
    
    /// Generates a new key pair in the Secure Enclave.
    ///
    /// - Parameters:
    ///   - tag: Unique identifier for the key (e.g., "com.app.signing-key").
    ///   - accessControl: Access control settings for the key.
    ///   - overwriteExisting: If true, deletes any existing key with the same tag.
    /// - Returns: A `KeyPair` containing the tag and public key.
    /// - Throws: `SecureEnclaveError` if generation fails.
    public func generateKeyPair(
        tag: String,
        accessControl: AccessControl = .biometric,
        overwriteExisting: Bool = false
    ) throws -> KeyPair {
        guard isAvailable else {
            throw SecureEnclaveError.notAvailable
        }
        
        // Check for existing key
        if keyExists(tag: tag) {
            if overwriteExisting {
                try deleteKey(tag: tag)
            } else {
                throw SecureEnclaveError.duplicateKeyTag
            }
        }
        
        // Create access control
        guard let access = createAccessControl(from: accessControl) else {
            throw SecureEnclaveError.accessControlCreationFailed
        }
        
        let tagData = tag.data(using: .utf8)!
        
        // Key attributes
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData,
                kSecAttrAccessControl as String: access
            ] as [String: Any]
        ]
        
        #if os(macOS)
        // On macOS, we need additional attributes
        attributes[kSecAttrKeyClass as String] = kSecAttrKeyClassPrivate
        #endif
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let err = error?.takeRetainedValue() {
                let nsError = err as Error as NSError
                throw SecureEnclaveError.keyGenerationFailed(OSStatus(nsError.code))
            }
            throw SecureEnclaveError.keyGenerationFailed(errSecParam)
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveError.keyGenerationFailed(errSecParam)
        }
        
        return KeyPair(tag: tag, publicKey: publicKey)
    }
    
    /// Generates a key pair with biometric protection.
    ///
    /// - Parameters:
    ///   - tag: Unique identifier for the key.
    ///   - reason: The reason to display for biometric prompt.
    /// - Returns: A `KeyPair` containing the tag and public key.
    public func generateBiometricKey(
        tag: String,
        reason: String = "Authenticate to create secure key"
    ) throws -> KeyPair {
        return try generateKeyPair(
            tag: tag,
            accessControl: .biometric,
            overwriteExisting: false
        )
    }
    
    // MARK: - Key Retrieval
    
    /// Retrieves an existing key pair by tag.
    ///
    /// - Parameter tag: The key's unique identifier.
    /// - Returns: The `KeyPair` if found.
    /// - Throws: `SecureEnclaveError.keyNotFound` if the key doesn't exist.
    public func getKeyPair(tag: String) throws -> KeyPair {
        guard let privateKey = try getPrivateKey(tag: tag) else {
            throw SecureEnclaveError.keyNotFound
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveError.keyNotFound
        }
        
        return KeyPair(tag: tag, publicKey: publicKey)
    }
    
    /// Checks if a key exists with the given tag.
    ///
    /// - Parameter tag: The key's unique identifier.
    /// - Returns: `true` if the key exists.
    public func keyExists(tag: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: false
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /// Lists all Secure Enclave key tags.
    ///
    /// - Returns: Array of key tags.
    public func listKeys() -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }
        
        return items.compactMap { dict in
            if let tagData = dict[kSecAttrApplicationTag as String] as? Data {
                return String(data: tagData, encoding: .utf8)
            }
            return nil
        }
    }
    
    // MARK: - Signing
    
    /// Signs data using a Secure Enclave private key.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    ///   - keyTag: The tag of the signing key.
    ///   - reason: Authentication reason for biometric prompt.
    /// - Returns: The signature data.
    /// - Throws: `SecureEnclaveError` if signing fails.
    public func sign(
        data: Data,
        keyTag: String,
        reason: String = "Authenticate to sign data"
    ) throws -> Data {
        guard let privateKey = try getPrivateKey(tag: keyTag, reason: reason) else {
            throw SecureEnclaveError.keyNotFound
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            if let err = error?.takeRetainedValue() {
                throw SecureEnclaveError.signingFailed(err as Error)
            }
            throw SecureEnclaveError.signingFailed(SecureEnclaveError.keyNotFound)
        }
        
        return signature
    }
    
    /// Signs a string message.
    ///
    /// - Parameters:
    ///   - message: The message to sign.
    ///   - keyTag: The tag of the signing key.
    /// - Returns: Base64-encoded signature.
    public func sign(message: String, keyTag: String) throws -> String {
        guard let data = message.data(using: .utf8) else {
            throw SecureEnclaveError.invalidKeyData
        }
        let signature = try sign(data: data, keyTag: keyTag)
        return signature.base64EncodedString()
    }
    
    // MARK: - Verification
    
    /// Verifies a signature using the public key.
    ///
    /// - Parameters:
    ///   - data: The original data that was signed.
    ///   - signature: The signature to verify.
    ///   - publicKey: The public key for verification.
    /// - Returns: `true` if the signature is valid.
    public func verify(data: Data, signature: Data, publicKey: SecKey) -> Bool {
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            signature as CFData,
            &error
        )
        return result
    }
    
    /// Verifies a signature using a key tag.
    ///
    /// - Parameters:
    ///   - data: The original data.
    ///   - signature: The signature to verify.
    ///   - keyTag: The tag of the key pair.
    /// - Returns: `true` if valid.
    public func verify(data: Data, signature: Data, keyTag: String) throws -> Bool {
        let keyPair = try getKeyPair(tag: keyTag)
        return verify(data: data, signature: signature, publicKey: keyPair.publicKey)
    }
    
    /// Verifies a signature from public key data (X9.63 format).
    ///
    /// - Parameters:
    ///   - data: The original data.
    ///   - signature: The signature to verify.
    ///   - publicKeyData: The public key in X9.63 format.
    /// - Returns: `true` if valid.
    public func verify(data: Data, signature: Data, publicKeyData: Data) throws -> Bool {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(
            publicKeyData as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            throw SecureEnclaveError.invalidPublicKey
        }
        
        return verify(data: data, signature: signature, publicKey: publicKey)
    }
    
    // MARK: - Key Agreement (ECDH)
    
    /// Performs ECDH key agreement to derive a shared secret.
    ///
    /// - Parameters:
    ///   - keyTag: The tag of the local private key.
    ///   - peerPublicKey: The peer's public key.
    /// - Returns: The shared secret data.
    public func keyAgreement(
        keyTag: String,
        peerPublicKey: SecKey
    ) throws -> Data {
        guard let privateKey = try getPrivateKey(tag: keyTag) else {
            throw SecureEnclaveError.keyNotFound
        }
        
        let parameters: [String: Any] = [:]
        var error: Unmanaged<CFError>?
        
        guard let sharedSecret = SecKeyCopyKeyExchangeResult(
            privateKey,
            .ecdhKeyExchangeStandard,
            peerPublicKey,
            parameters as CFDictionary,
            &error
        ) as Data? else {
            if let err = error?.takeRetainedValue() {
                throw SecureEnclaveError.keyAgreementFailed(err as Error)
            }
            throw SecureEnclaveError.keyAgreementFailed(SecureEnclaveError.keyNotFound)
        }
        
        return sharedSecret
    }
    
    /// Performs key agreement with public key data.
    ///
    /// - Parameters:
    ///   - keyTag: The local private key tag.
    ///   - peerPublicKeyData: The peer's public key in X9.63 format.
    /// - Returns: The shared secret.
    public func keyAgreement(
        keyTag: String,
        peerPublicKeyData: Data
    ) throws -> Data {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        
        var error: Unmanaged<CFError>?
        guard let peerKey = SecKeyCreateWithData(
            peerPublicKeyData as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            throw SecureEnclaveError.invalidPublicKey
        }
        
        return try keyAgreement(keyTag: keyTag, peerPublicKey: peerKey)
    }
    
    // MARK: - Key Deletion
    
    /// Deletes a key from the Secure Enclave.
    ///
    /// - Parameter tag: The key's unique identifier.
    /// - Throws: `SecureEnclaveError.keyDeletionFailed` if deletion fails.
    public func deleteKey(tag: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureEnclaveError.keyDeletionFailed(status)
        }
    }
    
    /// Deletes all Secure Enclave keys created by this app.
    ///
    /// - Warning: This action is irreversible.
    public func deleteAllKeys() throws {
        for tag in listKeys() {
            try deleteKey(tag: tag)
        }
    }
    
    // MARK: - Private Helpers
    
    /// Retrieves the private key reference.
    private func getPrivateKey(
        tag: String,
        reason: String = "Authenticate to access key"
    ) throws -> SecKey? {
        let context = LAContext()
        context.localizedReason = reason
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context
        ]
        
        #if !os(macOS)
        query[kSecUseOperationPrompt as String] = reason
        #endif
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return nil
            }
            throw SecureEnclaveError.keyNotFound
        }
        
        return (result as! SecKey)
    }
    
    /// Creates SecAccessControl from AccessControl options.
    private func createAccessControl(from options: AccessControl) -> SecAccessControl? {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        
        if options.biometricOnly {
            flags.insert(.biometryCurrentSet)
        } else if options.passcodeAsBackup {
            flags.insert(.userPresence)
        }
        
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        )
        
        return access
    }
}

// MARK: - CryptoKit Integration

@available(iOS 13.0, macOS 10.15, *)
extension SecureEnclaveManager {
    
    /// Converts a SecKey public key to CryptoKit P256 public key.
    ///
    /// - Parameter secKey: The SecKey public key.
    /// - Returns: A CryptoKit P256 public key.
    public func convertToCryptoKit(_ secKey: SecKey) throws -> P256.Signing.PublicKey {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw SecureEnclaveError.invalidPublicKey
        }
        
        return try P256.Signing.PublicKey(x963Representation: data)
    }
    
    /// Creates a SecKey from CryptoKit P256 public key.
    ///
    /// - Parameter publicKey: The CryptoKit public key.
    /// - Returns: A SecKey reference.
    public func convertFromCryptoKit(_ publicKey: P256.Signing.PublicKey) throws -> SecKey {
        let data = publicKey.x963Representation
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(
            data as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            throw SecureEnclaveError.invalidPublicKey
        }
        
        return secKey
    }
}
