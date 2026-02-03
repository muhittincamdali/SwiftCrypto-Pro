//
//  BiometricKeychain.swift
//  SwiftCrypto-Pro
//
//  Created by Muhittin Camdali on 2025-01-15.
//  Copyright © 2025 Muhittin Camdali. All rights reserved.
//

import Foundation
import Security
import LocalAuthentication
import CryptoKit

// MARK: - Biometric Type

/// Represents the type of biometric authentication available on the device.
public enum BiometricType: String, Codable, Sendable {
    /// Face ID authentication (iPhone X and later).
    case faceID = "Face ID"
    
    /// Touch ID authentication (devices with fingerprint sensor).
    case touchID = "Touch ID"
    
    /// Optic ID authentication (Apple Vision Pro).
    case opticID = "Optic ID"
    
    /// No biometric authentication available.
    case none = "None"
    
    /// Device passcode authentication.
    case passcode = "Passcode"
}

// MARK: - Biometric Authentication Status

/// Represents the current status of biometric authentication.
public enum BiometricAuthStatus: Sendable {
    /// Biometric authentication is available and ready.
    case available(BiometricType)
    
    /// Biometric authentication is not enrolled.
    case notEnrolled
    
    /// Biometric authentication is locked out due to failed attempts.
    case lockedOut
    
    /// Biometric authentication is not available on this device.
    case notAvailable
    
    /// Biometric authentication was denied by user.
    case denied
    
    /// Biometric hardware is not present.
    case hardwareNotPresent
    
    /// Returns whether biometric authentication is ready to use.
    public var isAvailable: Bool {
        if case .available = self {
            return true
        }
        return false
    }
    
    /// Returns the biometric type if available.
    public var biometricType: BiometricType? {
        if case .available(let type) = self {
            return type
        }
        return nil
    }
}

// MARK: - Biometric Keychain Error

/// Errors that can occur during biometric keychain operations.
public enum BiometricKeychainError: LocalizedError, Sendable {
    /// Biometric authentication is not available.
    case biometricNotAvailable
    
    /// Biometric authentication failed.
    case authenticationFailed(String)
    
    /// User cancelled the authentication.
    case userCancelled
    
    /// Biometric authentication is locked out.
    case lockedOut
    
    /// The keychain item was not found.
    case itemNotFound
    
    /// The keychain item already exists.
    case duplicateItem
    
    /// Failed to encode the data.
    case encodingFailed
    
    /// Failed to decode the data.
    case decodingFailed
    
    /// An underlying keychain error occurred.
    case keychainError(OSStatus)
    
    /// Access control creation failed.
    case accessControlCreationFailed
    
    /// Invalid configuration provided.
    case invalidConfiguration(String)
    
    /// The operation timed out.
    case timeout
    
    /// Biometric data has changed since enrollment.
    case biometricChanged
    
    /// The passcode is not set on the device.
    case passcodeNotSet
    
    public var errorDescription: String? {
        switch self {
        case .biometricNotAvailable:
            return "Biometric authentication is not available on this device."
        case .authenticationFailed(let reason):
            return "Authentication failed: \(reason)"
        case .userCancelled:
            return "Authentication was cancelled by the user."
        case .lockedOut:
            return "Biometric authentication is locked out due to too many failed attempts."
        case .itemNotFound:
            return "The requested keychain item was not found."
        case .duplicateItem:
            return "A keychain item with this identifier already exists."
        case .encodingFailed:
            return "Failed to encode the data for storage."
        case .decodingFailed:
            return "Failed to decode the stored data."
        case .keychainError(let status):
            return "Keychain operation failed with status: \(status)"
        case .accessControlCreationFailed:
            return "Failed to create access control for biometric protection."
        case .invalidConfiguration(let message):
            return "Invalid configuration: \(message)"
        case .timeout:
            return "The authentication operation timed out."
        case .biometricChanged:
            return "Biometric data has changed. Please re-authenticate."
        case .passcodeNotSet:
            return "A device passcode is required but not set."
        }
    }
    
    public var recoverySuggestion: String? {
        switch self {
        case .biometricNotAvailable:
            return "Please ensure biometric authentication is set up in Settings."
        case .authenticationFailed:
            return "Please try again or use your device passcode."
        case .userCancelled:
            return "You can try again when ready."
        case .lockedOut:
            return "Please use your device passcode to unlock biometric authentication."
        case .itemNotFound:
            return "The item may have been deleted or never saved."
        case .duplicateItem:
            return "Try updating the existing item instead."
        case .encodingFailed, .decodingFailed:
            return "Please ensure the data format is correct."
        case .keychainError:
            return "Please try the operation again."
        case .accessControlCreationFailed:
            return "Please check your device security settings."
        case .invalidConfiguration:
            return "Please review your configuration parameters."
        case .timeout:
            return "Please try again with better network conditions."
        case .biometricChanged:
            return "Please re-enroll your biometric data and save the item again."
        case .passcodeNotSet:
            return "Please set a device passcode in Settings > Face ID & Passcode."
        }
    }
}

// MARK: - Biometric Protection Level

/// Defines the level of biometric protection for keychain items.
public enum BiometricProtectionLevel: Sendable {
    /// Requires biometric authentication every time.
    case biometricOnly
    
    /// Allows biometric or device passcode.
    case biometricOrPasscode
    
    /// Requires biometric with fallback to passcode after failure.
    case biometricWithPasscodeFallback
    
    /// Requires current set of biometrics (invalidates if biometrics change).
    case biometricCurrentSet
    
    /// Requires device unlock (any method).
    case deviceUnlock
    
    /// Returns the SecAccessControlCreateFlags for this protection level.
    internal var accessControlFlags: SecAccessControlCreateFlags {
        switch self {
        case .biometricOnly:
            return .biometryAny
        case .biometricOrPasscode:
            return [.biometryAny, .or, .devicePasscode]
        case .biometricWithPasscodeFallback:
            return [.biometryAny, .or, .devicePasscode]
        case .biometricCurrentSet:
            return .biometryCurrentSet
        case .deviceUnlock:
            return .userPresence
        }
    }
}

// MARK: - Biometric Keychain Item

/// Represents a keychain item with biometric protection.
public struct BiometricKeychainItem: Sendable {
    /// Unique identifier for the keychain item.
    public let identifier: String
    
    /// The service name for the keychain item.
    public let service: String
    
    /// Optional access group for keychain sharing.
    public let accessGroup: String?
    
    /// The protection level for this item.
    public let protectionLevel: BiometricProtectionLevel
    
    /// Whether the item is synchronized with iCloud Keychain.
    public let isSynchronizable: Bool
    
    /// Optional label for the keychain item.
    public let label: String?
    
    /// Optional description for the keychain item.
    public let itemDescription: String?
    
    /// Creates a new biometric keychain item configuration.
    /// - Parameters:
    ///   - identifier: Unique identifier for the item.
    ///   - service: Service name (defaults to bundle identifier).
    ///   - accessGroup: Optional access group for sharing.
    ///   - protectionLevel: The biometric protection level.
    ///   - isSynchronizable: Whether to sync with iCloud Keychain.
    ///   - label: Optional human-readable label.
    ///   - itemDescription: Optional description.
    public init(
        identifier: String,
        service: String? = nil,
        accessGroup: String? = nil,
        protectionLevel: BiometricProtectionLevel = .biometricOrPasscode,
        isSynchronizable: Bool = false,
        label: String? = nil,
        itemDescription: String? = nil
    ) {
        self.identifier = identifier
        self.service = service ?? Bundle.main.bundleIdentifier ?? "com.swiftcrypto.biometricKeychain"
        self.accessGroup = accessGroup
        self.protectionLevel = protectionLevel
        self.isSynchronizable = isSynchronizable
        self.label = label
        self.itemDescription = itemDescription
    }
}

// MARK: - Biometric Authentication Context

/// Wrapper around LAContext for biometric authentication.
public final class BiometricAuthContext: @unchecked Sendable {
    
    /// The underlying LAContext.
    private let context: LAContext
    
    /// Lock for thread-safe access.
    private let lock = NSLock()
    
    /// The localized reason shown to the user.
    public let localizedReason: String
    
    /// The localized cancel title.
    public var localizedCancelTitle: String? {
        get { lock.withLock { context.localizedCancelTitle } }
        set { lock.withLock { context.localizedCancelTitle = newValue } }
    }
    
    /// The localized fallback title.
    public var localizedFallbackTitle: String? {
        get { lock.withLock { context.localizedFallbackTitle } }
        set { lock.withLock { context.localizedFallbackTitle = newValue } }
    }
    
    /// The interaction not allowed flag.
    public var interactionNotAllowed: Bool {
        get { lock.withLock { context.interactionNotAllowed } }
        set { lock.withLock { context.interactionNotAllowed = newValue } }
    }
    
    /// The touch ID authentication allowed reuse duration.
    public var touchIDAuthenticationAllowableReuseDuration: TimeInterval {
        get { lock.withLock { context.touchIDAuthenticationAllowableReuseDuration } }
        set { lock.withLock { context.touchIDAuthenticationAllowableReuseDuration = newValue } }
    }
    
    /// Creates a new biometric authentication context.
    /// - Parameter localizedReason: The reason shown to the user during authentication.
    public init(localizedReason: String) {
        self.context = LAContext()
        self.localizedReason = localizedReason
    }
    
    /// Returns the underlying LAContext for keychain operations.
    internal var underlyingContext: LAContext {
        lock.withLock { context }
    }
    
    /// Invalidates the context.
    public func invalidate() {
        lock.withLock {
            context.invalidate()
        }
    }
}

// MARK: - Biometric Keychain

/// A secure keychain manager with biometric authentication support.
///
/// `BiometricKeychain` provides a simple and secure way to store sensitive data
/// in the iOS Keychain with biometric protection. It supports Face ID, Touch ID,
/// and device passcode authentication.
///
/// ## Overview
///
/// Use `BiometricKeychain` to store secrets like encryption keys, authentication
/// tokens, and other sensitive data that should be protected by biometric
/// authentication.
///
/// ```swift
/// let keychain = BiometricKeychain()
///
/// // Check biometric availability
/// let status = await keychain.checkBiometricStatus()
/// guard status.isAvailable else { return }
///
/// // Store a secret
/// let item = BiometricKeychainItem(identifier: "user.secret")
/// try await keychain.store(data: secretData, for: item)
///
/// // Retrieve the secret with biometric authentication
/// let context = BiometricAuthContext(localizedReason: "Access your secrets")
/// let secret = try await keychain.retrieve(for: item, context: context)
/// ```
///
/// ## Topics
///
/// ### Creating a Keychain Manager
/// - ``init(configuration:)``
///
/// ### Checking Biometric Status
/// - ``checkBiometricStatus()``
/// - ``availableBiometricType``
///
/// ### Storing Data
/// - ``store(data:for:)``
/// - ``store(_:for:)``
/// - ``storeKey(_:for:)``
///
/// ### Retrieving Data
/// - ``retrieve(for:context:)``
/// - ``retrieve(_:for:context:)``
/// - ``retrieveKey(for:context:)``
///
/// ### Managing Items
/// - ``delete(item:)``
/// - ``exists(item:)``
/// - ``update(data:for:context:)``
///
public actor BiometricKeychain {
    
    // MARK: - Configuration
    
    /// Configuration for the biometric keychain.
    public struct Configuration: Sendable {
        /// Default service name for keychain items.
        public let defaultService: String
        
        /// Default access group for keychain sharing.
        public let defaultAccessGroup: String?
        
        /// Default protection level for new items.
        public let defaultProtectionLevel: BiometricProtectionLevel
        
        /// Whether to allow background access.
        public let allowBackgroundAccess: Bool
        
        /// The default authentication reuse duration.
        public let authenticationReuseDuration: TimeInterval
        
        /// Creates a new configuration.
        /// - Parameters:
        ///   - defaultService: Default service name.
        ///   - defaultAccessGroup: Default access group.
        ///   - defaultProtectionLevel: Default protection level.
        ///   - allowBackgroundAccess: Whether to allow background access.
        ///   - authenticationReuseDuration: How long to reuse authentication.
        public init(
            defaultService: String? = nil,
            defaultAccessGroup: String? = nil,
            defaultProtectionLevel: BiometricProtectionLevel = .biometricOrPasscode,
            allowBackgroundAccess: Bool = false,
            authenticationReuseDuration: TimeInterval = 0
        ) {
            self.defaultService = defaultService ?? Bundle.main.bundleIdentifier ?? "com.swiftcrypto.biometric"
            self.defaultAccessGroup = defaultAccessGroup
            self.defaultProtectionLevel = defaultProtectionLevel
            self.allowBackgroundAccess = allowBackgroundAccess
            self.authenticationReuseDuration = authenticationReuseDuration
        }
        
        /// Default configuration.
        public static let `default` = Configuration()
    }
    
    // MARK: - Properties
    
    /// The configuration for this keychain instance.
    public let configuration: Configuration
    
    /// Cache for biometric status.
    private var cachedBiometricStatus: BiometricAuthStatus?
    
    /// Last time biometric status was checked.
    private var lastStatusCheck: Date?
    
    /// Status cache duration in seconds.
    private let statusCacheDuration: TimeInterval = 5.0
    
    // MARK: - Initialization
    
    /// Creates a new biometric keychain manager.
    /// - Parameter configuration: The configuration to use.
    public init(configuration: Configuration = .default) {
        self.configuration = configuration
    }
    
    // MARK: - Biometric Status
    
    /// Checks the current biometric authentication status.
    /// - Returns: The current biometric authentication status.
    public func checkBiometricStatus() -> BiometricAuthStatus {
        // Check cache validity
        if let cached = cachedBiometricStatus,
           let lastCheck = lastStatusCheck,
           Date().timeIntervalSince(lastCheck) < statusCacheDuration {
            return cached
        }
        
        let context = LAContext()
        var error: NSError?
        
        let canEvaluate = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        )
        
        let status: BiometricAuthStatus
        
        if canEvaluate {
            status = .available(determineBiometricType(from: context))
        } else if let error = error {
            status = mapLAError(error)
        } else {
            status = .notAvailable
        }
        
        // Update cache
        cachedBiometricStatus = status
        lastStatusCheck = Date()
        
        return status
    }
    
    /// Returns the available biometric type without full status check.
    public var availableBiometricType: BiometricType {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
                return .passcode
            }
            return .none
        }
        
        return determineBiometricType(from: context)
    }
    
    /// Determines the biometric type from the context.
    private func determineBiometricType(from context: LAContext) -> BiometricType {
        switch context.biometryType {
        case .faceID:
            return .faceID
        case .touchID:
            return .touchID
        case .opticID:
            return .opticID
        case .none:
            return .none
        @unknown default:
            return .none
        }
    }
    
    /// Maps LAError to BiometricAuthStatus.
    private func mapLAError(_ error: NSError) -> BiometricAuthStatus {
        guard error.domain == LAError.errorDomain else {
            return .notAvailable
        }
        
        switch LAError.Code(rawValue: error.code) {
        case .biometryNotEnrolled:
            return .notEnrolled
        case .biometryLockout:
            return .lockedOut
        case .biometryNotAvailable:
            return .notAvailable
        case .userCancel:
            return .denied
        case .passcodeNotSet:
            return .notAvailable
        default:
            return .notAvailable
        }
    }
    
    // MARK: - Store Operations
    
    /// Stores data in the keychain with biometric protection.
    /// - Parameters:
    ///   - data: The data to store.
    ///   - item: The keychain item configuration.
    /// - Throws: `BiometricKeychainError` if the operation fails.
    public func store(data: Data, for item: BiometricKeychainItem) throws {
        // Create access control
        guard let accessControl = createAccessControl(for: item.protectionLevel) else {
            throw BiometricKeychainError.accessControlCreationFailed
        }
        
        // Build query
        var query = buildBaseQuery(for: item)
        query[kSecValueData as String] = data
        query[kSecAttrAccessControl as String] = accessControl
        
        if let label = item.label {
            query[kSecAttrLabel as String] = label
        }
        
        if let description = item.itemDescription {
            query[kSecAttrDescription as String] = description
        }
        
        // Attempt to add the item
        var status = SecItemAdd(query as CFDictionary, nil)
        
        // If item exists, try to update
        if status == errSecDuplicateItem {
            let updateQuery = buildBaseQuery(for: item)
            var attributesToUpdate: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessControl as String: accessControl
            ]
            
            if let label = item.label {
                attributesToUpdate[kSecAttrLabel as String] = label
            }
            
            status = SecItemUpdate(updateQuery as CFDictionary, attributesToUpdate as CFDictionary)
        }
        
        guard status == errSecSuccess else {
            throw mapKeychainError(status)
        }
    }
    
    /// Stores a Codable value in the keychain with biometric protection.
    /// - Parameters:
    ///   - value: The value to store.
    ///   - item: The keychain item configuration.
    /// - Throws: `BiometricKeychainError` if encoding or storage fails.
    public func store<T: Codable>(_ value: T, for item: BiometricKeychainItem) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        
        guard let data = try? encoder.encode(value) else {
            throw BiometricKeychainError.encodingFailed
        }
        
        try store(data: data, for: item)
    }
    
    /// Stores a symmetric key in the keychain with biometric protection.
    /// - Parameters:
    ///   - key: The symmetric key to store.
    ///   - item: The keychain item configuration.
    /// - Throws: `BiometricKeychainError` if the operation fails.
    public func storeKey(_ key: SymmetricKey, for item: BiometricKeychainItem) throws {
        let keyData = key.withUnsafeBytes { Data($0) }
        try store(data: keyData, for: item)
    }
    
    // MARK: - Retrieve Operations
    
    /// Retrieves data from the keychain with biometric authentication.
    /// - Parameters:
    ///   - item: The keychain item configuration.
    ///   - context: The authentication context.
    /// - Returns: The stored data.
    /// - Throws: `BiometricKeychainError` if retrieval fails.
    public func retrieve(
        for item: BiometricKeychainItem,
        context: BiometricAuthContext
    ) throws -> Data {
        var query = buildBaseQuery(for: item)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context.underlyingContext
        
        // Set the authentication UI preference
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIAllow
        
        // Set the operation prompt
        query[kSecUseOperationPrompt as String] = context.localizedReason
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw mapKeychainError(status)
        }
        
        guard let data = result as? Data else {
            throw BiometricKeychainError.decodingFailed
        }
        
        return data
    }
    
    /// Retrieves a Codable value from the keychain with biometric authentication.
    /// - Parameters:
    ///   - type: The type of value to retrieve.
    ///   - item: The keychain item configuration.
    ///   - context: The authentication context.
    /// - Returns: The stored value.
    /// - Throws: `BiometricKeychainError` if retrieval or decoding fails.
    public func retrieve<T: Codable>(
        _ type: T.Type,
        for item: BiometricKeychainItem,
        context: BiometricAuthContext
    ) throws -> T {
        let data = try retrieve(for: item, context: context)
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        guard let value = try? decoder.decode(T.self, from: data) else {
            throw BiometricKeychainError.decodingFailed
        }
        
        return value
    }
    
    /// Retrieves a symmetric key from the keychain with biometric authentication.
    /// - Parameters:
    ///   - item: The keychain item configuration.
    ///   - context: The authentication context.
    /// - Returns: The stored symmetric key.
    /// - Throws: `BiometricKeychainError` if retrieval fails.
    public func retrieveKey(
        for item: BiometricKeychainItem,
        context: BiometricAuthContext
    ) throws -> SymmetricKey {
        let data = try retrieve(for: item, context: context)
        return SymmetricKey(data: data)
    }
    
    // MARK: - Update Operations
    
    /// Updates data in the keychain with biometric authentication.
    /// - Parameters:
    ///   - data: The new data to store.
    ///   - item: The keychain item configuration.
    ///   - context: The authentication context.
    /// - Throws: `BiometricKeychainError` if the update fails.
    public func update(
        data: Data,
        for item: BiometricKeychainItem,
        context: BiometricAuthContext
    ) throws {
        // First verify the item exists and user can authenticate
        _ = try retrieve(for: item, context: context)
        
        // Delete and re-store with new data
        try delete(item: item)
        try store(data: data, for: item)
    }
    
    // MARK: - Delete Operations
    
    /// Deletes an item from the keychain.
    /// - Parameter item: The keychain item to delete.
    /// - Throws: `BiometricKeychainError` if deletion fails.
    public func delete(item: BiometricKeychainItem) throws {
        let query = buildBaseQuery(for: item)
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapKeychainError(status)
        }
    }
    
    /// Deletes all items for a service.
    /// - Parameter service: The service name.
    /// - Throws: `BiometricKeychainError` if deletion fails.
    public func deleteAll(for service: String? = nil) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service ?? configuration.defaultService
        ]
        
        if let accessGroup = configuration.defaultAccessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapKeychainError(status)
        }
    }
    
    // MARK: - Query Operations
    
    /// Checks if an item exists in the keychain.
    /// - Parameter item: The keychain item to check.
    /// - Returns: `true` if the item exists.
    public func exists(item: BiometricKeychainItem) -> Bool {
        var query = buildBaseQuery(for: item)
        query[kSecReturnData as String] = false
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }
    
    /// Returns all item identifiers for a service.
    /// - Parameter service: The service name.
    /// - Returns: Array of item identifiers.
    public func allItemIdentifiers(for service: String? = nil) -> [String] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service ?? configuration.defaultService,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        
        if let accessGroup = configuration.defaultAccessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }
        
        return items.compactMap { $0[kSecAttrAccount as String] as? String }
    }
    
    // MARK: - Async Authentication
    
    /// Authenticates the user with biometrics.
    /// - Parameter context: The authentication context.
    /// - Returns: `true` if authentication succeeded.
    /// - Throws: `BiometricKeychainError` if authentication fails.
    public func authenticate(with context: BiometricAuthContext) async throws -> Bool {
        let laContext = context.underlyingContext
        
        return try await withCheckedThrowingContinuation { continuation in
            laContext.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: context.localizedReason
            ) { success, error in
                if success {
                    continuation.resume(returning: true)
                } else if let error = error as NSError? {
                    let keychainError = self.mapLAErrorToKeychainError(error)
                    continuation.resume(throwing: keychainError)
                } else {
                    continuation.resume(throwing: BiometricKeychainError.authenticationFailed("Unknown error"))
                }
            }
        }
    }
    
    /// Authenticates with biometrics or passcode fallback.
    /// - Parameter context: The authentication context.
    /// - Returns: `true` if authentication succeeded.
    /// - Throws: `BiometricKeychainError` if authentication fails.
    public func authenticateWithPasscodeFallback(with context: BiometricAuthContext) async throws -> Bool {
        let laContext = context.underlyingContext
        
        return try await withCheckedThrowingContinuation { continuation in
            laContext.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: context.localizedReason
            ) { success, error in
                if success {
                    continuation.resume(returning: true)
                } else if let error = error as NSError? {
                    let keychainError = self.mapLAErrorToKeychainError(error)
                    continuation.resume(throwing: keychainError)
                } else {
                    continuation.resume(throwing: BiometricKeychainError.authenticationFailed("Unknown error"))
                }
            }
        }
    }
    
    // MARK: - Private Helpers
    
    /// Creates access control for the specified protection level.
    private func createAccessControl(for level: BiometricProtectionLevel) -> SecAccessControl? {
        let accessibility: CFString = configuration.allowBackgroundAccess
            ? kSecAttrAccessibleAfterFirstUnlock
            : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        
        return SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            accessibility,
            level.accessControlFlags,
            nil
        )
    }
    
    /// Builds the base query dictionary for a keychain item.
    private func buildBaseQuery(for item: BiometricKeychainItem) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: item.service,
            kSecAttrAccount as String: item.identifier,
            kSecAttrSynchronizable as String: item.isSynchronizable ? kCFBooleanTrue! : kCFBooleanFalse!
        ]
        
        if let accessGroup = item.accessGroup ?? configuration.defaultAccessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        return query
    }
    
    /// Maps keychain OSStatus to BiometricKeychainError.
    private func mapKeychainError(_ status: OSStatus) -> BiometricKeychainError {
        switch status {
        case errSecItemNotFound:
            return .itemNotFound
        case errSecDuplicateItem:
            return .duplicateItem
        case errSecUserCanceled:
            return .userCancelled
        case errSecAuthFailed:
            return .authenticationFailed("Keychain authentication failed")
        case errSecInteractionNotAllowed:
            return .authenticationFailed("User interaction required but not allowed")
        default:
            return .keychainError(status)
        }
    }
    
    /// Maps LAError to BiometricKeychainError.
    private nonisolated func mapLAErrorToKeychainError(_ error: NSError) -> BiometricKeychainError {
        guard error.domain == LAError.errorDomain else {
            return .authenticationFailed(error.localizedDescription)
        }
        
        switch LAError.Code(rawValue: error.code) {
        case .userCancel:
            return .userCancelled
        case .biometryLockout:
            return .lockedOut
        case .biometryNotAvailable:
            return .biometricNotAvailable
        case .biometryNotEnrolled:
            return .biometricNotAvailable
        case .authenticationFailed:
            return .authenticationFailed("Biometric authentication failed")
        case .passcodeNotSet:
            return .passcodeNotSet
        case .userFallback:
            return .authenticationFailed("User chose fallback authentication")
        case .systemCancel:
            return .authenticationFailed("System cancelled authentication")
        case .appCancel:
            return .userCancelled
        case .invalidContext:
            return .invalidConfiguration("Authentication context is invalid")
        default:
            return .authenticationFailed(error.localizedDescription)
        }
    }
}

// MARK: - Convenience Extensions

extension BiometricKeychain {
    
    /// Creates a quick item configuration for common use cases.
    /// - Parameters:
    ///   - identifier: The unique identifier.
    ///   - requireCurrentBiometrics: Whether to invalidate if biometrics change.
    /// - Returns: A configured keychain item.
    public func quickItem(
        identifier: String,
        requireCurrentBiometrics: Bool = false
    ) -> BiometricKeychainItem {
        BiometricKeychainItem(
            identifier: identifier,
            service: configuration.defaultService,
            accessGroup: configuration.defaultAccessGroup,
            protectionLevel: requireCurrentBiometrics ? .biometricCurrentSet : configuration.defaultProtectionLevel
        )
    }
    
    /// Creates an authentication context with standard settings.
    /// - Parameter reason: The reason shown to the user.
    /// - Returns: A configured authentication context.
    public func quickContext(reason: String) -> BiometricAuthContext {
        let context = BiometricAuthContext(localizedReason: reason)
        context.touchIDAuthenticationAllowableReuseDuration = configuration.authenticationReuseDuration
        return context
    }
}

// MARK: - Secure Key Generation

extension BiometricKeychain {
    
    /// Generates a new symmetric key and stores it with biometric protection.
    /// - Parameters:
    ///   - item: The keychain item configuration.
    ///   - keySize: The key size in bits (128, 192, or 256).
    /// - Returns: The generated symmetric key.
    /// - Throws: `BiometricKeychainError` if generation or storage fails.
    public func generateAndStoreKey(
        for item: BiometricKeychainItem,
        keySize: SymmetricKeySize = .bits256
    ) throws -> SymmetricKey {
        let key = SymmetricKey(size: keySize)
        try storeKey(key, for: item)
        return key
    }
    
    /// Retrieves or generates a symmetric key.
    /// - Parameters:
    ///   - item: The keychain item configuration.
    ///   - context: The authentication context.
    ///   - keySize: The key size for generation if needed.
    /// - Returns: The existing or newly generated key.
    /// - Throws: `BiometricKeychainError` if the operation fails.
    public func retrieveOrGenerateKey(
        for item: BiometricKeychainItem,
        context: BiometricAuthContext,
        keySize: SymmetricKeySize = .bits256
    ) throws -> SymmetricKey {
        if exists(item: item) {
            return try retrieveKey(for: item, context: context)
        } else {
            return try generateAndStoreKey(for: item, keySize: keySize)
        }
    }
}

// MARK: - Migration Support

extension BiometricKeychain {
    
    /// Migrates an existing keychain item to biometric protection.
    /// - Parameters:
    ///   - identifier: The existing item identifier.
    ///   - service: The service name.
    ///   - newItem: The new biometric-protected item configuration.
    ///   - context: The authentication context for reading the old item.
    /// - Throws: `BiometricKeychainError` if migration fails.
    public func migrateToProtected(
        identifier: String,
        service: String,
        to newItem: BiometricKeychainItem,
        context: BiometricAuthContext
    ) throws {
        // Build query for old item
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identifier,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        query[kSecUseAuthenticationContext as String] = context.underlyingContext
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let data = result as? Data else {
            throw mapKeychainError(status)
        }
        
        // Store with new biometric protection
        try store(data: data, for: newItem)
        
        // Delete old item
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identifier
        ]
        
        SecItemDelete(deleteQuery as CFDictionary)
    }
}

// MARK: - Credential Storage

/// A specialized wrapper for storing user credentials with biometric protection.
public struct BiometricCredential: Codable, Sendable {
    /// The username or email.
    public let username: String
    
    /// The password or secret.
    public let password: String
    
    /// Optional metadata.
    public let metadata: [String: String]?
    
    /// The date when the credential was stored.
    public let storedAt: Date
    
    /// Creates a new credential.
    public init(
        username: String,
        password: String,
        metadata: [String: String]? = nil
    ) {
        self.username = username
        self.password = password
        self.metadata = metadata
        self.storedAt = Date()
    }
}

extension BiometricKeychain {
    
    /// Stores user credentials with biometric protection.
    /// - Parameters:
    ///   - credential: The credential to store.
    ///   - identifier: The unique identifier for this credential.
    /// - Throws: `BiometricKeychainError` if storage fails.
    public func storeCredential(
        _ credential: BiometricCredential,
        identifier: String
    ) throws {
        let item = BiometricKeychainItem(
            identifier: "credential.\(identifier)",
            service: configuration.defaultService,
            protectionLevel: .biometricCurrentSet,
            label: "Credential: \(identifier)"
        )
        
        try store(credential, for: item)
    }
    
    /// Retrieves user credentials with biometric authentication.
    /// - Parameters:
    ///   - identifier: The credential identifier.
    ///   - context: The authentication context.
    /// - Returns: The stored credential.
    /// - Throws: `BiometricKeychainError` if retrieval fails.
    public func retrieveCredential(
        identifier: String,
        context: BiometricAuthContext
    ) throws -> BiometricCredential {
        let item = BiometricKeychainItem(
            identifier: "credential.\(identifier)",
            service: configuration.defaultService
        )
        
        return try retrieve(BiometricCredential.self, for: item, context: context)
    }
    
    /// Deletes stored credentials.
    /// - Parameter identifier: The credential identifier.
    /// - Throws: `BiometricKeychainError` if deletion fails.
    public func deleteCredential(identifier: String) throws {
        let item = BiometricKeychainItem(
            identifier: "credential.\(identifier)",
            service: configuration.defaultService
        )
        
        try delete(item: item)
    }
}
