import Foundation
import Security

// MARK: - Keychain Wrapper

/// A comprehensive wrapper for secure keychain operations.
///
/// This class provides a type-safe, Swift-friendly interface to the iOS/macOS
/// Keychain Services for storing sensitive data like passwords, tokens, and
/// cryptographic keys.
///
/// ## Features
/// - Generic storage for any Codable type
/// - Biometric and passcode protection options
/// - iCloud Keychain synchronization
/// - Access group support for app extensions
/// - Automatic data encryption
///
/// ## Usage
/// ```swift
/// let keychain = KeychainWrapper()
///
/// // Store a password
/// try keychain.set("MySecretPassword", forKey: "user_password")
///
/// // Retrieve a password
/// let password: String? = try keychain.get("user_password")
///
/// // Store a Codable object
/// struct Credentials: Codable {
///     let username: String
///     let token: String
/// }
/// let creds = Credentials(username: "user", token: "abc123")
/// try keychain.set(creds, forKey: "credentials")
/// ```
///
/// ## Security Considerations
/// - Data is encrypted at rest by the system
/// - Keys can be protected with biometrics
/// - Sensitive items should use `whenUnlocked` accessibility
public final class KeychainWrapper {
    
    // MARK: - Types
    
    /// Accessibility options for keychain items.
    public enum Accessibility {
        /// Data can only be accessed while the device is unlocked.
        case whenUnlocked
        
        /// Data can only be accessed while the device is unlocked.
        /// Item is not migrated to a new device.
        case whenUnlockedThisDeviceOnly
        
        /// Data can be accessed after the device has been unlocked once after boot.
        case afterFirstUnlock
        
        /// Data can be accessed after first unlock. Not migrated to new device.
        case afterFirstUnlockThisDeviceOnly
        
        /// Data can always be accessed regardless of lock state.
        /// - Warning: Use only for non-sensitive data.
        case always
        
        /// Data can be accessed only when the device is unlocked.
        /// Requires passcode to be set.
        case whenPasscodeSetThisDeviceOnly
        
        /// The corresponding Security framework constant.
        var cfValue: CFString {
            switch self {
            case .whenUnlocked:
                return kSecAttrAccessibleWhenUnlocked
            case .whenUnlockedThisDeviceOnly:
                return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .afterFirstUnlock:
                return kSecAttrAccessibleAfterFirstUnlock
            case .afterFirstUnlockThisDeviceOnly:
                return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            case .always:
                return kSecAttrAccessibleAlways
            case .whenPasscodeSetThisDeviceOnly:
                return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            }
        }
    }
    
    /// Authentication requirements for accessing keychain items.
    public enum AuthenticationPolicy {
        /// No additional authentication required.
        case none
        
        /// Require biometric authentication (Face ID / Touch ID).
        case biometricOnly
        
        /// Require biometrics or device passcode.
        case biometricOrPasscode
        
        /// Require device passcode.
        case devicePasscode
        
        /// The SecAccessControlCreateFlags for this policy.
        var flags: SecAccessControlCreateFlags {
            switch self {
            case .none:
                return []
            case .biometricOnly:
                return .biometryCurrentSet
            case .biometricOrPasscode:
                return .userPresence
            case .devicePasscode:
                return .devicePasscode
            }
        }
    }
    
    /// Errors that can occur during keychain operations.
    public enum KeychainError: LocalizedError {
        case itemNotFound
        case duplicateItem
        case authenticationFailed
        case invalidData
        case encodingFailed
        case decodingFailed
        case unexpectedStatus(OSStatus)
        case accessControlCreationFailed
        case invalidKey
        case operationNotSupported
        
        public var errorDescription: String? {
            switch self {
            case .itemNotFound:
                return "The requested item was not found in the keychain."
            case .duplicateItem:
                return "An item with this key already exists."
            case .authenticationFailed:
                return "User authentication failed."
            case .invalidData:
                return "The data format is invalid."
            case .encodingFailed:
                return "Failed to encode the data for storage."
            case .decodingFailed:
                return "Failed to decode the stored data."
            case .unexpectedStatus(let status):
                return "Keychain operation failed with status: \(status)"
            case .accessControlCreationFailed:
                return "Failed to create access control."
            case .invalidKey:
                return "The key is invalid or empty."
            case .operationNotSupported:
                return "This operation is not supported."
            }
        }
    }
    
    /// Configuration for keychain operations.
    public struct Configuration {
        /// The service name (typically your app's bundle identifier).
        public var service: String
        
        /// Access group for sharing between apps (optional).
        public var accessGroup: String?
        
        /// Default accessibility level.
        public var accessibility: Accessibility
        
        /// Whether to synchronize with iCloud Keychain.
        public var synchronizable: Bool
        
        /// Default authentication policy.
        public var authenticationPolicy: AuthenticationPolicy
        
        /// Creates a default configuration.
        public init(
            service: String = Bundle.main.bundleIdentifier ?? "com.app.keychain",
            accessGroup: String? = nil,
            accessibility: Accessibility = .whenUnlockedThisDeviceOnly,
            synchronizable: Bool = false,
            authenticationPolicy: AuthenticationPolicy = .none
        ) {
            self.service = service
            self.accessGroup = accessGroup
            self.accessibility = accessibility
            self.synchronizable = synchronizable
            self.authenticationPolicy = authenticationPolicy
        }
    }
    
    // MARK: - Properties
    
    /// The configuration for this keychain wrapper.
    public let configuration: Configuration
    
    /// Shared instance with default configuration.
    public static let shared = KeychainWrapper()
    
    // MARK: - Initialization
    
    /// Creates a keychain wrapper with default configuration.
    public init() {
        self.configuration = Configuration()
    }
    
    /// Creates a keychain wrapper with custom configuration.
    ///
    /// - Parameter configuration: The configuration to use.
    public init(configuration: Configuration) {
        self.configuration = configuration
    }
    
    /// Creates a keychain wrapper with a specific service name.
    ///
    /// - Parameter service: The service name.
    public init(service: String) {
        self.configuration = Configuration(service: service)
    }
    
    // MARK: - String Operations
    
    /// Stores a string value in the keychain.
    ///
    /// - Parameters:
    ///   - value: The string to store.
    ///   - key: The unique key for this item.
    ///   - accessibility: Override the default accessibility.
    ///   - authentication: Override the default authentication policy.
    public func set(
        _ value: String,
        forKey key: String,
        accessibility: Accessibility? = nil,
        authentication: AuthenticationPolicy? = nil
    ) throws {
        guard let data = value.data(using: .utf8) else {
            throw KeychainError.encodingFailed
        }
        try set(data, forKey: key, accessibility: accessibility, authentication: authentication)
    }
    
    /// Retrieves a string value from the keychain.
    ///
    /// - Parameters:
    ///   - key: The unique key for the item.
    ///   - promptMessage: Message to display for biometric prompt.
    /// - Returns: The stored string, or nil if not found.
    public func getString(
        forKey key: String,
        promptMessage: String? = nil
    ) throws -> String? {
        guard let data = try getData(forKey: key, promptMessage: promptMessage) else {
            return nil
        }
        guard let string = String(data: data, encoding: .utf8) else {
            throw KeychainError.decodingFailed
        }
        return string
    }
    
    // MARK: - Data Operations
    
    /// Stores raw data in the keychain.
    ///
    /// - Parameters:
    ///   - data: The data to store.
    ///   - key: The unique key for this item.
    ///   - accessibility: Override the default accessibility.
    ///   - authentication: Override the default authentication policy.
    public func set(
        _ data: Data,
        forKey key: String,
        accessibility: Accessibility? = nil,
        authentication: AuthenticationPolicy? = nil
    ) throws {
        guard !key.isEmpty else {
            throw KeychainError.invalidKey
        }
        
        let actualAccessibility = accessibility ?? configuration.accessibility
        let actualAuthentication = authentication ?? configuration.authenticationPolicy
        
        // Delete existing item first
        try? delete(key: key)
        
        var query = baseQuery(forKey: key)
        query[kSecValueData as String] = data
        
        // Set accessibility
        if actualAuthentication != .none {
            guard let accessControl = createAccessControl(
                accessibility: actualAccessibility,
                authentication: actualAuthentication
            ) else {
                throw KeychainError.accessControlCreationFailed
            }
            query[kSecAttrAccessControl as String] = accessControl
        } else {
            query[kSecAttrAccessible as String] = actualAccessibility.cfValue
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            throw KeychainError.duplicateItem
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    /// Retrieves raw data from the keychain.
    ///
    /// - Parameters:
    ///   - key: The unique key for the item.
    ///   - promptMessage: Message to display for biometric prompt.
    /// - Returns: The stored data, or nil if not found.
    public func getData(
        forKey key: String,
        promptMessage: String? = nil
    ) throws -> Data? {
        guard !key.isEmpty else {
            throw KeychainError.invalidKey
        }
        
        var query = baseQuery(forKey: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        
        if let message = promptMessage {
            query[kSecUseOperationPrompt as String] = message
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw KeychainError.invalidData
            }
            return data
        case errSecItemNotFound:
            return nil
        case errSecUserCanceled, errSecAuthFailed:
            throw KeychainError.authenticationFailed
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    // MARK: - Codable Operations
    
    /// Stores a Codable object in the keychain.
    ///
    /// - Parameters:
    ///   - value: The Codable object to store.
    ///   - key: The unique key for this item.
    ///   - accessibility: Override the default accessibility.
    ///   - authentication: Override the default authentication policy.
    public func set<T: Codable>(
        _ value: T,
        forKey key: String,
        accessibility: Accessibility? = nil,
        authentication: AuthenticationPolicy? = nil
    ) throws {
        let encoder = JSONEncoder()
        let data: Data
        do {
            data = try encoder.encode(value)
        } catch {
            throw KeychainError.encodingFailed
        }
        try set(data, forKey: key, accessibility: accessibility, authentication: authentication)
    }
    
    /// Retrieves a Codable object from the keychain.
    ///
    /// - Parameters:
    ///   - key: The unique key for the item.
    ///   - type: The type to decode to.
    ///   - promptMessage: Message to display for biometric prompt.
    /// - Returns: The decoded object, or nil if not found.
    public func get<T: Codable>(
        _ key: String,
        as type: T.Type,
        promptMessage: String? = nil
    ) throws -> T? {
        guard let data = try getData(forKey: key, promptMessage: promptMessage) else {
            return nil
        }
        
        let decoder = JSONDecoder()
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw KeychainError.decodingFailed
        }
    }
    
    // MARK: - Boolean Operations
    
    /// Stores a boolean value in the keychain.
    ///
    /// - Parameters:
    ///   - value: The boolean to store.
    ///   - key: The unique key for this item.
    public func set(_ value: Bool, forKey key: String) throws {
        let data = Data([value ? 1 : 0])
        try set(data, forKey: key)
    }
    
    /// Retrieves a boolean value from the keychain.
    ///
    /// - Parameter key: The unique key for the item.
    /// - Returns: The stored boolean, or nil if not found.
    public func getBool(forKey key: String) throws -> Bool? {
        guard let data = try getData(forKey: key),
              let byte = data.first else {
            return nil
        }
        return byte == 1
    }
    
    // MARK: - Integer Operations
    
    /// Stores an integer value in the keychain.
    ///
    /// - Parameters:
    ///   - value: The integer to store.
    ///   - key: The unique key for this item.
    public func set(_ value: Int, forKey key: String) throws {
        var intValue = value
        let data = Data(bytes: &intValue, count: MemoryLayout<Int>.size)
        try set(data, forKey: key)
    }
    
    /// Retrieves an integer value from the keychain.
    ///
    /// - Parameter key: The unique key for the item.
    /// - Returns: The stored integer, or nil if not found.
    public func getInt(forKey key: String) throws -> Int? {
        guard let data = try getData(forKey: key) else {
            return nil
        }
        guard data.count == MemoryLayout<Int>.size else {
            throw KeychainError.invalidData
        }
        return data.withUnsafeBytes { $0.load(as: Int.self) }
    }
    
    // MARK: - Delete Operations
    
    /// Deletes an item from the keychain.
    ///
    /// - Parameter key: The unique key for the item.
    public func delete(key: String) throws {
        guard !key.isEmpty else {
            throw KeychainError.invalidKey
        }
        
        let query = baseQuery(forKey: key)
        let status = SecItemDelete(query as CFDictionary)
        
        switch status {
        case errSecSuccess, errSecItemNotFound:
            return
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    /// Deletes all items for this service.
    ///
    /// - Warning: This is destructive and cannot be undone.
    public func deleteAll() throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.service
        ]
        
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemDelete(query as CFDictionary)
        
        switch status {
        case errSecSuccess, errSecItemNotFound:
            return
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    // MARK: - Query Operations
    
    /// Checks if an item exists in the keychain.
    ///
    /// - Parameter key: The unique key for the item.
    /// - Returns: `true` if the item exists.
    public func contains(key: String) -> Bool {
        var query = baseQuery(forKey: key)
        query[kSecReturnData as String] = false
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /// Lists all keys stored for this service.
    ///
    /// - Returns: Array of key names.
    public func allKeys() -> [String] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }
        
        return items.compactMap { dict in
            dict[kSecAttrAccount as String] as? String
        }
    }
    
    // MARK: - Update Operations
    
    /// Updates an existing item in the keychain.
    ///
    /// - Parameters:
    ///   - data: The new data.
    ///   - key: The unique key for the item.
    public func update(_ data: Data, forKey key: String) throws {
        guard !key.isEmpty else {
            throw KeychainError.invalidKey
        }
        
        let query = baseQuery(forKey: key)
        let attributesToUpdate: [String: Any] = [
            kSecValueData as String: data
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        
        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            throw KeychainError.itemNotFound
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    // MARK: - Private Helpers
    
    /// Creates the base query dictionary for keychain operations.
    private func baseQuery(forKey key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.service,
            kSecAttrAccount as String: key
        ]
        
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        if configuration.synchronizable {
            query[kSecAttrSynchronizable as String] = true
        }
        
        return query
    }
    
    /// Creates access control with the specified options.
    private func createAccessControl(
        accessibility: Accessibility,
        authentication: AuthenticationPolicy
    ) -> SecAccessControl? {
        var error: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            accessibility.cfValue,
            authentication.flags,
            &error
        )
        return accessControl
    }
}

// MARK: - Convenience Subscript

extension KeychainWrapper {
    
    /// Subscript access for string values.
    public subscript(key: String) -> String? {
        get {
            try? getString(forKey: key)
        }
        set {
            if let value = newValue {
                try? set(value, forKey: key)
            } else {
                try? delete(key: key)
            }
        }
    }
}

// MARK: - Password-Specific Operations

extension KeychainWrapper {
    
    /// Stores a password with internet password attributes.
    ///
    /// - Parameters:
    ///   - password: The password to store.
    ///   - server: The server/domain (e.g., "example.com").
    ///   - account: The account/username.
    public func setInternetPassword(
        _ password: String,
        server: String,
        account: String
    ) throws {
        guard let data = password.data(using: .utf8) else {
            throw KeychainError.encodingFailed
        }
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: server,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: configuration.accessibility.cfValue
        ]
        
        if configuration.synchronizable {
            query[kSecAttrSynchronizable as String] = true
        }
        
        // Delete existing first
        var deleteQuery = query
        deleteQuery.removeValue(forKey: kSecValueData as String)
        SecItemDelete(deleteQuery as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    /// Retrieves an internet password.
    ///
    /// - Parameters:
    ///   - server: The server/domain.
    ///   - account: The account/username.
    /// - Returns: The password, or nil if not found.
    public func getInternetPassword(
        server: String,
        account: String
    ) throws -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: server,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        if configuration.synchronizable {
            query[kSecAttrSynchronizable as String] = true
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        switch status {
        case errSecSuccess:
            guard let data = result as? Data,
                  let password = String(data: data, encoding: .utf8) else {
                throw KeychainError.decodingFailed
            }
            return password
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    /// Deletes an internet password.
    ///
    /// - Parameters:
    ///   - server: The server/domain.
    ///   - account: The account/username.
    public func deleteInternetPassword(server: String, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: server,
            kSecAttrAccount as String: account
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}