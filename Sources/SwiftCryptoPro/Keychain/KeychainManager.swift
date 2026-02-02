import Foundation
import Security
import LocalAuthentication

/// A secure wrapper around the iOS/macOS Keychain Services API.
///
/// Provides type-safe storage, retrieval, and deletion of sensitive data
/// with optional biometric protection (Face ID / Touch ID).
public final class KeychainManager {

    // MARK: - Types

    /// Keychain accessibility levels.
    public enum Accessibility {
        case whenUnlocked
        case afterFirstUnlock
        case whenUnlockedThisDeviceOnly
        case afterFirstUnlockThisDeviceOnly

        var secValue: CFString {
            switch self {
            case .whenUnlocked:
                return kSecAttrAccessibleWhenUnlocked
            case .afterFirstUnlock:
                return kSecAttrAccessibleAfterFirstUnlock
            case .whenUnlockedThisDeviceOnly:
                return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .afterFirstUnlockThisDeviceOnly:
                return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            }
        }
    }

    /// Errors that can occur during Keychain operations.
    public enum KeychainError: LocalizedError {
        case saveFailed(OSStatus)
        case loadFailed(OSStatus)
        case deleteFailed(OSStatus)
        case dataConversionFailed
        case itemNotFound
        case biometricNotAvailable
        case accessControlFailed

        public var errorDescription: String? {
            switch self {
            case .saveFailed(let status):
                return "Keychain save failed with status: \(status)"
            case .loadFailed(let status):
                return "Keychain load failed with status: \(status)"
            case .deleteFailed(let status):
                return "Keychain delete failed with status: \(status)"
            case .dataConversionFailed:
                return "Failed to convert keychain data."
            case .itemNotFound:
                return "Keychain item not found."
            case .biometricNotAvailable:
                return "Biometric authentication is not available."
            case .accessControlFailed:
                return "Failed to create access control."
            }
        }
    }

    // MARK: - Properties

    private let serviceName: String
    private let accessGroup: String?

    // MARK: - Initialization

    /// Creates a KeychainManager instance.
    /// - Parameters:
    ///   - serviceName: The service name for keychain queries (default: bundle identifier).
    ///   - accessGroup: Optional keychain access group for sharing between apps.
    public init(serviceName: String? = nil, accessGroup: String? = nil) {
        self.serviceName = serviceName ?? (Bundle.main.bundleIdentifier ?? "com.swiftcryptopro.keychain")
        self.accessGroup = accessGroup
    }

    // MARK: - Save

    /// Saves a string value to the keychain.
    /// - Parameters:
    ///   - value: The string to store.
    ///   - key: The key to associate with the value.
    ///   - biometric: Whether to require biometric authentication to access.
    ///   - accessibility: The accessibility level.
    public func save(
        _ value: String,
        forKey key: String,
        biometric: Bool = false,
        accessibility: Accessibility = .whenUnlocked
    ) throws {
        guard let data = value.data(using: .utf8) else {
            throw KeychainError.dataConversionFailed
        }
        try save(data, forKey: key, biometric: biometric, accessibility: accessibility)
    }

    /// Saves raw data to the keychain.
    /// - Parameters:
    ///   - data: The data to store.
    ///   - key: The key to associate with the data.
    ///   - biometric: Whether to require biometric authentication to access.
    ///   - accessibility: The accessibility level.
    public func save(
        _ data: Data,
        forKey key: String,
        biometric: Bool = false,
        accessibility: Accessibility = .whenUnlocked
    ) throws {
        try? delete(forKey: key)

        var query = baseQuery(forKey: key)
        query[kSecValueData as String] = data

        if biometric {
            guard let accessControl = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                .biometryCurrentSet,
                nil
            ) else {
                throw KeychainError.accessControlFailed
            }
            query[kSecAttrAccessControl as String] = accessControl
        } else {
            query[kSecAttrAccessible as String] = accessibility.secValue
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }

    // MARK: - Load

    /// Loads a string value from the keychain.
    /// - Parameter key: The key associated with the stored value.
    /// - Returns: The stored string, or `nil` if not found.
    public func load(forKey key: String) throws -> String? {
        guard let data = try loadData(forKey: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Loads raw data from the keychain.
    /// - Parameter key: The key associated with the stored data.
    /// - Returns: The stored data, or `nil` if not found.
    public func loadData(forKey key: String) throws -> Data? {
        var query = baseQuery(forKey: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess else {
            throw KeychainError.loadFailed(status)
        }

        return result as? Data
    }

    // MARK: - Delete

    /// Deletes a keychain item.
    /// - Parameter key: The key of the item to delete.
    public func delete(forKey key: String) throws {
        let query = baseQuery(forKey: key)
        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }

    /// Removes all items stored by this service.
    public func deleteAll() throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }

    // MARK: - Existence Check

    /// Checks if a keychain item exists for the given key.
    /// - Parameter key: The key to check.
    /// - Returns: `true` if an item exists.
    public func exists(forKey key: String) -> Bool {
        return (try? loadData(forKey: key)) != nil
    }

    // MARK: - Private

    private func baseQuery(forKey key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        return query
    }
}
