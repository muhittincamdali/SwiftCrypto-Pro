import Foundation
import LocalAuthentication

/// Provides Face ID and Touch ID authentication capabilities.
///
/// Wraps LAContext for simplified biometric authentication with clear error handling.
public final class BiometricAuth {

    // MARK: - Types

    /// The type of biometric authentication available on the device.
    public enum BiometricType {
        case none
        case touchID
        case faceID
        case opticID
    }

    /// Errors that can occur during biometric authentication.
    public enum BiometricError: LocalizedError {
        case notAvailable
        case notEnrolled
        case lockout
        case cancelled
        case failed(String)

        public var errorDescription: String? {
            switch self {
            case .notAvailable:
                return "Biometric authentication is not available on this device."
            case .notEnrolled:
                return "No biometric data is enrolled. Please set up Face ID or Touch ID."
            case .lockout:
                return "Biometric authentication is locked out due to too many failed attempts."
            case .cancelled:
                return "Authentication was cancelled by the user."
            case .failed(let reason):
                return "Authentication failed: \(reason)"
            }
        }
    }

    // MARK: - Properties

    private let context: LAContext

    // MARK: - Initialization

    public init() {
        self.context = LAContext()
    }

    // MARK: - Availability

    /// Whether biometric authentication is available and enrolled.
    public var isBiometricAvailable: Bool {
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    /// The type of biometric authentication available.
    public var biometricType: BiometricType {
        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }

        switch context.biometryType {
        case .touchID:
            return .touchID
        case .faceID:
            return .faceID
        case .opticID:
            return .opticID
        default:
            return .none
        }
    }

    // MARK: - Authentication

    /// Authenticates the user using biometrics.
    /// - Parameter reason: The reason shown to the user for authentication.
    /// - Returns: `true` if authentication succeeded.
    @MainActor
    public func authenticate(reason: String) async throws -> Bool {
        let authContext = LAContext()
        authContext.localizedCancelTitle = "Cancel"

        var error: NSError?
        guard authContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            if let nsError = error {
                throw mapLAError(nsError)
            }
            throw BiometricError.notAvailable
        }

        do {
            let success = try await authContext.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
            return success
        } catch let authError as LAError {
            throw mapLAError(authError)
        }
    }

    /// Authenticates with fallback to device passcode.
    /// - Parameter reason: The reason shown to the user.
    /// - Returns: `true` if authentication succeeded.
    @MainActor
    public func authenticateWithPasscodeFallback(reason: String) async throws -> Bool {
        let authContext = LAContext()

        do {
            let success = try await authContext.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )
            return success
        } catch let authError as LAError {
            throw mapLAError(authError)
        }
    }

    // MARK: - Private

    private func mapLAError(_ error: Error) -> BiometricError {
        let nsError = error as NSError
        switch nsError.code {
        case LAError.biometryNotAvailable.rawValue:
            return .notAvailable
        case LAError.biometryNotEnrolled.rawValue:
            return .notEnrolled
        case LAError.biometryLockout.rawValue:
            return .lockout
        case LAError.userCancel.rawValue, LAError.appCancel.rawValue:
            return .cancelled
        default:
            return .failed(error.localizedDescription)
        }
    }
}
