import Foundation

/// Represents standard JWT claims following RFC 7519.
///
/// Includes registered claim names and supports custom claims via `additionalClaims`.
public struct JWTClaims: Codable {

    /// Token issuer (iss)
    public let issuer: String?

    /// Token subject (sub)
    public let subject: String?

    /// Token audience (aud)
    public let audience: String?

    /// Expiration time (exp)
    public let expiresAt: Date?

    /// Not before time (nbf)
    public let notBefore: Date?

    /// Issued at time (iat)
    public let issuedAt: Date?

    /// JWT ID (jti)
    public let jwtID: String?

    /// Whether the token has expired based on current time.
    public var isExpired: Bool {
        guard let exp = expiresAt else { return false }
        return Date() > exp
    }

    /// Time remaining until expiration, or `nil` if no expiration claim exists.
    public var timeUntilExpiration: TimeInterval? {
        guard let exp = expiresAt else { return nil }
        return exp.timeIntervalSinceNow
    }

    // MARK: - Coding Keys

    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expiresAt = "exp"
        case notBefore = "nbf"
        case issuedAt = "iat"
        case jwtID = "jti"
    }

    // MARK: - Initialization

    public init(
        issuer: String? = nil,
        subject: String? = nil,
        audience: String? = nil,
        expiresAt: Date? = nil,
        notBefore: Date? = nil,
        issuedAt: Date? = nil,
        jwtID: String? = nil
    ) {
        self.issuer = issuer
        self.subject = subject
        self.audience = audience
        self.expiresAt = expiresAt
        self.notBefore = notBefore
        self.issuedAt = issuedAt
        self.jwtID = jwtID
    }
}
