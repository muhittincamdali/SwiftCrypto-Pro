import Foundation

/// Decodes and validates JSON Web Tokens (JWT) following RFC 7519.
///
/// Supports header parsing, claims extraction, and expiration validation.
/// Does not perform signature verification (use with trusted token sources).
public struct JWTDecoder {

    // MARK: - Types

    /// Errors that can occur during JWT decoding.
    public enum JWTError: LocalizedError {
        case invalidFormat
        case invalidBase64
        case invalidJSON
        case tokenExpired
        case tokenNotYetValid
        case missingClaim(String)

        public var errorDescription: String? {
            switch self {
            case .invalidFormat:
                return "Invalid JWT format. Expected three dot-separated segments."
            case .invalidBase64:
                return "Invalid Base64URL encoding in JWT segment."
            case .invalidJSON:
                return "Failed to parse JWT segment as JSON."
            case .tokenExpired:
                return "JWT token has expired."
            case .tokenNotYetValid:
                return "JWT token is not yet valid (nbf claim)."
            case .missingClaim(let claim):
                return "Missing required JWT claim: \(claim)"
            }
        }
    }

    /// Represents the JWT header.
    public struct JWTHeader: Codable {
        public let algorithm: String?
        public let type: String?
        public let keyID: String?

        enum CodingKeys: String, CodingKey {
            case algorithm = "alg"
            case type = "typ"
            case keyID = "kid"
        }
    }

    // MARK: - Initialization

    public init() {}

    // MARK: - Decoding

    /// Decodes a JWT string into claims.
    /// - Parameter token: The JWT string.
    /// - Returns: The decoded `JWTClaims`.
    public func decode(token: String) throws -> JWTClaims {
        let segments = token.components(separatedBy: ".")
        guard segments.count == 3 else {
            throw JWTError.invalidFormat
        }

        let payloadData = try decodeBase64URL(segments[1])
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970

        do {
            return try decoder.decode(JWTClaims.self, from: payloadData)
        } catch {
            throw JWTError.invalidJSON
        }
    }

    /// Decodes the JWT header.
    /// - Parameter token: The JWT string.
    /// - Returns: The decoded `JWTHeader`.
    public func decodeHeader(token: String) throws -> JWTHeader {
        let segments = token.components(separatedBy: ".")
        guard segments.count == 3 else {
            throw JWTError.invalidFormat
        }

        let headerData = try decodeBase64URL(segments[0])
        let decoder = JSONDecoder()

        do {
            return try decoder.decode(JWTHeader.self, from: headerData)
        } catch {
            throw JWTError.invalidJSON
        }
    }

    /// Decodes a JWT and validates it is not expired.
    /// - Parameters:
    ///   - token: The JWT string.
    ///   - leeway: Acceptable time difference in seconds (default: 0).
    /// - Returns: The decoded `JWTClaims` if valid.
    public func decodeAndValidate(token: String, leeway: TimeInterval = 0) throws -> JWTClaims {
        let claims = try decode(token: token)
        let now = Date()

        if let exp = claims.expiresAt, now.timeIntervalSince1970 > exp.timeIntervalSince1970 + leeway {
            throw JWTError.tokenExpired
        }

        if let nbf = claims.notBefore, now.timeIntervalSince1970 < nbf.timeIntervalSince1970 - leeway {
            throw JWTError.tokenNotYetValid
        }

        return claims
    }

    /// Extracts raw JSON payload as a dictionary.
    /// - Parameter token: The JWT string.
    /// - Returns: Dictionary of claims.
    public func decodeToDict(token: String) throws -> [String: Any] {
        let segments = token.components(separatedBy: ".")
        guard segments.count == 3 else {
            throw JWTError.invalidFormat
        }

        let payloadData = try decodeBase64URL(segments[1])
        guard let json = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw JWTError.invalidJSON
        }
        return json
    }

    // MARK: - Private Helpers

    private func decodeBase64URL(_ string: String) throws -> Data {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }

        guard let data = Data(base64Encoded: base64) else {
            throw JWTError.invalidBase64
        }
        return data
    }
}
