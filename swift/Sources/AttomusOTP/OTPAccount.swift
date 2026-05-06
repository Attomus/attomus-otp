import Foundation

public struct OTPAccount: Identifiable, Codable, Sendable, Equatable, Hashable {
    public let id: UUID
    public let type: OTPType
    public let label: String
    public let issuer: String?
    public let algorithm: OTPAlgorithm
    public let digits: Int
    public let period: Int
    public let counter: UInt64?
    public let createdAt: Date

    public init(
        id: UUID,
        type: OTPType,
        label: String,
        issuer: String?,
        algorithm: OTPAlgorithm,
        digits: Int,
        period: Int,
        counter: UInt64? = nil,
        createdAt: Date
    ) {
        self.id = id
        self.type = type
        self.label = label
        self.issuer = issuer
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.counter = counter
        self.createdAt = createdAt
    }
}

public enum OTPType: String, Codable, Sendable {
    case totp
    case hotp
}

public enum OTPAlgorithm: String, Sendable {
    case sha1
    case sha256
    case sha512
}

extension OTPAlgorithm: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)

        switch rawValue.lowercased() {
        case "sha1":
            self = .sha1
        case "sha256":
            self = .sha256
        case "sha512":
            self = .sha512
        default:
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported OTP algorithm: \(rawValue)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let rawValue: String

        switch self {
        case .sha1:
            rawValue = "SHA1"
        case .sha256:
            rawValue = "SHA256"
        case .sha512:
            rawValue = "SHA512"
        }

        try container.encode(rawValue)
    }
}

public struct OTPProvisioningResult: Sendable, Equatable {
    public let account: OTPAccount
    public let secret: Data

    public init(account: OTPAccount, secret: Data) {
        self.account = account
        self.secret = secret
    }
}
