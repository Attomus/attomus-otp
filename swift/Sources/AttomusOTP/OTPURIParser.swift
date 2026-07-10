import Foundation

public func parseOTPURI(_ uri: String) throws -> OTPProvisioningResult {
    let components = try parseComponents(from: uri)
    let type = try parseType(from: components)
    let label = try parseLabel(from: components.percentEncodedPath)
    let parameters = parseParameters(from: components)
    guard let encodedSecret = parameters["secret"], !encodedSecret.isEmpty else {
        throw OTPURIError.missingSecret
    }

    let secret: Data
    do {
        secret = try Base32.decode(encodedSecret)
    } catch {
        throw OTPURIError.invalidSecret
    }

    try OTPValidation.validateURISecret(secret)

    if type == .hotp {
        _ = try parseCounter(parameters["counter"])
    }

    return try OTPProvisioningResult(
        account: makeAccount(type: type, label: label, parameters: parameters),
        secret: secret
    )
}

private func parseComponents(from uri: String) throws -> URLComponents {
    guard uri.count <= 2048 else {
        throw OTPURIError.uriTooLong
    }

    try validatePercentEncoding(in: uri)

    guard let components = URLComponents(string: uri) else {
        throw OTPURIError.invalidScheme
    }

    guard components.scheme?.caseInsensitiveCompare("otpauth") == .orderedSame else {
        throw OTPURIError.invalidScheme
    }

    return components
}

private func parseType(from components: URLComponents) throws -> OTPType {
    guard let rawType = components.host?.lowercased() else {
        throw OTPURIError.invalidType
    }

    switch rawType {
    case "totp":
        return .totp
    case "hotp":
        return .hotp
    default:
        throw OTPURIError.invalidType
    }
}

private func parseParameters(from components: URLComponents) -> [String: String] {
    Dictionary(
        components.queryItems?.map { ($0.name.lowercased(), $0.value ?? "") } ?? [],
        uniquingKeysWith: { first, _ in first }
    )
}

private func makeAccount(
    type: OTPType,
    label: (issuer: String?, accountName: String),
    parameters: [String: String]
) throws -> OTPAccount {
    let algorithm = try parseAlgorithm(parameters["algorithm"])
    let digits = try parseDigits(parameters["digits"])
    let period = try parsePeriod(parameters["period"], type: type)
    let issuer = try resolveIssuer(labelIssuer: label.issuer, parameterIssuer: parameters["issuer"])

    return OTPAccount(
        id: UUID(),
        type: type,
        label: label.accountName,
        issuer: issuer,
        algorithm: algorithm,
        digits: digits,
        period: period,
        counter: type == .hotp ? try parseCounter(parameters["counter"]) : nil,
        createdAt: Date()
    )
}

private func parseLabel(from percentEncodedPath: String) throws -> (issuer: String?, accountName: String) {
    let trimmedPath = percentEncodedPath.hasPrefix("/") ? String(percentEncodedPath.dropFirst()) : percentEncodedPath
    guard !trimmedPath.isEmpty else {
        throw OTPURIError.missingLabel
    }

    guard let decoded = trimmedPath.removingPercentEncoding else {
        throw OTPURIError.malformedPercentEncoding
    }

    let parts = decoded.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
    if parts.count == 2 {
        let issuer = parts[0].trimmingCharacters(in: .whitespaces)
        let accountName = parts[1].trimmingCharacters(in: .whitespaces)
        guard !accountName.isEmpty else {
            throw OTPURIError.missingLabel
        }
        return (issuer.isEmpty ? nil : issuer, accountName)
    }

    let accountName = decoded.trimmingCharacters(in: .whitespaces)
    guard !accountName.isEmpty else {
        throw OTPURIError.missingLabel
    }
    return (nil, accountName)
}

private func parseAlgorithm(_ rawValue: String?) throws -> OTPAlgorithm {
    guard let rawValue, !rawValue.isEmpty else {
        return .sha1
    }

    switch rawValue.lowercased() {
    case "sha1":
        return .sha1
    case "sha256":
        return .sha256
    case "sha512":
        return .sha512
    default:
        throw OTPURIError.invalidAlgorithm
    }
}

private func parseDigits(_ rawValue: String?) throws -> Int {
    guard let rawValue, !rawValue.isEmpty else {
        return 6
    }

    guard let digits = Int(rawValue) else {
        throw OTPURIError.invalidDigits
    }

    try OTPValidation.validateURIDigits(digits)
    return digits
}

private func parsePeriod(_ rawValue: String?, type: OTPType) throws -> Int {
    guard type == .totp else {
        return 30
    }

    guard let rawValue, !rawValue.isEmpty else {
        return 30
    }

    guard let period = Int(rawValue) else {
        throw OTPURIError.invalidPeriod
    }

    try OTPValidation.validateURIPeriod(period)
    return period
}

private func parseCounter(_ rawValue: String?) throws -> UInt64 {
    guard let rawValue, !rawValue.isEmpty else {
        throw OTPURIError.missingCounter
    }

    guard !rawValue.hasPrefix("-"),
          let counter = UInt64(rawValue),
          counter <= UInt64(Int64.max) else {
        throw OTPURIError.missingCounter
    }

    return counter
}

private func resolveIssuer(labelIssuer: String?, parameterIssuer: String?) throws -> String? {
    let decodedParameter = parameterIssuer?.trimmingCharacters(in: .whitespacesAndNewlines)
    let normalizedParameter = decodedParameter?.isEmpty == true ? nil : decodedParameter

    if let labelIssuer, let normalizedParameter, labelIssuer != normalizedParameter {
        throw OTPURIError.issuerMismatch
    }

    return normalizedParameter ?? labelIssuer
}

private func validatePercentEncoding(in text: String) throws {
    var index = text.startIndex

    while index < text.endIndex {
        if text[index] == "%" {
            let first = text.index(after: index)
            guard first < text.endIndex else {
                throw OTPURIError.malformedPercentEncoding
            }

            let second = text.index(after: first)
            guard second < text.endIndex else {
                throw OTPURIError.malformedPercentEncoding
            }

            let pair = text[first...second]
            guard pair.allSatisfy(\.isHexDigit) else {
                throw OTPURIError.malformedPercentEncoding
            }

            index = text.index(after: second)
            continue
        }

        index = text.index(after: index)
    }
}
