import Foundation

public struct OTPExportDocument: Codable, Sendable, Equatable {
    public let schema: Int
    public let exported: Date
    public let accounts: [OTPAccountExport]

    public init(schema: Int = 1, exported: Date, accounts: [OTPAccountExport]) {
        self.schema = schema
        self.exported = exported
        self.accounts = accounts
    }
}

public struct OTPAccountExport: Codable, Sendable, Equatable {
    public let id: UUID
    public let type: OTPType
    public let accountName: String
    public let issuer: String?
    public let algorithm: OTPAlgorithm
    public let digits: Int
    public let period: Int?
    public let counter: UInt64?
    public let secret: String
    public let createdAt: Date

    public init(
        id: UUID,
        type: OTPType,
        accountName: String,
        issuer: String?,
        algorithm: OTPAlgorithm,
        digits: Int,
        period: Int? = nil,
        counter: UInt64? = nil,
        secret: String,
        createdAt: Date
    ) {
        self.id = id
        self.type = type
        self.accountName = accountName
        self.issuer = issuer
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.counter = counter
        self.secret = secret
        self.createdAt = createdAt
    }
}

public enum OTPBackupError: Error, Equatable, Sendable {
    case unsupportedSchemaVersion(Int)
    case malformedJSON
    case missingSecret(accountID: UUID)
    case missingCounter(accountID: UUID)
    case invalidSecret(accountID: UUID)
    case invalidDigits(accountID: UUID)
    case invalidPeriod(accountID: UUID)
    case emptyDocument
}

public func encodeExportDocument(
    accounts: [OTPAccount],
    secrets: [UUID: Data]
) throws -> Data {
    let accountExports = try accounts.map { account in
        try makeAccountExport(account: account, secrets: secrets)
    }

    let document = OTPExportDocument(
        schema: 1,
        exported: Date(),
        accounts: accountExports
    )

    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(document)
}

public func decodeExportDocument(_ data: Data) throws -> [OTPProvisioningResult] {
    let schema = try inspectSchemaVersion(in: data)
    guard schema == 1 else {
        throw OTPBackupError.unsupportedSchemaVersion(schema)
    }

    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601

    let document: RawExportDocument
    do {
        document = try decoder.decode(RawExportDocument.self, from: data)
    } catch {
        throw OTPBackupError.malformedJSON
    }

    guard !document.accounts.isEmpty else {
        throw OTPBackupError.emptyDocument
    }

    return try document.accounts.map { account in
        try makeProvisioningResult(from: account)
    }
}

private func makeAccountExport(
    account: OTPAccount,
    secrets: [UUID: Data]
) throws -> OTPAccountExport {
    guard let secret = secrets[account.id] else {
        throw OTPBackupError.missingSecret(accountID: account.id)
    }

    do {
        try OTPValidation.validateURISecret(secret)
    } catch {
        throw OTPBackupError.invalidSecret(accountID: account.id)
    }

    do {
        try OTPValidation.validateURIDigits(account.digits)
    } catch {
        throw OTPBackupError.invalidDigits(accountID: account.id)
    }

    if account.type == .totp {
        do {
            try OTPValidation.validateURIPeriod(account.period)
        } catch {
            throw OTPBackupError.invalidPeriod(accountID: account.id)
        }
    }

    if account.type == .hotp, account.counter == nil {
        throw OTPBackupError.missingCounter(accountID: account.id)
    }

    return OTPAccountExport(
        id: account.id,
        type: account.type,
        accountName: account.label,
        issuer: account.issuer,
        algorithm: account.algorithm,
        digits: account.digits,
        period: account.type == .totp ? account.period : nil,
        counter: account.type == .hotp ? account.counter : nil,
        secret: Base32.encode(secret),
        createdAt: account.createdAt
    )
}

private func makeProvisioningResult(from account: RawAccountExport) throws -> OTPProvisioningResult {
    let secret = try decodedSecret(for: account)
    try validateDigits(for: account)
    let period = try validatedPeriod(for: account)
    let counter = try validatedCounter(for: account)

    let exportedAccount = OTPAccount(
        id: account.id,
        type: account.type,
        label: account.accountName,
        issuer: account.issuer,
        algorithm: account.algorithm,
        digits: account.digits,
        period: period,
        counter: counter,
        createdAt: account.createdAt
    )

    return OTPProvisioningResult(account: exportedAccount, secret: secret)
}

private func decodedSecret(for account: RawAccountExport) throws -> Data {
    guard let secretString = account.secret else {
        throw OTPBackupError.missingSecret(accountID: account.id)
    }

    let secret: Data
    do {
        secret = try Base32.decode(secretString)
    } catch {
        throw OTPBackupError.invalidSecret(accountID: account.id)
    }

    do {
        try OTPValidation.validateURISecret(secret)
    } catch {
        throw OTPBackupError.invalidSecret(accountID: account.id)
    }

    return secret
}

private func validateDigits(for account: RawAccountExport) throws {
    do {
        try OTPValidation.validateURIDigits(account.digits)
    } catch {
        throw OTPBackupError.invalidDigits(accountID: account.id)
    }
}

private func validatedPeriod(for account: RawAccountExport) throws -> Int {
    switch account.type {
    case .totp:
        if let exportedPeriod = account.period {
            do {
                try OTPValidation.validateURIPeriod(exportedPeriod)
            } catch {
                throw OTPBackupError.invalidPeriod(accountID: account.id)
            }
            return exportedPeriod
        }
        return 30
    case .hotp:
        let period = account.period ?? 30
        do {
            try OTPValidation.validateURIPeriod(period)
        } catch {
            throw OTPBackupError.invalidPeriod(accountID: account.id)
        }
        return period
    }
}

private func validatedCounter(for account: RawAccountExport) throws -> UInt64? {
    switch account.type {
    case .totp:
        return nil
    case .hotp:
        guard let counter = account.counter else {
            throw OTPBackupError.missingCounter(accountID: account.id)
        }
        return counter
    }
}

private func inspectSchemaVersion(in data: Data) throws -> Int {
    let jsonObject: Any
    do {
        jsonObject = try JSONSerialization.jsonObject(with: data, options: [])
    } catch {
        throw OTPBackupError.malformedJSON
    }

    guard let root = jsonObject as? [String: Any] else {
        throw OTPBackupError.malformedJSON
    }

    guard let schema = root["schema"] as? Int else {
        throw OTPBackupError.malformedJSON
    }

    return schema
}

private struct RawExportDocument: Decodable {
    let schema: Int
    let exported: Date
    let accounts: [RawAccountExport]
}

private struct RawAccountExport: Decodable {
    let id: UUID
    let type: OTPType
    let accountName: String
    let issuer: String?
    let algorithm: OTPAlgorithm
    let digits: Int
    let period: Int?
    let counter: UInt64?
    let secret: String?
    let createdAt: Date
}
