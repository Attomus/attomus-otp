import Foundation

enum OTPValidation {
    static let minimumSecretLength = 16
    static let maximumSecretLength = 64
    static let validDigits: Set<Int> = [6, 7, 8]
    static let validPeriods: Set<Int> = [30, 60]

    static func validateHOTPSecret(_ secret: Data) throws {
        try validateSecret(secret, shortError: HOTPError.secretTooShort, longError: HOTPError.secretTooLong)
    }

    static func validateTOTPSecret(_ secret: Data) throws {
        try validateSecret(secret, shortError: TOTPError.secretTooShort, longError: TOTPError.secretTooLong)
    }

    static func validateHOTPDigits(_ digits: Int) throws {
        guard validDigits.contains(digits) else {
            throw HOTPError.invalidDigitCount
        }
    }

    static func validateTOTPDigits(_ digits: Int) throws {
        guard validDigits.contains(digits) else {
            throw TOTPError.invalidDigitCount
        }
    }

    static func validateTOTPPeriod(_ period: Int) throws {
        guard validPeriods.contains(period) else {
            throw TOTPError.invalidPeriod
        }
    }

    static func validateURISecret(_ secret: Data) throws {
        guard secret.count >= minimumSecretLength else {
            throw OTPURIError.secretTooShort
        }

        guard secret.count <= maximumSecretLength else {
            throw OTPURIError.secretTooLong
        }
    }

    static func validateURIDigits(_ digits: Int) throws {
        guard validDigits.contains(digits) else {
            throw OTPURIError.invalidDigits
        }
    }

    static func validateURIPeriod(_ period: Int) throws {
        guard validPeriods.contains(period) else {
            throw OTPURIError.invalidPeriod
        }
    }

    private static func validateSecret<E: Error>(_ secret: Data, shortError: E, longError: E) throws {
        guard !secret.isEmpty else {
            throw shortError
        }

        guard secret.count >= minimumSecretLength else {
            throw shortError
        }

        guard secret.count <= maximumSecretLength else {
            throw longError
        }
    }
}
