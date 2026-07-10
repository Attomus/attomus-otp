import Foundation

public enum TOTP {
    public static func generate(
        secret: Data,
        at date: Date,
        algorithm: OTPAlgorithm = .sha1,
        digits: Int = 6,
        period: Int = 30
    ) throws -> String {
        try OTPValidation.validateTOTPSecret(secret)
        try OTPValidation.validateTOTPDigits(digits)
        try OTPValidation.validateTOTPPeriod(period)

        let seconds = try unixSeconds(for: date)
        let counter = UInt64(seconds) / UInt64(period)
        return try HOTP.generate(secret: secret, counter: counter, algorithm: algorithm, digits: digits)
    }

    public static func remainingSeconds(at date: Date, period: Int = 30) throws -> Int {
        try OTPValidation.validateTOTPPeriod(period)

        let seconds = try unixSeconds(for: date)
        let remainder = seconds % Int64(period)
        return remainder == 0 ? period : period - Int(remainder)
    }

    private static func unixSeconds(for date: Date) throws -> Int64 {
        let timestamp = date.timeIntervalSince1970.rounded(.down)
        guard timestamp >= 0, timestamp <= Double(Int64.max) else {
            throw TOTPError.invalidTime
        }
        return Int64(timestamp)
    }
}
