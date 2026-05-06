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

        let timestamp = date.timeIntervalSince1970
        let counter = UInt64(timestamp / Double(period))
        return try HOTP.generate(secret: secret, counter: counter, algorithm: algorithm, digits: digits)
    }

    public static func remainingSeconds(at date: Date, period: Int = 30) -> Int {
        let timestamp = Int(date.timeIntervalSince1970)
        let remainder = timestamp % period
        return period - remainder
    }
}
