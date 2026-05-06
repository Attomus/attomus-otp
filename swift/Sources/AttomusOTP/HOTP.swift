#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

public enum HOTP {
    public static func generate(
        secret: Data,
        counter: UInt64,
        algorithm: OTPAlgorithm = .sha1,
        digits: Int = 6
    ) throws -> String {
        try OTPValidation.validateHOTPSecret(secret)
        try OTPValidation.validateHOTPDigits(digits)

        let counterData = counter.bigEndianData
        let hmac = try authenticationCode(for: counterData, secret: secret, algorithm: algorithm)
        let truncated = truncate(hmac)
        let modulus = UInt32(pow(10.0, Double(digits)))
        let code = truncated % modulus
        return String(format: "%0\(digits)u", code)
    }

    private static func authenticationCode(
        for counterData: Data,
        secret: Data,
        algorithm: OTPAlgorithm
    ) throws -> Data {
        let key = SymmetricKey(data: secret)

        switch algorithm {
        case .sha1:
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key))
        case .sha256:
            return Data(HMAC<SHA256>.authenticationCode(for: counterData, using: key))
        case .sha512:
            return Data(HMAC<SHA512>.authenticationCode(for: counterData, using: key))
        }
    }

    private static func truncate(_ hmac: Data) -> UInt32 {
        let bytes = Array(hmac)
        let offset = Int(bytes[bytes.count - 1] & 0x0F)

        let part0 = UInt32(bytes[offset] & 0x7F) << 24
        let part1 = UInt32(bytes[offset + 1]) << 16
        let part2 = UInt32(bytes[offset + 2]) << 8
        let part3 = UInt32(bytes[offset + 3])

        return part0 | part1 | part2 | part3
    }
}

private extension UInt64 {
    var bigEndianData: Data {
        withUnsafeBytes(of: bigEndian) { Data($0) }
    }
}
