import XCTest

@testable import AttomusOTP

final class OTPURIParserTests: XCTestCase {
    func testValidURIExamples() throws {
        let longSecret = "IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U"
        let alternateSecret = "ABCDEFGHIJKLMNOPQRSTUVWX23456723"
        let validCases: [(String, OTPType, String, String?, OTPAlgorithm, Int, Int)] = [
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&issuer=Example", .totp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://totp/alice@example.com?secret=\(longSecret)&issuer=Example", .totp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://totp/Example%20Corp:alice@example.com?secret=\(longSecret)&issuer=Example%20Corp", .totp, "alice@example.com", "Example Corp", .sha1, 6, 30),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret.lowercased())", .totp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://totp/Example:alice@example.com?secret=IFBE%20GRCF%20IZDU%20QSKK%20JNGE%202TSP%20KBIV%20EU2U&issuer=Example", .totp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&algorithm=SHA256&digits=7&issuer=Example", .totp, "alice@example.com", "Example", .sha256, 7, 30),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&algorithm=SHA512&digits=8&issuer=Example", .totp, "alice@example.com", "Example", .sha512, 8, 30),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&period=60&issuer=Example", .totp, "alice@example.com", "Example", .sha1, 6, 60),
            ("otpauth://totp/Example%3Aalice@example.com?secret=\(longSecret)&issuer=Example", .totp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://totp/Example:%20alice@example.com?secret=\(longSecret)&issuer=Example", .totp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://hotp/Example:alice@example.com?secret=\(longSecret)&issuer=Example&counter=0", .hotp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://hotp/Example:alice@example.com?secret=\(longSecret)&counter=18446744073709551615&issuer=Example", .hotp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://hotp/alice@example.com?secret=\(longSecret)&counter=42&issuer=Example", .hotp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://totp/alice@example.com?secret=\(longSecret)", .totp, "alice@example.com", nil, .sha1, 6, 30),
            ("otpauth://totp/Example:alice@example.com?secret=\(alternateSecret)&issuer=Example", .totp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30", .totp, "john.doe@email.com", "ACME Co", .sha1, 6, 30),
            ("otpauth://totp/Big%20Team:ops@example.com?secret=\(alternateSecret)&issuer=Big%20Team", .totp, "ops@example.com", "Big Team", .sha1, 6, 30),
            ("otpauth://totp/issuer-only?secret=\(longSecret)&issuer=Example&unknown=value", .totp, "issuer-only", "Example", .sha1, 6, 30),
            ("otpauth://totp/Provider1:Alice%20Smith?secret=\(longSecret)&issuer=Provider1", .totp, "Alice Smith", "Provider1", .sha1, 6, 30),
            ("otpauth://totp/Provider1:Alice%20Smith?secret=\(longSecret)&issuer=Provider1&algorithm=sha1", .totp, "Alice Smith", "Provider1", .sha1, 6, 30),
            ("otpauth://totp/Provider1:Alice%20Smith?secret=\(longSecret)&issuer=Provider1&algorithm=sha256", .totp, "Alice Smith", "Provider1", .sha256, 6, 30),
            ("otpauth://totp/Provider1:Alice%20Smith?secret=\(longSecret)&issuer=Provider1&algorithm=sha512", .totp, "Alice Smith", "Provider1", .sha512, 6, 30),
            ("otpauth://totp/team@example.com?secret=\(longSecret)&digits=7", .totp, "team@example.com", nil, .sha1, 7, 30),
            ("otpauth://totp/team@example.com?secret=\(longSecret)&digits=8", .totp, "team@example.com", nil, .sha1, 8, 30),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&issuer=Example", .totp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://hotp/Example:alice@example.com?secret=\(longSecret)&issuer=Example&counter=1", .hotp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://totp/Example%20Security:alice%2Bprod@example.com?secret=\(longSecret)&issuer=Example%20Security", .totp, "alice+prod@example.com", "Example Security", .sha1, 6, 30),
            ("otpauth://totp/AccountOnly?secret=\(alternateSecret)", .totp, "AccountOnly", nil, .sha1, 6, 30),
            ("otpauth://totp/Example:account?secret=\(alternateSecret)&issuer=Example&image=https%3A%2F%2Fexample.com%2Ficon.png", .totp, "account", "Example", .sha1, 6, 30),
            ("otpauth://totp/Label%20With%20Spaces?secret=\(alternateSecret)", .totp, "Label With Spaces", nil, .sha1, 6, 30),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&issuer=%20", .totp, "alice@example.com", "Example", .sha1, 6, 30),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&algorithm=&digits=&period=", .totp, "alice@example.com", "Example", .sha1, 6, 30)
        ]

        XCTAssertGreaterThanOrEqual(validCases.count, 30)

        for (uri, type, label, issuer, algorithm, digits, period) in validCases {
            let result = try parseOTPURI(uri)
            XCTAssertEqual(result.account.type, type)
            XCTAssertEqual(result.account.label, label)
            XCTAssertEqual(result.account.issuer, issuer)
            XCTAssertEqual(result.account.algorithm, algorithm)
            XCTAssertEqual(result.account.digits, digits)
            XCTAssertEqual(result.account.period, period)
            XCTAssertGreaterThanOrEqual(result.secret.count, 16)
        }
    }

    func testInvalidURIExamples() {
        let longSecret = "IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U"
        let invalidCases: [(String, OTPURIError)] = [
            (String(repeating: "a", count: 2049), .uriTooLong),
            ("https://totp/Example:alice@example.com?secret=\(longSecret)", .invalidScheme),
            ("otpauth://steam/Example:alice@example.com?secret=\(longSecret)", .invalidType),
            ("otpauth://totp/Example:alice@example.com", .missingSecret),
            ("otpauth://totp/?secret=\(longSecret)", .missingLabel),
            ("otpauth://totp/Example:alice@example.com?secret=JBSWY3DP!", .invalidSecret),
            ("otpauth://totp/Example:alice@example.com?secret=JBSWY3DP", .secretTooShort),
            ("otpauth://totp/Example:alice@example.com?secret=\(String(repeating: "A", count: 104))", .secretTooLong),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&digits=5", .invalidDigits),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&digits=9", .invalidDigits),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&digits=abc", .invalidDigits),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&period=45", .invalidPeriod),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&period=abc", .invalidPeriod),
            ("otpauth://hotp/Example:alice@example.com?secret=\(longSecret)", .missingCounter),
            ("otpauth://hotp/Example:alice@example.com?secret=\(longSecret)&counter=-1", .missingCounter),
            ("otpauth://hotp/Example:alice@example.com?secret=\(longSecret)&counter=abc", .missingCounter),
            ("otpauth://hotp/Example:alice@example.com?secret=\(longSecret)&counter=18446744073709551616", .missingCounter),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&issuer=Different", .issuerMismatch),
            ("otpauth://totp/Example:%ZZalice@example.com?secret=\(longSecret)", .malformedPercentEncoding),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)&algorithm=MD5", .invalidAlgorithm),
            ("otpauth://totp/%?secret=\(longSecret)", .malformedPercentEncoding),
            ("otpauth:///Example:alice@example.com?secret=\(longSecret)", .invalidType),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)%", .malformedPercentEncoding),
            ("otpauth://totp/Example:alice@example.com?secret=\(longSecret)%A", .malformedPercentEncoding),
            ("otpauth://totp/%C3%28?secret=\(longSecret)", .malformedPercentEncoding),
            ("otpauth://totp/Example:?secret=\(longSecret)", .missingLabel)
        ]

        XCTAssertGreaterThanOrEqual(invalidCases.count, 20)

        for (uri, expectedError) in invalidCases {
            XCTAssertThrowsError(try parseOTPURI(uri)) { error in
                XCTAssertEqual(error as? OTPURIError, expectedError)
            }
        }
    }

    func testHOTPParsesCounter() throws {
        let result = try parseOTPURI("otpauth://hotp/Example:alice@example.com?secret=IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U&issuer=Example&counter=42")
        XCTAssertEqual(result.account.type, .hotp)
        XCTAssertEqual(result.account.label, "alice@example.com")
        XCTAssertEqual(result.account.period, 30)
        XCTAssertEqual(result.account.counter, 42)
    }
}
