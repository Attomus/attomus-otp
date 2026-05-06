import Foundation
import XCTest

@testable import AttomusOTP

final class TOTPTests: XCTestCase {
    func testRFC6238AppendixB_SHA1() throws {
        try assertTOTPVectors(
            secret: TestSupport.asciiData("12345678901234567890"),
            algorithm: .sha1,
            expected: [
                (59, "94287082"),
                (1111111109, "07081804"),
                (1111111111, "14050471"),
                (1234567890, "89005924"),
                (2000000000, "69279037"),
                (20000000000, "65353130")
            ]
        )
    }

    func testRFC6238AppendixB_SHA256() throws {
        try assertTOTPVectors(
            secret: TestSupport.asciiData("12345678901234567890123456789012"),
            algorithm: .sha256,
            expected: [
                (59, "46119246"),
                (1111111109, "68084774"),
                (1111111111, "67062674"),
                (1234567890, "91819424"),
                (2000000000, "90698825"),
                (20000000000, "77737706")
            ]
        )
    }

    func testRFC6238AppendixB_SHA512() throws {
        try assertTOTPVectors(
            secret: TestSupport.asciiData("1234567890123456789012345678901234567890123456789012345678901234"),
            algorithm: .sha512,
            expected: [
                (59, "90693936"),
                (1111111109, "25091201"),
                (1111111111, "99943326"),
                (1234567890, "93441116"),
                (2000000000, "38618901"),
                (20000000000, "47863826")
            ]
        )
    }

    func testSupportsAllowedDigitCounts() throws {
        let secret = TestSupport.repeatedData(count: 20)
        let date = Date(timeIntervalSince1970: 1_234_567_890)
        XCTAssertEqual(try TOTP.generate(secret: secret, at: date, digits: 6).count, 6)
        XCTAssertEqual(try TOTP.generate(secret: secret, at: date, digits: 7).count, 7)
        XCTAssertEqual(try TOTP.generate(secret: secret, at: date, digits: 8).count, 8)
    }

    func testSupportsSixtySecondPeriod() throws {
        let secret = TestSupport.repeatedData(count: 20)
        let date = Date(timeIntervalSince1970: 120)
        XCTAssertEqual(try TOTP.generate(secret: secret, at: date, period: 60).count, 6)
        XCTAssertEqual(TOTP.remainingSeconds(at: date, period: 60), 60)
    }

    func testRejectsInvalidDigitCount() {
        XCTAssertThrowsError(try TOTP.generate(secret: TestSupport.repeatedData(count: 20), at: Date(timeIntervalSince1970: 0), digits: 9)) { error in
            XCTAssertEqual(error as? TOTPError, .invalidDigitCount)
        }
    }

    func testRejectsInvalidPeriod() {
        XCTAssertThrowsError(try TOTP.generate(secret: TestSupport.repeatedData(count: 20), at: Date(timeIntervalSince1970: 0), period: 45)) { error in
            XCTAssertEqual(error as? TOTPError, .invalidPeriod)
        }
    }

    func testRejectsShortSecret() {
        XCTAssertThrowsError(try TOTP.generate(secret: Data([0x01]), at: Date(timeIntervalSince1970: 0))) { error in
            XCTAssertEqual(error as? TOTPError, .secretTooShort)
        }
    }

    func testRejectsEmptySecret() {
        XCTAssertThrowsError(try TOTP.generate(secret: Data(), at: Date(timeIntervalSince1970: 0))) { error in
            XCTAssertEqual(error as? TOTPError, .secretTooShort)
        }
    }

    private func assertTOTPVectors(
        secret: Data,
        algorithm: OTPAlgorithm,
        expected: [(TimeInterval, String)]
    ) throws {
        for (timestamp, code) in expected {
            XCTAssertEqual(
                try TOTP.generate(
                    secret: secret,
                    at: Date(timeIntervalSince1970: timestamp),
                    algorithm: algorithm,
                    digits: 8,
                    period: 30
                ),
                code
            )
        }
    }
}
