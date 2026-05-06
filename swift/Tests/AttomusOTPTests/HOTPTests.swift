import XCTest

@testable import AttomusOTP

final class HOTPTests: XCTestCase {
    func testRFC4226AppendixDTestVectors() throws {
        let secret = TestSupport.asciiData("12345678901234567890")
        let expected = [
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489"
        ]

        for (counter, code) in expected.enumerated() {
            XCTAssertEqual(
                try HOTP.generate(secret: secret, counter: UInt64(counter)),
                code
            )
        }
    }

    func testSupportsAllowedDigitCounts() throws {
        let secret = TestSupport.repeatedData(count: 20)
        XCTAssertEqual(try HOTP.generate(secret: secret, counter: 1, digits: 6).count, 6)
        XCTAssertEqual(try HOTP.generate(secret: secret, counter: 1, digits: 7).count, 7)
        XCTAssertEqual(try HOTP.generate(secret: secret, counter: 1, digits: 8).count, 8)
    }

    func testRejectsShortSecret() {
        XCTAssertThrowsError(try HOTP.generate(secret: Data([0x00]), counter: 0)) { error in
            XCTAssertEqual(error as? HOTPError, .secretTooShort)
        }
    }

    func testRejectsEmptySecret() {
        XCTAssertThrowsError(try HOTP.generate(secret: Data(), counter: 0)) { error in
            XCTAssertEqual(error as? HOTPError, .secretTooShort)
        }
    }

    func testRejectsLongSecret() {
        XCTAssertThrowsError(try HOTP.generate(secret: TestSupport.repeatedData(count: 65), counter: 0)) { error in
            XCTAssertEqual(error as? HOTPError, .secretTooLong)
        }
    }

    func testRejectsInvalidDigitCount() {
        XCTAssertThrowsError(try HOTP.generate(secret: TestSupport.repeatedData(count: 20), counter: 0, digits: 5)) { error in
            XCTAssertEqual(error as? HOTPError, .invalidDigitCount)
        }
    }

    func testSupportsAlternateAlgorithms() throws {
        let secret = TestSupport.repeatedData(count: 32)
        XCTAssertEqual(try HOTP.generate(secret: secret, counter: 42, algorithm: .sha256, digits: 8).count, 8)
        XCTAssertEqual(try HOTP.generate(secret: secret, counter: 42, algorithm: .sha512, digits: 8).count, 8)
    }

    func testSupportsMaximumCounter() throws {
        let secret = TestSupport.repeatedData(count: 20)
        XCTAssertEqual(try HOTP.generate(secret: secret, counter: .max).count, 6)
    }
}
