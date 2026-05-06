import XCTest

@testable import AttomusOTP

final class Base32Tests: XCTestCase {
    func testEncodesRFC4648Example() {
        XCTAssertEqual(Base32.encode(TestSupport.asciiData("Hello")), "JBSWY3DP")
    }

    func testDecodesRFC4648Example() throws {
        XCTAssertEqual(try Base32.decode("JBSWY3DP"), TestSupport.asciiData("Hello"))
    }

    func testRoundTripsEncodeAndDecode() throws {
        let payload = TestSupport.asciiData("foobar")
        XCTAssertEqual(try Base32.decode(Base32.encode(payload)), payload)
    }

    func testDecodesCaseInsensitiveInput() throws {
        XCTAssertEqual(try Base32.decode("jbswy3dp"), TestSupport.asciiData("Hello"))
    }

    func testDecodesWithWhitespace() throws {
        XCTAssertEqual(try Base32.decode("JBSW Y3DP"), TestSupport.asciiData("Hello"))
    }

    func testDecodesPaddingVariants() throws {
        XCTAssertEqual(try Base32.decode("MY======"), TestSupport.asciiData("f"))
        XCTAssertEqual(try Base32.decode("MZXQ===="), TestSupport.asciiData("fo"))
        XCTAssertEqual(try Base32.decode("MZXW6==="), TestSupport.asciiData("foo"))
        XCTAssertEqual(try Base32.decode("MZXW6YQ="), TestSupport.asciiData("foob"))
        XCTAssertEqual(try Base32.decode("MZXW6YTB"), TestSupport.asciiData("fooba"))
        XCTAssertEqual(try Base32.decode("MZXW6YTBOI======"), TestSupport.asciiData("foobar"))
    }

    func testRejectsInvalidCharacter() {
        XCTAssertThrowsError(try Base32.decode("JBSWY3D!")) { error in
            XCTAssertEqual(error as? Base32Error, .invalidCharacter("!"))
        }
    }

    func testRejectsEmptyInput() {
        XCTAssertThrowsError(try Base32.decode("")) { error in
            XCTAssertEqual(error as? Base32Error, .emptyInput)
        }
    }

    func testRejectsAlphabetAfterPadding() {
        XCTAssertThrowsError(try Base32.decode("MY==A===")) { error in
            XCTAssertEqual(error as? Base32Error, .invalidPadding)
        }
    }

    func testRejectsNonZeroTrailingBits() {
        XCTAssertThrowsError(try Base32.decode("B")) { error in
            XCTAssertEqual(error as? Base32Error, .invalidPadding)
        }
    }
}
