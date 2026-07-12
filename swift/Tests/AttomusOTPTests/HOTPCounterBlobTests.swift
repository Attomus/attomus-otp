import XCTest

@testable import AttomusOTP

final class HOTPCounterBlobTests: XCTestCase {
    func testKnownVectorEncodesAndVerifies() throws {
        let key = Data(repeating: 0, count: 32)
        let expectedTagHex = "4ec8f5c4a80c126c30df0b3e6958b2b82ea4a85692bdde95cacf0d38eef04b74"
        let expectedBlob = try Data(
            hex: "010000000000000001" + expectedTagHex
        )

        let encoded = try encodeCounterBlob(counter: 1, integrityKey: key)
        XCTAssertEqual(encoded, expectedBlob)
        XCTAssertEqual(try verifyCounterBlob(encoded, integrityKey: key), 1)
    }

    func testRoundTripsMultipleCounters() throws {
        let key = TestSupport.asciiData("0123456789abcdef0123456789abcdef")
        let counters: [UInt64] = [0, 1, 42, UInt64.max - 1, UInt64.max]

        for counter in counters {
            let blob = try encodeCounterBlob(counter: counter, integrityKey: key)
            XCTAssertEqual(blob.count, 41)
            XCTAssertEqual(try verifyCounterBlob(blob, integrityKey: key), counter)
        }
    }

    func testVerifiesBlobWithNonZeroStartIndex() throws {
        let key = TestSupport.asciiData("0123456789abcdef0123456789abcdef")
        let blob = try encodeCounterBlob(counter: 42, integrityKey: key)
        let container = Data(repeating: 0xAA, count: 4) + blob + Data(repeating: 0xBB, count: 4)
        let slice = container.dropFirst(4).dropLast(4)

        XCTAssertEqual(slice.count, 41)
        XCTAssertEqual(try verifyCounterBlob(slice, integrityKey: key), 42)
    }

    func testRejectsInvalidBlobLengths() throws {
        let key = TestSupport.asciiData("0123456789abcdef0123456789abcdef")

        for count in [0, 1, 40, 42] {
            let blob = Data(repeating: 0xAB, count: count)
            XCTAssertThrowsError(try verifyCounterBlob(blob, integrityKey: key)) { error in
                XCTAssertEqual(error as? HOTPCounterBlobError, .invalidBlobLength)
            }
        }
    }

    func testRejectsUnknownVersion() throws {
        let key = TestSupport.asciiData("0123456789abcdef0123456789abcdef")
        let blob = try encodeCounterBlob(counter: 7, integrityKey: key)
        var mutated = blob
        mutated[0] = 0x02

        XCTAssertThrowsError(try verifyCounterBlob(mutated, integrityKey: key)) { error in
            XCTAssertEqual(error as? HOTPCounterBlobError, .unknownVersion)
        }
    }

    func testRejectsInvalidKeyLength() throws {
        let blob = try encodeCounterBlob(counter: 9, integrityKey: TestSupport.asciiData("0123456789abcdef0123456789abcdef"))

        XCTAssertThrowsError(try encodeCounterBlob(counter: 9, integrityKey: Data(repeating: 0, count: 31))) { error in
            XCTAssertEqual(error as? HOTPCounterBlobError, .invalidKeyLength)
        }

        XCTAssertThrowsError(try verifyCounterBlob(blob, integrityKey: Data(repeating: 0, count: 31))) { error in
            XCTAssertEqual(error as? HOTPCounterBlobError, .invalidKeyLength)
        }
    }

    func testRejectsInvalidHMAC() throws {
        let key = TestSupport.asciiData("0123456789abcdef0123456789abcdef")
        var blob = try encodeCounterBlob(counter: 12, integrityKey: key)
        blob[10] ^= 0xFF

        XCTAssertThrowsError(try verifyCounterBlob(blob, integrityKey: key)) { error in
            XCTAssertEqual(error as? HOTPCounterBlobError, .invalidHMAC)
        }
    }
}

private extension Data {
    init(hex: String) throws {
        let sanitized = hex.filter { !$0.isWhitespace }
        guard sanitized.count % 2 == 0 else {
            throw XCTestError()
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(sanitized.count / 2)

        var index = sanitized.startIndex
        while index < sanitized.endIndex {
            let next = sanitized.index(index, offsetBy: 2)
            let pair = sanitized[index..<next]
            guard let byte = UInt8(pair, radix: 16) else {
                throw XCTestError()
            }
            bytes.append(byte)
            index = next
        }

        self = Data(bytes)
    }
}

private struct XCTestError: Error {}
