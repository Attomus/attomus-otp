import XCTest

@testable import AttomusOTP

final class AlgorithmPropertyTests: XCTestCase {
    func testRandomSecretsAndCountersDoNotTrap() throws {
        var generator = SplitMix64(seed: 0xA770_BEEF_1234_5678)

        for _ in 0..<128 {
            let length = Int(generator.next() % 49) + 16
            let secret = Data((0..<length).map { _ in UInt8(truncatingIfNeeded: generator.next()) })
            let counter = generator.next()
            let digits = [6, 7, 8][Int(generator.next() % 3)]

            XCTAssertEqual(
                try HOTP.generate(secret: secret, counter: counter, algorithm: .sha1, digits: digits).count,
                digits
            )
            XCTAssertEqual(
                try HOTP.generate(secret: secret, counter: counter, algorithm: .sha256, digits: digits).count,
                digits
            )
            XCTAssertEqual(
                try HOTP.generate(secret: secret, counter: counter, algorithm: .sha512, digits: digits).count,
                digits
            )
        }
    }
}

private struct SplitMix64 {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var mixed = state
        mixed = (mixed ^ (mixed >> 30)) &* 0xBF58_476D_1CE4_E5B9
        mixed = (mixed ^ (mixed >> 27)) &* 0x94D0_49BB_1331_11EB
        return mixed ^ (mixed >> 31)
    }
}
