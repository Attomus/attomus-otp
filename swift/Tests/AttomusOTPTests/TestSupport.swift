import Foundation

@testable import AttomusOTP

enum TestSupport {
    static func asciiData(_ value: String) -> Data {
        Data(value.utf8)
    }

    static func repeatedData(count: Int, seed: UInt8 = 0xAB) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: Int(seed) + $0) })
    }
}
