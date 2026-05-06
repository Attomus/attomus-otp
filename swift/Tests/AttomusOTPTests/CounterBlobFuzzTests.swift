import Foundation
import XCTest

@testable import AttomusOTP

final class CounterBlobFuzzTests: XCTestCase {
    func testSeedCorpusDoesNotCrashVerifier() throws {
        let bundleURL = sourceSeedDirectory()
        let fileURLs = try FileManager.default.contentsOfDirectory(at: bundleURL, includingPropertiesForKeys: nil)
        XCTAssertGreaterThanOrEqual(fileURLs.count, 10)

        let dummyKey = Data(repeating: 0x00, count: 32)
        for fileURL in fileURLs {
            let payload = try Data(contentsOf: fileURL)
            _ = try? verifyCounterBlob(payload, integrityKey: dummyKey)
        }
    }

    private func sourceSeedDirectory() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("CounterBlobFuzzCorpus/seed", isDirectory: true)
    }
}
