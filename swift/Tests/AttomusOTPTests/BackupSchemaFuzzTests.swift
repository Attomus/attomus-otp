import Foundation
import XCTest

@testable import AttomusOTP

final class BackupSchemaFuzzTests: XCTestCase {
    func testSeedCorpusDoesNotCrashDecoder() throws {
        let bundleURL = sourceSeedDirectory()
        let fileURLs = try FileManager.default.contentsOfDirectory(at: bundleURL, includingPropertiesForKeys: nil)
        XCTAssertGreaterThanOrEqual(fileURLs.count, 30)

        for fileURL in fileURLs where fileURL.pathExtension == "json" {
            let payload = try Data(contentsOf: fileURL)
            _ = try? decodeExportDocument(payload)
        }
    }

    private func sourceSeedDirectory() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("BackupFuzzCorpus/seed", isDirectory: true)
    }
}
