import Foundation
import XCTest

@testable import AttomusOTP

final class URIParserFuzzTests: XCTestCase {
    func testSeedCorpusDoesNotCrashParser() throws {
        let resourceRoot = try XCTUnwrap(Bundle.module.resourceURL)
        let candidateDirectories = [
            resourceRoot.appendingPathComponent("seed", isDirectory: true),
            resourceRoot.appendingPathComponent("FuzzCorpus/seed", isDirectory: true)
        ]

        let bundleURL = try XCTUnwrap(
            candidateDirectories.first(where: {
                var isDirectory: ObjCBool = false
                return FileManager.default.fileExists(atPath: $0.path, isDirectory: &isDirectory) && isDirectory.boolValue
            })
        )

        let fileURLs = try FileManager.default.contentsOfDirectory(at: bundleURL, includingPropertiesForKeys: nil)

        XCTAssertGreaterThanOrEqual(fileURLs.count, 50)

        for fileURL in fileURLs where fileURL.pathExtension == "txt" {
            let payload = try String(contentsOf: fileURL, encoding: .utf8)
            _ = try? parseOTPURI(payload.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
}
