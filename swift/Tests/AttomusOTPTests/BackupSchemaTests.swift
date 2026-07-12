import Foundation
import XCTest

@testable import AttomusOTP

final class BackupSchemaTests: XCTestCase {
    func testEncodeDecodeRoundTripPreservesAccountsAndSecrets() throws {
        let totpID = try uuid("550E8400-E29B-41D4-A716-446655440001")
        let hotpID = try uuid("550E8400-E29B-41D4-A716-446655440002")
        let totpAccount = OTPAccount(
            id: totpID,
            type: .totp,
            label: "alice@example.com",
            issuer: "Example",
            algorithm: .sha1,
            digits: 6,
            period: 30,
            counter: nil,
            createdAt: Date(timeIntervalSince1970: 1)
        )
        let hotpAccount = OTPAccount(
            id: hotpID,
            type: .hotp,
            label: "bob@example.com",
            issuer: "Example",
            algorithm: .sha256,
            digits: 7,
            period: 30,
            counter: 42,
            createdAt: Date(timeIntervalSince1970: 2)
        )

        let secrets: [UUID: Data] = [
            totpID: TestSupport.asciiData("12345678901234567890"),
            hotpID: TestSupport.asciiData("12345678901234567890123456789012")
        ]
        let totpSecret = try XCTUnwrap(secrets[totpID])
        let hotpSecret = try XCTUnwrap(secrets[hotpID])

        let encoded = try encodeExportDocument(accounts: [totpAccount, hotpAccount], secrets: secrets)
        let decoded = try decodeExportDocument(encoded)

        XCTAssertEqual(decoded.count, 2)
        XCTAssertEqual(decoded[0].account, totpAccount)
        XCTAssertEqual(decoded[0].secret, secrets[totpID])
        XCTAssertEqual(decoded[1].account, hotpAccount)
        XCTAssertEqual(decoded[1].secret, secrets[hotpID])

        let exportDecoder = JSONDecoder()
        exportDecoder.dateDecodingStrategy = .iso8601
        let exportDocument = try exportDecoder.decode(OTPExportDocument.self, from: encoded)
        XCTAssertEqual(exportDocument.schema, 1)
        XCTAssertEqual(exportDocument.accounts[0].counter, nil)
        XCTAssertEqual(exportDocument.accounts[1].counter, 42)
        XCTAssertEqual(exportDocument.accounts[0].secret, Base32.encode(totpSecret))
        XCTAssertEqual(exportDocument.accounts[1].secret, Base32.encode(hotpSecret))
    }

    func testRejectsUnsupportedSchemaVersion() throws {
        let schema0 = #"""
        {"schema":0,"exported":"2026-04-17T12:00:00Z","accounts":[]}
        """#
        let schema2 = #"""
        {"schema":2,"exported":"2026-04-17T12:00:00Z","accounts":[]}
        """#

        XCTAssertThrowsError(try decodeExportDocument(Data(schema0.utf8))) { error in
            XCTAssertEqual(error as? OTPBackupError, .unsupportedSchemaVersion(0))
        }

        XCTAssertThrowsError(try decodeExportDocument(Data(schema2.utf8))) { error in
            XCTAssertEqual(error as? OTPBackupError, .unsupportedSchemaVersion(2))
        }
    }

    func testRejectsMalformedJSON() {
        XCTAssertThrowsError(try decodeExportDocument(Data("{".utf8))) { error in
            XCTAssertEqual(error as? OTPBackupError, .malformedJSON)
        }
    }

    func testRejectsEmptyDocument() throws {
        let data = #"""
        {"schema":1,"exported":"2026-04-17T12:00:00Z","accounts":[]}
        """#

        XCTAssertThrowsError(try decodeExportDocument(Data(data.utf8))) { error in
            XCTAssertEqual(error as? OTPBackupError, .emptyDocument)
        }
    }

    func testRejectsMissingSecret() throws {
        let accountID = try uuid("550E8400-E29B-41D4-A716-446655440003")
        let data = #"""
        {"schema":1,"exported":"2026-04-17T12:00:00Z","accounts":[{"id":"\#(accountID.uuidString)","type":"totp","accountName":"alice@example.com","issuer":"Example","algorithm":"SHA1","digits":6,"period":30,"createdAt":"2026-04-17T12:00:00Z"}]}
        """#

        XCTAssertThrowsError(try decodeExportDocument(Data(data.utf8))) { error in
            XCTAssertEqual(error as? OTPBackupError, .missingSecret(accountID: accountID))
        }
    }

    func testRejectsInvalidSecret() throws {
        let accountID = try uuid("550E8400-E29B-41D4-A716-446655440004")
        let data = #"""
        {"schema":1,"exported":"2026-04-17T12:00:00Z","accounts":[{"id":"\#(accountID.uuidString)","type":"totp","accountName":"alice@example.com","issuer":"Example","algorithm":"SHA1","digits":6,"period":30,"secret":"JBSWY3D!","createdAt":"2026-04-17T12:00:00Z"}]}
        """#

        XCTAssertThrowsError(try decodeExportDocument(Data(data.utf8))) { error in
            XCTAssertEqual(error as? OTPBackupError, .invalidSecret(accountID: accountID))
        }
    }

    func testRejectsInvalidDigits() throws {
        let accountID = try uuid("550E8400-E29B-41D4-A716-446655440005")
        let data = #"""
        {"schema":1,"exported":"2026-04-17T12:00:00Z","accounts":[{"id":"\#(accountID.uuidString)","type":"totp","accountName":"alice@example.com","issuer":"Example","algorithm":"SHA1","digits":5,"period":30,"secret":"IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U","createdAt":"2026-04-17T12:00:00Z"}]}
        """#

        XCTAssertThrowsError(try decodeExportDocument(Data(data.utf8))) { error in
            XCTAssertEqual(error as? OTPBackupError, .invalidDigits(accountID: accountID))
        }
    }

    func testRejectsInvalidPeriod() throws {
        let accountID = try uuid("550E8400-E29B-41D4-A716-446655440006")
        let data = #"""
        {"schema":1,"exported":"2026-04-17T12:00:00Z","accounts":[{"id":"\#(accountID.uuidString)","type":"totp","accountName":"alice@example.com","issuer":"Example","algorithm":"SHA1","digits":6,"period":45,"secret":"IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U","createdAt":"2026-04-17T12:00:00Z"}]}
        """#

        XCTAssertThrowsError(try decodeExportDocument(Data(data.utf8))) { error in
            XCTAssertEqual(error as? OTPBackupError, .invalidPeriod(accountID: accountID))
        }
    }

    func testRejectsInvalidHOTPPeriod() throws {
        let accountID = try uuid("550E8400-E29B-41D4-A716-446655440008")

        for period in [0, -30] {
            let data = #"""
            {"schema":1,"exported":"2026-04-17T12:00:00Z","accounts":[{"id":"\#(accountID.uuidString)","type":"hotp","accountName":"alice@example.com","issuer":"Example","algorithm":"SHA1","digits":6,"period":\#(period),"counter":42,"secret":"IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U","createdAt":"2026-04-17T12:00:00Z"}]}
            """#

            XCTAssertThrowsError(try decodeExportDocument(Data(data.utf8))) { error in
                XCTAssertEqual(error as? OTPBackupError, .invalidPeriod(accountID: accountID))
            }
        }
    }

    func testRejectsMissingHOTPCounter() throws {
        let accountID = try uuid("550E8400-E29B-41D4-A716-446655440007")
        let data = #"""
        {"schema":1,"exported":"2026-04-17T12:00:00Z","accounts":[{"id":"\#(accountID.uuidString)","type":"hotp","accountName":"alice@example.com","issuer":"Example","algorithm":"SHA1","digits":6,"secret":"IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U","createdAt":"2026-04-17T12:00:00Z"}]}
        """#

        XCTAssertThrowsError(try decodeExportDocument(Data(data.utf8))) { error in
            XCTAssertEqual(error as? OTPBackupError, .missingCounter(accountID: accountID))
        }
    }

    private func uuid(_ value: String) throws -> UUID {
        try XCTUnwrap(UUID(uuidString: value))
    }
}
