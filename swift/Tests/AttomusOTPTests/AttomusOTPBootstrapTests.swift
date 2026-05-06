import XCTest

@testable import AttomusOTP

final class AttomusOTPBootstrapTests: XCTestCase {
    func testAccountProvisioningResultIsEquatable() {
        let account = OTPAccount(
            id: UUID(),
            type: .totp,
            label: "example",
            issuer: "Example",
            algorithm: .sha1,
            digits: 6,
            period: 30,
            createdAt: Date(timeIntervalSince1970: 0)
        )

        let result = OTPProvisioningResult(account: account, secret: Data([1, 2, 3, 4]))
        XCTAssertEqual(result.account.label, "example")
        XCTAssertEqual(result.secret.count, 4)
    }
}
