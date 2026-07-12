# AttomusOTP

TOTP (RFC 6238) and HOTP (RFC 4226) implementations for iOS/Swift and Android/Kotlin.
Two independent engines sharing a common design: same RFC compliance, same `otpauth://`
parsing behaviour, same data model, interoperable backup format.

Used by [Attomus Signet](https://attomus.com/products/signet/) — a zero-cloud offline
authenticator for iOS and Android.

<a href="https://apps.apple.com/app/id6762213110"><img src="assets/badges/app-store.svg" alt="Download on the App Store" height="40"></a>&nbsp;&nbsp;<a href="https://play.google.com/store/apps/details?id=com.attomus.signet"><img src="assets/badges/google-play.png" alt="Get it on Google Play" height="40"></a>

---

## Implementations

| | Swift | Kotlin |
|---|---|---|
| Platform | iOS 16+, macOS 13+, watchOS 9+, tvOS 16+, Linux | Android (JVM/API 26+) |
| Package | `swift/` — Swift Package Manager | `kotlin/` — Gradle |
| Module | `import AttomusOTP` | `import com.attomus.otp.*` |
| TOTP / HOTP | ✓ | ✓ |
| `otpauth://` URI parsing | ✓ | ✓ |
| Base32 decoding | ✓ | ✓ |
| Portable backup schema | ✓ | — (consumed at app layer) |
| HOTP counter integrity blob | ✓ | — (consumed at app layer) |

The backup format and counter blob are defined in the Swift library and documented
below. Both the iOS and Android Signet apps produce and consume the same on-disk
formats, ensuring backup interoperability across platforms.

---

## Requirements

### Swift

- Swift 5.9+
- iOS 16+ / macOS 13+ / watchOS 9+ / tvOS 16+
- Linux: Swift 5.9+ via [swift-crypto](https://github.com/apple/swift-crypto)

### Kotlin

- Kotlin 1.9+ / JVM 17+
- Android API 26+ (minSdk 26)
- No additional dependencies — uses `javax.crypto` from the standard library

---

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/attomus/attomus-otp.git", from: "1.0.0")
]
```

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("com.attomus:attomus-otp-android:1.0.2")
}
```

---

## API

### TOTP

**Swift**
```swift
import AttomusOTP

let code = try TOTP.generate(
    secret: secretBytes,  // raw seed bytes, not Base32-encoded
    algorithm: .sha1,
    digits: 6,
    period: 30,
    at: Date()
)
// "048921" — zero-padded to the requested digit count
```

**Kotlin**
```kotlin
import com.attomus.otp.TOTP
import com.attomus.otp.OTPAlgorithm

val code = TOTP.generate(
    secret = secretBytes,  // raw seed bytes, not Base32-encoded
    algorithm = OTPAlgorithm.SHA1,
    digits = 6,
    period = 30
)
// "048921" — zero-padded to the requested digit count

val remaining = TOTP.remainingSeconds(period = 30)
// seconds until the current code expires
```

---

### HOTP

**Swift**
```swift
let code = try HOTP.generate(
    secret: secretBytes,
    algorithm: .sha1,
    digits: 6,
    counter: 42
)
```

**Kotlin**
```kotlin
import com.attomus.otp.HOTP
import com.attomus.otp.OTPAlgorithm

val code = HOTP.generate(
    secret = secretBytes,
    counter = 42L,
    algorithm = OTPAlgorithm.SHA1,
    digits = 6
)
```

---

### `otpauth://` URI parsing

**Swift**
```swift
let result = try parseOTPURI(
    "otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
)
// result.account.type    == .totp
// result.account.issuer  == "Example"
// result.account.label   == "alice@example.com"
// result.account.digits  == 6
// result.account.period  == 30
// result.secretBytes     — raw seed bytes, ready to pass to TOTP.generate
```

Errors are typed (`OTPURIError`) — no strings to parse. Full validation is applied:
secret length, digit count, period, algorithm, URI structure, and percent-encoding.

**Kotlin**
```kotlin
import com.attomus.otp.OTPURIParser

val result = OTPURIParser.parse(
    "otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
)
// result.account.type    == OTPType.TOTP
// result.account.issuer  == "Example"
// result.account.label   == "alice@example.com"
// result.account.digits  == 6
// result.account.period  == 30
// result.secret          — raw seed bytes, ready to pass to TOTP.generate
```

Errors are typed (`OTPURIError`) — the same error taxonomy as the Swift implementation.

---

### Portable backup schema *(Swift)*

The backup schema serialises accounts and their raw seed bytes to a JSON payload.
It is intentionally dependency-free (`Foundation` only) so any platform can implement
a compatible reader or writer.

```swift
// Export — produce the JSON payload for the application layer to encrypt
let jsonPayload = try encodeExportDocument(
    accounts: accounts,
    secrets: secretsByID  // [UUID: Data] — raw seed bytes keyed by account ID
)
// jsonPayload is UTF-8 JSON — hand directly to your encryption layer
// Never write this to disk unencrypted

// Import — decode and validate a decrypted payload
let provisioningResults = try decodeExportDocument(jsonPayload)
for result in provisioningResults {
    // result.account, result.secretBytes
}
```

Schema version 1 is defined in this library. The application layer is responsible for
the encrypted envelope — Signet uses Argon2id + AES-256-GCM. The schema is documented
so any platform can implement a compatible reader.

---

### HOTP counter integrity blob *(Swift)*

A 41-byte HMAC-SHA256-protected record for tamper-evident HOTP counter storage.

```swift
// Encode — produce a 41-byte blob for storage
let blob = try encodeCounterBlob(counter: 42, integrityKey: key)
// layout: [version:1][counter:8 BE][hmac-sha256:32] = 41 bytes

// Verify — decode and verify, recovering the counter value
let counter = try verifyCounterBlob(blob, integrityKey: key)
```

`integrityKey` must be 32 bytes. The format is fixed; Signet iOS and Android both
produce and consume the same 41-byte layout. HMAC comparison is constant-time
throughout (Swift: bitwise-XOR accumulator with no early exit; Kotlin:
`MessageDigest.isEqual`).

---

## Supported algorithms

| Algorithm | TOTP | HOTP |
|-----------|:----:|:----:|
| SHA-1     |  ✓   |  ✓   |
| SHA-256   |  ✓   |  ✓   |
| SHA-512   |  ✓   |  ✓   |

Digit counts: 6, 7, or 8. TOTP period: 30 s and 60 s. Values outside this range are
rejected.

---

## Security

- All RFC 4226 (HOTP) and RFC 6238 (TOTP) test vectors pass in both implementations
- HMAC comparison is constant-time throughout (Swift: bitwise-XOR accumulator with no early exit; Kotlin: `MessageDigest.isEqual`)
- No secrets are logged, written to disk, or captured in error messages by either library
- Fuzz-tested: the URI parser and backup schema decoder have been exercised through
  billions of iterations with zero crashes
- Swift: `Sources/AttomusOTP` uses only `Foundation` and `CryptoKit` (Apple platforms)
  or `swift-crypto` (Linux) — no other dependencies
- Kotlin: `com.attomus.otp` uses only `javax.crypto` from the JVM standard library
- No networking, no storage, no platform permissions required by either implementation

---

## Licence

[Apache License 2.0](LICENSE) — Copyright (c) 2026 Attomus Ltd

---

## Contributing

These libraries implement fixed cryptographic specifications (RFC 4226, RFC 6238, and
the Attomus backup schema). They are not general-purpose OTP toolkits.

**In scope:** bug fixes, RFC compliance corrections, test vector additions, documentation
improvements, platform compatibility.

**Out of scope:** new OTP algorithms, encryption primitives, key management, platform
integrations, or features beyond the defined scope.

Security issues: open a GitHub issue or email
[security@attomus.com](mailto:security@attomus.com). Please do not publish a finding
publicly before giving us a reasonable window to respond.
