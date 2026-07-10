# Changelog

All notable changes to AttomusOTP are documented here. Releases follow semantic versioning.

## [1.1.0] - 2026-07-10

### Fixed

- Rejected unsupported TOTP periods and pre-epoch timestamps consistently in Swift and Kotlin.
- Made Swift HOTP counter-blob verification safe for sliced `Data` values.
- Aligned URI HOTP counter parsing to the signed 64-bit range across Swift and Kotlin.
- Rejected invalid HOTP periods in Swift backup imports.

## [1.0.2] - 2026-05-19

### Fixed

- Accepted 16-character Base32 TOTP secrets used by GitHub and other deployed providers.
- Lowered the decoded secret minimum from 16 bytes to 10 bytes while retaining rejection of
  shorter inputs.

## [1.0.1] - 2026-05-06

### Changed

- Published the Swift and Kotlin package documentation and distribution metadata.

## [1.0.0] - 2026-05-05

### Added

- RFC 4226 HOTP and RFC 6238 TOTP engines.
- RFC 4648 Base32 support and `otpauth://` URI parsing.
- Portable backup schema and HOTP counter integrity blob in the Swift library.
