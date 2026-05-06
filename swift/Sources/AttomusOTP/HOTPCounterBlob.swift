#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

public enum HOTPCounterBlobError: Error, Equatable, Sendable {
    case invalidBlobLength
    case unknownVersion
    case invalidKeyLength
    case invalidHMAC
}

public func encodeCounterBlob(counter: UInt64, integrityKey: Data) throws -> Data {
    try validateIntegrityKey(integrityKey)

    var blob = Data()
    blob.reserveCapacity(41)
    blob.append(0x01)
    blob.append(contentsOf: counter.bigEndianBytes)

    let tag = hmacSHA256(for: blob, key: integrityKey)
    blob.append(tag)
    return blob
}

public func verifyCounterBlob(_ blob: Data, integrityKey: Data) throws -> UInt64 {
    try validateIntegrityKey(integrityKey)

    guard blob.count == 41 else {
        throw HOTPCounterBlobError.invalidBlobLength
    }

    guard blob.first == 0x01 else {
        throw HOTPCounterBlobError.unknownVersion
    }

    let payload = blob.prefix(9)
    let expectedTag = hmacSHA256(for: Data(payload), key: integrityKey)
    let actualTag = blob.suffix(32)

    guard constantTimeEquals(expectedTag, actualTag) else {
        throw HOTPCounterBlobError.invalidHMAC
    }

    return try extractCounter(from: blob)
}

private func validateIntegrityKey(_ integrityKey: Data) throws {
    guard integrityKey.count == 32 else {
        throw HOTPCounterBlobError.invalidKeyLength
    }
}

private func hmacSHA256(for data: Data, key: Data) -> Data {
    let symmetricKey = SymmetricKey(data: key)
    return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
}

private func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else {
        return false
    }

    let lhsBytes = Array(lhs)
    let rhsBytes = Array(rhs)
    var difference: UInt8 = 0
    for index in 0..<lhsBytes.count {
        difference |= lhsBytes[index] ^ rhsBytes[index]
    }
    return difference == 0
}

private func extractCounter(from blob: Data) throws -> UInt64 {
    guard blob.count >= 9 else {
        throw HOTPCounterBlobError.invalidBlobLength
    }

    let counterBytes = blob[1..<9]
    var counter: UInt64 = 0
    for byte in counterBytes {
        counter = (counter << 8) | UInt64(byte)
    }
    return counter
}

private extension UInt64 {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian) { Array($0) }
    }
}
