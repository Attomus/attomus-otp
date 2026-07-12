import AttomusOTP
import Foundation

private let fuzzAlgorithms: [OTPAlgorithm] = [.sha1, .sha256, .sha512]
private let fuzzDigits = [6, 7, 8]
private let fuzzPeriods = [-1, 0, 1, 15, 30, 60, 90]

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzTOTP(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int32 {
    let buffer = UnsafeBufferPointer(start: data, count: max(size, 0))
    let bytes = Data(buffer)
    let secret = normalizedSecret(from: bytes)

    let algorithm = fuzzAlgorithms[index(from: bytes, offset: 0, modulo: fuzzAlgorithms.count)]
    let digits = fuzzDigits[index(from: bytes, offset: 1, modulo: fuzzDigits.count)]
    let period = fuzzPeriods[index(from: bytes, offset: 2, modulo: fuzzPeriods.count)]
    let timestamp = TimeInterval(Int64(bitPattern: counterValue(from: bytes, takingFirst: true)))
    let counter = counterValue(from: bytes, takingFirst: false)

    _ = try? TOTP.generate(
        secret: secret,
        at: Date(timeIntervalSince1970: timestamp),
        algorithm: algorithm,
        digits: digits,
        period: period
    )

    _ = try? TOTP.remainingSeconds(at: Date(timeIntervalSince1970: timestamp), period: period)

    _ = try? HOTP.generate(
        secret: secret,
        counter: counter,
        algorithm: algorithm,
        digits: digits
    )

    if let uriString = String(data: bytes, encoding: .utf8) {
        _ = try? parseOTPURI(uriString)
        _ = try? Base32.decode(uriString)
    }

    return 0
}

private func normalizedSecret(from bytes: Data) -> Data {
    if bytes.isEmpty {
        return Data(repeating: 0x41, count: 16)
    }

    if bytes.count >= 16 {
        return bytes.prefix(64)
    }

    var expanded = Data()
    expanded.reserveCapacity(16)

    while expanded.count < 16 {
        expanded.append(bytes)
    }

    return expanded.prefix(16)
}

private func index(from bytes: Data, offset: Int, modulo: Int) -> Int {
    guard modulo > 0 else {
        return 0
    }

    let byte = bytes.indices.contains(offset) ? bytes[bytes.index(bytes.startIndex, offsetBy: offset)] : 0
    return Int(byte) % modulo
}

private func counterValue(from bytes: Data, takingFirst: Bool) -> UInt64 {
    let slice: Data

    if takingFirst {
        slice = bytes.prefix(8)
    } else {
        slice = bytes.suffix(8)
    }

    return slice.reduce(UInt64(0)) { partial, byte in
        (partial << 8) | UInt64(byte)
    }
}
