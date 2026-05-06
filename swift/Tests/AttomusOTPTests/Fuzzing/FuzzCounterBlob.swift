import AttomusOTP
import Foundation

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzVerifyCounterBlob(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int32 {
    let bytes = Data(bytes: data, count: max(size, 0))
    let dummyKey = Data(repeating: 0x00, count: 32)
    _ = try? verifyCounterBlob(bytes, integrityKey: dummyKey)
    return 0
}
