import AttomusOTP
import Foundation

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzDecodeExportDocument(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int32 {
    let bytes = Data(bytes: data, count: max(size, 0))
    _ = try? decodeExportDocument(bytes)
    return 0
}
