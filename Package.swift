// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "AttomusOTP",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "AttomusOTP",
            targets: ["AttomusOTP"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "AttomusOTP",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux]))
            ],
            path: "swift/Sources/AttomusOTP"
        ),
        .testTarget(
            name: "AttomusOTPTests",
            dependencies: ["AttomusOTP"],
            path: "swift/Tests/AttomusOTPTests",
            exclude: [
                "Fuzzing"
            ],
            resources: [
                .copy("FuzzCorpus"),
                .copy("BackupFuzzCorpus"),
                .copy("CounterBlobFuzzCorpus")
            ]
        )
    ]
)
