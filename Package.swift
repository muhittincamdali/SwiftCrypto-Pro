// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SwiftCryptoPro",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(
            name: "SwiftCryptoPro",
            targets: ["SwiftCryptoPro"]
        )
    ],
    targets: [
        .target(
            name: "SwiftCryptoPro",
            path: "Sources/SwiftCryptoPro"
        ),
        .testTarget(
            name: "SwiftCryptoProTests",
            dependencies: ["SwiftCryptoPro"],
            path: "Tests/SwiftCryptoProTests"
        )
    ]
)
