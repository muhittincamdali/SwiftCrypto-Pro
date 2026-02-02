// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SwiftCrypto-Pro",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
        .watchOS(.v8),
        .tvOS(.v15)
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
            dependencies: [],
            path: "Sources/SwiftCryptoPro"
        ),
        .testTarget(
            name: "SwiftCryptoProTests",
            dependencies: ["SwiftCryptoPro"]
        )
    ]
)
