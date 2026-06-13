// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwiftCrypto-Pro",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
        .watchOS(.v8),
        .tvOS(.v15),
        .visionOS(.v1)
    ],
    products: [
        .library(name: "SwiftCryptoPro", targets: ["SwiftCryptoPro"]),
    ],
    targets: [
        .target(
            name: "SwiftCryptoPro",
            path: "Sources/SwiftCryptoPro",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        .testTarget(
            name: "SwiftCryptoProTests",
            dependencies: ["SwiftCryptoPro"]
        )
    ]
)
