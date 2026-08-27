// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "diskplan",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "DiskplanCore", targets: ["DiskplanCore"]),
        .executable(name: "diskplan-engine", targets: ["DiskplanEngine"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-protobuf.git",
            exact: "1.38.0"
        ),
    ],
    targets: [
        .target(
            name: "DiskplanProto",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            path: "swift/Sources/DiskplanProto"
        ),
        .target(
            name: "DiskplanCore",
            dependencies: ["DiskplanProto"],
            path: "swift/Sources/DiskplanCore"
        ),
        .executableTarget(
            name: "DiskplanEngine",
            dependencies: ["DiskplanCore", "DiskplanProto"],
            path: "swift/Sources/DiskplanEngine"
        ),
        .executableTarget(
            name: "DiskplanFixtureGenerator",
            dependencies: ["DiskplanCore"],
            path: "swift/Tools/DiskplanFixtureGenerator"
        ),
        .testTarget(
            name: "DiskplanCoreTests",
            dependencies: ["DiskplanCore", "DiskplanProto"],
            path: "swift/Tests/DiskplanCoreTests"
        ),
    ]
)
