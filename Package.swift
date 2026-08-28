// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "diskplan",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "DiskplanCore", targets: ["DiskplanCore"]),
        .library(name: "DiskplanMacOS", targets: ["DiskplanMacOS"]),
        .library(name: "DiskplanScan", targets: ["DiskplanScan"]),
        .library(name: "DiskplanEngineCore", targets: ["DiskplanEngineCore"]),
        .executable(name: "diskplan-engine", targets: ["DiskplanEngine"]),
        .executable(name: "diskplan-macos-probe", targets: ["DiskplanMacOSProbe"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-protobuf.git",
            exact: "1.38.0"
        ),
    ],
    targets: [
        .target(
            name: "CDiskplanMacOS",
            path: "swift/Sources/CDiskplanMacOS",
            publicHeadersPath: "include"
        ),
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
        .target(
            name: "DiskplanMacOS",
            dependencies: ["CDiskplanMacOS"],
            path: "swift/Sources/DiskplanMacOS",
            linkerSettings: [.linkedFramework("FileProvider")]
        ),
        .target(
            name: "DiskplanScan",
            dependencies: ["DiskplanMacOS"],
            path: "swift/Sources/DiskplanScan"
        ),
        .target(
            name: "DiskplanEngineCore",
            dependencies: ["DiskplanCore", "DiskplanMacOS", "DiskplanProto", "DiskplanScan"],
            path: "swift/Sources/DiskplanEngineCore"
        ),
        .executableTarget(
            name: "DiskplanEngine",
            dependencies: ["DiskplanEngineCore"],
            path: "swift/Sources/DiskplanEngine"
        ),
        .executableTarget(
            name: "DiskplanFixtureGenerator",
            dependencies: ["DiskplanCore"],
            path: "swift/Tools/DiskplanFixtureGenerator"
        ),
        .executableTarget(
            name: "DiskplanMacOSProbe",
            dependencies: ["DiskplanMacOS"],
            path: "swift/Tools/DiskplanMacOSProbe"
        ),
        .testTarget(
            name: "DiskplanCoreTests",
            dependencies: ["DiskplanCore", "DiskplanProto"],
            path: "swift/Tests/DiskplanCoreTests"
        ),
        .testTarget(
            name: "DiskplanMacOSTests",
            dependencies: ["DiskplanMacOS"],
            path: "swift/Tests/DiskplanMacOSTests"
        ),
        .testTarget(
            name: "DiskplanScanTests",
            dependencies: ["DiskplanScan", "DiskplanMacOS"],
            path: "swift/Tests/DiskplanScanTests"
        ),
        .testTarget(
            name: "DiskplanEngineCoreTests",
            dependencies: [
                "DiskplanCore",
                "DiskplanEngineCore",
                "DiskplanProto",
                "DiskplanScan",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            path: "swift/Tests/DiskplanEngineCoreTests"
        ),
    ]
)
