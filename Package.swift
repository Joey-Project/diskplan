// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "diskplan",
  platforms: [.macOS(.v14)],
  products: [
    .library(name: "DiskplanCore", targets: ["DiskplanCore"]),
    .library(name: "DiskplanMacOS", targets: ["DiskplanMacOS"]),
    .library(name: "DiskplanPolicy", targets: ["DiskplanPolicy"]),
    .library(name: "DiskplanExecution", targets: ["DiskplanExecution"]),
    .executable(name: "diskplan-engine", targets: ["DiskplanEngine"]),
    .executable(name: "diskplan-macos-probe", targets: ["DiskplanMacOSProbe"]),
  ],
  dependencies: [
    .package(
      url: "https://github.com/apple/swift-protobuf.git",
      exact: "1.38.0"
    )
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
        .product(name: "SwiftProtobuf", package: "swift-protobuf")
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
      name: "DiskplanPolicy",
      path: "swift/Sources/DiskplanPolicy"
    ),
    .target(
      name: "DiskplanExecution",
      dependencies: ["DiskplanPolicy"],
      path: "swift/Sources/DiskplanExecution"
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
      name: "DiskplanPolicyTests",
      dependencies: ["DiskplanPolicy"],
      path: "swift/Tests/DiskplanPolicyTests"
    ),
    .testTarget(
      name: "DiskplanExecutionTests",
      dependencies: ["DiskplanExecution", "DiskplanPolicy"],
      path: "swift/Tests/DiskplanExecutionTests"
    ),
  ]
)
