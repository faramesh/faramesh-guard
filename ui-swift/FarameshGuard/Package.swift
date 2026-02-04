// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "FarameshGuard",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "FarameshGuard",
            targets: ["FarameshGuard"]
        ),
    ],
    dependencies: [
        // WebSocket for daemon communication
        .package(url: "https://github.com/vapor/websocket-kit.git", from: "2.14.0"),
    ],
    targets: [
        .executableTarget(
            name: "FarameshGuard",
            dependencies: [
                .product(name: "WebSocketKit", package: "websocket-kit"),
            ],
            path: ".",
            exclude: ["README.md", "Info.plist"],
            resources: [
                .process("Assets.xcassets"),
            ],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
            ]
        ),
    ]
)
