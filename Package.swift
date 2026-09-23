// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Shadow",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "PolicyCore", targets: ["PolicyCore"]),
        .library(name: "BrokerHost", targets: ["BrokerHost"]),
    ],
    targets: [
        .target(name: "PolicyCore", linkerSettings: [.linkedLibrary("sqlite3")]),
        .target(name: "BrokerHost", dependencies: ["PolicyCore"]),
        .testTarget(name: "PolicyCoreTests", dependencies: ["PolicyCore"], path: "tests/PolicyCoreTests"),
    ]
)
