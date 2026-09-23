// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Shadow",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "PolicyCore", targets: ["PolicyCore"]),
        .library(name: "BrokerHost", targets: ["BrokerHost"]),
        .library(name: "RuntimeHost", targets: ["RuntimeHost"]),
        .executable(name: "vm-config-probe", targets: ["VMConfigProbe"]),
    ],
    targets: [
        .target(name: "PolicyCore", linkerSettings: [.linkedLibrary("sqlite3")]),
        .target(name: "BrokerHost", dependencies: ["PolicyCore"]),
        .target(name: "RuntimeHost"),
        .executableTarget(name: "VMConfigProbe", dependencies: ["RuntimeHost"]),
        .testTarget(name: "PolicyCoreTests", dependencies: ["PolicyCore", "RuntimeHost"], path: "tests/PolicyCoreTests"),
    ]
)
