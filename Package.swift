// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Shadow",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "PolicyCore", targets: ["PolicyCore"]),
        .library(name: "BrokerHost", targets: ["BrokerHost"]),
        .library(name: "RuntimeHost", targets: ["RuntimeHost"]),
        .library(name: "ModelRelay", targets: ["ModelRelay"]),
        .library(name: "EgressGateway", targets: ["EgressGateway"]),
        .executable(name: "vm-config-probe", targets: ["VMConfigProbe"]),
        .executable(name: "vm-boot-probe", targets: ["VMBootProbe"]),
        .executable(name: "Shadow", targets: ["OwnerApp"]),
        .executable(name: "owner-ui-probe", targets: ["OwnerUIProbe"]),
        .executable(name: "source-fixture", targets: ["SourceFixture"]),
        .executable(name: "agent-api-probe", targets: ["AgentAPIProbe"]),
    ],
    targets: [
        .target(name: "PolicyCore", linkerSettings: [.linkedLibrary("sqlite3")]),
        .target(name: "BrokerHost", dependencies: ["PolicyCore", "RuntimeHost", "EgressGateway"]),
        .target(name: "RuntimeHost", dependencies: ["PolicyCore"]),
        .target(name: "ModelRelay", dependencies: ["PolicyCore"]),
        .target(name: "EgressGateway", dependencies: ["PolicyCore"]),
        .executableTarget(name: "VMConfigProbe", dependencies: ["RuntimeHost"]),
        .executableTarget(name: "VMBootProbe", dependencies: ["RuntimeHost", "ModelRelay", "EgressGateway", "BrokerHost", "OwnerUI"]),
        .target(name: "OwnerUI", dependencies: ["BrokerHost", "PolicyCore"]),
        .executableTarget(name: "OwnerApp", dependencies: ["OwnerUI"]),
        .executableTarget(name: "OwnerUIProbe", dependencies: ["OwnerUI"]),
        .executableTarget(name: "SourceFixture", dependencies: ["RuntimeHost"]),
        .executableTarget(name: "AgentAPIProbe", dependencies: ["BrokerHost", "PolicyCore", "RuntimeHost"]),
        .testTarget(name: "PolicyCoreTests", dependencies: ["PolicyCore", "RuntimeHost", "ModelRelay", "EgressGateway", "BrokerHost", "OwnerUI"], path: "tests/PolicyCoreTests"),
    ]
)
