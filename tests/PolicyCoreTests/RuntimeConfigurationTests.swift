import Foundation
import CryptoKit
import Testing
@testable import RuntimeHost

@Test func bothGuestRolesHaveNoNetworkOrHostShares() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-vm-test-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    for name in ["synthetic-kernel", "synthetic-initrd", "synthetic-image"] {
        try Data(repeating: 0, count: 4096).write(to: root.appendingPathComponent(name))
    }
    let digest = SHA256.hash(data: Data(repeating: 0, count: 4096)).map { String(format: "%02x", $0) }.joined()
    let identity = VMImageIdentity(kernelSHA256: digest, ramdiskSHA256: digest, imageSHA256: digest)
    for role in [VMRole.agent, .browser] {
        let config = try RuntimeVMConfiguration.make(
            role: role,
            kernel: root.appendingPathComponent("synthetic-kernel"),
            ramdisk: root.appendingPathComponent("synthetic-initrd"),
            image: root.appendingPathComponent("synthetic-image"),
            identity: identity
        )
        #expect(config.networkDevices.isEmpty)
        #expect(config.directorySharingDevices.isEmpty)
        #expect(config.socketDevices.count == 1)
        #expect(config.storageDevices.count == 1)
        #expect(config.memorySize == 4 * 1024 * 1024 * 1024)
        #expect(config.cpuCount == 2)
    }
    try Data(repeating: 1, count: 4096).write(to: root.appendingPathComponent("synthetic-image"))
    #expect(throws: VMConfigurationError.imageMismatch) {
        _ = try RuntimeVMConfiguration.make(
            role: .agent,
            kernel: root.appendingPathComponent("synthetic-kernel"),
            ramdisk: root.appendingPathComponent("synthetic-initrd"),
            image: root.appendingPathComponent("synthetic-image"),
            identity: identity
        )
    }
}
