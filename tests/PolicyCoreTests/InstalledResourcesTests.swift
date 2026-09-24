import Foundation
import CryptoKit
import Testing
@testable import OwnerUI

@Test func installedResourcesRejectTamperAndUnqualifiedHosts() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-install-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let original = Data("fixture-resource".utf8)
    let hash = SHA256.hash(data: original).map { String(format: "%02x", $0) }.joined()
    for name in ["worker.py", "image", "adapter.json"] { try original.write(to: root.appendingPathComponent(name)) }
    try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("python3").path, withDestinationPath: "worker.py")
    let manifest: [String: Any] = ["schema": 1, "macos": "26.6.2", "architecture": "arm64",
        "files": ["worker.py": hash, "image": hash, "adapter.json": hash], "links": ["python3": "worker.py"]]
    try JSONSerialization.data(withJSONObject: manifest).write(to: root.appendingPathComponent("installation.json"))
    try InstalledResources.verifyInventory(at: root, macos: "26.6.2", architecture: "arm64")
    #expect(throws: (any Error).self) { try InstalledResources.verifyInventory(at: root, macos: "26.6.3", architecture: "arm64") }
    #expect(throws: (any Error).self) { try InstalledResources.verifyInventory(at: root, macos: "26.6.2", architecture: "x86_64") }
    for name in ["worker.py", "image", "adapter.json"] {
        try Data("modified".utf8).write(to: root.appendingPathComponent(name))
        #expect(throws: (any Error).self) { try InstalledResources.verifyInventory(at: root, macos: "26.6.2", architecture: "arm64") }
        try original.write(to: root.appendingPathComponent(name))
    }
    try Data().write(to: root.appendingPathComponent("extra.py"))
    #expect(throws: (any Error).self) { try InstalledResources.verifyInventory(at: root, macos: "26.6.2", architecture: "arm64") }
    try FileManager.default.removeItem(at: root.appendingPathComponent("extra.py"))
    try FileManager.default.removeItem(at: root.appendingPathComponent("python3"))
    try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("python3").path, withDestinationPath: "/usr/bin/python3")
    #expect(throws: (any Error).self) { try InstalledResources.verifyInventory(at: root, macos: "26.6.2", architecture: "arm64") }
}
