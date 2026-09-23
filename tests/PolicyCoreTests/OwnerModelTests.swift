import Foundation
import Testing
import Security
import OwnerUI

@Test @MainActor func ownerLockPreventsLateUnlockPublication() async throws {
    let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-owner-model-\(UUID().uuidString)")
    let config = try OwnerConfiguration(root: root, python: source.appendingPathComponent(".venv/bin/python"))
    defer {
        try? FileManager.default.removeItem(at: root)
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: config.vaultID] as CFDictionary)
    }
    #expect(throws: OwnerConfigurationError.self) { _ = try OwnerConfiguration(root: root, python: source.appendingPathComponent(".venv/bin/python")) }
    let model = OwnerVaultModel(configuration: config)
    let opening = Task { await model.open(password: "synthetic-master-password", create: true) }
    for _ in 0..<100 where !model.busy { try await Task.sleep(for: .milliseconds(1)) }
    try #require(model.busy)
    await model.lock()
    await opening.value
    #expect(!model.unlocked)
    #expect(!model.busy)
    #expect(model.accounts.isEmpty)
    #expect(model.status == "Locked")
}
