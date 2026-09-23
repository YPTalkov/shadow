import Foundation
import Security
import Testing
import BrokerHost
import PolicyCore

@Test func nativeWorkerUsesKeychainAndImportsWithoutReturningSecrets() async throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-native-worker-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let vaultID = "synthetic-worker-\(UUID().uuidString)"
    defer {
        try? FileManager.default.removeItem(at: directory)
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: vaultID] as CFDictionary)
    }
    let client = try await PrivateVaultWorker.launch(python: root.appendingPathComponent(".venv/bin/python"), vaultDirectory: directory.appendingPathComponent("vault"), vaultID: vaultID)
    try await client.create(password: "synthetic-master-password")
    let anchor = GenerationAnchor(vaultID: vaultID)
    let before = try anchor.read()
    #expect(before?.count == 64)
    let liveVault = directory.appendingPathComponent("vault/vault.kdbx")
    let oldGeneration = try Data(contentsOf: liveVault)
    let source = directory.appendingPathComponent("synthetic.csv")
    try Data("Title,URL,Username,Password\nNative,https://example.invalid,owner,synthetic-password-canary\n".utf8).write(to: source)
    let headers = try await client.csvHeaders(path: source)
    #expect(headers == ["Title", "URL", "Username", "Password"])
    let preview = try await client.previewCSV(path: source, mapping: OwnerCSVMapping(title: "Title", url: "URL", username: "Username", password: "Password"))
    #expect(preview.accepted == 1)
    let result = try await client.commitCSV(operationID: UUID(), validRowsOnly: false)
    #expect(result.accepted == 1)
    #expect(try anchor.read() != before)
    let catalog = try await client.catalog()
    #expect(catalog.items.map(\.title) == ["Native"])
    #expect(!String(decoding: try JSONEncoder().encode(catalog), as: UTF8.self).contains("synthetic-password-canary"))
    await client.lock()
    let reopened = try await PrivateVaultWorker.launch(python: root.appendingPathComponent(".venv/bin/python"), vaultDirectory: directory.appendingPathComponent("vault"), vaultID: vaultID)
    try await reopened.unlock(password: "synthetic-master-password")
    #expect(try await reopened.catalog().items.count == 1)
    await reopened.lock()
    try oldGeneration.write(to: liveVault)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: liveVault.path)
    let restored = try await PrivateVaultWorker.launch(python: root.appendingPathComponent(".venv/bin/python"), vaultDirectory: directory.appendingPathComponent("vault"), vaultID: vaultID)
    do {
        try await restored.unlock(password: "synthetic-master-password")
        Issue.record("An older vault generation must require recovery")
    } catch VaultWorkerError.reported(let code) {
        #expect(code == "recovery_required")
    }
    await restored.lock()
}
