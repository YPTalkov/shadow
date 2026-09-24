import Foundation
import Security
import Testing
@testable import BrokerHost
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
    let selected = try #require(catalog.items.first)
    let credential = try await client.resolveCredential(entry: #require(UUID(uuidString: selected.id)), revision: selected.revision, origin: "https://example.invalid")
    #expect(credential.username == "owner" && credential.password == "synthetic-password-canary" && credential.totp == nil)
    #expect(!String(reflecting: credential).contains("synthetic-password-canary"))
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

@Test func ownerSnapshotIncludesAllPagesWithoutSecretFields() async throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-pages-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let vaultID = "synthetic-pages-\(UUID().uuidString)"
    defer {
        try? FileManager.default.removeItem(at: directory)
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: vaultID] as CFDictionary)
    }
    let worker = try await PrivateVaultWorker.launch(python: root.appendingPathComponent(".venv/bin/python"), vaultDirectory: directory.appendingPathComponent("vault"), vaultID: vaultID)
    try await worker.create(password: "synthetic-pages-master")
    let csv = directory.appendingPathComponent("synthetic.csv")
    let rows = (0..<61).map { "Account \($0),https://example.invalid,owner,synthetic-pagination-canary\n" }.joined()
    try Data(("Title,URL,Username,Password\n" + rows).utf8).write(to: csv)
    _ = try await worker.previewCSV(path: csv, mapping: OwnerCSVMapping(title: "Title", url: "URL", username: "Username", password: "Password"))
    _ = try await worker.commitCSV(operationID: UUID(), validRowsOnly: false)
    let items = try await worker.catalogSnapshot()
    #expect(items.count == 61 && Set(items.map(\.id)).count == 61)
    #expect(!String(decoding: try JSONEncoder().encode(items), as: UTF8.self).contains("synthetic-pagination-canary"))
    await worker.lock()
}
