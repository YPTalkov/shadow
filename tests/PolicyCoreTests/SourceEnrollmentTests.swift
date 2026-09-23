import Foundation
import Security
import Testing
import BrokerHost

@Test @MainActor func enrolledExecutableRefreshesOverPrivateChannelAndRemovalPreservesAccounts() async throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-source-enrollment-\(UUID().uuidString)").resolvingSymlinksInPath()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let vaultID = "synthetic-source-enrollment-\(UUID().uuidString)"
    var enrolled: UUID?
    defer {
        try? FileManager.default.removeItem(at: directory)
        for id in [vaultID, vaultID + ":restrictions"] {
            SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: id] as CFDictionary)
        }
        if let enrolled {
            SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.source-digest", kSecAttrAccount as String: vaultID + ":" + enrolled.uuidString.lowercased()] as CFDictionary)
        }
    }
    let app = directory.appendingPathComponent("Fixture.app")
    let contents = app.appendingPathComponent("Contents")
    try FileManager.default.createDirectory(at: contents.appendingPathComponent("MacOS"), withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: contents.appendingPathComponent("Resources"), withIntermediateDirectories: false)
    try FileManager.default.copyItem(at: root.appendingPathComponent(".build/debug/source-fixture"), to: contents.appendingPathComponent("MacOS/source-fixture"))
    let info = ["CFBundleIdentifier": "com.yptalkov.shadow.synthetic-source", "CFBundleExecutable": "source-fixture", "CFBundlePackageType": "APPL", "CFBundleVersion": "1"]
    try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: contents.appendingPathComponent("Info.plist"))
    let capabilities = SourceCapabilities(stableItems: true, stableGroups: true, completeScopes: ["account", "group"], deletionEvidence: ["item_tombstone"], distinguishesAccessLoss: true, totp: false, collectionMode: "unattended")
    let encoder = JSONEncoder(); encoder.keyEncodingStrategy = .convertToSnakeCase
    let manifest: [String: Any] = ["contract_major": 1, "capabilities": try JSONSerialization.jsonObject(with: encoder.encode(capabilities))]
    try JSONSerialization.data(withJSONObject: manifest).write(to: contents.appendingPathComponent("Resources/shadow-source.json"))
    let signer = Process(); signer.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    signer.arguments = ["--force", "--sign", "-", app.path]
    signer.standardOutput = FileHandle.nullDevice; signer.standardError = FileHandle.nullDevice
    try signer.run(); signer.waitUntilExit(); try #require(signer.terminationStatus == 0)
    let candidate = try SourceCandidate.inspect(app)
    let second = try SourceCandidate.inspect(app)
    #expect(candidate.executable == second.executable)
    #expect(candidate.identifier == second.identifier)
    #expect(candidate.fingerprint == second.fingerprint)
    #expect(candidate.requirement == second.requirement)
    #expect(candidate.capabilities == second.capabilities)
    #expect(candidate.capabilities == capabilities)
    let store = try SourceEnrollmentStore(root: directory, vaultID: vaultID)
    let source = try store.enroll(candidate, label: "Synthetic enrollment")
    enrolled = source.id
    #expect(try SourceEnrollmentStore(root: directory, vaultID: vaultID).sources.first?.id == source.id)
    let worker = try await PrivateVaultWorker.launch(python: root.appendingPathComponent(".venv/bin/python"), vaultDirectory: directory.appendingPathComponent("vault"), vaultID: vaultID)
    try await worker.create(password: "synthetic-enrollment-master")
    let runtime = SourceRuntime()
    let result = try await runtime.refresh(source, store: store, worker: worker)
    #expect(result.receipt?.accepted == 1)
    #expect(try await worker.catalogSnapshot().first?.title == "Synthetic source account")
    try store.setEnabled(source.id, false)
    do {
        _ = try await runtime.refresh(store.sources[0], store: store, worker: worker)
        Issue.record("Disabled connectors cannot run")
    } catch SourceHostError.notConfigured {}
    try store.setEnabled(source.id, true)
    let interrupted = Task { try await runtime.refresh(store.sources[0], store: store, worker: worker) }
    for _ in 0..<100 where !runtime.isRefreshing { await Task.yield() }
    try #require(runtime.isRefreshing)
    runtime.stop()
    do {
        _ = try await interrupted.value
        Issue.record("Stopped preparation cannot launch or collect later")
    } catch SourceHostError.cancelled {}
    #expect(try await worker.sources(instances: [source.id]).first?.generation == 1)
    try Data("tampered manifest".utf8).write(to: contents.appendingPathComponent("Resources/shadow-source.json"))
    do {
        _ = try await runtime.refresh(store.sources[0], store: store, worker: worker)
        Issue.record("Changed sealed connector resources cannot run")
    } catch {}
    try store.remove(source.id)
    #expect(store.sources.isEmpty)
    #expect(try await worker.catalogSnapshot().count == 1)
    await worker.lock()
}
