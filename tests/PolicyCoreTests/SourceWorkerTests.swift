import Foundation
import Security
import Testing
import BrokerHost
import PolicyCore

@MainActor private final class SourceInvalidations {
    var accounts: [UUID] = []
}

@Test @MainActor func nativeSourceCommitRestrictsBeforePublicationAndPreservesReappearanceHistory() async throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-source-worker-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let vaultID = "synthetic-source-\(UUID().uuidString)"
    defer {
        try? FileManager.default.removeItem(at: directory)
        for account in [vaultID, vaultID + ":restrictions"] {
            SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: account] as CFDictionary)
        }
    }
    let invalidated = SourceInvalidations()
    let worker = try await PrivateVaultWorker.launch(python: root.appendingPathComponent(".venv/bin/python"), vaultDirectory: directory.appendingPathComponent("vault"), vaultID: vaultID) { invalidated.accounts += $0 }
    try await worker.create(password: "synthetic-source-master")
    let instance = UUID(), epoch = UUID()
    let capabilities = SourceCapabilities(stableItems: true, stableGroups: true, completeScopes: ["account", "group"], deletionEvidence: ["item_tombstone"], distinguishesAccessLoss: true, totp: false, collectionMode: "unattended")
    try await worker.configureSource(instance: instance, label: "Synthetic source", epoch: epoch, capabilities: capabilities, digestKey: Data(repeating: 17, count: 32))
    let first = try await sendSyntheticBatch(worker, instance: instance, epoch: epoch, generation: 0, includeItem: true)
    #expect(first.state == "committed")
    #expect(first.receipt?.accepted == 1)
    let initial = try #require(try await worker.catalog().items.first)
    #expect(initial.sourceKind == "mirrored")
    #expect(initial.presence == "present")
    #expect(initial.restrictionEvent == nil)
    #expect(initial.observationDate != nil)
    let id = try #require(UUID(uuidString: initial.id))
    let second = try await sendSyntheticBatch(worker, instance: instance, epoch: epoch, generation: 1, includeItem: false)
    #expect(second.receipt?.retained == 1)
    // The native callback is awaited before the worker can publish and reply.
    #expect(invalidated.accounts.contains(id))
    let removed = try #require(try await worker.catalog().items.first)
    #expect(removed.presence == "deleted_at_source")
    let event = try #require(removed.restrictionEvent)
    let ledger = NativeRestrictions(vaultDirectory: directory.appendingPathComponent("vault"), vaultID: vaultID)
    #expect(try ledger.latest(requireExisting: true)[id]?.id.uuidString.lowercased() == event)
    _ = try await sendSyntheticBatch(worker, instance: instance, epoch: epoch, generation: 2, includeItem: true)
    let reappeared = try #require(try await worker.catalog().items.first)
    #expect(reappeared.id == initial.id)
    #expect(reappeared.presence == "present")
    #expect(reappeared.restrictionEvent == event)
    #expect(reappeared.revision > initial.revision)
    #expect(!String(decoding: try JSONEncoder().encode(reappeared), as: UTF8.self).contains("synthetic-source-canary"))
    #expect(try await worker.sources(instances: [instance]).first?.generation == 3)
    let batch = UUID()
    _ = try await worker.sourceFrame(instance: instance, frame: sourceMessage(instance, epoch, batch, 0, "begin", ["previous_generation": 3, "started_at": "2026-09-24T00:00:00Z", "mode": "snapshot"]))
    let aborted = try await worker.sourceFrame(instance: instance, frame: sourceMessage(instance, epoch, batch, 1, "abort", [:]))
    #expect(aborted.state == "aborted")
    #expect(aborted.receipt == nil)
    await worker.lock()
    let reopened = try await PrivateVaultWorker.launch(python: root.appendingPathComponent(".venv/bin/python"), vaultDirectory: directory.appendingPathComponent("vault"), vaultID: vaultID)
    try await reopened.unlock(password: "synthetic-source-master")
    #expect(try await reopened.catalog().items.first?.restrictionEvent == event)
    await reopened.lock()
}

private func sourceMessage(_ instance: UUID, _ epoch: UUID, _ batch: UUID, _ sequence: Int, _ kind: String, _ payload: [String: Any]) throws -> Data {
    try JSONSerialization.data(withJSONObject: ["contract_major": 1, "source_instance_id": instance.uuidString.lowercased(), "channel_epoch": epoch.uuidString.lowercased(), "batch_id": batch.uuidString.lowercased(), "producer_sequence": sequence, "kind": kind, "payload": payload])
}

private func sendSyntheticBatch(_ worker: PrivateVaultWorker, instance: UUID, epoch: UUID, generation: Int, includeItem: Bool) async throws -> SourceFrameResult {
    let batch = UUID()
    var messages: [(String, [String: Any])] = [
        ("begin", ["previous_generation": generation, "started_at": "2026-09-24T00:00:00Z", "mode": "snapshot"]),
        ("group", ["id": "group-a", "parent_id": NSNull(), "name": "Synthetic Group", "relationship": "member", "observation": "present"])
    ]
    if includeItem {
        messages.append(("item", ["id": "item-a", "source_revision": "revision_unknown", "title": "Synthetic account", "username": "owner", "urls": ["https://example.invalid/"], "groups": ["group-a"], "credential_kind": "password", "secret": ["password": "synthetic-source-canary"]]))
    }
    messages.append(("coverage", ["scope": "account", "id": "account", "state": "complete", "basis": "enumeration_complete", "capability_version": 1]))
    messages.append(("commit", ["finished_at": "2026-09-24T00:00:00Z", "final_sequence": messages.count, "coverage_count": 1]))
    var result: SourceFrameResult?
    for (index, message) in messages.enumerated() {
        result = try await worker.sourceFrame(instance: instance, frame: sourceMessage(instance, epoch, batch, index, message.0, message.1))
    }
    return try #require(result)
}
