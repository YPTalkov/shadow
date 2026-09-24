import Foundation
import Security
import Testing
import BrokerHost
import PolicyCore
import OwnerUI

private let recoverySource = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

private func removeRecoveryAnchors(_ id: String) {
    for account in [id, id + ":restrictions"] {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: account] as CFDictionary)
    }
}

@Test(arguments: ["current", "access_lost", "missing", "corrupt", "rollback", "full_system"])
func nativeRestorePreservesRestrictionsAndTreatsLostHistoryAsUnknown(history: String) async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-recovery-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let vault = root.appendingPathComponent("vault"), id = "synthetic-recovery-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(at: root); removeRecoveryAnchors(id) }
    func launch() async throws -> PrivateVaultWorker {
        try await PrivateVaultWorker.launch(python: recoverySource.appendingPathComponent(".venv/bin/python"), vaultDirectory: vault, vaultID: id)
    }
    let worker = try await launch()
    try await worker.create(password: "synthetic-recovery-master")
    let instance = UUID(), epoch = UUID()
    let capabilities = SourceCapabilities(stableItems: true, stableGroups: true, completeScopes: ["account"], deletionEvidence: ["item_tombstone"], distinguishesAccessLoss: true, totp: false, collectionMode: "unattended")
    try await worker.configureSource(instance: instance, label: "Recovery fixture", epoch: epoch, capabilities: capabilities, digestKey: Data(repeating: 18, count: 32))
    _ = try await sendSyntheticBatch(worker, instance: instance, epoch: epoch, generation: 0, includeItem: true)
    let selected = root.appendingPathComponent("selected.kdbx")
    try await worker.exportBackup(to: selected)
    let ledgerPath = vault.appendingPathComponent("restrictions.sqlite")
    let oldLedger = try Data(contentsOf: ledgerPath)
    _ = try await sendSyntheticBatch(worker, instance: instance, epoch: epoch, generation: 1, includeItem: false)
    if history == "access_lost" {
        let account = try #require(try await worker.catalog().items.first)
        let identity = try #require(UUID(uuidString: account.id))
        try NativeRestrictions(vaultDirectory: vault, vaultID: id).record(account: identity, kind: .accessLost, eventID: UUID())
    }
    let deleted = try #require(try await worker.catalog().items.first)
    let deletedEvent = try #require(deleted.restrictionEvent)
    await worker.lock()
    switch history {
    case "missing": try FileManager.default.removeItem(at: ledgerPath)
    case "corrupt": try Data("synthetic-corruption".utf8).write(to: ledgerPath)
    case "rollback": try oldLedger.write(to: ledgerPath)
    case "full_system":
        try FileManager.default.removeItem(at: vault)
        removeRecoveryAnchors(id)
    default: break
    }
    let restored = try await launch()
    let review = try await restored.previewRestore(path: selected, password: "synthetic-recovery-master")
    #expect(review.accounts == 1 && review.mirrored == 1)
    #expect(review.historyUnknown == (!["current", "access_lost"].contains(history)))
    try await restored.commitRestore(reviewID: review.reviewID, acknowledgeUnknownHistory: review.historyUnknown)
    // A successful restore deliberately remains locked.
    do { _ = try await restored.catalog(); Issue.record("Restore exposed a catalog before unlock") }
    catch VaultWorkerError.reported(let code) { #expect(code == "vault_locked") }
    try await restored.unlock(password: "synthetic-recovery-master")
    let item = try #require(try await restored.catalog().items.first)
    #expect(item.id == deleted.id && item.sourceKind == "mirrored")
    #expect(item.observedAt == nil && item.authorization == "unapproved")
    let restrictions = NativeRestrictions(vaultDirectory: vault, vaultID: id)
    let accountID = try #require(UUID(uuidString: item.id))
    let event = try #require(try restrictions.latest(requireExisting: true)[accountID])
    if ["current", "access_lost"].contains(history) {
        #expect(event.id.uuidString.lowercased() == deletedEvent)
        #expect(event.kind == (history == "current" ? .deletedAtSource : .accessLost))
        #expect(item.presence == (history == "current" ? "deleted_at_source" : "access_lost"))
    } else {
        #expect(event.kind == .historyUnknown && item.presence == "unknown")
    }
    await restored.lock()
}

@Test @MainActor func ownerRestoreRevokesGrantsAndRequiresExplicitUncertaintyReview() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-owner-restore-\(UUID().uuidString)")
    let configuration = try OwnerConfiguration(root: root, python: recoverySource.appendingPathComponent(".venv/bin/python"))
    defer { try? FileManager.default.removeItem(at: root); removeRecoveryAnchors(configuration.vaultID) }
    let model = OwnerVaultModel(configuration: configuration)
    await model.open(password: "synthetic-owner-recovery-master", create: true)
    try #require(model.unlocked)
    let csv = root.appendingPathComponent("synthetic.csv")
    try Data("Title,URL,Username,Password\nRecovery fixture,https://example.invalid,owner,synthetic-recovery-canary\n".utf8).write(to: csv)
    await model.selectCSV(csv)
    await model.previewCSV()
    await model.commitCSV()
    let caller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Recovery test agent")
    model.access.enroll(caller)
    let consent = try model.access.requestCatalog(caller: caller, requestID: UUID())
    let account = try #require(model.access.accounts.first)
    try model.access.approveCatalog(consent.requestRef, selected: [account.id], duration: 300)
    let oldReference = try model.access.accountReference(account.id, caller: caller)
    try #require(!model.access.grants.isEmpty)
    let selected = root.appendingPathComponent("selected.kdbx")
    await model.exportBackup(to: selected)
    await model.previewRestore(path: selected, password: "synthetic-owner-recovery-master")
    let review = try #require(model.restoreReview)
    #expect(review.historyUnknown && !model.unlocked && model.accounts.isEmpty && model.access.grants.isEmpty)
    await model.commitRestore(acknowledgeUnknownHistory: false)
    #expect(model.restoreReview != nil)
    await model.commitRestore(acknowledgeUnknownHistory: true)
    #expect(model.restoreReview == nil && !model.unlocked && !model.busy)
    await model.open(password: "synthetic-owner-recovery-master", create: false)
    #expect(model.unlocked && model.accounts.count == 1 && model.access.grants.isEmpty)
    #expect(throws: ConsentError.invalidReference) {
        _ = try model.access.requestUse(caller: caller, requestID: UUID(), accountRef: oldReference, adapterID: "synthetic-v1", actions: [.login])
    }
    await model.lock()
}

@Test func interruptedRestrictionRecoveryCannotCreateEmptyTrustedHistory() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-history-restore-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let id = "synthetic-history-restore-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(at: root); removeRecoveryAnchors(id) }
    let service = NativeRestrictions(vaultDirectory: root, vaultID: id)
    try service.initializeForEnrollment()
    let account = UUID()
    try service.record(account: account, kind: .accessLost, eventID: UUID())
    let anchor = GenerationAnchor(vaultID: id + ":restrictions")
    let unpublished = try RestrictionLedger.recover(at: root.appendingPathComponent("unpublished.sqlite"), anchor: anchor, accounts: [account])
    try unpublished.close()
    #expect(throws: RestrictionLedgerError.self) { _ = try service.latest(requireExisting: true) }
    #expect(throws: RestrictionLedgerError.self) { try service.reconcileRestore(mirrored: [account], acknowledgeUnknownHistory: false) }
    try service.reconcileRestore(mirrored: [account], acknowledgeUnknownHistory: true)
    #expect(try service.latest(requireExisting: true)[account]?.kind == .historyUnknown)
}

@Test @MainActor func ownerLockPreventsLateRestorePublication() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-cancel-restore-\(UUID().uuidString)")
    let config = try OwnerConfiguration(root: root, python: recoverySource.appendingPathComponent(".venv/bin/python"))
    defer { try? FileManager.default.removeItem(at: root); removeRecoveryAnchors(config.vaultID) }
    let model = OwnerVaultModel(configuration: config)
    await model.open(password: "synthetic-cancel-restore-master", create: true)
    let selected = root.appendingPathComponent("selected.kdbx")
    await model.exportBackup(to: selected)
    let reviewing = Task { await model.previewRestore(path: selected, password: "synthetic-cancel-restore-master") }
    for _ in 0..<100 where !model.busy { try await Task.sleep(for: .milliseconds(1)) }
    try #require(model.busy)
    await model.lock()
    await reviewing.value
    #expect(model.restoreReview == nil && !model.unlocked && !model.busy && model.status == "Locked")
}
