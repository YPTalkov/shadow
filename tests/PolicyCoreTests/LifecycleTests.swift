import Foundation
import Darwin
import Testing
@testable import BrokerHost
import OwnerUI
import PolicyCore
import Security
import SQLite3
import AppKit

@Test @MainActor func revocationObserversReleaseOwnersAndCloseAuthorityBeforeOutputs() throws {
    final class Owner {}
    let access = AccessCoordinator()
    var calls: [String] = []
    let output = Owner(), authority = Owner()
    access.observeRevocation(owner: output) { _ in calls.append("output") }
    let token = access.observeRevocation(owner: authority, authority: true) { _ in calls.append("authority") }
    do {
        let temporary = Owner()
        access.observeRevocation(owner: temporary, authority: true) { _ in calls.append("released") }
        withExtendedLifetime(temporary) {}
    }
    access.lock()
    #expect(calls == ["authority", "output"])
    calls = []
    access.removeRevocationObserver(token)
    access.lock()
    #expect(calls == ["output"])
}

@Test @MainActor func ownerLifecycleClosesPermissionsOnTheCurrentTurn() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-lifecycle-\(UUID())")
    let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let config = try OwnerConfiguration(root: root, python: source.appendingPathComponent(".venv/bin/python"))
    defer { try? FileManager.default.removeItem(at: root) }
    let model = OwnerVaultModel(configuration: config)
    for reason in OwnerLockReason.allCases {
        let agent = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "synthetic-title-canary")
        model.access.enroll(agent)
        model.access.openVault(accounts: [])
        _ = try model.access.requestCatalog(caller: agent, requestID: UUID())
        model.lockImmediately(reason: reason)
        // No suspension between the event and these assertions.
        #expect(!model.access.unlocked && model.access.pending.isEmpty && model.access.grants.isEmpty)
        #expect(!model.unlocked && model.protectedSessions == nil)
        await model.finishLock()
        model.access.removeAgent(agent)
    }
    model.prepareDiagnostics()
    let report = try #require(model.diagnostics)
    #expect(Set(report.counts.map(\.code)) == Set(OwnerLockReason.allCases.map { AuditCode(lock: $0).rawValue }))
    #expect(!report.text.contains("synthetic-title-canary"))
}

@Test @MainActor func lifecycleNotificationBridgeClosesBeforeReturningAndStopsObserving() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-notifications-\(UUID())")
    let config = try OwnerConfiguration(root: root, python: URL(fileURLWithPath: "/unused"))
    defer { try? FileManager.default.removeItem(at: root) }
    let model = OwnerVaultModel(configuration: config), workspace = NotificationCenter(), distributed = NotificationCenter()
    @MainActor final class Availability { var value = true }
    let available = Availability()
    let monitor = OwnerLifecycleMonitor(model: model, workspace: workspace, distributed: distributed, sessionAvailable: { available.value })
    defer { monitor.stop() }
    for event in [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification, NSWorkspace.screensDidSleepNotification, NSWorkspace.sessionDidResignActiveNotification, NSWorkspace.sessionDidBecomeActiveNotification] {
        model.access.openVault(accounts: [])
        workspace.post(name: event, object: nil)
        #expect(!model.access.unlocked)
        await model.finishLock()
    }
    model.access.openVault(accounts: [])
    distributed.post(name: Notification.Name("com.apple.screenIsLocked"), object: nil)
    #expect(!model.access.unlocked)
    await model.finishLock()
    model.access.openVault(accounts: [])
    available.value = false
    await monitor.check()
    #expect(!model.access.unlocked)
    await model.finishLock()
    monitor.stop()
    model.access.openVault(accounts: [])
    workspace.post(name: NSWorkspace.willSleepNotification, object: nil)
    distributed.post(name: Notification.Name("com.apple.screenIsLocked"), object: nil)
    #expect(model.access.unlocked)
    await model.lock()
}

@Test @MainActor func ownerIdleUsesContinuousTimeAndInteractionResetsItsDeadline() async throws {
    let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-idle-\(UUID())")
    let config = try OwnerConfiguration(root: root, python: source.appendingPathComponent(".venv/bin/python"))
    defer {
        try? FileManager.default.removeItem(at: root)
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: config.vaultID] as CFDictionary)
    }
    var now: TimeInterval = 100
    let model = OwnerVaultModel(configuration: config, clock: { now })
    await model.open(password: "synthetic-idle-password", create: true)
    try #require(model.unlocked)
    now += 899
    await model.checkIdle()
    #expect(model.unlocked)
    model.noteInteraction()
    now += 899
    await model.checkIdle()
    #expect(model.unlocked)
    now += 1
    await model.checkIdle()
    #expect(!model.unlocked && !model.access.unlocked)
    await model.finishLock()
    model.prepareDiagnostics()
    #expect(model.diagnostics?.counts.contains(where: { $0.code == "lock_idle" && $0.count == 1 }) == true)
}

@Test @MainActor func vaultWorkerCrashNotifiesAuthorityAndIntentionalExitDoesNot() async throws {
    let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-worker-crash-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    var failures = 0
    let worker = try await PrivateVaultWorker.launch(python: source.appendingPathComponent(".venv/bin/python"), vaultDirectory: root.appendingPathComponent("one"), vaultID: "synthetic-crash-\(UUID())", onTermination: { failures += 1 })
    #expect(worker.isRunning)
    #expect(kill(worker.processIdentifier, SIGKILL) == 0)
    for _ in 0..<100 where failures == 0 { try await Task.sleep(for: .milliseconds(20)) }
    #expect(failures == 1 && !worker.isRunning)
    await worker.lock()
    let second = try await PrivateVaultWorker.launch(python: source.appendingPathComponent(".venv/bin/python"), vaultDirectory: root.appendingPathComponent("two"), vaultID: "synthetic-exit-\(UUID())", onTermination: { failures += 1 })
    await second.lock()
    try await Task.sleep(for: .milliseconds(100))
    #expect(failures == 1 && !second.isRunning)
}

@Test @MainActor func diagnosticsRetainOnlyBoundedCodesAndCountsForSevenDays() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-audit-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    var now = Date(timeIntervalSince1970: 1_800_000_000)
    let journal = try OperationJournal(path: root.appendingPathComponent("operations.sqlite"), date: { now })
    for _ in 0..<100 { try journal.record(.vaultOpened) }
    #expect(try journal.diagnosticReport().counts.first?.count == 100)
    for _ in 0..<12 {
        now = now.addingTimeInterval(86400)
        for code in AuditCode.allCases { try journal.record(code) }
    }
    let report = try journal.diagnosticReport()
    #expect(report.counts.count == AuditCode.allCases.count * 7)
    #expect(report.counts.allSatisfy { $0.count == 1 && AuditCode(rawValue: $0.code) != nil })
    #expect(report.data.count < 65536)
    now = now.addingTimeInterval(-20 * 86400)
    #expect(try journal.diagnosticReport().counts.isEmpty)
    let exported = try #require(JSONSerialization.jsonObject(with: report.data) as? [String: Any])
    #expect(Set(exported.keys) == ["schema_version", "retention_days", "counts"])
    #expect(!report.text.contains(root.path))
}

@Test @MainActor func diagnosticsRejectUnrecognizedStoredCodesAndOversizedFiles() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-audit-corruption-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("operations.sqlite")
    let journal = try OperationJournal(path: path)
    try journal.close()
    var database: OpaquePointer?
    #expect(sqlite3_open(path.path, &database) == SQLITE_OK)
    #expect(sqlite3_exec(database, "INSERT INTO audit_count(day,code,count) VALUES (CAST(strftime('%s','now') AS INTEGER)/86400,'synthetic-diagnostic-canary',1)", nil, nil, nil) == SQLITE_OK)
    sqlite3_close(database)
    let corrupted = try OperationJournal(path: path)
    #expect(throws: OperationJournalError.storageUnavailable) { _ = try corrupted.diagnosticReport() }
    try corrupted.close()
    let file = try FileHandle(forWritingTo: path)
    try file.truncate(atOffset: 4 * 1024 * 1024 + 1)
    try file.close()
    #expect(throws: OperationJournalError.unsafePath) { _ = try OperationJournal(path: path) }
}
