import AppKit
import SwiftUI
import Security
import QuartzCore
import OwnerUI
import BrokerHost
import PolicyCore

@MainActor
func snapshot(_ window: NSWindow, to url: URL) throws {
    guard let view = window.contentView else { throw OwnerConfigurationError.unavailable }
    view.layoutSubtreeIfNeeded()
    view.displayIfNeeded()
    CATransaction.flush()
    guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw OwnerConfigurationError.unavailable }
    window.appearance?.performAsCurrentDrawingAppearance { view.cacheDisplay(in: view.bounds, to: bitmap) }
    guard let jpeg = bitmap.representation(using: .jpeg, properties: [.compressionFactor: 0.95]) else { throw OwnerConfigurationError.unavailable }
    try jpeg.write(to: url)
}

@MainActor
func show(_ panel: OwnerPanel, in window: NSWindow) {
    let view = NSHostingView(rootView: panel)
    view.sizingOptions = []
    window.contentView = view
    window.setContentSize(NSSize(width: 1080, height: 820))
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-ui-probe-\(UUID().uuidString)")
let evidence = source.appendingPathComponent(".build/evidence")
let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1080, height: 820), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
window.appearance = NSAppearance(named: .aqua)
window.title = "Shadow — Synthetic UI qualification"
window.center()
window.makeKeyAndOrderFront(nil)

Task { @MainActor in
    var model: OwnerVaultModel?
    var config: OwnerConfiguration?
    var succeeded = false
    var stage = "open"
    do {
        try FileManager.default.createDirectory(at: evidence, withIntermediateDirectories: true)
        let configuration = try OwnerConfiguration(root: root, python: source.appendingPathComponent(".venv/bin/python"), agentImage: AgentVMImage.packaged(at: source.appendingPathComponent(".build/guest-cache/agent")))
        config = configuration
        let owner = OwnerVaultModel(configuration: configuration)
        model = owner
        show(OwnerPanel(model: owner), in: window)
        await owner.open(password: "synthetic-ui-master-password", create: true)
        guard owner.unlocked else { throw OwnerConfigurationError.unavailable }
        let csv = root.appendingPathComponent("synthetic.csv")
        let data = "Title,URL,Username,Password,Group\nDemo workspace,https://workspace.example.invalid,owner@example.invalid,synthetic-one,Demo\nSynthetic CI,https://ci.example.invalid,agent@example.invalid,synthetic-two,Development\nSynthetic status,https://status.example.invalid,reader@example.invalid,synthetic-three,Demo\n"
        try Data(data.utf8).write(to: csv)
        await owner.selectCSV(csv)
        owner.mapping.group = "Group"
        await owner.previewCSV()
        guard owner.preview?.accepted == 3 else { throw OwnerConfigurationError.unavailable }
        show(OwnerPanel(model: owner, initialDestination: .importCSV), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-import.jpg"))
        await owner.commitCSV()
        guard owner.accounts.count == 3 else { throw OwnerConfigurationError.unavailable }
        owner.message = nil
        show(OwnerPanel(model: owner), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-vault.jpg"))
        let caller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Codex CLI · Synthetic probe")
        owner.access.enroll(caller)
        let request = try owner.access.requestCatalog(caller: caller, requestID: UUID())
        let account = owner.access.accounts.first { $0.metadata.title == "Demo workspace" }!
        try owner.access.approveCatalog(request.requestRef, selected: [account.id], duration: 300)
        owner.access.installQualifiedAdapter(QualifiedAdapterPolicy(id: "synthetic-workspace-v1", credentialOrigins: ["https://workspace.example.invalid"], resourceOrigins: [], actions: [.login, .observe]))
        let reference = try owner.access.accountReference(account.id, caller: caller)
        _ = try owner.access.requestUse(caller: caller, requestID: UUID(), accountRef: reference, adapterID: "synthetic-workspace-v1", actions: [.login, .observe])
        show(OwnerPanel(model: owner, initialDestination: .access), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-consent.jpg"))
        await owner.inspectSource(source.appendingPathComponent(".build/fixtures/SyntheticSource.app"))
        guard owner.sourceCandidate != nil else { throw OwnerConfigurationError.unavailable }
        owner.enrollSource(label: "Synthetic connector")
        guard let enrolled = owner.sources.first else { throw OwnerConfigurationError.unavailable }
        await owner.refreshSource(enrolled.id)
        guard owner.unlocked, owner.accounts.count == 4 else { throw OwnerConfigurationError.unavailable }
        stage = "agent_connector_refresh"
        let sourceCaller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Synthetic source job")
        owner.access.enroll(sourceCaller)
        guard let mirror = owner.access.accounts.first(where: { $0.metadata.sourceInstance == enrolled.id.uuidString.lowercased() }) else { throw OwnerConfigurationError.unavailable }
        let sourceConsent = try owner.access.requestCatalog(caller: sourceCaller, requestID: UUID())
        try owner.access.approveCatalog(sourceConsent.requestRef, selected: [mirror.id], duration: 300)
        func sourceCall(_ operation: String, _ arguments: [String: JSONValue] = [:], id: UUID = UUID()) async throws -> JSONValue {
            let request = try JSONValue.object(["protocol_major": .integer(1), "request_id": .string(id.uuidString.lowercased()), "operation": .string(operation), "arguments": .object(arguments)]).encoded()
            return try BoundedJSON.parse(await owner.agentAPI.handle(request, caller: sourceCaller))
        }
        let catalog = try await sourceCall("catalog.search")
        guard let sourceReference = catalog["result"]?["items"]?.array?.first?["source_ref"]?.string else { throw OwnerConfigurationError.unavailable }
        let sourceRequest = UUID()
        let job = try await sourceCall("connector.request_refresh", ["source_ref": .string(sourceReference)], id: sourceRequest)
        guard let operation = job["result"]?["operation_ref"]?.string else { throw OwnerConfigurationError.unavailable }
        var sourceJob = try await sourceCall("operation.get", ["operation_ref": .string(operation)])
        let sourceDeadline = DeadlineClock.now + 15
        while sourceJob["result"]?["state"] == .string("running"), DeadlineClock.now < sourceDeadline {
            try await Task.sleep(for: .milliseconds(100))
            sourceJob = try await sourceCall("operation.get", ["operation_ref": .string(operation)])
        }
        guard sourceJob["result"]?["state"] == .string("succeeded"), owner.accounts.count == 4, owner.unlocked,
              owner.sourceSummaries.first(where: { $0.id == enrolled.id.uuidString.lowercased() })?.generation == 2 else { throw OwnerConfigurationError.unavailable }
        let repeated = try await sourceCall("connector.request_refresh", ["source_ref": .string(sourceReference)], id: sourceRequest)
        guard repeated["result"]?["operation_ref"] == .string(operation) else { throw OwnerConfigurationError.unavailable }
        owner.access.removeAgent(sourceCaller)
        show(OwnerPanel(model: owner, initialDestination: .sources), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-sources.jpg"))
        stage = "remove_source"
        owner.removeSource(enrolled.id)
        guard owner.sources.isEmpty, owner.accounts.count == 4 else { throw OwnerConfigurationError.unavailable }
        stage = "begin_editor"
        await owner.beginEditing()
        guard owner.editor != nil, !owner.unlocked, owner.access.grants.isEmpty, owner.access.pending.isEmpty else { throw OwnerConfigurationError.unavailable }
        stage = "preview_editor"
        await owner.previewEditing(password: "synthetic-ui-master-password")
        guard owner.editorReview?.changed == 0 else { throw OwnerConfigurationError.unavailable }
        show(OwnerPanel(model: owner), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-editor-review.jpg"))
        stage = "apply_editor"
        await owner.applyEditing()
        guard owner.editor == nil, !owner.unlocked else { throw OwnerConfigurationError.unavailable }
        stage = "reopen"
        await owner.open(password: "synthetic-ui-master-password", create: false)
        guard owner.unlocked, owner.accounts.count == 4 else { throw OwnerConfigurationError.unavailable }
        stage = "backup_export"
        let exported = root.appendingPathComponent("owner-export.kdbx")
        await owner.exportBackup(to: exported)
        guard FileManager.default.fileExists(atPath: exported.path) else { throw OwnerConfigurationError.unavailable }
        stage = "restore_preview"
        await owner.previewRestore(path: exported, password: "synthetic-ui-master-password")
        guard owner.restoreReview?.accounts == 4, owner.restoreReview?.mirrored == 1, !owner.unlocked else { throw OwnerConfigurationError.unavailable }
        show(OwnerPanel(model: owner, initialDestination: .recovery), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-restore-review.jpg"))
        stage = "restore_commit"
        await owner.commitRestore(acknowledgeUnknownHistory: false)
        guard !owner.unlocked, owner.restoreReview == nil else { throw OwnerConfigurationError.unavailable }
        await owner.open(password: "synthetic-ui-master-password", create: false)
        guard owner.unlocked, owner.accounts.count == 4, owner.access.grants.isEmpty,
              owner.accounts.first(where: { $0.sourceKind == "mirrored" })?.presence == "unknown" else { throw OwnerConfigurationError.unavailable }
        stage = "missing_history_review"
        await owner.lock()
        try FileManager.default.removeItem(at: configuration.vaultDirectory.appendingPathComponent("restrictions.sqlite"))
        await owner.previewRestore(path: exported, password: "synthetic-ui-master-password")
        guard owner.restoreReview?.historyUnknown == true else { throw OwnerConfigurationError.unavailable }
        show(OwnerPanel(model: owner, initialDestination: .recovery), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-restore-uncertain.jpg"))
        await owner.commitRestore(acknowledgeUnknownHistory: false)
        guard owner.restoreReview != nil else { throw OwnerConfigurationError.unavailable }
        await owner.commitRestore(acknowledgeUnknownHistory: true)
        guard owner.restoreReview == nil, !owner.unlocked else { throw OwnerConfigurationError.unavailable }
        stage = "independent_keepassxc_recovery"
        // Test-only inspection of the owner export, with the app locked and the
        // master password sent through a pipe, never a process argument.
        await owner.lock()
        let recovered = try await Task.detached {
            let process = Process(), input = Pipe(), output = Pipe()
            process.executableURL = URL(fileURLWithPath: "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli")
            process.arguments = ["ls", "-q", "-R", exported.path]
            process.standardInput = input
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            try process.run()
            try input.fileHandleForWriting.write(contentsOf: Data("synthetic-ui-master-password\n".utf8))
            try input.fileHandleForWriting.close()
            let listed = try output.fileHandleForReading.readToEnd() ?? Data()
            process.waitUntilExit()
            return process.terminationStatus == 0 && String(decoding: listed, as: UTF8.self).contains("Demo workspace")
        }.value
        guard recovered else { throw OwnerConfigurationError.unavailable }
        await owner.lock()
        show(OwnerPanel(model: owner), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-locked.jpg"))
        guard !owner.unlocked, owner.accounts.isEmpty else { throw OwnerConfigurationError.unavailable }
        stage = "diagnostics"
        owner.prepareDiagnostics()
        guard let report = owner.diagnostics, !report.text.contains("synthetic-one"), !report.text.contains("Demo workspace") else { throw OwnerConfigurationError.unavailable }
        let diagnosticFile = root.appendingPathComponent("reviewed-diagnostics.json")
        owner.exportDiagnostics(to: diagnosticFile)
        guard try Data(contentsOf: diagnosticFile) == report.data else { throw OwnerConfigurationError.unavailable }
        owner.message = nil
        show(OwnerPanel(model: owner, initialDestination: .recovery), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-diagnostics.jpg"))
        succeeded = true
    } catch {
        print("owner_ui_probe_failed: " + stage)
    }
    await model?.lock()
    if let config {
        for id in [config.vaultID, config.vaultID + ":restrictions"] {
            SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: id] as CFDictionary)
        }
        for enrolled in model?.sources ?? [] {
            SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.source-digest", kSecAttrAccount as String: config.vaultID + ":" + enrolled.id.uuidString.lowercased()] as CFDictionary)
        }
    }
    try? FileManager.default.removeItem(at: root)
    print(succeeded ? "owner_ui_probe_passed" : "owner_ui_probe_incomplete")
    exit(succeeded ? 0 : 1)
}
app.run()
