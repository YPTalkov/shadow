import AppKit
import SwiftUI
import Security
import QuartzCore
import OwnerUI
import BrokerHost

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
        let configuration = try OwnerConfiguration(root: root, python: source.appendingPathComponent(".venv/bin/python"))
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
