import AppKit
import SwiftUI
import Security
import QuartzCore
import OwnerUI

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
        await owner.beginEditing()
        guard owner.editor != nil, !owner.unlocked else { throw OwnerConfigurationError.unavailable }
        await owner.previewEditing(password: "synthetic-ui-master-password")
        guard owner.editorReview?.changed == 0 else { throw OwnerConfigurationError.unavailable }
        show(OwnerPanel(model: owner), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-editor-review.jpg"))
        await owner.applyEditing()
        guard owner.editor == nil, !owner.unlocked else { throw OwnerConfigurationError.unavailable }
        await owner.open(password: "synthetic-ui-master-password", create: false)
        guard owner.unlocked, owner.accounts.count == 3 else { throw OwnerConfigurationError.unavailable }
        await owner.lock()
        show(OwnerPanel(model: owner), in: window)
        try await Task.sleep(for: .milliseconds(500))
        try snapshot(window, to: evidence.appendingPathComponent("owner-locked.jpg"))
        guard !owner.unlocked, owner.accounts.isEmpty else { throw OwnerConfigurationError.unavailable }
        succeeded = true
    } catch {
        print("owner_ui_probe_failed")
    }
    await model?.lock()
    if let config {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: config.vaultID] as CFDictionary)
    }
    try? FileManager.default.removeItem(at: root)
    print(succeeded ? "owner_ui_probe_passed" : "owner_ui_probe_incomplete")
    exit(succeeded ? 0 : 1)
}
app.run()
