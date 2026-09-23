import Foundation
import Security
import Testing
import BrokerHost

@Test func nativeEditorLeaseAndJournalCloseAccessUntilConfirmed() async throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-native-editor-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let vaultID = "synthetic-editor-\(UUID().uuidString)", vault = directory.appendingPathComponent("vault")
    defer {
        try? FileManager.default.removeItem(at: directory)
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: vaultID] as CFDictionary)
    }
    let first = try await PrivateVaultWorker.launch(python: root.appendingPathComponent(".venv/bin/python"), vaultDirectory: vault, vaultID: vaultID)
    try await first.create(password: "synthetic-editor-master")
    let state = try await first.beginEditor()
    #expect(state.state == "editing")
    await first.lock()
    let reservation = try EditorReservation(vaultDirectory: vault)
    #expect(throws: VaultWorkerError.self) { _ = try EditorReservation(vaultDirectory: vault) }
    let second = try await PrivateVaultWorker.launch(python: root.appendingPathComponent(".venv/bin/python"), vaultDirectory: vault, vaultID: vaultID)
    #expect(try await second.editorStatus().checkoutId == state.checkoutId)
    do {
        try await second.unlock(password: "synthetic-editor-master")
        Issue.record("Active checkout must deny ordinary unlock")
    } catch VaultWorkerError.reported(let code) { #expect(code == "editor_active") }
    reservation.release()
    let review = try await second.previewEditor(password: "synthetic-editor-master")
    #expect(review.added == 0 && review.changed == 0 && review.removed == 0)
    let result = try await second.commitEditor(reviewID: review.reviewId)
    #expect(result.state == "applied" && result.checkoutRetained && !result.lateChange)
    #expect(try await second.editorStatus().state == "none")
    try await second.unlock(password: "synthetic-editor-master")
    #expect(try await second.catalog().items.isEmpty)
    await second.lock()
}
