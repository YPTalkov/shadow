import Foundation
import Security
import Testing
@testable import PolicyCore

@Test func restrictionLedgerRejectsRollback() throws {
    let id = "shadow-synthetic-policy-\(UUID().uuidString)"
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.yptalkov.shadow.generation-anchor",
        kSecAttrAccount as String: id,
    ]
    defer { SecItemDelete(query as CFDictionary) }
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-policy-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
    defer { try? FileManager.default.removeItem(at: dir) }
    let path = dir.appendingPathComponent("policy.sqlite")
    let anchor = GenerationAnchor(vaultID: id)
    let account = UUID()

    let ledger = try RestrictionLedger(path: path, anchor: anchor)
    let first = try ledger.append(account: account, kind: .deletedAtSource)
    #expect(try ledger.events(for: account).map(\.id) == [first.id])
    let oldFile = try Data(contentsOf: path)
    _ = try ledger.append(account: account, kind: .accessLost)
    #expect(try ledger.events(for: account).count == 2)
    try ledger.close()
    let reopened = try RestrictionLedger(path: path, anchor: anchor)
    #expect(try reopened.events(for: account).count == 2)
    try reopened.close()

    try oldFile.write(to: path, options: .atomic)
    #expect(throws: RestrictionLedgerError.recoveryRequired) {
        _ = try RestrictionLedger(path: path, anchor: anchor)
    }
}
