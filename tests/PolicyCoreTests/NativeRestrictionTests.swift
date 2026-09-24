import Foundation
import Security
import Testing
import BrokerHost
import PolicyCore

@Test func nativeRestrictionBatchIsIdempotentAndRejectsMissingHistory() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-native-restrictions-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let identity = "synthetic-source-restrictions-\(UUID().uuidString)"
    defer {
        try? FileManager.default.removeItem(at: root)
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: identity + ":restrictions"] as CFDictionary)
    }
    let service = NativeRestrictions(vaultDirectory: root, vaultID: identity)
    #expect(try service.latest(requireExisting: false).isEmpty)
    #expect(throws: RestrictionLedgerError.self) { try service.latest(requireExisting: true) }
    try service.initializeForEnrollment()
    let entries = (0..<256).map { _ in RestrictionEvent(id: UUID(), account: UUID(), kind: .deletedAtSource) }
    try service.record(entries)
    let anchor = try GenerationAnchor(vaultID: identity + ":restrictions").read()
    try service.record(entries)
    #expect(try service.latest(requireExisting: true).count == 256)
    #expect(try GenerationAnchor(vaultID: identity + ":restrictions").read() == anchor)
    #expect(throws: RestrictionLedgerError.self) { try service.record(account: UUID(), kind: .deletedAtSource, eventID: entries[0].id) }
    try FileManager.default.removeItem(at: root.appendingPathComponent("restrictions.sqlite"))
    #expect(throws: RestrictionLedgerError.self) { try service.latest(requireExisting: false) }
    #expect(throws: RestrictionLedgerError.self) { try service.initializeForEnrollment() }
}
