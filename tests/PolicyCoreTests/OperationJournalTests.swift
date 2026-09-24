import Foundation
import Testing
@testable import BrokerHost
import PolicyCore

private func operationDirectory() throws -> URL {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-operations-\(UUID())")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    return dir
}

private func loginRequest(id: UUID = UUID(), reference: String = String(repeating: "a", count: 64)) -> AgentRequest {
    AgentRequest(id: id, operation: "auth.login", arguments: ["account_ref": .string(reference), "grant_ref": .string(String(repeating: "b", count: 64)), "adapter_id": .string("synthetic-v1")])
}

@Test @MainActor func operationJournalNeverReplaysSubmittedRequestsAfterRestart() throws {
    let dir = try operationDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
    let file = dir.appendingPathComponent("operations.sqlite")
    let caller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Synthetic")
    let request = loginRequest()
    let journal = try OperationJournal(path: file)
    let started = try journal.begin(request, caller: caller)
    #expect(started.created && started.status.state == .running)
    let duplicate = try journal.begin(request, caller: caller)
    #expect(!duplicate.created && duplicate.status.reference == started.status.reference)
    #expect(throws: ConsentError.requestConflict) { _ = try journal.begin(loginRequest(id: request.id, reference: String(repeating: "c", count: 64)), caller: caller) }
    try journal.markSubmitted(started.status.reference, caller: caller)
    try journal.close()
    let reopened = try OperationJournal(path: file)
    defer { try? reopened.close() }
    let recovered = try reopened.begin(request, caller: caller)
    #expect(!recovered.created && recovered.status.state == .outcomeUnknown)
    #expect(recovered.status.session == nil)
    #expect(throws: OperationJournalError.invalidTransition) { try reopened.finish(recovered.status.reference, caller: caller, state: .succeeded) }
    let wrongBoot = EnrolledAgent(id: caller.id, boot: UUID(), displayName: "New boot")
    #expect(throws: ConsentError.invalidReference) { _ = try reopened.status(recovered.status.reference, caller: wrongBoot) }
    let data = try Data(contentsOf: file)
    #expect(!String(decoding: data, as: UTF8.self).contains("synthetic-v1"))
    #expect(!String(decoding: data, as: UTF8.self).contains(String(repeating: "a", count: 64)))
}

@Test @MainActor func operationJournalCancelsUnsubmittedWorkAndBoundsStorage() throws {
    let dir = try operationDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
    let file = dir.appendingPathComponent("operations.sqlite")
    let caller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Synthetic")
    var now = Date()
    let journal = try OperationJournal(path: file, capacity: 2, date: { now })
    let first = try journal.begin(loginRequest(), caller: caller)
    let second = try journal.begin(loginRequest(), caller: caller)
    #expect(throws: OperationJournalError.capacityExceeded) { _ = try journal.begin(loginRequest(), caller: caller) }
    try journal.finish(second.status.reference, caller: caller, state: .succeeded)
    try journal.close()
    let reopened = try OperationJournal(path: file, capacity: 2, date: { now })
    defer { try? reopened.close() }
    #expect(try reopened.status(first.status.reference, caller: caller).state == .cancelled)
    #expect(try reopened.status(second.status.reference, caller: caller).state == .succeeded)
    now = now.addingTimeInterval(8 * 86400)
    #expect(try reopened.begin(loginRequest(), caller: caller).created)
    #expect(throws: ConsentError.invalidReference) { _ = try reopened.status(first.status.reference, caller: caller) }
}

@Test @MainActor func operationJournalRejectsUnsafePathsAndConcurrentWriters() throws {
    let dir = try operationDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
    let file = dir.appendingPathComponent("operations.sqlite")
    let journal = try OperationJournal(path: file)
    defer { try? journal.close() }
    #expect(throws: OperationJournalError.storageUnavailable) { _ = try OperationJournal(path: file) }
    let link = dir.appendingPathComponent("alias.sqlite")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
    #expect(throws: OperationJournalError.unsafePath) { _ = try OperationJournal(path: link) }
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
    #expect(throws: OperationJournalError.unsafePath) { _ = try journal.begin(loginRequest(), caller: EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Synthetic")) }
}
