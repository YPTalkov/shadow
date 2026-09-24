import Foundation
import Testing
@testable import BrokerHost
import PolicyCore

@MainActor private final class ConnectorJobFixture {
    enum Mode { case success, ownerAction, holdBeforeCommit, holdAfterCommit }
    let access = AccessCoordinator()
    let caller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Synthetic connector caller")
    let source = UUID()
    let account = UUID()
    let directory: URL
    let journal: OperationJournal
    let api: AgentAPI
    var service: ConnectorRefreshService!
    var refreshes = 0
    var cancelled = 0
    var configured = true
    var mode: Mode = .success
    var now = DeadlineClock.now

    init() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-connector-jobs-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        journal = try OperationJournal(path: directory.appendingPathComponent("operations.sqlite"))
        api = AgentAPI(access: access)
        let metadata = OwnerCatalogItem(id: account.uuidString, title: "Synthetic mirror", username: "owner", origins: ["https://example.invalid"], group: "Synthetic", sourceKind: "mirrored", sourceInstance: source.uuidString)
        access.openVault(accounts: [ConsentAccount(metadata: metadata, policy: AccountPolicy(id: account, revision: 1, source: .mirrored, presence: .present, lastObserved: Date(), restrictionEvent: nil))])
        access.enroll(caller)
        service = ConnectorRefreshService(access: access, journal: journal, isConfigured: { [weak self] source in
            self?.configured == true && self?.source == source
        }, refresh: { [weak self] _, beforeCommit in
            guard let self else { throw SourceHostError.cancelled }
            self.refreshes += 1
            if self.mode == .ownerAction, self.refreshes == 1 { return SourceRefreshResult(state: "needs_owner_action", receipt: nil) }
            if self.mode == .holdBeforeCommit { try await Task.sleep(for: .seconds(30)) }
            try beforeCommit()
            if self.mode == .holdAfterCommit { try await Task.sleep(for: .seconds(30)) }
            return SourceRefreshResult(state: "committed", receipt: nil)
        }, cancel: { [weak self] in self?.cancelled += 1 }, clock: { [weak self] in self?.now ?? DeadlineClock.now })
        api.connectorService = service
    }

    func close() throws {
        service.shutdown()
        try journal.close()
        try FileManager.default.removeItem(at: directory)
    }

    func call(_ operation: String, _ arguments: [String: JSONValue] = [:], id: UUID = UUID()) async throws -> JSONValue {
        let bytes = try JSONValue.object(["protocol_major": .integer(1), "request_id": .string(id.uuidString.lowercased()), "operation": .string(operation), "arguments": .object(arguments)]).encoded()
        return try BoundedJSON.parse(await api.handle(bytes, caller: caller))
    }

    func disclose() throws {
        let pending = try access.requestCatalog(caller: caller, requestID: UUID())
        try access.approveCatalog(pending.requestRef, selected: [account], duration: 300)
    }
}

@Test @MainActor func connectorOwnerCheckpointResumesOnceAndRequiresExactReference() async throws {
    let fixture = try ConnectorJobFixture()
    defer { try? fixture.close() }
    fixture.mode = .ownerAction
    try fixture.disclose()
    let catalog = try await fixture.call("catalog.search")
    let source = try #require(catalog["result"]?["items"]?.array?.first?["source_ref"]?.string)
    let accepted = try await fixture.call("connector.request_refresh", ["source_ref": .string(source)])
    let operation = try #require(accepted["result"]?["operation_ref"]?.string)
    try await Task.sleep(for: .milliseconds(10))
    let waiting = try await fixture.call("operation.get", ["operation_ref": .string(operation)])
    #expect(waiting["result"]?["state"] == .string("needs_owner_action"))
    let checkpoint = try #require(waiting["result"]?["checkpoint_ref"]?.string)
    #expect(try await fixture.call("operation.resume", ["operation_ref": .string(operation), "checkpoint_ref": .string(String(repeating: "0", count: 64))])["error"]?["code"] == .string("stale_request"))
    let id = UUID(), args: [String: JSONValue] = ["operation_ref": .string(operation), "checkpoint_ref": .string(checkpoint)]
    _ = try await fixture.call("operation.resume", args, id: id)
    try await Task.sleep(for: .milliseconds(10))
    #expect(try await fixture.call("operation.resume", args, id: id)["result"]?["state"] == .string("succeeded"))
    #expect(fixture.refreshes == 2)
}

@Test @MainActor func connectorCancellationDistinguishesUnsubmittedAndUncertainCommit() async throws {
    for mode in [ConnectorJobFixture.Mode.holdBeforeCommit, .holdAfterCommit] {
        let fixture = try ConnectorJobFixture()
        defer { try? fixture.close() }
        fixture.mode = mode
        try fixture.disclose()
        let catalog = try await fixture.call("catalog.search")
        let source = try #require(catalog["result"]?["items"]?.array?.first?["source_ref"]?.string)
        let accepted = try await fixture.call("connector.request_refresh", ["source_ref": .string(source)])
        let operation = try #require(accepted["result"]?["operation_ref"]?.string)
        try await Task.sleep(for: .milliseconds(10))
        let cancelled = try await fixture.call("operation.cancel", ["operation_ref": .string(operation)])
        #expect(cancelled["result"]?["state"] == .string(mode == .holdBeforeCommit ? "cancelled" : "outcome_unknown"))
        #expect(fixture.cancelled == 1)
        #expect(try await fixture.call("operation.resume", ["operation_ref": .string(operation), "checkpoint_ref": .string(String(repeating: "0", count: 64))])["error"] != nil)
    }
}

@Test @MainActor func connectorDisabledSourceAndExpiredJobCannotPublish() async throws {
    let fixture = try ConnectorJobFixture()
    defer { try? fixture.close() }
    try fixture.disclose()
    let catalog = try await fixture.call("catalog.search")
    let source = try #require(catalog["result"]?["items"]?.array?.first?["source_ref"]?.string)
    fixture.configured = false
    #expect(try await fixture.call("connector.request_refresh", ["source_ref": .string(source)])["error"]?["code"] == .string("not_configured"))
    #expect(fixture.refreshes == 0)
    fixture.configured = true
    fixture.mode = .holdBeforeCommit
    let accepted = try await fixture.call("connector.request_refresh", ["source_ref": .string(source)])
    let operation = try #require(accepted["result"]?["operation_ref"]?.string)
    try await Task.sleep(for: .milliseconds(10))
    fixture.now += 301
    #expect(try await fixture.call("operation.get", ["operation_ref": .string(operation)])["result"]?["state"] == .string("cancelled"))
    #expect(fixture.cancelled == 1)
}

@Test @MainActor func connectorSourceReferencesRequireDisclosureAndHideSourceIdentity() async throws {
    let fixture = try ConnectorJobFixture()
    defer { try? fixture.close() }
    #expect(try await fixture.call("catalog.search")["error"]?["code"] == .string("catalog_consent_required"))
    try fixture.disclose()
    let response = try await fixture.call("catalog.search")
    let source = try #require(response["result"]?["items"]?.array?.first?["source_ref"]?.string)
    #expect(source.count == 64)
    let encoded = String(decoding: try response.encoded(), as: UTF8.self).lowercased()
    #expect(!encoded.contains(fixture.source.uuidString.lowercased()))
    let accounts = fixture.access.accounts
    fixture.access.lock()
    fixture.access.openVault(accounts: [])
    #expect(try await fixture.call("connector.request_refresh", ["source_ref": .string(source)])["error"] != nil)
    #expect(fixture.refreshes == 0)
    fixture.access.openVault(accounts: accounts)
    try fixture.disclose()
    #expect(try await fixture.call("catalog.search")["result"]?["items"]?.array?.first?["source_ref"]?.string != nil)
}

@Test @MainActor func connectorJobReturnsReceiptAndNeverReplaysCommittedRequest() async throws {
    let fixture = try ConnectorJobFixture()
    defer { try? fixture.close() }
    try fixture.disclose()
    let result = try await fixture.call("catalog.search")
    let source = try #require(result["result"]?["items"]?.array?.first?["source_ref"]?.string)
    let id = UUID()
    let accepted = try await fixture.call("connector.request_refresh", ["source_ref": .string(source)], id: id)
    let operation = try #require(accepted["result"]?["operation_ref"]?.string)
    let deadline = DeadlineClock.now + 2
    var status = try await fixture.call("operation.get", ["operation_ref": .string(operation)])
    while status["result"]?["state"] == .string("running"), DeadlineClock.now < deadline {
        await Task.yield()
        status = try await fixture.call("operation.get", ["operation_ref": .string(operation)])
    }
    #expect(status["result"]?["state"] == .string("succeeded"))
    let retry = try await fixture.call("connector.request_refresh", ["source_ref": .string(source)], id: id)
    #expect(retry["result"]?["operation_ref"] == .string(operation))
    #expect(fixture.refreshes == 1)
    let raw = String(decoding: try status.encoded(), as: UTF8.self)
    #expect(!raw.contains("receipt") && !raw.contains("source_instance"))
}
