import Foundation
import Testing
@testable import BrokerHost
import PolicyCore

@MainActor private final class SyntheticBrowser: ProtectedBrowserDriver {
    var submissions = 0
    var resolutions = 0
    var revoked = false
    var stopAt: AuthenticationStage?
    var reached: AuthenticationStage?
    var resume: CheckedContinuation<Void, Never>?
    func renew(sequence: Int) async throws { if revoked { throw AgentAPIError.unavailable } }
    func checkLease() throws { if revoked { throw AgentAPIError.unavailable } }
    func perform(_ operation: String, arguments: [String: JSONValue]) async throws -> ProtectedBrowserResult { throw AgentAPIError.capabilityUnavailable }
    func revoke() { revoked = true; resume?.resume(); resume = nil }
    func authenticate(authorize: @escaping @MainActor (AuthenticationStage) throws -> Void, resolve: @escaping @MainActor () async throws -> PrivateCredential) async throws -> BrowserAuthenticationResult {
        for stage in AuthenticationStage.allCases {
            try authorize(stage)
            reached = stage
            if stage == .resolve { _ = try await resolve(); resolutions += 1 }
            if stage == .submit { submissions += 1 }
            if stage == stopAt { await withCheckedContinuation { resume = $0 } }
        }
        return .succeeded
    }
}

@MainActor private func sessionSetup(retained: Bool = false, browser: SyntheticBrowser) throws -> (ProtectedSessionService, AccessCoordinator, AgentAPI, AgentRequest, EnrolledAgent, URL) {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-sessions-\(UUID())")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let access = AccessCoordinator(), caller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Synthetic")
    access.enroll(caller)
    let id = UUID()
    access.openVault(accounts: [ConsentAccount(metadata: OwnerCatalogItem(id: id.uuidString.lowercased(), title: "Synthetic", username: "owner", origins: ["https://app.shadow.test"], group: "Synthetic"), policy: AccountPolicy(id: id, revision: 1, source: retained ? .mirrored : .local, presence: retained ? .deletedAtSource : .present, lastObserved: nil, restrictionEvent: retained ? UUID() : nil))])
    access.installQualifiedAdapter(QualifiedAdapterPolicy(id: "synthetic-v1", credentialOrigins: ["https://app.shadow.test"], resourceOrigins: ["https://app.shadow.test"], actions: [.login, .observe]))
    let disclosure = try access.requestCatalog(caller: caller, requestID: UUID())
    try access.approveCatalog(disclosure.requestRef, selected: [id], duration: 300)
    let accountRef = try access.accountReference(id, caller: caller)
    let consent = try access.requestUse(caller: caller, requestID: UUID(), accountRef: accountRef, adapterID: "synthetic-v1", actions: [.login, .observe])
    try access.approveUse(consent.requestRef, duration: 300, approveRetained: retained)
    let grant = try #require(access.status(consent.requestRef, caller: caller).grantRef)
    let journal = try OperationJournal(path: dir.appendingPathComponent("operations.sqlite"))
    let service = ProtectedSessionService(access: access, journal: journal, resolve: { account, origin in
        #expect(account.id == id && account.policy.revision == 1 && origin == "https://app.shadow.test")
        return PrivateCredential(username: "owner", password: "synthetic-password-canary", totp: nil)
    }, makeDriver: { _ in browser })
    let api = AgentAPI(access: access); api.protectedService = service
    let request = AgentRequest(id: UUID(), operation: "auth.login", arguments: ["account_ref": .string(accountRef), "grant_ref": .string(grant), "adapter_id": .string("synthetic-v1")])
    return (service, access, api, request, caller, dir)
}

@MainActor private func publicLogin(_ api: AgentAPI, _ request: AgentRequest, _ caller: EnrolledAgent) async throws -> JSONValue {
    let data = try JSONValue.object(["protocol_major": .integer(1), "request_id": .string(request.id.uuidString.lowercased()), "operation": .string(request.operation), "arguments": .object(request.arguments)]).encoded()
    return try BoundedJSON.parse(await api.handle(data, caller: caller))
}

@Test @MainActor func protectedSessionRetainedRetryReturnsReceiptWithoutSecondSubmission() async throws {
    let browser = SyntheticBrowser()
    let (service, _, api, request, caller, dir) = try sessionSetup(retained: true, browser: browser)
    defer { service.shutdown(); try? FileManager.default.removeItem(at: dir) }
    let first = try await publicLogin(api, request, caller)
    let reference = try #require(first["result"]?["operation_ref"]?.string)
    for _ in 0..<100 where browser.reached != .output { await Task.yield() }
    for _ in 0..<100 where try service.status(reference, caller: caller).state == .running { await Task.yield() }
    let duplicate = try await publicLogin(api, request, caller)
    #expect(duplicate["result"]?["operation_ref"]?.string == reference)
    #expect(duplicate["result"]?["state"]?.string == "succeeded")
    #expect(duplicate["result"]?["session_ref"]?.string?.count == 64)
    #expect(browser.submissions == 1 && browser.resolutions == 1)
    #expect(!String(decoding: try duplicate.encoded(), as: UTF8.self).contains("canary"))
    let changed = AgentRequest(id: request.id, operation: request.operation, arguments: request.arguments.merging(["adapter_id": .string("different-v1")]) { _, new in new })
    #expect(try await publicLogin(api, changed, caller)["error"]?["code"]?.string == "request_conflict")
}

@Test @MainActor func protectedSessionRevocationClosesBrowserAndCannotResolveOrReplay() async throws {
    for stop in [AuthenticationStage.navigate, .resolve, .submit] {
        let browser = SyntheticBrowser(); browser.stopAt = stop
        let (service, access, api, request, caller, dir) = try sessionSetup(browser: browser)
        defer { service.shutdown(); try? FileManager.default.removeItem(at: dir) }
        let first = try await publicLogin(api, request, caller)
        let reference = try #require(first["result"]?["operation_ref"]?.string)
        for _ in 0..<100 where browser.reached != stop { await Task.yield() }
        #expect(browser.reached == stop)
        access.revoke(try #require(request.arguments["grant_ref"]?.string))
        #expect(browser.revoked)
        let duplicate = try await publicLogin(api, request, caller)
        #expect(duplicate["result"]?["state"]?.string == (stop == .submit ? "outcome_unknown" : "cancelled"))
        #expect(duplicate["result"]?["session_ref"] == .null)
        #expect(browser.resolutions == (stop == .navigate ? 0 : 1))
        #expect(try service.status(reference, caller: caller).state == (stop == .submit ? .outcomeUnknown : .cancelled))
    }
}
