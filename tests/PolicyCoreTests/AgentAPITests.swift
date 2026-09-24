import Foundation
import Testing
import BrokerHost
import PolicyCore

private func request(_ operation: String, _ arguments: JSONValue = .object([:]), id: UUID = UUID()) throws -> Data {
    try JSONValue.object(["protocol_major": .integer(1), "request_id": .string(id.uuidString.lowercased()), "operation": .string(operation), "arguments": arguments]).encoded()
}

@Test func publicRequestsRejectAmbiguityUnknownFieldsAndUnsafeTargets() throws {
    let id = UUID().uuidString.lowercased()
    let malformed = [
        "{\"protocol_major\":1,\"protocol_major\":1,\"request_id\":\"\(id)\",\"operation\":\"vault.status\",\"arguments\":{}}",
        "{\"protocol_major\":true,\"request_id\":\"\(id)\",\"operation\":\"vault.status\",\"arguments\":{}}",
        "{\"protocol_major\":1.0,\"request_id\":\"\(id)\",\"operation\":\"vault.status\",\"arguments\":{}}",
        "{\"protocol_major\":1,\"request_id\":\"\(id)\",\"operation\":\"vault.status\",\"arguments\":{},\"caller\":\"forged\"}",
        "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":0}}}}}}}}}",
        "{\"a\":\"\\ud800\"}", "{\"a\":01}", "{}{}", "[1,]"
    ]
    for value in malformed { #expect(throws: (any Error).self) { _ = try AgentRequest.decode(Data(value.utf8)) } }
    #expect(throws: (any Error).self) { _ = try AgentRequest.decode(Data(repeating: 32, count: 65_537)) }
    #expect(throws: (any Error).self) { _ = try AgentRequest.decode(request("browser.navigate", .object(["session_ref": .string(String(repeating: "a", count: 64)), "url": .string("https://example.invalid/?secret=canary")]))) }
    #expect(throws: (any Error).self) { _ = try AgentRequest.decode(request("access.request", .object(["kind": .string("catalog"), "approve": .bool(true)]))) }
    #expect(throws: (any Error).self) { _ = try AgentRequest.decode(request("catalog.search", .object(["limit": .bool(true)]))) }
    #expect(try AgentRequest.decode(request("catalog.search", .object(["query": .string("👩‍💻 Café")]))).operation == "catalog.search")
}

@Test @MainActor func publicAPISeparatesDisclosureUseAndCallerBoots() async throws {
    let authority = AccessCoordinator()
    let api = AgentAPI(access: authority)
    let caller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Synthetic agent")
    authority.enroll(caller)
    let first = UUID(), hidden = UUID()
    func account(_ id: UUID, title: String) -> ConsentAccount {
        ConsentAccount(metadata: OwnerCatalogItem(id: id.uuidString.lowercased(), title: title, username: "owner", origins: ["https://example.invalid"], group: "Synthetic"), policy: AccountPolicy(id: id, revision: 1, source: .local, presence: .present, lastObserved: nil, restrictionEvent: nil))
    }
    authority.openVault(accounts: [account(first, title: "Straße"), account(hidden, title: "Undisclosed")])
    authority.installQualifiedAdapter(QualifiedAdapterPolicy(id: "synthetic-v1", credentialOrigins: ["https://example.invalid"], resourceOrigins: [], actions: [.login]))
    func call(_ name: String, _ args: JSONValue = .object([:])) async throws -> JSONValue {
        try BoundedJSON.parse(await api.handle(request(name, args), caller: caller))
    }
    #expect(try await call("catalog.search")["error"]?["code"]?.string == "catalog_consent_required")
    let consent = try await call("access.request", .object(["kind": .string("catalog")]))
    let consentRef = try #require(consent["result"]?["operation_ref"]?.string)
    try authority.approveCatalog(consentRef, selected: [first], duration: 300)
    let results = try await call("catalog.search", .object(["query": .string("strasse")]))
    let items = try #require(results["result"]?["items"]?.array)
    #expect(items.count == 1 && items[0]["title"]?.string == "Straße")
    let reference = try #require(items.first?["account_ref"]?.string)
    #expect(!String(decoding: try results.encoded(), as: UTF8.self).contains(first.uuidString.lowercased()))
    let disclosure = try #require(try await call("operation.get", .object(["operation_ref": .string(consentRef)]))["result"]?["grant_ref"]?.string)
    let wrongGrant = try await call("auth.login", .object(["account_ref": .string(reference), "grant_ref": .string(disclosure), "adapter_id": .string("synthetic-v1")]))
    #expect(wrongGrant["error"]?["code"]?.string == "account_consent_required")
    let use = try await call("access.request", .object(["kind": .string("account_use"), "account_ref": .string(reference), "adapter_id": .string("synthetic-v1"), "actions": .array([.string("login")])]))
    let useRef = try #require(use["result"]?["operation_ref"]?.string)
    try authority.approveUse(useRef, duration: 300, approveRetained: false)
    let grant = try #require(try await call("operation.get", .object(["operation_ref": .string(useRef)]))["result"]?["grant_ref"]?.string)
    #expect(try await call("auth.login", .object(["account_ref": .string(reference), "grant_ref": .string(grant), "adapter_id": .string("synthetic-v1")]))["error"]?["code"]?.string == "capability_unavailable")
    let other = EnrolledAgent(id: caller.id, boot: UUID(), displayName: "New boot")
    authority.enroll(other)
    let replay = try BoundedJSON.parse(await api.handle(request("operation.get", .object(["operation_ref": .string(useRef)])), caller: caller))
    #expect(replay["error"]?["code"]?.string == "caller_unavailable")
    authority.lock()
    #expect(try BoundedJSON.parse(await api.handle(request("vault.status"), caller: other))["result"]?["state"]?.string == "locked")
}
