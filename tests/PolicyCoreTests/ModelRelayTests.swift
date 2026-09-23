import Foundation
import Testing
@testable import ModelRelay

private let credential = CodexCredential(accessToken: "synthetic-access-canary", accountID: "synthetic-account", expiresAt: Date(timeIntervalSince1970: 2000))
private let requestBody = Data(#"{"model":"qualified-model","instructions":"Synthetic test","input":[],"stream":true,"store":false}"#.utf8)

@Test func relayFixesDestinationAndInjectsOnlyHostCredentials() throws {
    let policy = CodexRelayPolicy(models: ["qualified-model"])
    let request = try policy.request(method: "POST", path: "/v1/responses", headers: ["Content-Type": "application/json"], body: requestBody, credential: credential, now: Date(timeIntervalSince1970: 1000))
    #expect(request.url?.absoluteString == "https://chatgpt.com/backend-api/codex/responses")
    #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-access-canary")
    #expect(request.value(forHTTPHeaderField: "chatgpt-account-id") == "synthetic-account")
    #expect(try JSONSerialization.jsonObject(with: request.httpBody!) as? NSDictionary == JSONSerialization.jsonObject(with: requestBody) as? NSDictionary)
}

@Test func relayRejectsRoutingAuthUnknownFieldsAndExpiredCredentials() throws {
    let policy = CodexRelayPolicy(models: ["qualified-model"])
    for headers in [["Authorization": "caller-token"], ["HOST": "elsewhere.invalid"], ["x-api-key": "caller-token"], ["ChatGPT-Account-Id": "caller-account"], ["X-Forwarded-Host": "elsewhere.invalid"], ["Connection": "upgrade"]] {
        #expect(throws: RelayError.invalidRequest) {
            _ = try policy.request(method: "POST", path: "/v1/responses", headers: headers, body: requestBody, credential: credential, now: Date(timeIntervalSince1970: 1000))
        }
    }
    for path in ["https://elsewhere.invalid/v1/responses", "/v1/responses?url=elsewhere.invalid", "/v1/responses/compact", "/v1/models", "/v1/%72esponses"] {
        #expect(throws: RelayError.invalidRequest) {
            _ = try policy.request(method: "POST", path: path, headers: [:], body: requestBody, credential: credential, now: Date(timeIntervalSince1970: 1000))
        }
    }
    #expect(throws: RelayError.signInRequired) {
        _ = try policy.request(method: "POST", path: "/v1/responses", headers: [:], body: requestBody, credential: credential, now: Date(timeIntervalSince1970: 1990))
    }
    for body in [#"{"model":"other","input":[],"stream":true,"store":false}"#, #"{"model":"qualified-model","input":[],"stream":true,"store":false,"webhook_url":"https://elsewhere.invalid"}"#, #"{"model":"qualified-model","input":[],"stream":true,"store":true}"#] {
        #expect(throws: RelayError.invalidRequest) {
            _ = try policy.request(method: "POST", path: "/v1/responses", headers: [:], body: Data(body.utf8), credential: credential, now: Date(timeIntervalSince1970: 1000))
        }
    }
}

@Test func codexClientMetadataDoesNotBecomeUpstreamRouting() throws {
    let policy = CodexRelayPolicy(models: ["qualified-model"])
    var body = try JSONSerialization.jsonObject(with: requestBody) as! [String: Any]
    body["client_metadata"] = ["x-codex-turn-metadata": "synthetic"]
    let request = try policy.request(method: "POST", path: "/v1/responses", headers: ["thread-id": "synthetic", "x-codex-window-id": "synthetic"], body: JSONSerialization.data(withJSONObject: body), credential: credential, now: Date(timeIntervalSince1970: 1000))
    #expect(request.value(forHTTPHeaderField: "thread-id") == nil)
    #expect(try (JSONSerialization.jsonObject(with: request.httpBody!) as! [String: Any])["client_metadata"] == nil)
}

@Test func relayLeaseCannotBeReusedByAnotherBootOrAfterItsBudget() async throws {
    let lease = RelayLease(instance: "host-created-instance", boot: "boot-one", expiresAt: 200, maximumRequests: 2, maximumInputBytes: 100)
    #expect(throws: RelayError.denied) { try lease.reserve(instance: "other", boot: "boot-one", bytes: 1, now: 100) }
    #expect(throws: RelayError.denied) { try lease.reserve(instance: "host-created-instance", boot: "old-boot", bytes: 1, now: 100) }
    try lease.reserve(instance: "host-created-instance", boot: "boot-one", bytes: 60, now: 100)
    #expect(throws: RelayError.limitExceeded) { try lease.reserve(instance: "host-created-instance", boot: "boot-one", bytes: 41, now: 100) }
    try lease.reserve(instance: "host-created-instance", boot: "boot-one", bytes: 40, now: 100)
    #expect(throws: RelayError.limitExceeded) { try lease.reserve(instance: "host-created-instance", boot: "boot-one", bytes: 1, now: 100) }
    lease.revoke()
    #expect(throws: RelayError.denied) { try lease.check(instance: "host-created-instance", boot: "boot-one", now: 100) }
}

@Test func relayDropsProviderErrorsAndReflectedAuthentication() throws {
    for payload in [#"{"type":"response.failed","error":{"message":"synthetic-access-canary"}}"#, #"{"type":"response.output_text.delta","delta":"synthetic-access-canary"}"#, #"{"type":"response.output_text.delta","delta":"synthetic-\u0061ccess-canary"}"#] {
        var decoder = RelayEventDecoder(credential: credential)
        var emitted = Data()
        #expect(throws: RelayError.providerUnavailable) {
            for byte in Data("data: \(payload)\n\n".utf8) {
                if let event = try decoder.append(byte) { emitted.append(event) }
            }
        }
        #expect(emitted.isEmpty)
    }
    var decoder = RelayEventDecoder(credential: credential)
    let payload = Data(#"data: {"type":"response.completed","response":{"status":"completed","output":[]}}"#.utf8) + Data("\n\n".utf8)
    var emitted = Data()
    for byte in payload { if let event = try decoder.append(byte) { emitted.append(event) } }
    try decoder.finish()
    #expect(!emitted.isEmpty)
    var truncated = RelayEventDecoder(credential: credential)
    _ = try truncated.append(100)
    #expect(throws: RelayError.providerUnavailable) { try truncated.finish() }
}
