import Foundation
import Testing
@testable import ModelRelay

actor OAuthFixture: CodexOAuthTransport {
    var replies: [OAuthHTTPReply]
    var requests: [URLRequest] = []
    init(_ replies: [OAuthHTTPReply]) { self.replies = replies }
    func post(_ request: URLRequest) async throws -> OAuthHTTPReply {
        requests.append(request)
        guard !replies.isEmpty else { throw CodexOAuthError.unavailable }
        return replies.removeFirst()
    }
}

func oauthReply(_ body: String, status: Int = 200) -> OAuthHTTPReply {
    OAuthHTTPReply(status: status, body: Data(body.utf8))
}

private func fixtureToken(account: String = "synthetic-oauth-account", expires: Int = 7200) -> String {
    let body = #"{"https://api.openai.com/auth":{"chatgpt_account_id":"\#(account)"},"exp":\#(expires)}"#
    return "synthetic." + Data(body.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") + ".synthetic"
}

func fixtureTokens(account: String = "synthetic-oauth-account") -> OAuthHTTPReply {
    oauthReply(#"{"access_token":"\#(fixtureToken(account: account))","refresh_token":"synthetic-refresh-canary","expires_in":3600}"#)
}

@Test func codexDeviceSignInKeepsExchangeAtFixedProviderEndpoints() async throws {
    let transport = OAuthFixture([
        oauthReply(#"{"device_auth_id":"synthetic-device-canary","user_code":"ABCD-EFGH","interval":"5"}"#),
        oauthReply("{}", status: 403),
        oauthReply(#"{"authorization_code":"synthetic-code-canary","code_verifier":"synthetic-verifier-canary"}"#),
        fixtureTokens(),
    ])
    let client = CodexOAuthClient(transport: transport)
    let challenge = try await client.start()
    #expect(challenge.userCode == "ABCD-EFGH" && challenge.interval == 5)
    #expect(challenge.verificationURL.absoluteString == "https://auth.openai.com/codex/device")
    if case .pending = try await client.poll(challenge, now: Date(timeIntervalSince1970: 1000)) {} else { Issue.record("Expected pending sign-in") }
    guard case .complete(let tokens) = try await client.poll(challenge, now: Date(timeIntervalSince1970: 1000)) else { Issue.record("Expected completed exchange"); return }
    #expect(tokens.accountID == "synthetic-oauth-account" && tokens.expiresAt == Date(timeIntervalSince1970: 4600))
    #expect(!String(reflecting: tokens).contains("canary"))
    #expect(!String(reflecting: tokens.credential).contains("synthetic"))
    #expect(!String(reflecting: challenge).contains("canary"))
    let requests = await transport.requests
    #expect(requests.map { $0.url!.absoluteString } == [
        "https://auth.openai.com/api/accounts/deviceauth/usercode",
        "https://auth.openai.com/api/accounts/deviceauth/token",
        "https://auth.openai.com/api/accounts/deviceauth/token",
        "https://auth.openai.com/oauth/token",
    ])
    #expect(requests.allSatisfy { $0.httpMethod == "POST" && $0.value(forHTTPHeaderField: "Authorization") == nil })
    let body = String(decoding: try #require(requests.last?.httpBody), as: UTF8.self)
    #expect(body.contains("grant_type=authorization_code") && body.contains("code_verifier=synthetic-verifier-canary"))
    #expect(body.contains("redirect_uri=https%3A%2F%2Fauth.openai.com%2Fdeviceauth%2Fcallback"))
}

@Test func codexOAuthRejectsMalformedResponsesAndUnsafeDeviceValues() async throws {
    for response in [
        #"{"device_auth_id":"id","user_code":"ABCD","interval":true}"#,
        #"{"device_auth_id":"id","user_code":"<script>","interval":5}"#,
        #"{"device_auth_id":"id","user_code":"ABCD","interval":5,"interval":1}"#,
        #"{"device_auth_id":"id","user_code":"ABCD","interval":999999}"#,
    ] {
        let client = CodexOAuthClient(transport: OAuthFixture([oauthReply(response)]))
        await #expect(throws: CodexOAuthError.invalidResponse) { _ = try await client.start() }
    }
    let disabled = CodexOAuthClient(transport: OAuthFixture([oauthReply("synthetic-provider-secret", status: 404)]))
    await #expect(throws: CodexOAuthError.deviceLoginDisabled) { _ = try await disabled.start() }
}

@Test func codexOAuthRefreshRejectsAccountSwitchAndNeverFormatsCredentials() async throws {
    let tokens = try CodexTokens.parse(fixtureTokens().body, now: Date(timeIntervalSince1970: 1000))
    let transport = OAuthFixture([fixtureTokens(account: "unexpected-account")])
    let client = CodexOAuthClient(transport: transport)
    await #expect(throws: CodexOAuthError.accountChanged) { _ = try await client.refresh(tokens, now: Date(timeIntervalSince1970: 1000)) }
    for response in [
        #"{"access_token":"not-a-jwt","refresh_token":"secret","expires_in":3600}"#,
        #"{"access_token":"\#(fixtureToken())","refresh_token":"secret\nheader","expires_in":3600}"#,
        #"{"access_token":"\#(fixtureToken(expires: 1001))","refresh_token":"secret","expires_in":3600}"#,
        #"{"access_token":"\#(fixtureToken())","refresh_token":"secret","expires_in":true}"#,
    ] {
        #expect(throws: CodexOAuthError.invalidResponse) { _ = try CodexTokens.parse(Data(response.utf8), now: Date(timeIntervalSince1970: 1000)) }
    }
}
