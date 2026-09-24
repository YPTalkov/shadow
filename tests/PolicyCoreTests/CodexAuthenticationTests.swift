import Foundation
import Testing
import OwnerUI
@testable import ModelRelay

private final class AuthFixtureState: CodexTokenStore, @unchecked Sendable {
    private let lock = NSLock()
    private var tokens: CodexTokens?
    private var current: TimeInterval = 0
    private var writes = 0
    func read() throws -> CodexTokens? { lock.withLock { tokens } }
    func write(_ tokens: CodexTokens) throws { lock.withLock { self.tokens = tokens; writes += 1 } }
    func delete() throws { lock.withLock { tokens = nil } }
    func now() -> TimeInterval { lock.withLock { current } }
    func advance(_ seconds: TimeInterval) { lock.withLock { current += seconds } }
    var writeCount: Int { lock.withLock { writes } }
}

private actor GatedOAuthFixture: CodexOAuthTransport {
    private var gate: CheckedContinuation<OAuthHTTPReply, Never>?
    private(set) var tokenRequests = 0
    var waiting: Bool { gate != nil }
    func post(_ request: URLRequest) async throws -> OAuthHTTPReply {
        if request.url?.path == "/api/accounts/deviceauth/usercode" {
            return oauthReply(#"{"device_auth_id":"id","user_code":"ABCD-EFGH","interval":5}"#)
        }
        if request.url?.path == "/api/accounts/deviceauth/token" {
            return oauthReply(#"{"authorization_code":"synthetic-code","code_verifier":"synthetic-verifier"}"#)
        }
        tokenRequests += 1
        // Deliberately ignores task cancellation to test stale network replies.
        return await withCheckedContinuation { gate = $0 }
    }
    func release() { gate?.resume(returning: fixtureTokens()); gate = nil }
}

@Test func nativeSignInPollsAtProviderIntervalAndPublishesOnlyDurableTokens() async throws {
    let transport = OAuthFixture([
        oauthReply(#"{"device_auth_id":"id","user_code":"ABCD-EFGH","interval":5}"#),
        oauthReply(#"{"error":"slow_down"}"#, status: 429),
        oauthReply(#"{"authorization_code":"synthetic-code","code_verifier":"synthetic-verifier"}"#),
        fixtureTokens(),
    ])
    let state = AuthFixtureState()
    let auth = CodexAuthentication(store: state, client: CodexOAuthClient(transport: transport), clock: { state.now() }, date: { Date(timeIntervalSince1970: 1000) })
    let prompt = try await auth.begin()
    #expect(prompt.userCode == "ABCD-EFGH")
    #expect(try await auth.poll() == false)
    #expect(await transport.requests.count == 1)
    state.advance(5)
    #expect(try await auth.poll() == false)
    state.advance(9)
    #expect(try await auth.poll() == false)
    #expect(await transport.requests.count == 2)
    state.advance(1)
    #expect(try await auth.poll())
    #expect(state.writeCount == 1)
    #expect(try await auth.isSignedIn())
    #expect(!String(reflecting: try await auth.credential()).contains("synthetic"))
    try await auth.signOut()
    #expect(try await auth.isSignedIn() == false)
    await #expect(throws: CodexOAuthError.signInRequired) { _ = try await auth.credential() }
}

@Test func nativeSignInExpiresOnContinuousTimeAndCancellationRevokesPendingFlow() async throws {
    let transport = OAuthFixture([
        oauthReply(#"{"device_auth_id":"id","user_code":"ABCD-EFGH","interval":5}"#),
        oauthReply(#"{"device_auth_id":"id","user_code":"ABCD-EFGH","interval":5}"#),
    ])
    let state = AuthFixtureState()
    let auth = CodexAuthentication(store: state, client: CodexOAuthClient(transport: transport), clock: { state.now() }, date: { Date(timeIntervalSince1970: 1000) })
    _ = try await auth.begin()
    state.advance(901)
    await #expect(throws: CodexOAuthError.expired) { _ = try await auth.poll() }
    _ = try await auth.begin()
    await auth.cancelPending()
    await #expect(throws: CodexOAuthError.cancelled) { _ = try await auth.poll() }
    #expect(state.writeCount == 0)
    #expect(try state.read() == nil)
}

@Test func nativeModelTokensRoundTripThroughSeparateKeychainItem() throws {
    let id = "synthetic-model-auth-\(UUID().uuidString)"
    let store = CodexKeychainStore(vaultID: id)
    defer { try? store.delete() }
    #expect(try store.read() == nil)
    let tokens = try CodexTokens.parse(fixtureTokens().body, now: Date(timeIntervalSince1970: 1000))
    try store.write(tokens)
    let reopened = CodexKeychainStore(vaultID: id)
    #expect(try reopened.read()?.accountID == "synthetic-oauth-account")
    try reopened.delete()
    #expect(try store.read() == nil)
}

@Test func signOutDuringTokenExchangeRejectsTheLateSuccessfulResponse() async throws {
    let transport = GatedOAuthFixture(), state = AuthFixtureState()
    let auth = CodexAuthentication(store: state, client: CodexOAuthClient(transport: transport), clock: { state.now() }, date: { Date(timeIntervalSince1970: 1000) })
    _ = try await auth.begin()
    state.advance(5)
    let polling = Task { try await auth.poll() }
    for _ in 0..<100 where !(await transport.waiting) { try await Task.sleep(for: .milliseconds(1)) }
    try #require(await transport.waiting)
    try await auth.signOut()
    await transport.release()
    await #expect(throws: CodexOAuthError.cancelled) { _ = try await polling.value }
    #expect(state.writeCount == 0)
    #expect(try state.read() == nil)
}

@Test func simultaneousRelayRequestsShareOneDurableTokenRefresh() async throws {
    let transport = GatedOAuthFixture(), state = AuthFixtureState()
    try state.write(CodexTokens.parse(fixtureTokens().body, now: Date(timeIntervalSince1970: 1000)))
    let auth = CodexAuthentication(store: state, client: CodexOAuthClient(transport: transport), clock: { state.now() }, date: { Date(timeIntervalSince1970: 4500) })
    let first = Task { try await auth.credential() }
    for _ in 0..<100 where !(await transport.waiting) { try await Task.sleep(for: .milliseconds(1)) }
    try #require(await transport.waiting)
    let second = Task { try await auth.credential() }
    await transport.release()
    _ = try await first.value
    _ = try await second.value
    #expect(await transport.tokenRequests == 1)
    #expect(state.writeCount == 2)
    #expect(try state.read()?.expiresAt == Date(timeIntervalSince1970: 7200))
}

@Test @MainActor func nativeSignInPanelClearsTheCodeOnCancellation() async throws {
    let state = AuthFixtureState()
    let transport = OAuthFixture([oauthReply(#"{"device_auth_id":"id","user_code":"ABCD-EFGH","interval":5}"#)])
    let auth = CodexAuthentication(store: state, client: CodexOAuthClient(transport: transport), clock: { state.now() }, date: { Date(timeIntervalSince1970: 1000) })
    let model = ModelSignInModel(authentication: auth)
    for _ in 0..<100 where model.phase == .checking { try await Task.sleep(for: .milliseconds(1)) }
    try #require(model.phase == .signedOut)
    model.start()
    for _ in 0..<100 where model.prompt == nil { try await Task.sleep(for: .milliseconds(1)) }
    try #require(model.prompt != nil)
    model.cancelImmediately()
    #expect(model.prompt == nil)
    for _ in 0..<100 where model.phase == .checking { try await Task.sleep(for: .milliseconds(1)) }
    #expect(model.phase == .signedOut)
    #expect(state.writeCount == 0)
    #expect(await transport.requests.count == 1)
}
