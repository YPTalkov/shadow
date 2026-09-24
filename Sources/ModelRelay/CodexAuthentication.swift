import Foundation
import PolicyCore

/// Native owner projection only; never serialized to an agent channel.
public struct CodexSignInPrompt: Sendable, CustomStringConvertible, CustomReflectable {
    public let userCode: String
    public let verificationURL: URL
    public let expiresAt: Date
    public var description: String { "CodexSignInPrompt(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

public actor CodexAuthentication {
    private struct Pending {
        let challenge: CodexDeviceChallenge
        let expires: TimeInterval
        var nextPoll: TimeInterval
        var interval: TimeInterval
    }
    private let store: any CodexTokenStore
    private let client: CodexOAuthClient
    private let clock: @Sendable () -> TimeInterval
    private let date: @Sendable () -> Date
    private var pending: Pending?
    private var generation = 0
    private var busy = false
    private var refreshTask: Task<CodexCredential, any Error>?

    public init(vaultID: String) {
        store = CodexKeychainStore(vaultID: vaultID)
        client = CodexOAuthClient()
        clock = { DeadlineClock.now }
        date = { Date() }
    }

    init(store: any CodexTokenStore, client: CodexOAuthClient, clock: @escaping @Sendable () -> TimeInterval, date: @escaping @Sendable () -> Date) {
        self.store = store; self.client = client; self.clock = clock; self.date = date
    }

    public func isSignedIn() throws -> Bool { try store.read() != nil }

    public func begin() async throws -> CodexSignInPrompt {
        guard !busy, pending == nil, refreshTask == nil, try store.read() == nil else { throw CodexOAuthError.busy }
        busy = true
        let epoch = generation
        let expires = clock() + 900, displayExpiry = date().addingTimeInterval(900)
        defer { if epoch == generation { busy = false } }
        let challenge = try await client.start()
        guard epoch == generation, !Task.isCancelled else { throw CodexOAuthError.cancelled }
        guard clock() < expires else { throw CodexOAuthError.expired }
        pending = Pending(challenge: challenge, expires: expires, nextPoll: clock() + challenge.interval, interval: challenge.interval)
        return CodexSignInPrompt(userCode: challenge.userCode, verificationURL: challenge.verificationURL, expiresAt: displayExpiry)
    }

    public func poll() async throws -> Bool {
        guard var state = pending else { throw CodexOAuthError.cancelled }
        guard clock() < state.expires else { pending = nil; throw CodexOAuthError.expired }
        guard !busy, clock() >= state.nextPoll else { return false }
        busy = true
        let epoch = generation
        defer { if epoch == generation { busy = false } }
        let reply = try await client.poll(state.challenge, now: date())
        guard epoch == generation, !Task.isCancelled else { throw CodexOAuthError.cancelled }
        guard clock() < state.expires else { pending = nil; throw CodexOAuthError.expired }
        switch reply {
        case .complete(let tokens):
            try store.write(tokens)
            pending = nil
            return true
        case .slowDown:
            state.interval = min(60, state.interval + 5)
        case .pending: break
        }
        state.nextPoll = clock() + state.interval
        pending = state
        return false
    }

    public func credential() async throws -> CodexCredential {
        guard pending == nil, !busy else { throw CodexOAuthError.busy }
        let epoch = generation
        if let running = refreshTask {
            let credential = try await running.value
            guard epoch == generation, !Task.isCancelled else { throw CodexOAuthError.cancelled }
            return credential
        }
        guard let tokens = try store.read() else { throw CodexOAuthError.signInRequired }
        if tokens.expiresAt.timeIntervalSince(date()) > 120 { return tokens.credential }
        let task = Task {
            let next = try await client.refresh(tokens, now: date())
            guard epoch == generation, !Task.isCancelled else { throw CodexOAuthError.cancelled }
            try store.write(next)
            return next.credential
        }
        refreshTask = task
        defer { if epoch == generation { refreshTask = nil } }
        do {
            let credential = try await task.value
            guard epoch == generation, !Task.isCancelled else { throw CodexOAuthError.cancelled }
            return credential
        } catch let error as CodexOAuthError {
            if epoch == generation, error == .signInRequired || error == .accountChanged { try store.delete() }
            throw error
        }
    }

    public func cancelPending() {
        generation += 1
        pending = nil
        busy = false
        refreshTask?.cancel()
        refreshTask = nil
    }

    public func signOut() throws {
        cancelPending()
        try store.delete()
    }
}
