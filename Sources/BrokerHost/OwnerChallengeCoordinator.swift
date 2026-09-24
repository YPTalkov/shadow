import Foundation
import Observation
import PolicyCore

public struct OwnerChallenge: Identifiable, Sendable {
    public let id: String
    public let account: String
    public let caller: String
    public let origin: String
    public let expiresAt: Date
    let session: UUID
    let deadline: TimeInterval
}

/// Native controls resolve this checkpoint. There is no agent-side resume
/// operation, and no website text can supply its approval labels or origin.
@Observable @MainActor public final class OwnerChallengeCoordinator {
    public private(set) var pending: OwnerChallenge?
    @ObservationIgnored private var continuation: CheckedContinuation<Void, any Error>?
    @ObservationIgnored private let clock: () -> TimeInterval
    @ObservationIgnored var onCancel: ((UUID) -> Void)?

    public init(clock: @escaping () -> TimeInterval = { DeadlineClock.now }) { self.clock = clock }

    func request(session: UUID, checkpoint: String, account: String, caller: String, origin: String) async throws {
        guard pending == nil, !Task.isCancelled else { throw AgentAPIError.sessionClosed }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                self.continuation = continuation
                pending = OwnerChallenge(id: checkpoint, account: account, caller: caller, origin: origin, expiresAt: Date().addingTimeInterval(120), session: session, deadline: clock() + 120)
            }
        } onCancel: {
            Task { @MainActor [weak self] in self?.cancel(session: session) }
        }
    }

    public func complete(_ checkpoint: String) throws {
        expire()
        guard pending?.id == checkpoint else { throw AgentAPIError.invalidReference }
        finish(error: nil)
    }

    public func cancel(_ checkpoint: String) {
        guard pending?.id == checkpoint else { return }
        finish(error: .sessionClosed)
    }

    func cancel(session: UUID) {
        guard pending?.session == session else { return }
        finish(error: .sessionClosed)
    }

    public func expire() {
        if let pending, clock() >= pending.deadline { finish(error: .sessionClosed) }
    }

    private func finish(error: AgentAPIError?) {
        let continuation = continuation
        let session = pending?.session
        self.continuation = nil
        pending = nil
        if error != nil, let session { onCancel?(session) }
        if let error { continuation?.resume(throwing: error) }
        else { continuation?.resume() }
    }
}
