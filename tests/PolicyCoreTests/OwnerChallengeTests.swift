import Foundation
import Testing
@testable import BrokerHost

@Test @MainActor func ownerChallengeIsBoundToCheckpointAndExpires() async throws {
    var now = 10.0
    let owner = OwnerChallengeCoordinator(clock: { now })
    let session = UUID()
    let task = Task { try await owner.request(session: session, checkpoint: String(repeating: "a", count: 64), account: "Synthetic account", caller: "Synthetic agent", origin: "https://example.invalid") }
    for _ in 0..<100 where owner.pending == nil { await Task.yield() }
    #expect(owner.pending?.id == String(repeating: "a", count: 64))
    #expect(throws: AgentAPIError.invalidReference) { try owner.complete(String(repeating: "b", count: 64)) }
    now += 121
    owner.expire()
    #expect(owner.pending == nil)
    do { try await task.value; Issue.record("Expired challenge resumed") } catch { #expect(error as? AgentAPIError == .sessionClosed) }
    #expect(throws: AgentAPIError.invalidReference) { try owner.complete(String(repeating: "a", count: 64)) }
}

@Test @MainActor func ownerChallengeCompletionAndRevocationAreOneShot() async throws {
    let owner = OwnerChallengeCoordinator()
    let session = UUID()
    let first = Task { try await owner.request(session: session, checkpoint: String(repeating: "a", count: 64), account: "Synthetic", caller: "Agent", origin: "https://example.invalid") }
    for _ in 0..<100 where owner.pending == nil { await Task.yield() }
    try owner.complete(String(repeating: "a", count: 64))
    try await first.value
    #expect(owner.pending == nil)
    let second = Task { try await owner.request(session: session, checkpoint: String(repeating: "b", count: 64), account: "Synthetic", caller: "Agent", origin: "https://example.invalid") }
    for _ in 0..<100 where owner.pending == nil { await Task.yield() }
    owner.cancel(session: UUID())
    #expect(owner.pending != nil)
    owner.cancel(session: session)
    do { try await second.value; Issue.record("Cancelled challenge resumed") } catch { #expect(error as? AgentAPIError == .sessionClosed) }
    #expect(owner.pending == nil)
}
