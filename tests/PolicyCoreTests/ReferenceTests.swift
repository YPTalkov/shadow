import Foundation
import Testing
@testable import PolicyCore

@Test func referenceIsOpaqueAndBoundToAgentBootRevisionAndGrant() throws {
    var registry = ReferenceRegistry()
    let now = Date()
    let account = UUID()
    let agent = UUID()
    let boot = UUID()
    let grant = UUID()
    let token = try registry.mint(account: account, revision: 1, agent: agent, boot: boot, grant: grant, expiresAt: now.addingTimeInterval(300))
    #expect(token.count == 64)
    #expect(!token.contains(account.uuidString))
    #expect(registry.resolve(token, account: account, revision: 1, agent: agent, boot: boot, grant: grant, now: now))
    #expect(!registry.resolve(token, account: account, revision: 2, agent: agent, boot: boot, grant: grant, now: now))
    #expect(!registry.resolve(token, account: account, revision: 1, agent: UUID(), boot: boot, grant: grant, now: now))
    #expect(!registry.resolve(token, account: account, revision: 1, agent: agent, boot: UUID(), grant: grant, now: now))
    #expect(!registry.resolve(token, account: account, revision: 1, agent: agent, boot: boot, grant: grant, now: now.addingTimeInterval(301)))
    registry.invalidateAll()
    #expect(!registry.resolve(token, account: account, revision: 1, agent: agent, boot: boot, grant: grant, now: now))
}
