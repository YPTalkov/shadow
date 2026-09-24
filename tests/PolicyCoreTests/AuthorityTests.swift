import Foundation
import Testing
@testable import PolicyCore

@Test func catalogConsentDoesNotAuthorizeCredentialUse() {
    let account = UUID()
    let agent = UUID()
    let boot = UUID()
    let now = Date()
    let disclosure = CatalogDisclosureGrant(agent: agent, boot: boot, accounts: [account], expiresAt: now.addingTimeInterval(300))
    #expect(Authority.canDisclose(account: account, agent: agent, boot: boot, grant: disclosure, now: now))
    #expect(!Authority.canDisclose(account: account, agent: UUID(), boot: boot, grant: disclosure, now: now))
    #expect(!Authority.canDisclose(account: account, agent: agent, boot: boot, grant: disclosure, now: now.addingTimeInterval(301)))
}

@Test func retainedRestrictionSurvivesReappearance() {
    let account = UUID()
    let event = UUID()
    let agent = UUID()
    let boot = UUID()
    let now = Date()
    let state = AccountPolicy(id: account, revision: 2, source: .mirrored, presence: .present, lastObserved: now, restrictionEvent: event)
    let ordinary = AccountUseGrant(agent: agent, boot: boot, account: account, revision: 2, origins: ["https://example.invalid"], actions: [.login], expiresAt: now.addingTimeInterval(3600), retainedEvent: nil)
    #expect(!Authority.canUse(state: state, grant: ordinary, agent: agent, boot: boot, origin: "https://example.invalid", action: .login, now: now))
    var retained = ordinary
    retained.retainedEvent = event
    #expect(Authority.canUse(state: state, grant: retained, agent: agent, boot: boot, origin: "https://example.invalid", action: .login, now: now))
    #expect(!Authority.canUse(state: state, grant: retained, agent: agent, boot: boot, origin: "https://other.invalid", action: .login, now: now))
    #expect(!Authority.canUse(state: state, grant: retained, agent: agent, boot: boot, origin: "https://example.invalid", action: .extract, now: now))
    #expect(!Authority.canUse(state: state, grant: retained, agent: agent, boot: boot, origin: "https://example.invalid", action: .login, now: now.addingTimeInterval(3601)))
    #expect(!Authority.canUse(state: AccountPolicy(id: account, revision: 3, source: .mirrored, presence: .present, lastObserved: now, restrictionEvent: event), grant: retained, agent: agent, boot: boot, origin: "https://example.invalid", action: .login, now: now))
}

@Test func staleMirrorNeedsRetainedEventAndLocalDoesNot() {
    let account = UUID()
    let agent = UUID()
    let boot = UUID()
    let now = Date()
    let grant = AccountUseGrant(agent: agent, boot: boot, account: account, revision: 1, origins: ["https://example.invalid"], actions: [.login], expiresAt: now.addingTimeInterval(60), retainedEvent: nil)
    let stale = AccountPolicy(id: account, revision: 1, source: .mirrored, presence: .present, lastObserved: now.addingTimeInterval(-90000), restrictionEvent: nil)
    #expect(!Authority.canUse(state: stale, grant: grant, agent: agent, boot: boot, origin: "https://example.invalid", action: .login, now: now))
    let local = AccountPolicy(id: account, revision: 1, source: .local, presence: .present, lastObserved: nil, restrictionEvent: nil)
    #expect(Authority.canUse(state: local, grant: grant, agent: agent, boot: boot, origin: "https://example.invalid", action: .login, now: now))
}
