import Foundation
import Testing
import BrokerHost
import PolicyCore

@MainActor private final class ConsentFixture {
    var monotonic: TimeInterval = 1000
    var wall = Date()
    let caller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Synthetic Codex CLI")
    let account = UUID()
    lazy var access = AccessCoordinator(clock: { self.monotonic }, date: { self.wall })

    func item(revision: UInt64 = 1, restriction: UUID? = nil) -> ConsentAccount {
        ConsentAccount(metadata: OwnerCatalogItem(id: account.uuidString, title: "Synthetic account", username: "owner", origins: ["https://app.example.invalid"], group: "Synthetic", revision: revision), policy: AccountPolicy(id: account, revision: revision, source: restriction == nil ? .local : .mirrored, presence: restriction == nil ? .present : .deletedAtSource, lastObserved: wall, restrictionEvent: restriction))
    }

    func open(restriction: UUID? = nil) {
        access.enroll(caller)
        access.openVault(accounts: [item(restriction: restriction)])
        access.installQualifiedAdapter(QualifiedAdapterPolicy(id: "synthetic-v1", credentialOrigins: ["https://app.example.invalid"], resourceOrigins: ["https://cdn.example.invalid"], actions: [.login, .observe]))
    }

    func disclose() throws -> String {
        let request = try access.requestCatalog(caller: caller, requestID: UUID())
        try access.approveCatalog(request.requestRef, selected: [account], duration: 300)
        return try access.accountReference(account, caller: caller)
    }
}

@Test @MainActor func disclosureAndUseRequireSeparateNativeApproval() throws {
    let fixture = ConsentFixture()
    fixture.open()
    let access = fixture.access, caller = fixture.caller
    #expect(throws: ConsentError.self) { try access.disclosedAccounts(caller: caller) }
    let reference = try fixture.disclose()
    #expect(try access.disclosedAccounts(caller: caller).map(\.id) == [fixture.account])
    #expect(!access.authorize(grantRef: access.grants[0].id, caller: caller, account: fixture.account, adapterID: "synthetic-v1", origin: "https://app.example.invalid", action: .login))
    let request = try access.requestUse(caller: caller, requestID: UUID(), accountRef: reference, adapterID: "synthetic-v1", actions: [.login])
    #expect(request.state == .pendingOwner && request.grantRef == nil)
    try access.approveUse(request.requestRef, duration: 300, approveRetained: false)
    let grant = try #require(access.status(request.requestRef, caller: caller).grantRef)
    #expect(access.authorize(grantRef: grant, caller: caller, account: fixture.account, adapterID: "synthetic-v1", origin: "https://app.example.invalid", action: .login))
    #expect(!access.authorize(grantRef: grant, caller: caller, account: fixture.account, adapterID: "synthetic-v1", origin: "https://cdn.example.invalid", action: .login))
    #expect(!access.authorize(grantRef: grant, caller: caller, account: fixture.account, adapterID: "synthetic-v1", origin: "https://app.example.invalid", action: .observe))
    let impostor = EnrolledAgent(id: caller.id, boot: UUID(), displayName: caller.displayName)
    #expect(!access.authorize(grantRef: grant, caller: impostor, account: fixture.account, adapterID: "synthetic-v1", origin: "https://app.example.invalid", action: .login))
    #expect(throws: ConsentError.self) { try access.status(request.requestRef, caller: impostor) }
    access.revoke(grant)
    #expect(!access.authorize(grantRef: grant, caller: caller, account: fixture.account, adapterID: "synthetic-v1", origin: "https://app.example.invalid", action: .login))
}

@Test @MainActor func changedEntryCannotBeApprovedFromAnOldPrompt() throws {
    let fixture = ConsentFixture()
    fixture.open()
    let reference = try fixture.disclose()
    let request = try fixture.access.requestUse(caller: fixture.caller, requestID: UUID(), accountRef: reference, adapterID: "synthetic-v1", actions: [.login])
    fixture.access.updateAccounts([fixture.item(revision: 2)])
    #expect(throws: ConsentError.self) { try fixture.access.approveUse(request.requestRef, duration: 300, approveRetained: false) }
    #expect(try fixture.access.status(request.requestRef, caller: fixture.caller).state == .revoked)
    #expect(throws: ConsentError.self) { try fixture.access.requestUse(caller: fixture.caller, requestID: UUID(), accountRef: reference, adapterID: "synthetic-v1", actions: [.login]) }
}

@Test @MainActor func useRequestRetryKeepsItsResultAfterReferenceRevocation() throws {
    let fixture = ConsentFixture()
    fixture.open()
    let reference = try fixture.disclose(), id = UUID()
    let request = try fixture.access.requestUse(caller: fixture.caller, requestID: id, accountRef: reference, adapterID: "synthetic-v1", actions: [.login])
    fixture.access.deny(request.requestRef)
    fixture.access.revoke(fixture.access.grants[0].id)
    #expect(try fixture.access.requestUse(caller: fixture.caller, requestID: id, accountRef: reference, adapterID: "synthetic-v1", actions: [.login]).state == .denied)
    #expect(throws: ConsentError.self) { try fixture.access.requestUse(caller: fixture.caller, requestID: id, accountRef: reference, adapterID: "synthetic-v1", actions: [.observe]) }
}

@Test @MainActor func consentTimeoutAndMonotonicGrantExpiryDenyAccess() throws {
    let fixture = ConsentFixture()
    fixture.open()
    let timed = try fixture.access.requestCatalog(caller: fixture.caller, requestID: UUID())
    fixture.monotonic += 121
    #expect(throws: ConsentError.self) { try fixture.access.approveCatalog(timed.requestRef, selected: [fixture.account], duration: 300) }
    #expect(try fixture.access.status(timed.requestRef, caller: fixture.caller).state == .expired)
    _ = try fixture.disclose()
    fixture.wall = fixture.wall.addingTimeInterval(-3600)
    fixture.monotonic += 301
    #expect(throws: ConsentError.self) { try fixture.access.disclosedAccounts(caller: fixture.caller) }
    #expect(fixture.access.grants.isEmpty)
}

@Test @MainActor func requestsAreIdempotentAndPromptSpamIsBounded() throws {
    let fixture = ConsentFixture()
    fixture.open()
    let identity = UUID()
    let first = try fixture.access.requestCatalog(caller: fixture.caller, requestID: identity)
    #expect(try fixture.access.requestCatalog(caller: fixture.caller, requestID: identity).requestRef == first.requestRef)
    #expect(fixture.access.pending.count == 1)
    fixture.access.deny(first.requestRef)
    #expect(try fixture.access.status(first.requestRef, caller: fixture.caller).state == .denied)
    for _ in 0..<2 { _ = try fixture.access.requestCatalog(caller: fixture.caller, requestID: UUID()) }
    #expect(throws: ConsentError.self) { try fixture.access.requestCatalog(caller: fixture.caller, requestID: UUID()) }
    fixture.access.lock()
    #expect(fixture.access.pending.isEmpty && fixture.access.grants.isEmpty)
}

@Test @MainActor func retainedApprovalIsExplicitAndBoundToOneSession() throws {
    let fixture = ConsentFixture()
    fixture.open(restriction: UUID())
    let reference = try fixture.disclose()
    let request = try fixture.access.requestUse(caller: fixture.caller, requestID: UUID(), accountRef: reference, adapterID: "synthetic-v1", actions: [.login, .observe])
    #expect(throws: ConsentError.self) { try fixture.access.approveUse(request.requestRef, duration: 300, approveRetained: false) }
    try fixture.access.approveUse(request.requestRef, duration: 300, approveRetained: true)
    let grant = try #require(fixture.access.status(request.requestRef, caller: fixture.caller).grantRef)
    let session = UUID()
    try fixture.access.claimRetainedSession(grantRef: grant, session: session)
    #expect(throws: ConsentError.self) { try fixture.access.claimRetainedSession(grantRef: grant, session: UUID()) }
    #expect(!fixture.access.authorize(grantRef: grant, caller: fixture.caller, account: fixture.account, adapterID: "synthetic-v1", origin: "https://app.example.invalid", action: .login))
    #expect(fixture.access.authorize(grantRef: grant, caller: fixture.caller, account: fixture.account, adapterID: "synthetic-v1", origin: "https://app.example.invalid", action: .observe, session: session))
    #expect(!fixture.access.authorize(grantRef: grant, caller: fixture.caller, account: fixture.account, adapterID: "synthetic-v1", origin: "https://app.example.invalid", action: .observe, session: UUID()))
}
