import Foundation
import Observation
import PolicyCore

public struct EnrolledAgent: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let boot: UUID
    public let displayName: String
    public init(id: UUID, boot: UUID, displayName: String) {
        self.id = id; self.boot = boot; self.displayName = String(displayName.prefix(80))
    }
}

public struct ConsentAccount: Identifiable, Sendable {
    public var id: UUID { policy.id }
    public let metadata: OwnerCatalogItem
    public let policy: AccountPolicy
    public init(metadata: OwnerCatalogItem, policy: AccountPolicy) { self.metadata = metadata; self.policy = policy }
}

public struct QualifiedAdapterPolicy: Sendable {
    public let id: String
    public let credentialOrigins: Set<String>
    public let resourceOrigins: Set<String>
    public let actions: Set<ProtectedAction>
    public init(id: String, credentialOrigins: Set<String>, resourceOrigins: Set<String>, actions: Set<ProtectedAction>) {
        self.id = id; self.credentialOrigins = credentialOrigins; self.resourceOrigins = resourceOrigins; self.actions = actions
    }
}

public enum ConsentState: String, Codable, Sendable { case pendingOwner = "pending_owner", granted, denied, expired, revoked }
public enum ConsentKind: String, Codable, Sendable { case catalog, accountUse = "account_use" }

public struct ConsentRequest: Identifiable, Sendable {
    public let id: String
    public let caller: EnrolledAgent
    public let kind: ConsentKind
    public let account: ConsentAccount?
    public let adapter: QualifiedAdapterPolicy?
    public let actions: Set<ProtectedAction>
    public let expiresAt: Date
    let deadline: TimeInterval
    let catalogSnapshot: [UUID: AccountPolicy]
    public var availableAccountIDs: Set<UUID> { Set(catalogSnapshot.keys) }
}

public struct ConsentReply: Codable, Sendable {
    public let requestRef: String
    public let state: ConsentState
    public let grantRef: String?
}

public struct ActiveAccessGrant: Identifiable, Sendable {
    public let id: String
    public let kind: ConsentKind
    public let caller: EnrolledAgent
    public let accountIDs: Set<UUID>
    public let adapter: QualifiedAdapterPolicy?
    public let actions: Set<ProtectedAction>
    public let expiresAt: Date
    public let retainedEvent: UUID?
    let catalogIdentity: UUID
    let deadline: TimeInterval
    let use: AccountUseGrant?
    var retainedSession: UUID?
}

public enum ConsentError: String, Error, Sendable {
    case vaultLocked = "vault_locked", callerUnavailable = "caller_unavailable", rateLimited = "rate_limited"
    case consentRequired = "catalog_consent_required", invalidReference = "invalid_reference"
    case unsupportedAdapter = "unsupported_adapter", staleRequest = "stale_request", invalidScope = "invalid_scope"
    case unavailable = "unavailable", requestConflict = "request_conflict"
}

/// Native authority only. Transport callers may request or inspect consent;
/// approve/deny/revoke are called exclusively by the owner's native controls.
@Observable @MainActor public final class AccessCoordinator {
    public private(set) var unlocked = false
    public private(set) var agents: [EnrolledAgent] = []
    public private(set) var pending: [ConsentRequest] = []
    public private(set) var grants: [ActiveAccessGrant] = []
    public private(set) var accounts: [ConsentAccount] = []
    public var onRevoke: (@MainActor (String?) -> Void)?
    @ObservationIgnored private var adapters: [String: QualifiedAdapterPolicy] = [:]
    @ObservationIgnored private var replies: [String: (EnrolledAgent, ConsentReply)] = [:]
    @ObservationIgnored private var retryKeys: [String: (String, String)] = [:]
    @ObservationIgnored private var prompts: [UUID: [TimeInterval]] = [:]
    @ObservationIgnored private var references = ReferenceRegistry()
    @ObservationIgnored private let clock: () -> TimeInterval
    @ObservationIgnored private let date: () -> Date

    public init(clock: @escaping () -> TimeInterval = { DeadlineClock.now }, date: @escaping () -> Date = { Date() }) {
        self.clock = clock; self.date = date
    }

    public func enroll(_ caller: EnrolledAgent) {
        if let old = agents.first(where: { $0.id == caller.id }), old != caller { removeAgent(old) }
        if !agents.contains(caller) { agents.append(caller) }
    }

    public func removeAgent(_ caller: EnrolledAgent) {
        for grant in grants.filter({ $0.caller == caller }) { revoke(grant.id) }
        for request in pending.filter({ $0.caller == caller }) { finish(request, state: .revoked) }
        agents.removeAll { $0 == caller }
    }

    public func installQualifiedAdapter(_ adapter: QualifiedAdapterPolicy) {
        // Installation/version changes invalidate any previous qualification.
        for grant in grants.filter({ $0.adapter?.id == adapter.id }) { revoke(grant.id) }
        for request in pending.filter({ $0.adapter?.id == adapter.id }) { finish(request, state: .revoked) }
        adapters[adapter.id] = adapter
    }

    public func openVault(accounts: [ConsentAccount]) {
        lock()
        self.accounts = accounts
        unlocked = true
    }

    public func updateAccounts(_ updated: [ConsentAccount]) {
        var positions = Dictionary(uniqueKeysWithValues: accounts.enumerated().map { ($0.element.id, $0.offset) })
        for item in updated {
            if let index = positions[item.id] {
                let previous = accounts[index]
                if previous.policy != item.policy || previous.metadata != item.metadata { invalidate(account: item.id) }
                accounts[index] = item
            } else {
                positions[item.id] = accounts.count
                accounts.append(item)
            }
        }
    }

    public func lock() {
        unlocked = false
        references.invalidateAll()
        for request in pending { finish(request, state: .revoked) }
        for grant in grants { revoke(grant.id) }
        accounts = []
        onRevoke?(nil)
    }

    public func invalidate(account: UUID) {
        references.invalidate(account: account)
        for grant in grants.filter({ $0.accountIDs.contains(account) }) { revoke(grant.id) }
        for request in pending.filter({ $0.account?.id == account || $0.catalogSnapshot[account] != nil }) { finish(request, state: .revoked) }
    }

    public func expire() {
        for request in pending.filter({ $0.deadline <= clock() || $0.expiresAt <= date() }) { finish(request, state: .expired) }
        for grant in grants.filter({ $0.deadline <= clock() || $0.expiresAt <= date() }) { revoke(grant.id, state: .expired) }
    }

    public func requestCatalog(caller: EnrolledAgent, requestID: UUID) throws -> ConsentReply {
        try check(caller)
        return try request(caller: caller, requestID: requestID, signature: "catalog", kind: .catalog, account: nil, adapter: nil, actions: [])
    }

    public func requestUse(caller: EnrolledAgent, requestID: UUID, accountRef: String, adapterID: String, actions: Set<ProtectedAction>) throws -> ConsentReply {
        try check(caller)
        guard accountRef.count == 64, accountRef.allSatisfy({ "0123456789abcdef".contains($0) }),
              !adapterID.isEmpty, adapterID.count <= 128, adapterID.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "._-".contains($0)) }) else { throw ConsentError.invalidReference }
        let signature = "use|\(accountRef)|\(adapterID)|\(actions.map(\.rawValue).sorted().joined(separator: ","))"
        if let prior = try priorReply(caller: caller, requestID: requestID, signature: signature) { return prior }
        guard let binding = references.lookup(accountRef, agent: caller.id, boot: caller.boot, now: date()),
              let disclosure = catalogGrant(caller), disclosure.catalogIdentity == binding.grant,
              disclosure.accountIDs.contains(binding.account),
              let account = accounts.first(where: { $0.id == binding.account }), account.policy.revision == binding.revision else { throw ConsentError.invalidReference }
        guard let adapter = adapters[adapterID], !actions.isEmpty, actions.isSubset(of: adapter.actions),
              !adapter.credentialOrigins.isEmpty, !Set(account.metadata.origins).isDisjoint(with: adapter.credentialOrigins) else { throw ConsentError.unsupportedAdapter }
        return try request(caller: caller, requestID: requestID, signature: signature, kind: .accountUse, account: account, adapter: adapter, actions: actions)
    }

    private func priorReply(caller: EnrolledAgent, requestID: UUID, signature: String) throws -> ConsentReply? {
        let key = "\(caller.id)|\(caller.boot)|\(requestID)"
        guard let prior = retryKeys[key] else { return nil }
        guard prior.0 == signature else { throw ConsentError.requestConflict }
        return try status(prior.1, caller: caller)
    }

    private func request(caller: EnrolledAgent, requestID: UUID, signature: String, kind: ConsentKind, account: ConsentAccount?, adapter: QualifiedAdapterPolicy?, actions: Set<ProtectedAction>) throws -> ConsentReply {
        let key = "\(caller.id)|\(caller.boot)|\(requestID)"
        if let prior = try priorReply(caller: caller, requestID: requestID, signature: signature) { return prior }
        let recent = (prompts[caller.id] ?? []).filter { $0 > clock() - 60 }
        guard recent.count < 3, pending.count < 32, pending.filter({ $0.caller == caller }).count < 8, replies.count < 1024 else { throw ConsentError.rateLimited }
        prompts[caller.id] = recent + [clock()]
        let token = try ReferenceRegistry.randomToken()
        let snapshot = Dictionary(uniqueKeysWithValues: accounts.map { ($0.id, $0.policy) })
        let request = ConsentRequest(id: token, caller: caller, kind: kind, account: account, adapter: adapter, actions: actions, expiresAt: date().addingTimeInterval(120), deadline: clock() + 120, catalogSnapshot: snapshot)
        pending.append(request)
        let reply = ConsentReply(requestRef: token, state: .pendingOwner, grantRef: nil)
        replies[token] = (caller, reply)
        retryKeys[key] = (signature, token)
        return reply
    }

    public func status(_ requestRef: String, caller: EnrolledAgent) throws -> ConsentReply {
        expire()
        guard agents.contains(caller), let record = replies[requestRef], record.0 == caller else { throw ConsentError.invalidReference }
        return record.1
    }

    public func approveCatalog(_ requestRef: String, selected: Set<UUID>, duration: TimeInterval) throws {
        let request = try approvalRequest(requestRef, duration: duration)
        guard request.kind == .catalog, !selected.isEmpty,
              selected.allSatisfy({ id in accounts.contains { $0.id == id && request.catalogSnapshot[id] == $0.policy } }) else { throw ConsentError.staleRequest }
        for previous in grants.filter({ $0.caller == request.caller && $0.kind == .catalog }) { revoke(previous.id) }
        let grant = ActiveAccessGrant(id: try ReferenceRegistry.randomToken(), kind: .catalog, caller: request.caller, accountIDs: selected, adapter: nil, actions: [], expiresAt: date().addingTimeInterval(duration), retainedEvent: nil, catalogIdentity: UUID(), deadline: clock() + duration, use: nil)
        grants.append(grant)
        finish(request, state: .granted, grant: grant.id)
    }

    public func approveUse(_ requestRef: String, duration: TimeInterval, approveRetained: Bool) throws {
        let request = try approvalRequest(requestRef, duration: duration)
        guard request.kind == .accountUse, let snapshot = request.account, let adapter = request.adapter,
              let current = accounts.first(where: { $0.id == snapshot.id }), snapshot.policy == current.policy,
              catalogGrant(request.caller)?.accountIDs.contains(current.id) == true else { throw ConsentError.staleRequest }
        let retained = approveRetained ? current.policy.restrictionEvent : nil
        let use = AccountUseGrant(agent: request.caller.id, boot: request.caller.boot, account: current.id, revision: current.policy.revision, origins: adapter.credentialOrigins.union(adapter.resourceOrigins), actions: request.actions, expiresAt: date().addingTimeInterval(duration), retainedEvent: retained)
        guard adapter.credentialOrigins.allSatisfy({ origin in request.actions.allSatisfy { Authority.canUse(state: current.policy, grant: use, agent: request.caller.id, boot: request.caller.boot, origin: origin, action: $0, now: date()) } }) else { throw ConsentError.invalidScope }
        let grant = ActiveAccessGrant(id: try ReferenceRegistry.randomToken(), kind: .accountUse, caller: request.caller, accountIDs: [current.id], adapter: adapter, actions: request.actions, expiresAt: use.expiresAt, retainedEvent: retained, catalogIdentity: UUID(), deadline: clock() + duration, use: use)
        grants.append(grant)
        finish(request, state: .granted, grant: grant.id)
    }

    public func deny(_ requestRef: String) {
        guard let request = pending.first(where: { $0.id == requestRef }) else { return }
        finish(request, state: .denied)
    }

    public func revoke(_ grantRef: String, state: ConsentState = .revoked) {
        guard let grant = grants.first(where: { $0.id == grantRef }) else { return }
        references.invalidate(grant: grant.catalogIdentity)
        grants.removeAll { $0.id == grantRef }
        for (key, record) in replies where record.1.grantRef == grantRef {
            replies[key] = (record.0, ConsentReply(requestRef: key, state: state, grantRef: nil))
        }
        onRevoke?(grantRef)
    }

    public func disclosedAccounts(caller: EnrolledAgent) throws -> [ConsentAccount] {
        try check(caller)
        guard let grant = catalogGrant(caller) else { throw ConsentError.consentRequired }
        return accounts.filter { grant.accountIDs.contains($0.id) }
    }

    public func accountReference(_ id: UUID, caller: EnrolledAgent) throws -> String {
        try check(caller)
        guard let grant = catalogGrant(caller), grant.accountIDs.contains(id), let account = accounts.first(where: { $0.id == id }) else { throw ConsentError.consentRequired }
        return try references.mint(account: id, revision: account.policy.revision, agent: caller.id, boot: caller.boot, grant: grant.catalogIdentity, expiresAt: min(grant.expiresAt, date().addingTimeInterval(300)))
    }

    public func accountForReference(_ reference: String, caller: EnrolledAgent) throws -> ConsentAccount {
        try check(caller)
        guard let binding = references.lookup(reference, agent: caller.id, boot: caller.boot, now: date()),
              let grant = catalogGrant(caller), binding.grant == grant.catalogIdentity,
              grant.accountIDs.contains(binding.account),
              let account = accounts.first(where: { $0.id == binding.account && $0.policy.revision == binding.revision }) else { throw ConsentError.invalidReference }
        return account
    }

    public func disclosureIdentity(caller: EnrolledAgent) -> UUID? { expire(); return catalogGrant(caller)?.catalogIdentity }

    public func adapter(_ id: String) -> QualifiedAdapterPolicy? { adapters[id] }

    public func supportedAdapters(for account: ConsentAccount) -> [String] {
        adapters.values.filter { !Set(account.metadata.origins).isDisjoint(with: $0.credentialOrigins) }.map(\.id).sorted()
    }

    public func cancelRequest(_ reference: String, caller: EnrolledAgent) throws -> ConsentReply {
        _ = try status(reference, caller: caller)
        if let request = pending.first(where: { $0.id == reference && $0.caller == caller }) { finish(request, state: .denied) }
        return try status(reference, caller: caller)
    }

    public func authorize(grantRef: String, caller: EnrolledAgent, account: UUID, adapterID: String, origin: String, action: ProtectedAction, session: UUID? = nil) -> Bool {
        expire()
        guard unlocked, agents.contains(caller), let grant = grants.first(where: { $0.id == grantRef }), grant.caller == caller,
              grant.adapter?.id == adapterID, let use = grant.use, let state = accounts.first(where: { $0.id == account })?.policy,
              action != .login || grant.adapter?.credentialOrigins.contains(origin) == true else { return false }
        if grant.retainedEvent != nil, let claimed = grant.retainedSession, claimed != session { return false }
        return Authority.canUse(state: state, grant: use, agent: caller.id, boot: caller.boot, origin: origin, action: action, now: date())
    }

    public func claimRetainedSession(grantRef: String, session: UUID) throws {
        expire()
        guard let index = grants.firstIndex(where: { $0.id == grantRef }) else { throw ConsentError.invalidReference }
        if grants[index].retainedEvent != nil {
            guard grants[index].retainedSession == nil else { throw ConsentError.invalidReference }
            grants[index].retainedSession = session
        }
    }

    private func approvalRequest(_ reference: String, duration: TimeInterval) throws -> ConsentRequest {
        expire()
        guard unlocked, duration > 0, duration <= 3600, duration.isFinite,
              let request = pending.first(where: { $0.id == reference }), agents.contains(request.caller) else { throw ConsentError.staleRequest }
        return request
    }

    private func check(_ caller: EnrolledAgent) throws {
        expire()
        guard unlocked else { throw ConsentError.vaultLocked }
        guard agents.contains(caller) else { throw ConsentError.callerUnavailable }
    }

    private func catalogGrant(_ caller: EnrolledAgent) -> ActiveAccessGrant? {
        grants.first { $0.caller == caller && $0.kind == .catalog && $0.deadline > clock() && $0.expiresAt > date() }
    }

    private func finish(_ request: ConsentRequest, state: ConsentState, grant: String? = nil) {
        pending.removeAll { $0.id == request.id }
        replies[request.id] = (request.caller, ConsentReply(requestRef: request.id, state: state, grantRef: grant))
    }
}
