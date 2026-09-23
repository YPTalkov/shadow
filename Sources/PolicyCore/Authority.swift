import Foundation

public enum AccountSource: Sendable, Equatable {
    case local
    case mirrored
}

public enum SourcePresence: Sendable, Equatable {
    case present
    case deletedAtSource
    case accessLost
    case unknown
}

public enum ProtectedAction: String, Codable, CaseIterable, Hashable, Sendable {
    case login
    case observe
    case extract
    case navigate
    case click
    case scroll
    case fillNonsecret = "fill_nonsecret"
}

public struct AccountPolicy: Sendable, Equatable {
    public let id: UUID
    public let revision: UInt64
    public let source: AccountSource
    public let presence: SourcePresence
    public let lastObserved: Date?
    public let restrictionEvent: UUID?
    public let conflicted: Bool

    public init(id: UUID, revision: UInt64, source: AccountSource, presence: SourcePresence, lastObserved: Date?, restrictionEvent: UUID?, conflicted: Bool = false) {
        self.id = id
        self.revision = revision
        self.source = source
        self.presence = presence
        self.lastObserved = lastObserved
        self.restrictionEvent = restrictionEvent
        self.conflicted = conflicted
    }
}

public struct CatalogDisclosureGrant: Sendable {
    public let agent: UUID
    public let boot: UUID
    public let accounts: Set<UUID>
    public let expiresAt: Date

    public init(agent: UUID, boot: UUID, accounts: Set<UUID>, expiresAt: Date) {
        self.agent = agent
        self.boot = boot
        self.accounts = accounts
        self.expiresAt = expiresAt
    }
}

public struct AccountUseGrant: Sendable {
    public let agent: UUID
    public let boot: UUID
    public let account: UUID
    public let revision: UInt64
    public let origins: Set<String>
    public let actions: Set<ProtectedAction>
    public let expiresAt: Date
    public var retainedEvent: UUID?

    public init(agent: UUID, boot: UUID, account: UUID, revision: UInt64, origins: Set<String>, actions: Set<ProtectedAction>, expiresAt: Date, retainedEvent: UUID?) {
        self.agent = agent
        self.boot = boot
        self.account = account
        self.revision = revision
        self.origins = origins
        self.actions = actions
        self.expiresAt = expiresAt
        self.retainedEvent = retainedEvent
    }
}

public enum Authority {
    public static func canDisclose(account: UUID, agent: UUID, boot: UUID, grant: CatalogDisclosureGrant, now: Date) -> Bool {
        grant.agent == agent && grant.boot == boot && grant.expiresAt > now && grant.accounts.contains(account)
    }

    public static func canUse(state: AccountPolicy, grant: AccountUseGrant, agent: UUID, boot: UUID, origin: String, action: ProtectedAction, now: Date) -> Bool {
        guard !state.conflicted,
              grant.agent == agent,
              grant.boot == boot,
              grant.account == state.id,
              grant.revision == state.revision,
              grant.expiresAt > now,
              grant.origins.contains(origin),
              grant.actions.contains(action) else {
            return false
        }
        if state.source == .local {
            return state.presence == .present && state.restrictionEvent == nil
        }
        let stale = state.lastObserved.map { now.timeIntervalSince($0) > 24 * 60 * 60 } ?? true
        if state.presence != .present || stale || state.restrictionEvent != nil {
            guard let event = state.restrictionEvent else { return false }
            return grant.retainedEvent == event
        }
        return true
    }
}
