import Foundation
import Security

public enum ReferenceError: Error {
    case randomUnavailable
    case capacityExceeded
}

/// Ephemeral references are never serialized to the policy ledger.
public struct ReferenceRegistry {
    public struct Resolved: Sendable {
        public let account: UUID
        public let revision: UInt64
        public let grant: UUID
    }
    private struct Binding {
        let account: UUID
        let revision: UInt64
        let agent: UUID
        let boot: UUID
        let grant: UUID
        let expiresAt: Date
        let deadline: TimeInterval
    }

    private var bindings: [String: Binding] = [:]

    public init() {}

    public mutating func mint(account: UUID, revision: UInt64, agent: UUID, boot: UUID, grant: UUID, expiresAt: Date) throws -> String {
        bindings = bindings.filter { $0.value.expiresAt > Date() && $0.value.deadline > DeadlineClock.now }
        guard bindings.count < 4096 else { throw ReferenceError.capacityExceeded }
        let token = try Self.randomToken()
        bindings[token] = Binding(account: account, revision: revision, agent: agent, boot: boot, grant: grant, expiresAt: expiresAt, deadline: DeadlineClock.now + min(300, max(0, expiresAt.timeIntervalSinceNow)))
        return token
    }

    public static func randomToken() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw ReferenceError.randomUnavailable
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    public func resolve(_ token: String, account: UUID, revision: UInt64, agent: UUID, boot: UUID, grant: UUID, now: Date) -> Bool {
        guard let binding = bindings[token] else { return false }
        return binding.account == account
            && binding.revision == revision
            && binding.agent == agent
            && binding.boot == boot
            && binding.grant == grant
            && binding.expiresAt > now
            && binding.deadline > DeadlineClock.now
    }

    public func lookup(_ token: String, agent: UUID, boot: UUID, now: Date) -> Resolved? {
        guard let binding = bindings[token], binding.agent == agent, binding.boot == boot,
              binding.expiresAt > now, binding.deadline > DeadlineClock.now else { return nil }
        return Resolved(account: binding.account, revision: binding.revision, grant: binding.grant)
    }

    public mutating func invalidate(grant: UUID) { bindings = bindings.filter { $0.value.grant != grant } }

    public mutating func invalidate(account: UUID) {
        bindings = bindings.filter { $0.value.account != account }
    }

    public mutating func invalidateAll() {
        bindings.removeAll(keepingCapacity: false)
    }
}
