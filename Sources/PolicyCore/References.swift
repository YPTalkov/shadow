import Foundation
import Security

public enum ReferenceError: Error {
    case randomUnavailable
}

/// Ephemeral references are never serialized to the policy ledger.
public struct ReferenceRegistry {
    private struct Binding {
        let account: UUID
        let revision: UInt64
        let agent: UUID
        let boot: UUID
        let grant: UUID
        let expiresAt: Date
    }

    private var bindings: [String: Binding] = [:]

    public init() {}

    public mutating func mint(account: UUID, revision: UInt64, agent: UUID, boot: UUID, grant: UUID, expiresAt: Date) throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw ReferenceError.randomUnavailable
        }
        let token = bytes.map { String(format: "%02x", $0) }.joined()
        bindings[token] = Binding(account: account, revision: revision, agent: agent, boot: boot, grant: grant, expiresAt: expiresAt)
        return token
    }

    public func resolve(_ token: String, account: UUID, revision: UInt64, agent: UUID, boot: UUID, grant: UUID, now: Date) -> Bool {
        guard let binding = bindings[token] else { return false }
        return binding.account == account
            && binding.revision == revision
            && binding.agent == agent
            && binding.boot == boot
            && binding.grant == grant
            && binding.expiresAt > now
    }

    public mutating func invalidate(account: UUID) {
        bindings = bindings.filter { $0.value.account != account }
    }

    public mutating func invalidateAll() {
        bindings.removeAll(keepingCapacity: false)
    }
}
