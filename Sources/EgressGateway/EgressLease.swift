import Foundation
import PolicyCore

public final class EgressLease: @unchecked Sendable {
    private let lock = NSLock()
    private let instance: String
    private let boot: String
    private let session: String
    private let destinations: Set<HTTPSDestination>
    private var expiresAt: TimeInterval
    private var sequence = 0
    private var revoked = false

    public init(instance: String, boot: String, session: String, destinations: Set<HTTPSDestination>, expiresAt: TimeInterval) {
        self.instance = instance
        self.boot = boot
        self.session = session
        self.destinations = destinations
        self.expiresAt = expiresAt
    }

    public func check(instance: String, boot: String, session: String, destination: HTTPSDestination, now: TimeInterval = DeadlineClock.now) throws {
        lock.lock()
        defer { lock.unlock() }
        if now >= expiresAt { revoked = true }
        guard !revoked, now.isFinite, now < expiresAt,
              instance == self.instance, boot == self.boot, session == self.session,
              destinations.contains(destination) else { throw EgressError.denied }
    }

    public func renew(sequence: Int, ttl: TimeInterval = 10, now: TimeInterval = DeadlineClock.now) throws {
        lock.lock()
        defer { lock.unlock() }
        if now >= expiresAt { revoked = true }
        guard !revoked, now.isFinite, sequence > self.sequence,
              ttl.isFinite, ttl > 0, ttl <= 10 else { throw EgressError.denied }
        self.sequence = sequence
        expiresAt = now + ttl
    }

    public func revoke() {
        lock.lock()
        defer { lock.unlock() }
        revoked = true
    }
}
