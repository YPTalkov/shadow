import Foundation
import PolicyCore

public final class EgressLease: @unchecked Sendable {
    private let lock = NSLock()
    private let instance: String
    private let boot: String
    private let session: String
    private let destinations: Set<HTTPSDestination>
    private let expiresAt: TimeInterval
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
        guard !revoked, now.isFinite, now < expiresAt,
              instance == self.instance, boot == self.boot, session == self.session,
              destinations.contains(destination) else { throw EgressError.denied }
    }

    public func revoke() {
        lock.lock()
        defer { lock.unlock() }
        revoked = true
    }
}
