import Foundation

/// Identity and deadlines are supplied by the supervisor, never a guest envelope.
public final class RelayLease: @unchecked Sendable {
    private let lock = NSLock()
    private let instance: String
    private let boot: String
    private let expiresAt: TimeInterval
    private let maximumRequests: Int
    private let maximumInputBytes: Int
    private var requests = 0
    private var inputBytes = 0
    private var revoked = false

    public init(instance: String, boot: String, expiresAt: TimeInterval, maximumRequests: Int, maximumInputBytes: Int) {
        self.instance = instance
        self.boot = boot
        self.expiresAt = expiresAt
        self.maximumRequests = max(0, maximumRequests)
        self.maximumInputBytes = max(0, maximumInputBytes)
    }

    public func reserve(instance: String, boot: String, bytes: Int, now: TimeInterval = ProcessInfo.processInfo.systemUptime) throws {
        lock.lock()
        defer { lock.unlock() }
        try valid(instance: instance, boot: boot, now: now)
        guard bytes > 0, requests < maximumRequests, bytes <= maximumInputBytes - inputBytes else { throw RelayError.limitExceeded }
        requests += 1
        inputBytes += bytes
    }

    public func check(instance: String, boot: String, now: TimeInterval = ProcessInfo.processInfo.systemUptime) throws {
        lock.lock()
        defer { lock.unlock() }
        try valid(instance: instance, boot: boot, now: now)
    }

    public func revoke() {
        lock.lock()
        defer { lock.unlock() }
        revoked = true
    }

    private func valid(instance: String, boot: String, now: TimeInterval) throws {
        guard !revoked, now.isFinite, now < expiresAt, instance == self.instance, boot == self.boot else { throw RelayError.denied }
    }
}
