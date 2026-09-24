import Foundation
import Testing
import Darwin
import PolicyCore
@testable import EgressGateway

@Test func renewableEgressCannotReviveExpiredOrRevokedAuthority() throws {
    let destination = try HTTPSDestination(host: "example.com", port: 443)
    let lease = EgressLease(instance: "vm", boot: "boot", session: "session", destinations: [destination], expiresAt: 20)
    try lease.renew(sequence: 1, ttl: 10, now: 15)
    #expect(throws: EgressError.denied) { try lease.renew(sequence: 1, ttl: 10, now: 16) }
    #expect(throws: EgressError.denied) { try lease.renew(sequence: 2, ttl: 11, now: 16) }
    try lease.check(instance: "vm", boot: "boot", session: "session", destination: destination, now: 24)
    #expect(throws: EgressError.denied) { try lease.renew(sequence: 2, ttl: 10, now: 25) }
    #expect(throws: EgressError.denied) { try lease.renew(sequence: 3, ttl: 10, now: 15) }
}

@Test func egressRejectsSpecialAndAmbiguousAddresses() throws {
    for address in ["0.0.0.0", "10.1.2.3", "100.64.1.1", "127.0.0.1", "169.254.169.254", "172.31.255.255", "192.168.1.1", "192.0.0.8", "192.0.2.1", "192.88.99.1", "198.18.0.1", "198.51.100.2", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "2002:7f00:1::", "3fff::1"] {
        #expect(!PublicAddress.isAllowed(address), "Special address accepted")
    }
    for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"] {
        #expect(PublicAddress.isAllowed(address))
    }
    for host in ["127.0.0.1", "2130706433", "0x7f000001", "0x7f.0x0.0x0.0x1", "[::1]", "example.com@other.com", "example.com:443", "example.com.", "example.com/path", "a..com", "EXAMPLE.com", "localhost", "a.local", "example.com\r\nHost: other.com"] {
        #expect(throws: EgressError.denied) { _ = try HTTPSDestination(host: host, port: 443) }
    }
    #expect(throws: EgressError.denied) { _ = try HTTPSDestination(host: "example.com", port: 80) }
    #expect(try HTTPSDestination(host: "example.com", port: 443).host == "example.com")
}

@Test func mixedPublicAndPrivateDNSAnswerFailsClosed() throws {
    #expect(throws: EgressError.denied) {
        _ = try DestinationResolver.validate([PinnedAddress(value: "1.1.1.1", family: AF_INET), PinnedAddress(value: "127.0.0.1", family: AF_INET)])
    }
    #expect(throws: EgressError.denied) { _ = try DestinationResolver.validate([]) }
}

@Test func activeTunnelStopsOnRevocation() async throws {
    var guest: [Int32] = [-1, -1]
    var host: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &guest) == 0)
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &host) == 0)
    defer { (guest + host).forEach { Darwin.close($0) } }
    let destination = try HTTPSDestination(host: "example.com", port: 443)
    let lease = EgressLease(instance: "vm", boot: "boot", session: "session", destinations: [destination], expiresAt: DeadlineClock.now + 10)
    let guestFD = guest[1], hostFD = host[0]
    let (started, signalStarted) = AsyncStream<Void>.makeStream()
    let task = Task.detached {
        signalStarted.yield()
        signalStarted.finish()
        do {
            try Gateway.forward(guest: guestFD, host: hostFD) {
                try lease.check(instance: "vm", boot: "boot", session: "session", destination: destination)
            }
        } catch EgressError.denied { return (denied: true, stoppedAt: DeadlineClock.now) }
        catch { return (denied: false, stoppedAt: DeadlineClock.now) }
        return (denied: false, stoppedAt: DeadlineClock.now)
    }
    // Fixture startup is not the revocation interval. Let the forwarding task
    // start before blocking a cooperative worker in the socket handshake.
    for await _ in started {}
    let guestHandle = FileHandle(fileDescriptor: guest[0], closeOnDealloc: false)
    let hostHandle = FileHandle(fileDescriptor: host[1], closeOnDealloc: false)
    do {
        try guestHandle.write(contentsOf: Data("synthetic-request".utf8))
        var ready = pollfd(fd: host[1], events: Int16(POLLIN), revents: 0)
        try #require(poll(&ready, 1, 1000) > 0)
        #expect(try hostHandle.read(upToCount: 17) == Data("synthetic-request".utf8))
        try hostHandle.write(contentsOf: Data("synthetic-response".utf8))
        ready = pollfd(fd: guest[0], events: Int16(POLLIN), revents: 0)
        try #require(poll(&ready, 1, 1000) > 0)
        #expect(try guestHandle.read(upToCount: 18) == Data("synthetic-response".utf8))
    } catch {
        lease.revoke()
        _ = await task.value
        throw error
    }
    let revokedAt = DeadlineClock.now
    lease.revoke()
    let result = await task.value
    #expect(result.denied)
    // Measure the forwarding thread's exit, excluding time spent waiting for
    // this test task to be scheduled again on a busy runner.
    #expect(result.stoppedAt >= revokedAt)
    #expect(result.stoppedAt - revokedAt < 1)
    try guestHandle.write(contentsOf: Data("after-revocation".utf8))
    var ready = pollfd(fd: host[1], events: Int16(POLLIN), revents: 0)
    #expect(poll(&ready, 1, 100) == 0)
}

@Test func idleTunnelExpiresWithoutGuestTraffic() throws {
    var guest: [Int32] = [-1, -1]
    var host: [Int32] = [-1, -1]
    try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &guest) == 0)
    try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &host) == 0)
    defer { (guest + host).forEach { Darwin.close($0) } }
    let destination = try HTTPSDestination(host: "example.com", port: 443)
    let started = DeadlineClock.now
    let lease = EgressLease(instance: "vm", boot: "boot", session: "session", destinations: [destination], expiresAt: started + 0.03)
    #expect(throws: EgressError.denied) {
        try Gateway.forward(guest: guest[1], host: host[0]) {
            try lease.check(instance: "vm", boot: "boot", session: "session", destination: destination)
        }
    }
    #expect(DeadlineClock.now - started < 1)
}

@Test func egressLeaseBindsSessionAndExpires() throws {
    let destination = try HTTPSDestination(host: "example.com", port: 443)
    let lease = EgressLease(instance: "vm", boot: "boot", session: "session", destinations: [destination], expiresAt: 20)
    try lease.check(instance: "vm", boot: "boot", session: "session", destination: destination, now: 10)
    #expect(throws: EgressError.denied) { try lease.check(instance: "vm", boot: "other", session: "session", destination: destination, now: 10) }
    #expect(throws: EgressError.denied) { try lease.check(instance: "vm", boot: "boot", session: "other", destination: destination, now: 10) }
    #expect(throws: EgressError.denied) { try lease.check(instance: "vm", boot: "boot", session: "session", destination: destination, now: 20) }
    #expect(throws: EgressError.denied) { try lease.check(instance: "vm", boot: "boot", session: "session", destination: HTTPSDestination(host: "other.com", port: 443), now: 10) }
    lease.revoke()
    #expect(throws: EgressError.denied) { try lease.check(instance: "vm", boot: "boot", session: "session", destination: destination, now: 10) }
}
