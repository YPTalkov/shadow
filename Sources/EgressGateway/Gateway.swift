import Foundation
import Darwin
import PolicyCore

struct PinnedAddress: Sendable {
    let value: String
    let family: Int32
}

enum DestinationResolver {
    static func validate(_ addresses: [PinnedAddress]) throws -> [PinnedAddress] {
        guard !addresses.isEmpty, addresses.count <= 32, addresses.allSatisfy({ PublicAddress.isAllowed($0.value) }) else { throw EgressError.denied }
        return addresses
    }

    static func resolve(_ destination: HTTPSDestination) throws -> [PinnedAddress] {
        var hints = addrinfo()
        hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(destination.host, String(destination.port), &hints, &result) == 0 else { throw EgressError.unavailable }
        defer { if let result { freeaddrinfo(result) } }
        var addresses: [PinnedAddress] = []
        var cursor = result
        while let current = cursor {
            let info = current.pointee
            guard addresses.count < 32, info.ai_family == AF_INET || info.ai_family == AF_INET6 else { throw EgressError.denied }
            var name = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(info.ai_addr, info.ai_addrlen, &name, socklen_t(name.count), nil, 0, NI_NUMERICHOST) == 0 else { throw EgressError.unavailable }
            let numeric = String(decoding: name.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            addresses.append(PinnedAddress(value: numeric, family: info.ai_family))
            cursor = info.ai_next
        }
        return try validate(addresses).sorted { $0.family < $1.family }
    }
}

/// Run on a worker thread. TLS remains between the browser and the pinned destination.
public enum Gateway {
    public static func tunnel(guest: Int32, destination: HTTPSDestination, lease: EgressLease, instance: String, boot: String, session: String, connected: () throws -> Void) throws {
        let authorize = { try lease.check(instance: instance, boot: boot, session: session, destination: destination) }
        try authorize()
        let addresses = try DestinationResolver.resolve(destination)
        try authorize()
        let host = try connect(addresses: addresses, port: destination.port, authorize: authorize)
        defer {
            var abort = linger(l_onoff: 1, l_linger: 0)
            setsockopt(host, SOL_SOCKET, SO_LINGER, &abort, socklen_t(MemoryLayout<linger>.size))
            shutdown(host, SHUT_RDWR)
            Darwin.close(host)
        }
        try authorize()
        try connected()
        try forward(guest: guest, host: host, authorize: authorize)
    }

    private static func connect(addresses: [PinnedAddress], port: UInt16, authorize: () throws -> Void) throws -> Int32 {
        let deadline = DeadlineClock.now + 10
        for address in addresses {
            try authorize()
            let fd = socket(address.family, SOCK_STREAM, IPPROTO_TCP)
            guard fd >= 0 else { throw EgressError.unavailable }
            do {
                try nonblocking(fd)
                let result: Int32
                if address.family == AF_INET {
                    var target = sockaddr_in()
                    target.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    target.sin_family = sa_family_t(AF_INET)
                    target.sin_port = port.bigEndian
                    guard inet_pton(AF_INET, address.value, &target.sin_addr) == 1 else { throw EgressError.denied }
                    result = withUnsafePointer(to: &target) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
                } else {
                    var target = sockaddr_in6()
                    target.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                    target.sin6_family = sa_family_t(AF_INET6)
                    target.sin6_port = port.bigEndian
                    guard inet_pton(AF_INET6, address.value, &target.sin6_addr) == 1 else { throw EgressError.denied }
                    result = withUnsafePointer(to: &target) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
                }
                guard result == 0 || errno == EINPROGRESS else { throw EgressError.unavailable }
                while result != 0 {
                    try authorize()
                    guard DeadlineClock.now < deadline else { throw EgressError.unavailable }
                    var event = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                    let ready = poll(&event, 1, 100)
                    if ready == 0 || (ready < 0 && errno == EINTR) { continue }
                    var error: Int32 = 0
                    var length = socklen_t(MemoryLayout<Int32>.size)
                    guard ready > 0, getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error == 0 else { throw EgressError.unavailable }
                    break
                }
                try authorize()
                return fd
            } catch {
                Darwin.close(fd)
                if case EgressError.denied = error { throw error }
            }
        }
        throw EgressError.unavailable
    }

    package static func forward(guest: Int32, host: Int32, authorize: () throws -> Void) throws {
        try nonblocking(guest)
        try nonblocking(host)
        var toGuest = Data()
        var toHost = Data()
        var guestEOF = false
        var hostEOF = false
        var total = 0
        while true {
            try authorize()
            if (guestEOF && toHost.isEmpty) || (hostEOF && toGuest.isEmpty) { return }
            let guestEvents = (toHost.isEmpty && !guestEOF ? POLLIN : 0) | (!toGuest.isEmpty ? POLLOUT : 0)
            let hostEvents = (toGuest.isEmpty && !hostEOF ? POLLIN : 0) | (!toHost.isEmpty ? POLLOUT : 0)
            var events = [pollfd(fd: guest, events: Int16(guestEvents), revents: 0), pollfd(fd: host, events: Int16(hostEvents), revents: 0)]
            let ready = poll(&events, 2, 100)
            if ready == 0 || (ready < 0 && errno == EINTR) { continue }
            guard ready > 0 else { throw EgressError.unavailable }
            try authorize()
            for index in 0...1 {
                try authorize()
                let event = events[index]
                guard event.revents & Int16(POLLERR | POLLNVAL) == 0 else { throw EgressError.unavailable }
                if event.revents & Int16(POLLOUT) != 0 {
                    if index == 0 { try drain(&toGuest, to: guest) } else { try drain(&toHost, to: host) }
                }
                if event.events & Int16(POLLIN) != 0 && event.revents & Int16(POLLIN | POLLHUP) != 0 {
                    var bytes = [UInt8](repeating: 0, count: 65_536)
                    let count = Darwin.read(event.fd, &bytes, bytes.count)
                    if count < 0 && [EAGAIN, EINTR].contains(errno) { continue }
                    guard count >= 0 else { throw EgressError.unavailable }
                    if count == 0 {
                        if index == 0 { guestEOF = true } else { hostEOF = true }
                    } else {
                        total += count
                        guard total <= 16 * 1024 * 1024 else { throw EgressError.limitExceeded }
                        if index == 0 { toHost.append(contentsOf: bytes.prefix(count)) } else { toGuest.append(contentsOf: bytes.prefix(count)) }
                    }
                }
            }
        }
    }

    private static func drain(_ buffer: inout Data, to fd: Int32) throws {
        let count = buffer.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, buffer.count) }
        if count < 0 && [EAGAIN, EINTR].contains(errno) { return }
        guard count > 0 else { throw EgressError.unavailable }
        buffer.removeFirst(count)
    }

    private static func nonblocking(_ fd: Int32) throws {
        var enabled: Int32 = 1
        guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw EgressError.unavailable }
    }
}
