import Foundation
import Darwin
import PolicyCore

public enum FrameError: String, Error, Sendable {
    case invalidFrame = "invalid_frame"
    case closed = "channel_closed"
    case timeout = "channel_timeout"
}

public final class FramedChannel: @unchecked Sendable {
    private let descriptor: Int32
    private let maximumBytes: Int
    private let readLock = NSLock()
    private let writeLock = NSLock()

    public init(descriptor: Int32, maximumBytes: Int = 65_536) throws {
        guard (1...4_194_304).contains(maximumBytes) else { throw FrameError.invalidFrame }
        let copy = dup(descriptor)
        guard copy >= 0 else { throw FrameError.closed }
        var enabled: Int32 = 1
        guard fcntl(copy, F_SETFL, fcntl(copy, F_GETFL) | O_NONBLOCK) == 0,
              fcntl(copy, F_SETFD, FD_CLOEXEC) == 0,
              setsockopt(copy, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            Darwin.close(copy)
            throw FrameError.closed
        }
        self.descriptor = copy
        self.maximumBytes = maximumBytes
    }

    deinit { Darwin.close(descriptor) }

    public func invalidate() { shutdown(descriptor, SHUT_RDWR) }

    public func read(timeout: TimeInterval = 5) throws -> Data {
        guard timeout.isFinite, timeout > 0 else { throw FrameError.timeout }
        readLock.lock()
        defer { readLock.unlock() }
        let deadline = DeadlineClock.now + min(timeout, 180)
        let header = try readExact(4, deadline: deadline)
        let count = header.reduce(0) { ($0 << 8) | Int($1) }
        guard (1...maximumBytes).contains(count) else { throw FrameError.invalidFrame }
        return try readExact(count, deadline: deadline)
    }

    public func write(_ data: Data, timeout: TimeInterval = 5) throws {
        guard timeout.isFinite, timeout > 0 else { throw FrameError.timeout }
        guard (1...maximumBytes).contains(data.count) else { throw FrameError.invalidFrame }
        writeLock.lock()
        defer { writeLock.unlock() }
        let deadline = DeadlineClock.now + min(timeout, 180)
        let length = UInt32(data.count)
        var frame = Data([UInt8(length >> 24), UInt8((length >> 16) & 255), UInt8((length >> 8) & 255), UInt8(length & 255)])
        frame.append(data)
        var offset = 0
        while offset < frame.count {
            try ready(Int16(POLLOUT), deadline: deadline)
            let count = frame.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress!.advanced(by: offset), frame.count - offset) }
            if count < 0 && [EAGAIN, EINTR].contains(errno) { continue }
            guard count > 0 else { throw FrameError.closed }
            offset += count
        }
    }

    private func readExact(_ length: Int, deadline: TimeInterval) throws -> Data {
        var data = Data(count: length)
        var offset = 0
        while offset < length {
            try ready(Int16(POLLIN), deadline: deadline)
            let count = data.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress!.advanced(by: offset), length - offset) }
            if count < 0 && [EAGAIN, EINTR].contains(errno) { continue }
            guard count > 0 else { throw FrameError.closed }
            offset += count
        }
        return data
    }

    private func ready(_ event: Int16, deadline: TimeInterval) throws {
        while true {
            let remaining = deadline - DeadlineClock.now
            guard remaining > 0 else { throw FrameError.timeout }
            var request = pollfd(fd: descriptor, events: event, revents: 0)
            let result = poll(&request, 1, Int32(min(remaining * 1000 + 1, 100)))
            if result < 0 && errno == EINTR { continue }
            if result == 0 { continue }
            guard DeadlineClock.now < deadline else { throw FrameError.timeout }
            guard result > 0, request.revents & event != 0 else { throw FrameError.closed }
            return
        }
    }
}
