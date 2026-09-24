import Foundation
import Darwin
import PolicyCore
import EgressGateway
import RuntimeHost

/// Synthetic test executable only. Never linked into the owner application.
/// The only mapping is app.shadow.test:443 to the runner's loopback TLS fixture.
enum FixtureTunnel {
    static func run(guest: Int32, port: UInt16, transport: FramedChannel) throws {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0, port >= 1024 else { throw FrameError.invalidFrame }
        defer { shutdown(fd, SHUT_RDWR); Darwin.close(fd) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard connected == 0 else { throw FrameError.invalidFrame }
        let deadline = DeadlineClock.now + 10
        try transport.write(JSONSerialization.data(withJSONObject: ["kind": "connected"]))
        try Gateway.forward(guest: guest, host: fd) {
            guard DeadlineClock.now < deadline else { throw EgressError.denied }
        }
    }
}
