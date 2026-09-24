import Foundation
import Darwin

public enum EgressError: String, Error, Sendable {
    case denied = "egress_denied"
    case unavailable = "destination_unavailable"
    case limitExceeded = "egress_limit_exceeded"
}

public struct HTTPSDestination: Hashable, Sendable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) throws {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        var numeric = in_addr()
        guard port == 443, host.utf8.count <= 253, labels.count >= 2,
              inet_aton(host, &numeric) == 0,
              labels.allSatisfy({ label in
                  !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
                  label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
              }),
              let last = labels.last, last.utf8.contains(where: { (97...122).contains($0) }),
              !["local", "localhost", "internal", "test", "invalid", "onion"].contains(last),
              !host.hasSuffix(".home.arpa") else { throw EgressError.denied }
        self.host = host
        self.port = port
    }
}

public enum PublicAddress {
    public static func isAllowed(_ address: String) -> Bool {
        var ipv4 = in_addr()
        if inet_pton(AF_INET, address, &ipv4) == 1 {
            let value = UInt32(bigEndian: ipv4.s_addr)
            let denied: [(UInt32, UInt32)] = [
                (0x00000000, 8), (0x0a000000, 8), (0x64400000, 10), (0x7f000000, 8),
                (0xa9fe0000, 16), (0xac100000, 12), (0xc0000000, 24), (0xc0000200, 24),
                (0xc0586300, 24), (0xc0a80000, 16), (0xc6120000, 15), (0xc6336400, 24),
                (0xcb007100, 24), (0xe0000000, 4), (0xf0000000, 4),
            ]
            return !denied.contains { prefix, bits in value >> (32 - bits) == prefix >> (32 - bits) }
        }
        var ipv6 = in6_addr()
        guard inet_pton(AF_INET6, address, &ipv6) == 1 else { return false }
        let bytes = withUnsafeBytes(of: ipv6) { Array($0) }
        guard bytes[0] & 0xe0 == 0x20 else { return false }
        // Conservative exclusions cover IETF protocol assignments, documentation and 6to4.
        if bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] < 2 { return false }
        if bytes[0...3] == [0x20, 0x01, 0x0d, 0xb8] { return false }
        if bytes[0...1] == [0x20, 0x02] { return false }
        if bytes[0] == 0x3f && bytes[1] == 0xff && bytes[2] & 0xf0 == 0 { return false }
        return true
    }
}
