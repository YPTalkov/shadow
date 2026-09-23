public struct ProtocolVersion: Equatable, Sendable {
    public let major: UInt16
    public let minor: UInt16

    public init(major: UInt16, minor: UInt16) {
        self.major = major
        self.minor = minor
    }

    public func accepts(_ peer: ProtocolVersion) -> Bool {
        major == peer.major
    }
}
