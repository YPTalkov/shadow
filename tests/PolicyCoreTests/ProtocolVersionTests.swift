import Testing
@testable import PolicyCore

@Test func rejectsDifferentMajorVersion() {
    #expect(!ProtocolVersion(major: 1, minor: 0).accepts(.init(major: 2, minor: 0)))
    #expect(ProtocolVersion(major: 1, minor: 0).accepts(.init(major: 1, minor: 3)))
}
