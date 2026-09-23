import XCTest
@testable import PolicyCore

final class ProtocolVersionTests: XCTestCase {
    func testRejectsDifferentMajorVersion() {
        XCTAssertFalse(ProtocolVersion(major: 1, minor: 0).accepts(.init(major: 2, minor: 0)))
        XCTAssertTrue(ProtocolVersion(major: 1, minor: 0).accepts(.init(major: 1, minor: 3)))
    }
}
