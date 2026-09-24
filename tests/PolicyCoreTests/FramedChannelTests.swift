import Foundation
import Darwin
import Testing
@testable import RuntimeHost

@Test func framesRejectOversizeTimeoutAndTruncation() throws {
    var descriptors: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0)
    defer { descriptors.forEach { Darwin.close($0) } }
    let sender = try FramedChannel(descriptor: descriptors[0], maximumBytes: 32)
    let receiver = try FramedChannel(descriptor: descriptors[1], maximumBytes: 16)
    try sender.write(Data("synthetic-frame".utf8))
    #expect(try receiver.read() == Data("synthetic-frame".utf8))
    #expect(throws: FrameError.timeout) { _ = try receiver.read(timeout: 0.01) }
    try sender.write(Data(repeating: 0, count: 17))
    #expect(throws: FrameError.invalidFrame) { _ = try receiver.read() }
    #expect(throws: FrameError.invalidFrame) { try sender.write(Data(repeating: 0, count: 33)) }
    shutdown(descriptors[0], SHUT_RDWR)
    #expect(throws: FrameError.closed) { try sender.write(Data([1])) }
}
