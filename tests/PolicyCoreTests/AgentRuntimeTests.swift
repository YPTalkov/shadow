import Foundation
import Testing
@testable import BrokerHost
import ModelRelay
import RuntimeHost
import PolicyCore

@Test func agentRelayHeartbeatCannotReviveExpiredAuthority() throws {
    let lease = RelayLease(instance: "agent", boot: "boot", expiresAt: 100, maximumRequests: 2, maximumInputBytes: 100,
                           heartbeatRequired: true, now: 1)
    try lease.renew(sequence: 1, now: 2)
    try lease.check(instance: "agent", boot: "boot", now: 11)
    #expect(throws: RelayError.self) { try lease.renew(sequence: 2, now: 12) }
    #expect(throws: RelayError.self) { try lease.check(instance: "agent", boot: "boot", now: 12) }
}

@Test func agentRuntimeAcceptsOnlyBoundedPlainMessages() throws {
    var output = AgentTaskOutput()
    _ = try output.accept(Data(#"{"kind":"message","text":"result"}"#.utf8))
    #expect(output.text == "result")
    #expect(throws: (any Error).self) { try output.accept(Data(#"{"kind":"message","text":"x","approve":true}"#.utf8)) }
    #expect(throws: (any Error).self) { try output.accept(Data(#"{"kind":"message","text":"x","text":"y"}"#.utf8)) }
    for _ in 0..<3 { _ = try output.accept(JSONValue.object(["kind": .string("message"), "text": .string(String(repeating: "x", count: 8192))]).encoded()) }
    #expect(throws: (any Error).self) { try output.accept(JSONValue.object(["kind": .string("message"), "text": .string(String(repeating: "x", count: 8192))]).encoded()) }
}

@Test @MainActor func agentRuntimeRejectsInvalidNativeTaskBeforeBoot() async {
    let file = URL(fileURLWithPath: "/nonexistent-shadow-test-image")
    let image = AgentVMImage(kernel: file, ramdisk: file, disk: file,
                             identity: VMImageIdentity(kernelSHA256: "", ramdiskSHA256: "", imageSHA256: ""))
    let access = AccessCoordinator()
    let runtime = AgentRuntime(image: image, access: access, api: AgentAPI(access: access), authentication: CodexAuthentication(vaultID: "synthetic-unused"))
    access.openVault(accounts: [])
    for (prompt, model, limit) in [("", "gpt-6-sol", 30), ("ok", "unknown", 30), ("ok", "gpt-6-sol", 0),
                                   ("ok", "gpt-6-sol", 121), (String(repeating: "x", count: 8193), "gpt-6-sol", 30)] {
        await runtime.start(prompt: prompt, model: model, maximumRequests: limit)
        #expect(runtime.state == .idle)
        #expect(access.agents.isEmpty)
    }
}
