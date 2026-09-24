import Foundation
import RuntimeHost
import Virtualization
import ModelRelay
import EgressGateway
import PolicyCore
import BrokerHost

@MainActor
final class Probe: NSObject, VZVirtualMachineDelegate {
    private var vm: VZVirtualMachine?
    private var channels: InstanceChannels?
    private let authority = AccessCoordinator()
    private lazy var agentAPI = AgentAPI(access: authority)

    func start() throws {
        guard CommandLine.arguments.count == 8,
              ["agent", "browser"].contains(CommandLine.arguments[1]) else { throw VMConfigurationError.unsafeImage }
        let args = CommandLine.arguments
        let config = try RuntimeVMConfiguration.make(
            role: args[1] == "browser" ? .browser : .agent,
            kernel: URL(fileURLWithPath: args[2]), ramdisk: URL(fileURLWithPath: args[3]), image: URL(fileURLWithPath: args[4]),
            identity: VMImageIdentity(kernelSHA256: args[5], ramdiskSHA256: args[6], imageSHA256: args[7])
        )
        guard let loader = config.bootLoader as? VZLinuxBootLoader else { throw VMConfigurationError.unsafeImage }
        loader.commandLine = "console=hvc0 rdinit=/init panic=-1 shadow.role=\(args[1])"
        if ProcessInfo.processInfo.environment["SHADOW_LIVE_EGRESS"] == "1" { loader.commandLine += " shadow.egress=1" }
        let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
        serial.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: .standardOutput)
        config.serialPorts = [serial]
        try config.validate()
        let machine = VZVirtualMachine(configuration: config)
        vm = machine
        machine.delegate = self
        channels = try InstanceChannels(machine: machine, role: args[1] == "browser" ? .browser : .agent) { [weak self] connection, identity, channel in
            do {
                let transport = try FramedChannel(descriptor: connection.fileDescriptor, maximumBytes: channel == .agentBroker ? 65_536 : 4 * 1024 * 1024)
                let data = try transport.read(timeout: 3)
                guard let message = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw FrameError.invalidFrame }
                if message.count == 1, message["probe"] as? String == "role" {
                    try transport.write(JSONSerialization.data(withJSONObject: ["kind": "probe", "channel": channel.rawValue]))
                } else if channel == .agentBroker, let self {
                    // Probe-only empty synthetic vault. Production enrollment
                    // and unlocking come exclusively from native owner controls.
                    let caller = EnrolledAgent(id: identity.instance, boot: identity.boot, displayName: "Codex CLI synthetic VM")
                    self.authority.enroll(caller)
                    if !self.authority.unlocked { self.authority.openVault(accounts: []) }
                    Task { @MainActor in
                        let reply = await self.agentAPI.handle(data, caller: caller)
                        try? transport.write(reply)
                        self.channels?.close(connection)
                    }
                    return
                } else if channel == .agentModel {
                    try Self.syntheticModel(message, transport: transport)
                } else if channel == .browserEgress {
                    guard Set(message.keys) == ["host", "port"], let host = message["host"] as? String,
                          let port = message["port"] as? Int, port == 443 else { throw FrameError.invalidFrame }
                    let descriptor = connection.fileDescriptor
                    if let configured = ProcessInfo.processInfo.environment["SHADOW_FIXTURE_PORT"], let fixturePort = UInt16(configured) {
                        guard host == "app.shadow.test", fixturePort >= 1024 else { throw FrameError.invalidFrame }
                        Task { @MainActor in
                            _ = await Task.detached { try? FixtureTunnel.run(guest: descriptor, port: fixturePort, transport: transport) }.value
                            self?.channels?.close(connection)
                        }
                        return
                    }
                    let destination = try HTTPSDestination(host: host, port: 443)
                    let instance = identity.instance.uuidString, boot = identity.boot.uuidString
                    let lease = EgressLease(instance: instance, boot: boot, session: "synthetic-session", destinations: [try HTTPSDestination(host: "example.com", port: 443)], expiresAt: DeadlineClock.now + 10)
                    Task { @MainActor in
                        _ = await Task.detached {
                            try? Gateway.tunnel(guest: descriptor, destination: destination, lease: lease, instance: instance, boot: boot, session: "synthetic-session") {
                                try transport.write(JSONSerialization.data(withJSONObject: ["kind": "connected"]))
                            }
                        }.value
                        self?.channels?.close(connection)
                    }
                    return
                } else { throw FrameError.invalidFrame }
            } catch let error as RelayError {
                print("relay_probe_\(error.rawValue)")
            } catch let error as FrameError {
                print("relay_probe_\(error.rawValue)")
            } catch {
                print("relay_probe_rejected")
            }
            self?.channels?.close(connection)
        }
        machine.start { result in
            if case .failure = result { print("vm_start_failed"); exit(1) }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 60) {
            print("vm_probe_timeout")
            exit(2)
        }
    }

    private static func syntheticModel(_ message: [String: Any], transport: FramedChannel) throws {
        guard Set(message.keys) == ["method", "path", "headers", "body"],
              let method = message["method"] as? String, let path = message["path"] as? String,
              let headers = message["headers"] as? [String: String], let body = message["body"] as? [String: Any] else { throw FrameError.invalidFrame }
        _ = try CodexRelayPolicy(models: ["synthetic-model"]).request(
            method: method, path: path, headers: headers, body: JSONSerialization.data(withJSONObject: body),
            credential: CodexCredential(accessToken: "host-only-synthetic-canary", accountID: "host-only-synthetic-account", expiresAt: Date().addingTimeInterval(120))
        )
        let input = body["input"] as? [[String: Any]] ?? []
        let hasResult = input.contains { item in
            item["type"] as? String == "function_call_output" && (item["output"] as? String)?.contains("shadow-tool-ok") == true
        }
        let hasMCP = input.contains { item in
            guard item["type"] as? String == "function_call_output", let output = item["output"],
                  JSONSerialization.isValidJSONObject([output]), let encoded = try? JSONSerialization.data(withJSONObject: [output]) else { return false }
            return String(decoding: encoded, as: UTF8.self).contains("catalog_consent_required")
        }
        let item: [String: Any]
        if hasResult && hasMCP {
            item = ["type": "message", "id": "msg_synthetic", "role": "assistant", "status": "completed", "content": [["type": "output_text", "text": "shadow-client-ok", "annotations": []]]]
            print("CODEX_TOOL_RESULT=pass")
            print("CODEX_MCP_RESULT=pass")
        } else {
            let names = (body["tools"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
            let name = hasResult ? "shadow_vault_status" : names.contains("exec_command") ? "exec_command" : "shell_command"
            if hasResult {
                let namespace = (body["tools"] as? [[String: Any]] ?? []).first { $0["type"] as? String == "namespace" && $0["name"] as? String == "mcp__shadow" }
                guard (namespace?["tools"] as? [[String: Any]] ?? []).contains(where: { $0["name"] as? String == name }) else { throw FrameError.invalidFrame }
            } else { guard names.contains(name) else { throw FrameError.invalidFrame } }
            let arguments: [String: Any] = hasResult
                ? ["request_id": UUID().uuidString.lowercased(), "arguments": [String: String]()]
                : name == "exec_command" ? ["cmd": "printf shadow-tool-ok"] : ["command": "printf shadow-tool-ok"]
            let encoded = try JSONSerialization.data(withJSONObject: arguments)
            var call: [String: Any] = ["type": "function_call", "id": hasResult ? "fc_mcp" : "fc_synthetic", "call_id": hasResult ? "call_mcp" : "call_synthetic", "name": name, "arguments": String(decoding: encoded, as: UTF8.self), "status": "completed"]
            if hasResult { call["namespace"] = "mcp__shadow" }
            item = call
        }
        let response: [String: Any] = ["id": hasResult ? "resp_second" : "resp_first", "object": "response", "status": "completed", "output": [item], "usage": ["input_tokens": 1, "output_tokens": 1, "total_tokens": 2]]
        let events: [[String: Any]] = [
            ["type": "response.created", "response": ["id": "resp_synthetic", "status": "in_progress", "output": []]],
            ["type": "response.output_item.added", "output_index": 0, "item": item],
            ["type": "response.output_item.done", "output_index": 0, "item": item],
            ["type": "response.completed", "response": response],
        ]
        try transport.write(JSONSerialization.data(withJSONObject: ["kind": "start", "status": 200]))
        for event in events {
            let encoded = try JSONSerialization.data(withJSONObject: event)
            let sse = "event: \(event["type"]!)\ndata: \(String(decoding: encoded, as: UTF8.self))\n\n"
            try transport.write(JSONSerialization.data(withJSONObject: ["kind": "event", "data": sse]))
        }
        try transport.write(JSONSerialization.data(withJSONObject: ["kind": "end"]))
    }

    nonisolated func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        print("vm_guest_stopped")
        exit(0)
    }

    nonisolated func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
        print("vm_stopped_with_error")
        exit(1)
    }
}

let probe = Probe()
if CommandLine.arguments.dropFirst().first == "browser-session" {
    Task { @MainActor in
        do { try await SessionProbe.run(); print("BROWSER_SESSION=pass"); exit(0) }
        catch { print("BROWSER_SESSION=failed"); exit(1) }
    }
} else {
    do { try probe.start() } catch { print("vm_configuration_failed"); exit(1) }
}
RunLoop.main.run()
