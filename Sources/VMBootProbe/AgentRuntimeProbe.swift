import Foundation
import BrokerHost
import ModelRelay
import RuntimeHost
import PolicyCore

@MainActor enum AgentRuntimeProbe {
    static func run() async throws {
        guard (3...4).contains(CommandLine.arguments.count) else { throw AgentAPIError.unavailable }
        let model = CommandLine.arguments.count == 4 ? CommandLine.arguments[3] : "gpt-6-sol"
        guard AgentRuntime.models.contains(model) else { throw AgentAPIError.unavailable }
        let image = try AgentVMImage.packaged(at: URL(fileURLWithPath: CommandLine.arguments[2]))
        let access = AccessCoordinator()
        let api = AgentAPI(access: access)
        let fixture = AgentProbeModel()
        let runtime = AgentRuntime(image: image, access: access, api: api) { request, send in
            try await fixture.respond(request, send: send)
        }
        await runtime.start(prompt: "Do not run while locked", model: model)
        guard runtime.state == .idle else { throw AgentAPIError.unavailable }
        access.openVault(accounts: [])
        await runtime.start(prompt: "Run printf shadow-tool-ok once, call Shadow vault status through MCP, then say shadow-client-ok.", model: model)
        let deadline = DeadlineClock.now + 55
        while runtime.active, DeadlineClock.now < deadline { try await Task.sleep(for: .milliseconds(100)) }
        guard runtime.state == .succeeded, runtime.output == "shadow-client-ok", access.agents.isEmpty, access.grants.isEmpty,
              await fixture.verified else {
            print("AGENT_TASK_STATE=\(runtime.state)")
            runtime.stop(); throw AgentAPIError.unavailable
        }
        print("AGENT_CODEX_SHELL_MCP=pass")
        print("AGENT_TASK_TEARDOWN=pass")
        await fixture.holdNextTask()
        await runtime.start(prompt: "Check status", model: model)
        let lockDeadline = DeadlineClock.now + 30
        while runtime.active, !(await fixture.holding), DeadlineClock.now < lockDeadline { try await Task.sleep(for: .milliseconds(50)) }
        guard runtime.state == .running, await fixture.holding, access.agents.count == 1 else { throw AgentAPIError.unavailable }
        let old = access.agents[0]
        _ = try access.requestCatalog(caller: old, requestID: UUID())
        access.lock()
        guard runtime.state == .stopped, runtime.output.isEmpty, access.agents.isEmpty, access.pending.isEmpty else { throw AgentAPIError.unavailable }
        access.openVault(accounts: [])
        let request = try JSONValue.object(["protocol_major": .integer(1), "request_id": .string(UUID().uuidString), "operation": .string("vault.status"), "arguments": .object([:])]).encoded()
        let reply = try BoundedJSON.parse(await api.handle(request, caller: old))
        guard reply["error"]?["code"] == .string("caller_unavailable") else { throw AgentAPIError.unavailable }
        print("AGENT_LOCK_REJECTS_OLD_BOOT=pass")
    }
}

private actor AgentProbeModel {
    private(set) var verified = false
    private(set) var holding = false
    private var shouldHold = false
    private var requests = 0

    func holdNextTask() { shouldHold = true }

    func respond(_ request: AgentModelRequest, send: @escaping @Sendable (Data) async throws -> Void) async throws {
        if shouldHold {
            holding = true
            while true {
                try request.lease.check(instance: request.instance, boot: request.boot)
                try await Task.sleep(for: .milliseconds(100))
            }
        }
        requests += 1
        guard requests <= 4 else { throw AgentAPIError.unavailable }
        _ = try CodexRelayPolicy(models: [request.model]).request(method: request.method, path: request.path, headers: request.headers,
            body: request.body, credential: CodexCredential(accessToken: "host-only-synthetic-canary", accountID: "host-only-synthetic-account", expiresAt: Date().addingTimeInterval(120)))
        try request.lease.reserve(instance: request.instance, boot: request.boot, bytes: request.body.count)
        guard let body = try JSONSerialization.jsonObject(with: request.body) as? [String: Any] else { throw AgentAPIError.invalidRequest }
        let input = body["input"] as? [[String: Any]] ?? []
        let results: [String] = input.compactMap { item in
            guard ["function_call_output", "custom_tool_call_output"].contains(item["type"] as? String ?? ""), let output = item["output"],
                  JSONSerialization.isValidJSONObject([output]), let data = try? JSONSerialization.data(withJSONObject: [output]) else { return nil }
            return String(decoding: data, as: UTF8.self)
        }
        let hasResult = results.contains { $0.contains("shadow-tool-ok") }
        let hasMCP = results.contains { $0.contains("catalog_consent_required") }
        let item: [String: Any]
        if hasResult && hasMCP {
            verified = true
            item = ["type": "message", "id": "msg_synthetic", "role": "assistant", "status": "completed", "content": [["type": "output_text", "text": "shadow-client-ok", "annotations": []]]]
        } else {
            let tools = body["tools"] as? [[String: Any]] ?? input.first(where: { $0["type"] as? String == "additional_tools" })?["tools"] as? [[String: Any]] ?? []
            let names = tools.compactMap { $0["name"] as? String }
            if let functions = tools.first(where: { $0["name"] as? String == "functions" }),
               (functions["tools"] as? [[String: Any]] ?? []).contains(where: { $0["name"] as? String == "exec" && $0["type"] as? String == "custom" }) {
                let code = "text(await tools.exec_command({cmd: 'printf shadow-tool-ok'})); text(await tools.mcp__shadow__shadow_vault_status({request_id: '\(UUID().uuidString.lowercased())', arguments: {}}));"
                item = ["type": "custom_tool_call", "id": "ctc_synthetic", "call_id": "call_code", "name": "exec", "namespace": "functions", "input": code, "status": "completed"]
            } else {
                let name = hasResult ? "shadow_vault_status" : names.contains("exec_command") ? "exec_command" : "shell_command"
                if hasResult {
                    let namespace = tools.first { $0["type"] as? String == "namespace" && $0["name"] as? String == "mcp__shadow" }
                    guard (namespace?["tools"] as? [[String: Any]] ?? []).contains(where: { $0["name"] as? String == name }) else { throw AgentAPIError.unavailable }
                } else { guard names.contains(name) else { throw AgentAPIError.unavailable } }
                let arguments: [String: Any] = hasResult ? ["request_id": UUID().uuidString.lowercased(), "arguments": [String: String]()]
                    : name == "exec_command" ? ["cmd": "printf shadow-tool-ok"] : ["command": "printf shadow-tool-ok"]
                var call: [String: Any] = ["type": "function_call", "id": hasResult ? "fc_mcp" : "fc_synthetic", "call_id": hasResult ? "call_mcp" : "call_synthetic", "name": name,
                                          "arguments": String(decoding: try JSONSerialization.data(withJSONObject: arguments), as: UTF8.self), "status": "completed"]
                if hasResult { call["namespace"] = "mcp__shadow" }
                item = call
            }
        }
        let response: [String: Any] = ["id": "resp_synthetic", "object": "response", "status": "completed", "output": [item], "usage": ["input_tokens": 1, "output_tokens": 1, "total_tokens": 2]]
        let events: [[String: Any]] = [
            ["type": "response.created", "response": ["id": "resp_synthetic", "status": "in_progress", "output": []]],
            ["type": "response.output_item.added", "output_index": 0, "item": item],
            ["type": "response.output_item.done", "output_index": 0, "item": item],
            ["type": "response.completed", "response": response],
        ]
        for event in events {
            let encoded = try JSONSerialization.data(withJSONObject: event)
            try await send(Data("event: \(event["type"]!)\ndata: \(String(decoding: encoded, as: UTF8.self))\n\n".utf8))
        }
    }
}
