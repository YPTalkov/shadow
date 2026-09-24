import Foundation

/// Only text and guest-executed tool definitions cross the model boundary.
/// Hosted tools and media/file fetches would turn it into a network proxy.
enum RelayInputPolicy {
    static func accepts(_ request: [String: Any]) -> Bool {
        guard let input = request["input"] as? [[String: Any]], input.count <= 4096,
              input.allSatisfy(item) else { return false }
        if let tools = request["tools"], !toolList(tools) { return false }
        return true
    }

    private static func toolList(_ value: Any, depth: Int = 0) -> Bool {
        guard depth < 4, let tools = value as? [[String: Any]], tools.count <= 256 else { return false }
        return tools.allSatisfy { tool in
            switch tool["type"] as? String {
            case "function": return Set(tool.keys).isSubset(of: ["type", "name", "description", "parameters", "strict"])
            case "custom": return Set(tool.keys).isSubset(of: ["type", "name", "description", "format"])
            case "namespace":
                guard Set(tool.keys).isSubset(of: ["type", "name", "description", "tools"]), let children = tool["tools"] else { return false }
                return toolList(children, depth: depth + 1)
            default: return false
            }
        }
    }

    private static func text(_ value: Any) -> Bool {
        if value is String { return true }
        guard let contents = value as? [[String: Any]] else { return false }
        return contents.allSatisfy { part in
            ["input_text", "output_text"].contains(part["type"] as? String ?? "") && part["text"] is String
                && Set(part.keys).isSubset(of: ["type", "text", "annotations", "logprobs"])
        }
    }

    private static func item(_ value: [String: Any]) -> Bool {
        switch value["type"] as? String {
        case "message", nil:
            guard Set(value.keys).isSubset(of: ["type", "id", "role", "content", "status", "phase", "end_turn"]),
                  ["user", "assistant", "system", "developer"].contains(value["role"] as? String ?? ""), let content = value["content"] else { return false }
            return text(content)
        case "additional_tools":
            guard Set(value.keys).isSubset(of: ["type", "id", "role", "tools"]), let tools = value["tools"] else { return false }
            return toolList(tools)
        case "function_call_output", "custom_tool_call_output":
            guard Set(value.keys).isSubset(of: ["type", "id", "call_id", "output", "status"]), let output = value["output"] else { return false }
            return text(output)
        case "function_call": return Set(value.keys).isSubset(of: ["type", "id", "call_id", "name", "namespace", "arguments", "status"])
        case "custom_tool_call": return Set(value.keys).isSubset(of: ["type", "id", "call_id", "name", "namespace", "input", "status"])
        case "reasoning": return Set(value.keys).isSubset(of: ["type", "id", "summary", "content", "encrypted_content", "status"])
        case "compaction": return Set(value.keys).isSubset(of: ["type", "id", "encrypted_content"])
        case "configuration_update": return Set(value.keys).isSubset(of: ["type", "id", "reasoning"])
        default: return false
        }
    }
}
