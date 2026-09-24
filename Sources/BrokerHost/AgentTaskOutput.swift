import Foundation
import PolicyCore

/// A small native projection of untrusted agent text, never a consent surface.
struct AgentTaskOutput {
    private(set) var text = ""
    private var messages = 0

    mutating func accept(_ data: Data) throws -> Bool? {
        let value = try BoundedJSON.parse(data)
        guard let fields = value.object else { throw AgentAPIError.invalidRequest }
        if Set(fields.keys) == ["kind", "succeeded"], fields["kind"] == .string("finished"),
           case .bool(let succeeded) = fields["succeeded"] { return succeeded }
        guard Set(fields.keys) == ["kind", "text"], fields["kind"] == .string("message"),
              let message = fields["text"]?.string, !message.isEmpty, message.utf8.count <= 8192,
              messages < 32, text.utf8.count + message.utf8.count + 2 <= 32768 else { throw AgentAPIError.responseLimit }
        text += (text.isEmpty ? "" : "\n\n") + message
        messages += 1
        return nil
    }
}
