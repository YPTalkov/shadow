import Foundation
import CoreFoundation

public enum RelayError: String, Error, Sendable {
    case invalidRequest = "invalid_request"
    case signInRequired = "model_sign_in_required"
    case denied = "relay_denied"
    case limitExceeded = "relay_limit_exceeded"
    case providerUnavailable = "model_provider_unavailable"
}

public struct CodexCredential: Sendable {
    let accessToken: String
    let accountID: String
    let expiresAt: Date

    public init(accessToken: String, accountID: String, expiresAt: Date) {
        self.accessToken = accessToken
        self.accountID = accountID
        self.expiresAt = expiresAt
    }
}

public struct CodexRelayPolicy: Sendable {
    public static let maximumRequestBytes = 4 * 1024 * 1024
    private let models: Set<String>
    private let fields: Set<String> = ["model", "instructions", "input", "tools", "tool_choice", "parallel_tool_calls", "reasoning", "include", "text", "service_tier", "prompt_cache_key", "stream", "store"]
    private let allowedHeaders: Set<String> = ["content-type", "accept", "user-agent", "session_id", "session-id", "x-client-request-id", "x-codex-turn-metadata", "x-codex-beta-features", "openai-beta", "originator"]

    public init(models: Set<String>) {
        self.models = models
    }

    public func request(method: String, path: String, headers: [String: String], body: Data, credential: CodexCredential, now: Date = Date()) throws -> URLRequest {
        guard method == "POST", path == "/v1/responses", body.count <= Self.maximumRequestBytes,
              headers.count <= 24,
              headers.allSatisfy({ allowedHeaders.contains($0.key.lowercased()) && $0.value.utf8.count <= 4096 && !$0.value.contains("\r") && !$0.value.contains("\n") }),
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              Set(json.keys).isSubset(of: fields),
              let model = json["model"] as? String, models.contains(model),
              let instructions = json["instructions"] as? String, instructions.utf8.count <= 1024 * 1024,
              json["input"] is [Any],
              let stream = json["stream"] as? NSNumber, CFGetTypeID(stream) == CFBooleanGetTypeID(), stream.boolValue,
              let store = json["store"] as? NSNumber, CFGetTypeID(store) == CFBooleanGetTypeID(), !store.boolValue else {
            throw RelayError.invalidRequest
        }
        guard credential.expiresAt.timeIntervalSince(now) > 30,
              Self.safeHeader(credential.accessToken), Self.safeHeader(credential.accountID) else {
            throw RelayError.signInRequired
        }
        var request = URLRequest(url: URL(string: "https://chatgpt.com/backend-api/codex/responses")!)
        request.httpMethod = "POST"
        // Canonical serialization prevents a second parser from interpreting duplicate keys differently.
        request.httpBody = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])
        request.setValue("Bearer \(credential.accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue(credential.accountID, forHTTPHeaderField: "chatgpt-account-id")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        request.setValue("responses=experimental", forHTTPHeaderField: "OpenAI-Beta")
        request.setValue("codex_cli_rs", forHTTPHeaderField: "originator")
        request.setValue("shadow/0.1", forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 120
        return request
    }

    private static func safeHeader(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 16_384 && value.unicodeScalars.allSatisfy { $0.value >= 33 && $0.value <= 126 }
    }
}
