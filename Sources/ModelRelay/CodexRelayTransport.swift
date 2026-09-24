import Foundation

final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

public struct CodexRelayTransport: Sendable {
    private let policy: CodexRelayPolicy

    public init(models: Set<String>) {
        policy = CodexRelayPolicy(models: models)
    }

    public func stream(method: String, path: String, headers: [String: String], body: Data, credential: CodexCredential, lease: RelayLease, instance: String, boot: String, send: @escaping @Sendable (Data) async throws -> Void) async throws {
        let request = try policy.request(method: method, path: path, headers: headers, body: body, credential: credential)
        try lease.reserve(instance: instance, boot: boot, bytes: body.count)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.connectionProxyDictionary = [:]
        configuration.timeoutIntervalForResource = 180
        configuration.waitsForConnectivity = false
        let session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    let (bytes, response) = try await session.bytes(for: request)
                    guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                          http.value(forHTTPHeaderField: "Content-Type")?.split(separator: ";").first == "text/event-stream" else { throw RelayError.providerUnavailable }
                    var decoder = RelayEventDecoder(credential: credential)
                    for try await byte in bytes {
                        if let event = try decoder.append(byte) {
                            try lease.check(instance: instance, boot: boot)
                            try Task.checkCancellation()
                            try await send(event)
                            if decoder.isComplete { break }
                        }
                    }
                    try decoder.finish()
                }
                group.addTask {
                    while true {
                        try await Task.sleep(for: .milliseconds(100))
                        try lease.check(instance: instance, boot: boot)
                    }
                }
                defer { group.cancelAll() }
                try await group.next()
            }
        } catch let error as RelayError {
            throw error
        } catch {
            throw RelayError.providerUnavailable
        }
    }
}

struct RelayEventDecoder {
    private let protectedValues: [String]
    private var buffer = Data()
    private var total = 0
    private var completed = false
    var isComplete: Bool { completed }

    init(credential: CodexCredential) {
        protectedValues = [credential.accessToken, credential.accountID]
    }

    mutating func append(_ byte: UInt8) throws -> Data? {
        guard !completed, buffer.count < 1024 * 1024, total < 8 * 1024 * 1024 else { throw RelayError.providerUnavailable }
        total += 1
        buffer.append(byte)
        guard buffer.suffix(2) == Data([10, 10]) || buffer.suffix(4) == Data([13, 10, 13, 10]) else { return nil }
        defer { buffer.removeAll(keepingCapacity: true) }
        guard let text = String(data: buffer, encoding: .utf8) else { throw RelayError.providerUnavailable }
        let lines = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        let dataLines = lines.filter { $0.hasPrefix("data:") }
        if dataLines.isEmpty { return nil }
        guard dataLines.count == 1,
              let data = dataLines[0].dropFirst(5).data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String, type.hasPrefix("response."), type.utf8.count <= 128,
              type.unicodeScalars.allSatisfy({ (97...122).contains($0.value) || (48...57).contains($0.value) || $0 == "." || $0 == "_" }),
              !["response.failed", "response.error", "response.incomplete"].contains(type),
              !containsCredential(json) else { throw RelayError.providerUnavailable }
        if type == "response.completed" {
            guard let response = json["response"] as? [String: Any], response["status"] as? String == "completed" else { throw RelayError.providerUnavailable }
            completed = true
        }
        let encoded = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])
        var event = Data("event: \(type)\ndata: ".utf8)
        event.append(encoded)
        event.append(Data("\n\n".utf8))
        return event
    }

    func finish() throws {
        guard completed, buffer.isEmpty else { throw RelayError.providerUnavailable }
    }

    private func containsCredential(_ value: Any) -> Bool {
        if let string = value as? String { return protectedValues.contains { !($0.isEmpty) && string.contains($0) } }
        if let array = value as? [Any] { return array.contains(where: containsCredential) }
        if let object = value as? [String: Any] { return object.contains { containsCredential($0.key) || containsCredential($0.value) } }
        return false
    }
}
