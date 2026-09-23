import Foundation
import Darwin
import PolicyCore
import RuntimeHost

public enum VaultWorkerError: Error, Sendable {
    case unavailable
    case busy
    case reported(String)
}

public struct OwnerCSVMapping: Codable, Sendable {
    public var title: String
    public var url: String
    public var username: String
    public var password: String
    public var notes: String?
    public var totp: String?
    public var group: String?

    public init(title: String, url: String, username: String, password: String, notes: String? = nil, totp: String? = nil, group: String? = nil) {
        self.title = title; self.url = url; self.username = username; self.password = password
        self.notes = notes; self.totp = totp; self.group = group
    }
}

public struct OwnerCatalogItem: Codable, Identifiable, Sendable {
    public let id: String
    public let title: String
    public let username: String
    public let origins: [String]
    public let group: String
    public let sourceKind: String
    public let presence: String
    public let authorization: String
}

public struct OwnerCatalogPage: Codable, Sendable {
    public let items: [OwnerCatalogItem]
    public let nextOffset: Int?
}

public struct OwnerImportPreview: Codable, Sendable {
    public struct Row: Codable, Sendable {
        public let title: String
        public let origin: String
        public let username: String
        public let group: String
    }
    public let accepted: Int
    public let rejected: Int
    public let rows: [Row]
    public let codes: [String]
    public let plaintextSourceWarning: Bool
}

public struct OwnerImportResult: Codable, Sendable {
    public let accepted: Int
    public let rejected: Int
    public let replayed: Bool
}

public struct OwnerEditorStatus: Codable, Sendable {
    public let state: String
    public let checkoutId: String?
    public let checkoutPath: String?
}

public struct OwnerEditorReview: Codable, Sendable {
    public let reviewId: String
    public let added: Int
    public let changed: Int
    public let removed: Int
    public let groupsChanged: Bool
    public let protectedMetadataRestored: Int
}

public struct OwnerEditorResult: Codable, Sendable {
    public let state: String
    public let checkoutRetained: Bool
    public let lateChange: Bool
}

public actor PrivateVaultWorker {
    private let process: Process
    private let transport: FramedChannel
    private let anchor: GenerationAnchor
    private let epoch = UUID().uuidString.lowercased()
    private var sequence = 0
    private var busy = false
    private var closed = false

    private init(python: URL, vaultID: String) throws {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw VaultWorkerError.unavailable }
        defer { Darwin.close(pair[0]); Darwin.close(pair[1]) }
        guard fcntl(pair[0], F_SETFD, FD_CLOEXEC) == 0, fcntl(pair[1], F_SETFD, FD_CLOEXEC) == 0 else { throw VaultWorkerError.unavailable }
        transport = try FramedChannel(descriptor: pair[0])
        anchor = GenerationAnchor(vaultID: vaultID)
        let child = FileHandle(fileDescriptor: pair[1], closeOnDealloc: false)
        process = Process()
        process.executableURL = python
        process.arguments = ["-I", "-m", "vault_worker.ipc"]
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"]
        process.standardInput = child
        process.standardOutput = child
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { transport.invalidate(); throw VaultWorkerError.unavailable }
    }

    deinit {
        transport.invalidate()
        if process.isRunning { process.terminate() }
    }

    public static func launch(python: URL, vaultDirectory: URL, vaultID: String) async throws -> PrivateVaultWorker {
        let worker = try PrivateVaultWorker(python: python, vaultID: vaultID)
        do {
            let _: State = try await worker.request("initialize", payload: Initialize(vaultDirectory: vaultDirectory.path))
            return worker
        } catch {
            await worker.lock()
            throw error
        }
    }

    public func create(password: String) async throws {
        let state: State = try await request("vault.create", payload: Password(password: password))
        guard state.state == "unlocked" else { throw VaultWorkerError.unavailable }
    }

    public func unlock(password: String) async throws {
        let state: State = try await request("vault.unlock", payload: Password(password: password))
        guard state.state == "unlocked" else { throw VaultWorkerError.unavailable }
    }

    public func lock() async {
        closed = true
        transport.invalidate()
        let child = process
        if child.isRunning { child.terminate() }
        await Task.detached { child.waitUntilExit() }.value
    }

    public func csvHeaders(path: URL) async throws -> [String] {
        let result: Headers = try await request("csv.headers", payload: PathRequest(path: path.path))
        return result.headers
    }

    public func previewCSV(path: URL, mapping: OwnerCSVMapping) async throws -> OwnerImportPreview {
        try await request("csv.preview", payload: Preview(path: path.path, mapping: mapping))
    }

    public func commitCSV(operationID: UUID, validRowsOnly: Bool) async throws -> OwnerImportResult {
        try await request("csv.commit", payload: Commit(operationId: operationID.uuidString.lowercased(), validRowsOnly: validRowsOnly))
    }

    public func cancelCSV() async throws {
        let _: State = try await request("csv.cancel", payload: Empty())
    }

    public func catalog(offset: Int = 0) async throws -> OwnerCatalogPage {
        try await request("owner.catalog", payload: Page(offset: offset))
    }

    public func editorStatus() async throws -> OwnerEditorStatus {
        try await request("editor.status", payload: Empty())
    }

    public func beginEditor() async throws -> OwnerEditorStatus {
        try await request("editor.begin", payload: Empty())
    }

    public func previewEditor(password: String) async throws -> OwnerEditorReview {
        try await request("editor.preview", payload: Password(password: password))
    }

    public func commitEditor(reviewID: String) async throws -> OwnerEditorResult {
        try await request("editor.commit", payload: EditorCommit(reviewId: reviewID))
    }

    public func cancelEditor(discard: Bool) async throws -> OwnerEditorResult {
        try await request("editor.cancel", payload: EditorCancel(discard: discard))
    }

    private func request<P: Encodable & Sendable, R: Decodable & Sendable>(_ kind: String, payload: P) async throws -> R {
        guard !closed else { throw VaultWorkerError.unavailable }
        guard !busy else { throw VaultWorkerError.busy }
        busy = true
        defer { busy = false }
        let current = sequence
        sequence += 1
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try encoder.encode(Envelope(channelEpoch: epoch, sequence: current, kind: kind, payload: payload))
        let channel = transport, authority = anchor, channelEpoch = epoch
        let task = Task.detached { try Self.exchange(data, channel: channel, anchor: authority, epoch: channelEpoch, sequence: current) }
        do {
            let reply = try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                channel.invalidate()
                task.cancel()
            }
            try Task.checkCancellation()
            guard !closed else { throw VaultWorkerError.unavailable }
            if reply.kind == "error" {
                let error = try JSONDecoder().decode(ReportedError.self, from: reply.payload)
                throw VaultWorkerError.reported(Self.safeCodes.contains(error.code) ? error.code : "worker_unavailable")
            }
            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase
            return try decoder.decode(R.self, from: reply.payload)
        } catch let error as VaultWorkerError {
            if case .reported = error { throw error }
            await lock()
            throw error
        } catch {
            await lock()
            throw VaultWorkerError.unavailable
        }
    }

    private nonisolated static func exchange(_ request: Data, channel: FramedChannel, anchor: GenerationAnchor, epoch: String, sequence: Int) throws -> Reply {
        try channel.write(request)
        for _ in 0..<32 {
            let data = try channel.read(timeout: 60)
            guard let message = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(message.keys) == ["protocol_major", "channel_epoch", "sequence", "kind", "payload"],
                  message["protocol_major"] as? Int == 1, message["channel_epoch"] as? String == epoch,
                  message["sequence"] as? Int == sequence, let kind = message["kind"] as? String,
                  let payload = message["payload"] as? [String: Any] else { throw VaultWorkerError.unavailable }
            if kind == "result" || kind == "error" {
                return Reply(kind: kind, payload: try JSONSerialization.data(withJSONObject: payload))
            }
            let digest: String?
            if kind == "anchor.read", payload.isEmpty {
                digest = try anchor.read()
            } else if kind == "anchor.advance", Set(payload.keys) == ["expected", "digest"],
                      let next = payload["digest"] as? String,
                      payload["expected"] is NSNull || payload["expected"] is String {
                try anchor.advance(expected: payload["expected"] as? String, to: next)
                digest = next
            } else { throw VaultWorkerError.unavailable }
            let response: [String: Any] = ["protocol_major": 1, "channel_epoch": epoch, "sequence": sequence, "kind": "anchor.result", "payload": ["digest": digest as Any? ?? NSNull()]]
            try channel.write(JSONSerialization.data(withJSONObject: response))
        }
        throw VaultWorkerError.unavailable
    }

    private struct Envelope<P: Encodable>: Encodable {
        let protocolMajor = 1
        let channelEpoch: String
        let sequence: Int
        let kind: String
        let payload: P
    }
    private struct Reply: Sendable { let kind: String; let payload: Data }
    private struct ReportedError: Decodable { let code: String }
    private struct State: Decodable, Sendable { let state: String }
    private struct Initialize: Encodable, Sendable { let vaultDirectory: String }
    private struct Password: Encodable, Sendable { let password: String }
    private struct PathRequest: Encodable, Sendable { let path: String }
    private struct Preview: Encodable, Sendable { let path: String; let mapping: OwnerCSVMapping }
    private struct Commit: Encodable, Sendable { let operationId: String; let validRowsOnly: Bool }
    private struct Page: Encodable, Sendable { let offset: Int }
    private struct Headers: Decodable, Sendable { let headers: [String] }
    private struct Empty: Encodable, Sendable {}
    private struct EditorCommit: Encodable, Sendable { let reviewId: String }
    private struct EditorCancel: Encodable, Sendable { let discard: Bool }
    private static let safeCodes: Set<String> = ["unsafe_path", "writer_busy", "recovery_required", "already_exists", "storage_unavailable", "invalid_credentials", "invalid_vault", "unsupported_profile", "kdf_limit_exceeded", "external_modification", "unsafe_source", "source_unavailable", "source_changed", "limit_exceeded", "invalid_mapping", "invalid_rows", "invalid_csv", "preview_required", "invalid_request", "operation_conflict", "vault_unavailable", "vault_locked", "unsupported_operation", "worker_unavailable", "editor_active", "editor_unavailable", "editor_changed"]
}
