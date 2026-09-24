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

public struct OwnerCatalogItem: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let title: String
    public let username: String
    public let origins: [String]
    public let group: String
    public var sourceKind: String
    public var presence: String
    public let authorization: String
    public let revision: UInt64
    public let observedAt: String?
    public let sourceInstance: String?
    public var restrictionEvent: String?
    public let conflicted: Bool
    public let diverged: Bool

    public init(id: String, title: String, username: String, origins: [String], group: String, sourceKind: String = "local", presence: String = "present", authorization: String = "unapproved", revision: UInt64 = 1, observedAt: String? = nil, sourceInstance: String? = nil, restrictionEvent: String? = nil, conflicted: Bool = false, diverged: Bool = false) {
        self.id = id; self.title = title; self.username = username; self.origins = origins; self.group = group
        self.sourceKind = sourceKind; self.presence = presence; self.authorization = authorization; self.revision = revision
        self.observedAt = observedAt; self.sourceInstance = sourceInstance; self.restrictionEvent = restrictionEvent; self.conflicted = conflicted; self.diverged = diverged
    }

    public var observationDate: Date? {
        guard let observedAt else { return nil }
        let parser = ISO8601DateFormatter()
        parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = parser.date(from: observedAt) { return date }
        parser.formatOptions = [.withInternetDateTime]
        return parser.date(from: observedAt)
    }
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

private final class WorkerTermination: @unchecked Sendable {
    private let mutex = NSLock()
    private var expected = false
    func expectExit() { mutex.withLock { expected = true } }
    func unexpectedExit() -> Bool { mutex.withLock { !expected } }
}

public actor PrivateVaultWorker {
    private let process: Process
    private let transport: FramedChannel
    private let anchor: GenerationAnchor
    private let restrictions: NativeRestrictions
    private let onInvalidate: @MainActor @Sendable ([UUID]) -> Void
    private let epoch = UUID().uuidString.lowercased()
    private var sequence = 0
    private var busy = false
    private var closed = false
    private let termination = WorkerTermination()
    public nonisolated var isRunning: Bool { process.isRunning && termination.unexpectedExit() }
    package nonisolated var processIdentifier: Int32 { process.processIdentifier }

    private init(python: URL, vaultDirectory: URL, vaultID: String, onInvalidate: @escaping @MainActor @Sendable ([UUID]) -> Void, onTermination: @escaping @MainActor @Sendable () -> Void) throws {
        self.onInvalidate = onInvalidate
        restrictions = NativeRestrictions(vaultDirectory: vaultDirectory, vaultID: vaultID)
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw VaultWorkerError.unavailable }
        defer { Darwin.close(pair[0]); Darwin.close(pair[1]) }
        guard fcntl(pair[0], F_SETFD, FD_CLOEXEC) == 0, fcntl(pair[1], F_SETFD, FD_CLOEXEC) == 0 else { throw VaultWorkerError.unavailable }
        transport = try FramedChannel(descriptor: pair[0], maximumBytes: 2 * 1024 * 1024)
        anchor = GenerationAnchor(vaultID: vaultID)
        let child = FileHandle(fileDescriptor: pair[1], closeOnDealloc: false)
        process = Process()
        process.executableURL = python
        process.arguments = ["-I", "-m", "vault_worker.ipc"]
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"]
        process.standardInput = child
        process.standardOutput = child
        process.standardError = FileHandle.nullDevice
        let termination = termination
        process.terminationHandler = { _ in
            if termination.unexpectedExit() { Task { @MainActor in onTermination() } }
        }
        do { try process.run() } catch { transport.invalidate(); throw VaultWorkerError.unavailable }
    }

    deinit {
        termination.expectExit()
        transport.invalidate()
        if process.isRunning { process.terminate() }
    }

    public static func launch(python: URL, vaultDirectory: URL, vaultID: String, onInvalidate: @escaping @MainActor @Sendable ([UUID]) -> Void = { _ in }, onTermination: @escaping @MainActor @Sendable () -> Void = {}) async throws -> PrivateVaultWorker {
        let worker = try PrivateVaultWorker(python: python, vaultDirectory: vaultDirectory, vaultID: vaultID, onInvalidate: onInvalidate, onTermination: onTermination)
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
        termination.expectExit()
        closed = true
        transport.invalidate()
        let child = process
        if child.isRunning { child.terminate() }
        await Task.detached { child.waitUntilExit() }.value
    }

    // Never dispatched by the agent API. The session coordinator checks grant
    // and revision both before and after awaiting this private worker request.
    func resolveCredential(entry: UUID, revision: UInt64, origin: String, includeTOTP: Bool = false) async throws -> PrivateCredential {
        try await request("credential.resolve", payload: CredentialRequest(entryId: entry.uuidString.lowercased(), expectedRevision: revision, origin: origin, includeTotp: includeTOTP))
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
        let page: OwnerCatalogPage = try await request("owner.catalog", payload: Page(offset: offset))
        do {
            var events = try restrictions.latest(requireExisting: page.items.contains { $0.sourceKind == "mirrored" })
            var items: [OwnerCatalogItem] = []
            for var item in page.items {
                guard let id = UUID(uuidString: item.id) else { throw VaultWorkerError.unavailable }
                if let expected = item.restrictionEvent, events[id] == nil || UUID(uuidString: expected) == nil { throw VaultWorkerError.reported("recovery_required") }
                if item.sourceKind == "mirrored", events[id] == nil {
                    let observed = item.observationDate
                    let unknown = observed == nil || observed! > Date().addingTimeInterval(60) || item.presence != "present"
                    if unknown || Date().timeIntervalSince(observed!) > 86400 {
                        let event = RestrictionEvent(id: UUID(), account: id, kind: unknown ? .historyUnknown : .staleMirror)
                        await onInvalidate([id])
                        try restrictions.record([event])
                        events[id] = event
                    }
                }
                if let event = events[id] {
                    item.restrictionEvent = event.id.uuidString.lowercased()
                    if item.sourceKind != "mirrored" { item.sourceKind = "mirrored"; item.presence = "unknown" }
                }
                items.append(item)
            }
            return OwnerCatalogPage(items: items, nextOffset: page.nextOffset)
        } catch { throw VaultWorkerError.reported("recovery_required") }
    }

    public func configureSource(instance: UUID, label: String, epoch: UUID, capabilities: SourceCapabilities, digestKey: Data) async throws {
        guard !busy, !closed, digestKey.count == 32 else { throw VaultWorkerError.unavailable }
        try restrictions.initializeForEnrollment()
        let _: State = try await request("source.configure", payload: SourceConfiguration(instance: instance.uuidString.lowercased(), label: label, epoch: epoch.uuidString.lowercased(), capabilities: capabilities, digestKey: digestKey.base64EncodedString()))
    }

    public func catalogSnapshot() async throws -> [OwnerCatalogItem] {
        var result: [OwnerCatalogItem] = []
        var offset = 0
        repeat {
            let page = try await catalog(offset: offset)
            result += page.items
            guard result.count <= 50_000 else { throw VaultWorkerError.unavailable }
            guard let next = page.nextOffset else { return result }
            guard next > offset, !page.items.isEmpty else { throw VaultWorkerError.unavailable }
            offset = next
        } while true
    }

    public func sourceFrame(instance: UUID, frame: Data) async throws -> SourceFrameResult {
        guard !frame.isEmpty, frame.count <= 1024 * 1024 else { throw VaultWorkerError.unavailable }
        return try await request("source.frame", payload: SourceFrame(instance: instance.uuidString.lowercased(), frame: frame.base64EncodedString()))
    }

    public func closeSource(instance: UUID) async throws {
        let _: State = try await request("source.close", payload: SourceInstance(instance: instance.uuidString.lowercased()))
    }

    public func sources(instances: [UUID]) async throws -> [OwnerSourceSummary] {
        guard instances.count <= 16 else { throw VaultWorkerError.unavailable }
        let result: SourceStatus = try await request("source.status", payload: SourceStatusRequest(instances: instances.map { $0.uuidString.lowercased() }))
        return result.sources
    }

    public func resolveConflict(entry: UUID, revision: UInt64, choice: String, operationID: UUID) async throws -> OwnerConflictResult {
        try await request("source.resolve_conflict", payload: ResolveConflict(entryId: entry.uuidString.lowercased(), expectedRevision: revision, choice: choice, operationId: operationID.uuidString.lowercased()))
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
        let channel = transport, authority = anchor, channelEpoch = epoch, restrictions = restrictions, invalidate = onInvalidate
        let task = Task.detached { try await Self.exchange(data, channel: channel, anchor: authority, restrictions: restrictions, invalidate: invalidate, epoch: channelEpoch, sequence: current) }
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
                throw VaultWorkerError.reported(Self.safeCodes.contains(error.code) || error.code == "stale_credential" ? error.code : "worker_unavailable")
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

    private nonisolated static func exchange(_ request: Data, channel: FramedChannel, anchor: GenerationAnchor, restrictions: NativeRestrictions, invalidate: @escaping @MainActor @Sendable ([UUID]) -> Void, epoch: String, sequence: Int) async throws -> Reply {
        try channel.write(request)
        for _ in 0..<4096 {
            let data = try channel.read(timeout: 60)
            guard let message = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(message.keys) == ["protocol_major", "channel_epoch", "sequence", "kind", "payload"],
                  message["protocol_major"] as? Int == 1, message["channel_epoch"] as? String == epoch,
                  message["sequence"] as? Int == sequence, let kind = message["kind"] as? String,
                  let payload = message["payload"] as? [String: Any] else { throw VaultWorkerError.unavailable }
            if kind == "result" || kind == "error" {
                return Reply(kind: kind, payload: try JSONSerialization.data(withJSONObject: payload))
            }
            if kind == "mutation.invalidate", Set(payload.keys) == ["accounts"], let raw = payload["accounts"] as? [String], raw.count <= 256 {
                let accounts = raw.compactMap(UUID.init(uuidString:))
                guard accounts.count == raw.count else { throw VaultWorkerError.unavailable }
                await invalidate(accounts)
                try nativeAcknowledgement(channel: channel, epoch: epoch, sequence: sequence)
                continue
            }
            if kind == "restriction.record", Set(payload.keys) == ["events"], let raw = payload["events"] as? [[String: String]], raw.count <= 256 {
                let events = try raw.map { event -> RestrictionEvent in
                    guard Set(event.keys) == ["account", "kind", "event_id"], let account = UUID(uuidString: event["account"]!), let id = UUID(uuidString: event["event_id"]!), let kind = RestrictionKind(rawValue: event["kind"]!) else { throw VaultWorkerError.unavailable }
                    return RestrictionEvent(id: id, account: account, kind: kind)
                }
                await invalidate(events.map(\.account))
                try restrictions.record(events)
                try nativeAcknowledgement(channel: channel, epoch: epoch, sequence: sequence)
                continue
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

    private nonisolated static func nativeAcknowledgement(channel: FramedChannel, epoch: String, sequence: Int) throws {
        try channel.write(JSONSerialization.data(withJSONObject: ["protocol_major": 1, "channel_epoch": epoch, "sequence": sequence, "kind": "native.result", "payload": ["state": "accepted"]]))
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
    private struct SourceConfiguration: Encodable, Sendable { let instance: String; let label: String; let epoch: String; let capabilities: SourceCapabilities; let digestKey: String }
    private struct SourceFrame: Encodable, Sendable { let instance: String; let frame: String }
    private struct SourceInstance: Encodable, Sendable { let instance: String }
    private struct SourceStatus: Decodable, Sendable { let sources: [OwnerSourceSummary] }
    private struct SourceStatusRequest: Encodable, Sendable { let instances: [String] }
    private struct ResolveConflict: Encodable, Sendable { let entryId: String; let expectedRevision: UInt64; let choice: String; let operationId: String }
    private struct CredentialRequest: Encodable, Sendable { let entryId: String; let expectedRevision: UInt64; let origin: String; let includeTotp: Bool }
    private static let safeCodes: Set<String> = ["already_exists", "ambiguous_identity", "batch_conflict", "contradictory_coverage", "contradictory_evidence", "editor_active", "editor_changed", "editor_unavailable", "external_modification", "generation_conflict", "history_limit", "identity_mismatch", "invalid_credentials", "invalid_csv", "invalid_enrollment", "invalid_group_hierarchy", "invalid_mapping", "invalid_record", "invalid_request", "invalid_rows", "invalid_vault", "kdf_limit_exceeded", "limit_exceeded", "operation_conflict", "preview_required", "recovery_required", "sequence_mismatch", "source_changed", "source_unavailable", "stale_conflict", "storage_unavailable", "unknown_group", "unlinked_identity", "unsafe_path", "unsafe_source", "unstable_identity", "unsupported_credential", "unsupported_evidence", "unsupported_message", "unsupported_operation", "unsupported_profile", "unsupported_version", "vault_locked", "vault_unavailable", "worker_unavailable", "writer_busy"]
}
