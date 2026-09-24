import Darwin
import Foundation
import PolicyCore
import RuntimeHost

public struct SourceRefreshResult: Sendable {
    public let state: String
    public let receipt: SourceReceipt?
}

/// Launched only from enrolled owner state. No guest accepts an executable path,
/// source identity, channel epoch, digest key, or connector command line.
@MainActor public final class SourceRuntime {
    private var active: (id: UUID, process: Process, channel: FramedChannel)?
    private var pendingRequest: UUID?

    public init() {}

    public var isRefreshing: Bool { pendingRequest != nil }

    public func stop() {
        pendingRequest = nil
        guard let running = active else { return }
        active = nil
        running.channel.invalidate()
        if running.process.isRunning { kill(running.process.processIdentifier, SIGKILL) }
    }

    public func refresh(_ source: EnrolledSource, store: SourceEnrollmentStore, worker: PrivateVaultWorker, beforeCommit: @MainActor () throws -> Void = {}) async throws -> SourceRefreshResult {
        guard source.enabled else { throw SourceHostError.notConfigured }
        guard pendingRequest == nil else { throw VaultWorkerError.busy }
        let epoch = UUID(), request = UUID()
        pendingRequest = request
        defer { if pendingRequest == request { stop() } }
        let generation = try await worker.sources(instances: [source.id]).first?.generation ?? 0
        guard pendingRequest == request, !Task.isCancelled else { throw SourceHostError.cancelled }
        try source.candidate.verify()
        let key = try store.digestKey(source.id)
        try await worker.configureSource(instance: source.id, label: source.label, epoch: epoch, capabilities: source.candidate.capabilities, digestKey: key)
        do {
            guard pendingRequest == request, !Task.isCancelled else { throw SourceHostError.cancelled }
            let connection = try launch(source.candidate)
            active = (request, connection.0, connection.1)
            let channel = connection.1
            let command = try JSONSerialization.data(withJSONObject: [
                "contract_major": 1, "kind": "refresh", "source_instance_id": source.id.uuidString.lowercased(),
                "channel_epoch": epoch.uuidString.lowercased(), "request_id": request.uuidString.lowercased(),
                "previous_generation": generation, "scope": "account"
            ])
            try await Task.detached { try channel.write(command) }.value
            let deadline = DeadlineClock.now + 300
            for _ in 0..<60_004 {
                try Task.checkCancellation()
                guard active?.id == request, DeadlineClock.now < deadline else { throw SourceHostError.cancelled }
                let remaining = min(60, deadline - DeadlineClock.now)
                let data = try await Task.detached { try channel.read(timeout: remaining) }.value
                guard active?.id == request, DeadlineClock.now < deadline else { throw SourceHostError.cancelled }
                let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                if let status = try terminalStatus(object, byteCount: data.count, source: source.id, epoch: epoch, request: request) {
                    stop()
                    try await worker.closeSource(instance: source.id)
                    return SourceRefreshResult(state: status, receipt: nil)
                }
                if object?["kind"] as? String == "commit" {
                    try beforeCommit()
                }
                let result = try await worker.sourceFrame(instance: source.id, frame: data)
                guard active?.id == request else { throw SourceHostError.cancelled }
                let encoder = JSONEncoder(); encoder.keyEncodingStrategy = .convertToSnakeCase
                let acknowledgement = try encoder.encode(result)
                try await Task.detached { try channel.write(acknowledgement) }.value
                if result.state == "committed" || result.state == "aborted" {
                    stop()
                    try await worker.closeSource(instance: source.id)
                    return SourceRefreshResult(state: result.state, receipt: result.receipt)
                }
            }
            throw SourceHostError.unavailable
        } catch {
            if pendingRequest == request { stop() }
            try? await worker.closeSource(instance: source.id)
            // Connector stderr and exception strings never become status text.
            if let error = error as? VaultWorkerError { throw error }
            if let error = error as? SourceHostError { throw error }
            throw SourceHostError.unavailable
        }
    }

    private func launch(_ candidate: SourceCandidate) throws -> (Process, FramedChannel) {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw SourceHostError.unavailable }
        defer { close(pair[0]); close(pair[1]) }
        guard fcntl(pair[0], F_SETFD, FD_CLOEXEC) == 0, fcntl(pair[1], F_SETFD, FD_CLOEXEC) == 0 else { throw SourceHostError.unavailable }
        let channel = try FramedChannel(descriptor: pair[0], maximumBytes: 1024 * 1024)
        let child = FileHandle(fileDescriptor: pair[1], closeOnDealloc: false)
        let process = Process()
        process.executableURL = candidate.executable
        process.arguments = ["--shadow-source-v1"]
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"]
        process.standardInput = child; process.standardOutput = child
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            try candidate.verify(process: process)
            return (process, channel)
        } catch {
            channel.invalidate()
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            throw SourceHostError.identityChanged
        }
    }

    private func terminalStatus(_ object: [String: Any]?, byteCount: Int, source: UUID, epoch: UUID, request: UUID) throws -> String? {
        guard let object, object["kind"] as? String == "status" else { return nil }
        guard byteCount <= 1024,
              Set(object.keys) == ["contract_major", "kind", "source_instance_id", "channel_epoch", "request_id", "state"],
              object["contract_major"] as? Int == 1,
              object["source_instance_id"] as? String == source.uuidString.lowercased(),
              object["channel_epoch"] as? String == epoch.uuidString.lowercased(),
              object["request_id"] as? String == request.uuidString.lowercased(),
              let state = object["state"] as? String,
              ["needs_owner_action", "unsupported", "not_configured"].contains(state) else { throw SourceHostError.unavailable }
        return state
    }
}
