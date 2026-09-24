import Foundation
import Observation
import Virtualization
import RuntimeHost
import ModelRelay
import PolicyCore

public struct AgentVMImage: Sendable {
    public let kernel: URL
    public let ramdisk: URL
    public let disk: URL
    public let identity: VMImageIdentity

    public static func packaged(at directory: URL) throws -> Self {
        let manifest = try BoundedJSON.parse(Data(contentsOf: directory.appendingPathComponent("manifest.json")), maximumBytes: 8192)
        guard manifest["profile"]?.string == "agent", let files = manifest["files"]?.object,
              let kernel = files["kernel"]?.string, let ramdisk = files["initrd"]?.string, let disk = files["disk"]?.string else { throw AgentAPIError.unavailable }
        return Self(kernel: directory.appendingPathComponent("kernel"), ramdisk: directory.appendingPathComponent("initrd"),
                    disk: directory.appendingPathComponent("disk"), identity: VMImageIdentity(kernelSHA256: kernel, ramdiskSHA256: ramdisk, imageSHA256: disk))
    }
}

package struct AgentModelRequest: Sendable {
    package let method: String
    package let path: String
    package let headers: [String: String]
    package let body: Data
    package let lease: RelayLease
    package let instance: String
    package let boot: String
    package let model: String

    init(data: Data, lease: RelayLease, identity: VMInstanceIdentity, model: String) throws {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(json.keys) == ["method", "path", "headers", "body"],
              let method = json["method"] as? String, let path = json["path"] as? String,
              let headers = json["headers"] as? [String: String], let body = json["body"] as? [String: Any],
              body["model"] as? String == model else { throw RelayError.invalidRequest }
        self.method = method; self.path = path; self.headers = headers
        self.body = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        self.lease = lease; instance = identity.instance.uuidString; boot = identity.boot.uuidString
        self.model = model
    }
}

package typealias AgentModelStream = @Sendable (AgentModelRequest, @escaping @Sendable (Data) async throws -> Void) async throws -> Void

/// One task, one boot, no reusable guest identity. All authority closes synchronously.
@Observable @MainActor public final class AgentRuntime: NSObject, @preconcurrency VZVirtualMachineDelegate {
    public enum State { case idle, starting, running, succeeded, failed, stopped }
    public static let models = ["gpt-6-sol", "gpt-6-luna", "gpt-6-astra"]
    public private(set) var state: State = .idle
    public private(set) var output = ""
    public var active: Bool { state == .starting || state == .running }
    private let image: AgentVMImage
    private let access: AccessCoordinator
    private let api: AgentAPI
    private let stream: AgentModelStream
    private var machine: VZVirtualMachine?
    private var channels: InstanceChannels?
    private var caller: EnrolledAgent?
    private var lease: RelayLease?
    private var control: FramedChannel?
    private var heartbeat: Task<Void, Never>?
    private var generation = UUID()
    private var connections = 0
    private var modelConnections = 0
    private var heartbeatSequence = 0
    private var acknowledgedSequence = 0
    private var taskPrompt = ""
    private var taskModel = ""
    private var requestLimit = 30
    private var projection = AgentTaskOutput()

    public convenience init(image: AgentVMImage, access: AccessCoordinator, api: AgentAPI, authentication: CodexAuthentication) {
        self.init(image: image, access: access, api: api) { request, send in
            try request.lease.check(instance: request.instance, boot: request.boot)
            let credential = try await authentication.credential()
            try request.lease.check(instance: request.instance, boot: request.boot)
            try await CodexRelayTransport(models: [request.model]).stream(method: request.method, path: request.path,
                headers: request.headers, body: request.body, credential: credential, lease: request.lease,
                instance: request.instance, boot: request.boot, send: send)
        }
    }

    package init(image: AgentVMImage, access: AccessCoordinator, api: AgentAPI, stream: @escaping AgentModelStream) {
        self.image = image; self.access = access; self.api = api; self.stream = stream
        super.init()
        access.observeRevocation(owner: self, authority: true) { [weak self] grant in
            if grant == nil { self?.stop(clearOutput: true) }
        }
    }

    public func start(prompt: String, model: String, maximumRequests: Int = 30) async {
        guard !active, access.unlocked, !prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              prompt.utf8.count <= 8192, Self.models.contains(model), (1...120).contains(maximumRequests) else { return }
        generation = UUID()
        let epoch = generation
        state = .starting; output = ""; projection = AgentTaskOutput()
        taskPrompt = prompt; taskModel = model; connections = 0; modelConnections = 0
        requestLimit = maximumRequests
        heartbeatSequence = 0; acknowledgedSequence = 0
        do {
            let config = try RuntimeVMConfiguration.make(role: .agent, kernel: image.kernel, ramdisk: image.ramdisk, image: image.disk, identity: image.identity)
            guard let boot = config.bootLoader as? VZLinuxBootLoader else { throw AgentAPIError.unavailable }
            boot.commandLine = "console=hvc0 rdinit=/init panic=-1 quiet"
            let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
            serial.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: try FileHandle(forWritingTo: URL(fileURLWithPath: "/dev/null")))
            config.serialPorts = [serial]
            try config.validate()
            let machine = VZVirtualMachine(configuration: config)
            machine.delegate = self
            self.machine = machine
            let channels = try InstanceChannels(machine: machine, role: .agent) { [weak self] connection, identity, role in
                self?.accept(connection, identity: identity, role: role, epoch: epoch)
            }
            self.channels = channels
            let identity = channels.identity
            let caller = EnrolledAgent(id: identity.instance, boot: identity.boot, displayName: "Codex · isolated task")
            self.caller = caller
            access.enroll(caller)
            // Boot has its own bound. Renewable model authority begins only after the guest hello.
            heartbeat = Task { [weak self] in
                try? await Task.sleep(for: .seconds(30))
                guard !Task.isCancelled, let self, self.generation == epoch, self.state == .starting else { return }
                self.finish(.failed)
            }
            try await machine.startOnMainActor()
        } catch { if generation == epoch { finish(.failed) } }
    }

    public func stop(clearOutput: Bool = false) {
        if active { finish(.stopped) }
        if clearOutput { output = ""; projection = AgentTaskOutput() }
    }

    private func finish(_ result: State) {
        guard active else { return }
        state = result
        generation = UUID()
        lease?.revoke(); lease = nil
        control?.invalidate(); control = nil
        channels?.revoke(); channels = nil
        heartbeat?.cancel(); heartbeat = nil
        taskPrompt = ""; taskModel = ""
        if let caller { self.caller = nil; access.removeAgent(caller) }
        if let machine { self.machine = nil; Task { try? await machine.stop() } }
    }

    private func accept(_ connection: VZVirtioSocketConnection, identity: VMInstanceIdentity, role: VMChannelRole, epoch: UUID) {
        guard let channels else { connection.close(); return }
        guard active, generation == epoch, access.unlocked, connections < 2048,
              let caller else { channels.close(connection); return }
        connections += 1
        do {
            let channel = try FramedChannel(descriptor: connection.fileDescriptor, maximumBytes: role == .agentModel ? CodexRelayPolicy.maximumRequestBytes : 65536)
            if role == .agentModel {
                guard state == .running, let lease, modelConnections < requestLimit else { channel.invalidate(); channels.close(connection); return }
                modelConnections += 1
                let stream = stream
                let model = taskModel
                Task {
                    await Task.detached {
                        defer { channel.invalidate() }
                        do {
                            let request = try AgentModelRequest(data: channel.read(timeout: 5), lease: lease, identity: identity, model: model)
                            try lease.check(instance: request.instance, boot: request.boot)
                            try channel.write(Data(#"{"kind":"start","status":200}"#.utf8), timeout: 2)
                            try await stream(request) { event in
                                try lease.check(instance: request.instance, boot: request.boot)
                                guard let text = String(data: event, encoding: .utf8) else { throw RelayError.providerUnavailable }
                                try channel.write(JSONValue.object(["kind": .string("event"), "data": .string(text)]).encoded(), timeout: 2)
                            }
                            try lease.check(instance: request.instance, boot: request.boot)
                            try channel.write(Data(#"{"kind":"end"}"#.utf8), timeout: 2)
                        } catch { /* Fixed EOF: no provider errors or request logging. */ }
                    }.value
                    channels.close(connection)
                }
            } else {
                Task {
                    defer { channel.invalidate(); channels.close(connection) }
                    do {
                        let bytes = try await Task.detached { try channel.read(timeout: 5) }.value
                        guard active, generation == epoch else { return }
                        if (try? BoundedJSON.parse(bytes)) == .object(["kind": .string("runtime_ready"), "protocol_major": .integer(1)]) {
                            guard control == nil, state == .starting else { throw AgentAPIError.invalidRequest }
                            control = channel
                            lease = RelayLease(instance: identity.instance.uuidString, boot: identity.boot.uuidString,
                                expiresAt: DeadlineClock.now + 900, maximumRequests: requestLimit, maximumInputBytes: 32 * 1024 * 1024, heartbeatRequired: true)
                            let task = JSONValue.object(["kind": .string("task"), "protocol_major": .integer(1), "prompt": .string(taskPrompt), "model": .string(taskModel)])
                            taskPrompt = ""
                            try await Task.detached { try channel.write(task.encoded(), timeout: 2) }.value
                            guard active, generation == epoch else { return }
                            state = .running
                            startHeartbeat(channel, epoch: epoch)
                            var frames = 0
                            while active, generation == epoch {
                                let message = try await Task.detached { try channel.read(timeout: 20) }.value
                                guard active, generation == epoch else { return }
                                frames += 1
                                guard frames <= 1000 else { throw AgentAPIError.rateLimited }
                                try lease?.check(instance: identity.instance.uuidString, boot: identity.boot.uuidString)
                                let value = try BoundedJSON.parse(message)
                                if let fields = value.object, Set(fields.keys) == ["kind", "sequence"], fields["kind"] == .string("alive"),
                                   let sequence = fields["sequence"]?.integer, sequence > acknowledgedSequence, sequence <= heartbeatSequence {
                                    acknowledgedSequence = Int(sequence)
                                    continue
                                }
                                if let succeeded = try projection.accept(message) { finish(succeeded ? .succeeded : .failed); return }
                                output = projection.text
                            }
                        } else {
                            guard state == .running, let lease else { throw AgentAPIError.unavailable }
                            await api.serve(channel, caller: caller, request: bytes) {
                                try lease.check(instance: identity.instance.uuidString, boot: identity.boot.uuidString)
                            }
                        }
                    } catch { if control === channel, generation == epoch { finish(.failed) } }
                }
            }
        } catch { channels.close(connection) }
    }

    private func startHeartbeat(_ channel: FramedChannel, epoch: UUID) {
        heartbeat?.cancel()
        heartbeat = Task { [weak self] in
            do {
                while !Task.isCancelled {
                    guard let self, self.active, self.generation == epoch, let lease = self.lease else { return }
                    self.heartbeatSequence += 1
                    let sequence = self.heartbeatSequence
                    try lease.renew(sequence: sequence)
                    let message = JSONValue.object(["kind": .string("lease"), "sequence": .integer(Int64(sequence)), "ttl_ms": .integer(10000)])
                    try await Task.detached { try channel.write(message.encoded(), timeout: 1) }.value
                    try await Task.sleep(for: .seconds(2))
                }
            } catch { if let self, self.generation == epoch { self.finish(.failed) } }
        }
    }

    public func guestDidStop(_ virtualMachine: VZVirtualMachine) { if machine === virtualMachine { finish(.failed) } }
    public func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) { if machine === virtualMachine { finish(.failed) } }
}
