import Foundation
import PolicyCore
import RuntimeHost
import EgressGateway
import Virtualization

public struct BrowserVMImage: Sendable {
    public let kernel: URL
    public let ramdisk: URL
    public let disk: URL
    public let identity: VMImageIdentity
    public init(kernel: URL, ramdisk: URL, disk: URL, identity: VMImageIdentity) {
        self.kernel = kernel; self.ramdisk = ramdisk; self.disk = disk; self.identity = identity
    }

    public static func packaged(at directory: URL) throws -> Self {
        let bytes = try Data(contentsOf: directory.appendingPathComponent("production-manifest.json"))
        let manifest = try BoundedJSON.parse(bytes, maximumBytes: 8192)
        guard manifest["profile"]?.string == "runtime", let files = manifest["files"]?.object,
              let kernel = files["kernel"]?.string, let ramdisk = files["initrd"]?.string, let disk = files["disk"]?.string else { throw AgentAPIError.unavailable }
        return Self(kernel: directory.appendingPathComponent("kernel"), ramdisk: directory.appendingPathComponent("initrd-runtime"),
                    disk: directory.appendingPathComponent("disk"), identity: VMImageIdentity(kernelSHA256: kernel, ramdiskSHA256: ramdisk, imageSHA256: disk))
    }
}

extension QualifiedAdapterPolicy {
    public static var packaged: [Self] {
        (PackagedAdapters.manifests.object ?? [:]).compactMap { id, value in
            guard let loginURL = value["login"]?["url"]?.string, let host = URLComponents(string: loginURL)?.host,
                  let origin = value["origin"]?.string else { return nil }
            return Self(id: id, credentialOrigins: ["https://" + host], resourceOrigins: [origin], actions: [.login, .observe, .extract, .navigate, .click])
        }
    }
}

/// Only the diagnostic executable supplies this fixed synthetic gateway. The
/// owner application constructs the driver through the production initializer.
package typealias BrowserFixtureTunnel = @Sendable (Int32, FramedChannel, @Sendable () throws -> Void) throws -> Void

private actor ControlWriter {
    let channel: FramedChannel
    init(_ channel: FramedChannel) { self.channel = channel }
    func write(_ value: JSONValue) throws { try channel.write(value.encoded(), timeout: 1) }
}

@MainActor final class ProtectedBrowserVM: NSObject, ProtectedBrowserDriver, @preconcurrency VZVirtualMachineDelegate {
    private let image: BrowserVMImage
    private let adapter: QualifiedAdapterPolicy
    private let fixture: BrowserFixtureTunnel?
    private let destinations: Set<HTTPSDestination>
    private let session = UUID().uuidString
    private var machine: VZVirtualMachine?
    private var channels: InstanceChannels?
    private var channel: FramedChannel?
    private var writer: ControlWriter?
    private var lease: EgressLease?
    private var sequence = 0
    private var revoked = false
    private var acceptingControl = false

    init(image: BrowserVMImage, adapter: QualifiedAdapterPolicy, fixture: BrowserFixtureTunnel? = nil) throws {
        self.image = image; self.adapter = adapter; self.fixture = fixture
        if fixture != nil {
            guard ["synthetic-v1", "synthetic-sso-v1"].contains(adapter.id),
                  adapter.credentialOrigins == [adapter.id == "synthetic-sso-v1" ? "https://auth.shadow.test" : "https://app.shadow.test"],
                  adapter.resourceOrigins == ["https://app.shadow.test"] else { throw AgentAPIError.unavailable }
            // Synthetic forwarding still uses the real expiring native lease.
            // This sentinel destination is never resolved or connected to.
            destinations = [try HTTPSDestination(host: "example.com", port: 443)]
        } else {
            destinations = try Set(adapter.credentialOrigins.union(adapter.resourceOrigins).map { origin in
                guard let url = URLComponents(string: origin), url.scheme == "https", let host = url.host,
                      origin == "https://" + host else { throw AgentAPIError.unavailable }
                return try HTTPSDestination(host: host, port: 443)
            })
        }
        super.init()
    }

    var ownerMachine: VZVirtualMachine? { revoked ? nil : machine }

    func authenticate(authorize: @escaping @MainActor (AuthenticationStage) throws -> Void, resolve: @escaping @MainActor () async throws -> PrivateCredential, owner: @escaping @MainActor () async throws -> Void) async throws -> BrowserAuthenticationResult {
        do {
            try await start()
            guard try await receive() == .object(["kind": .string("ready")]) else { throw AgentAPIError.unavailable }
            try await send(.object(["kind": .string("login"), "adapter_id": .string(adapter.id)]))
            for _ in 0..<10 {
                let message = try await receive()
                if let fields = message.object, Set(fields.keys) == ["kind", "stage"], fields["kind"]?.string == "authorize",
                   let stage = fields["stage"]?.string.flatMap(AuthenticationStage.init(rawValue:)) {
                    try authorize(stage)
                    try await send(.object(["kind": .string("authorized"), "stage": .string(stage.rawValue)]))
                } else if message == .object(["kind": .string("resolve")]) {
                    let credential = try await resolve()
                    try await send(.object(["kind": .string("credential"), "username": .string(credential.username), "password": .string(credential.password), "totp": credential.totp.map(JSONValue.string) ?? .null]))
                } else if message == .object(["kind": .string("owner_challenge")]) {
                    try await owner()
                    try await send(.object(["kind": .string("owner_completed")]))
                } else if let fields = message.object, Set(fields.keys) == ["kind", "state", "code"], fields["kind"]?.string == "authentication" {
                    let code = fields["code"]?.string.flatMap(AgentAPIError.init(rawValue:))
                    switch fields["state"]?.string {
                    case "succeeded":
                        guard fields["code"] == .null else { throw AgentAPIError.unavailable }
                        return .succeeded
                    case "failed": return .failed(code ?? .unavailable)
                    case "outcome_unknown": return .outcomeUnknown(code ?? .unavailable)
                    default: throw AgentAPIError.unavailable
                    }
                } else { throw AgentAPIError.unavailable }
            }
            throw AgentAPIError.unavailable
        } catch { revoke(); throw AgentAPIError.unavailable }
    }

    func renew(sequence: Int) async throws {
        guard !revoked, sequence > self.sequence else { throw AgentAPIError.unavailable }
        self.sequence = sequence
        if let lease { try lease.renew(sequence: sequence) }
        if writer != nil { try await send(.object(["kind": .string("lease"), "sequence": .integer(Int64(sequence)), "ttl_ms": .integer(10000)])) }
    }

    func perform(_ operation: String, arguments: [String: JSONValue]) async throws -> ProtectedBrowserResult {
        try checkLease()
        try await send(.object(["kind": .string("action"), "operation": .string(operation), "arguments": .object(arguments)]))
        let message = try await receive()
        if let fields = message.object, Set(fields.keys) == ["kind", "view"], fields["kind"]?.string == "view", let view = fields["view"] {
            guard view["view_id"]?.string == (arguments["view_id"] ?? arguments["schema_id"])?.string else { throw AgentAPIError.unsupportedView }
            return .view(try SafeBrowserView(view, adapterID: adapter.id))
        }
        if message == .object(["kind": .string("completed")]) { return .completed }
        if let fields = message.object, Set(fields.keys) == ["kind", "code"], fields["kind"]?.string == "error",
           let code = fields["code"]?.string.flatMap(AgentAPIError.init(rawValue:)) { throw code }
        throw AgentAPIError.unavailable
    }

    func revoke() {
        guard !revoked else { return }
        revoked = true
        lease?.revoke()
        channel?.invalidate()
        channels?.revoke()
        if let machine {
            self.machine = nil
            Task { try? await machine.stop() }
        }
    }

    func checkLease() throws {
        guard !revoked else { throw AgentAPIError.unavailable }
        if let lease, let identity = channels?.identity, let destination = destinations.first {
            try lease.check(instance: identity.instance.uuidString, boot: identity.boot.uuidString, session: session, destination: destination)
        }
    }

    private func start() async throws {
        guard !revoked, machine == nil, sequence > 0 else { throw AgentAPIError.unavailable }
        let config = try RuntimeVMConfiguration.make(role: .browser, kernel: image.kernel, ramdisk: image.ramdisk, image: image.disk, identity: image.identity)
        guard let boot = config.bootLoader as? VZLinuxBootLoader else { throw AgentAPIError.unavailable }
        boot.commandLine = "console=hvc0 rdinit=/init panic=-1 quiet"
        let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
        serial.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: try FileHandle(forWritingTo: URL(fileURLWithPath: "/dev/null")))
        config.serialPorts = [serial]
        try config.validate()
        let machine = VZVirtualMachine(configuration: config)
        machine.delegate = self
        self.machine = machine
        channels = try InstanceChannels(machine: machine, role: .browser) { [weak self] connection, identity, role in
            guard let self, !self.revoked else { connection.close(); return }
            self.accept(connection, identity: identity, role: role)
        }
        guard let identity = channels?.identity else { throw AgentAPIError.unavailable }
        lease = EgressLease(instance: identity.instance.uuidString, boot: identity.boot.uuidString, session: session, destinations: destinations, expiresAt: DeadlineClock.now + 10)
        try lease?.renew(sequence: sequence)
        try await machine.startOnMainActor()
        let deadline = DeadlineClock.now + 20
        while channel == nil {
            guard !revoked, DeadlineClock.now < deadline else { throw AgentAPIError.unavailable }
            try await Task.sleep(for: .milliseconds(50))
        }
    }

    private func accept(_ connection: VZVirtioSocketConnection, identity: VMInstanceIdentity, role: VMChannelRole) {
        do {
            let transport = try FramedChannel(descriptor: connection.fileDescriptor, maximumBytes: role == .browserControl ? 2 * 1024 * 1024 : 512)
            if role == .browserControl {
                guard !acceptingControl else { channels?.close(connection); return }
                acceptingControl = true
                Task {
                    do {
                        let hello = try await Task.detached { try BoundedJSON.parse(transport.read(timeout: 3)) }.value
                        guard !revoked, hello == .object(["kind": .string("supervisor"), "protocol_major": .integer(1)]) else { throw AgentAPIError.unavailable }
                        writer = ControlWriter(transport)
                        try await send(.object(["kind": .string("lease"), "sequence": .integer(Int64(sequence)), "ttl_ms": .integer(10000)]))
                        channel = transport
                    } catch { revoke() }
                }
            } else if role == .browserEgress, let lease {
                let instance = identity.instance.uuidString, boot = identity.boot.uuidString, session = session
                let destinations = destinations, fixture = fixture, descriptor = connection.fileDescriptor
                let fixtureHosts = Set(adapter.credentialOrigins.union(adapter.resourceOrigins).compactMap { URLComponents(string: $0)?.host })
                Task {
                    _ = await Task.detached {
                        do {
                            let message = try BoundedJSON.parse(transport.read(timeout: 2), maximumBytes: 512)
                            guard let fields = message.object, Set(fields.keys) == ["host", "port"], fields["port"]?.integer == 443, let host = fields["host"]?.string else { throw EgressError.denied }
                            if let fixture {
                                guard fixtureHosts.contains(host), let sentinel = destinations.first else { throw EgressError.denied }
                                try fixture(descriptor, transport) { try lease.check(instance: instance, boot: boot, session: session, destination: sentinel) }
                            } else {
                                let destination = try HTTPSDestination(host: host, port: 443)
                                try Gateway.tunnel(guest: descriptor, destination: destination, lease: lease, instance: instance, boot: boot, session: session) {
                                    try transport.write(JSONValue.object(["kind": .string("connected")]).encoded(), timeout: 1)
                                }
                            }
                        } catch { /* Close the tunnel without raw diagnostics. */ }
                    }.value
                    channels?.close(connection)
                }
            } else { channels?.close(connection) }
        } catch { channels?.close(connection) }
    }

    private func send(_ message: JSONValue) async throws {
        guard !revoked, let writer else { throw AgentAPIError.unavailable }
        try await writer.write(message)
        guard !revoked else { throw AgentAPIError.unavailable }
    }

    private func receive() async throws -> JSONValue {
        guard !revoked, let channel else { throw AgentAPIError.unavailable }
        let result = try await Task.detached { try BoundedJSON.parse(channel.read(timeout: 20), maximumBytes: 2 * 1024 * 1024) }.value
        guard !revoked else { throw AgentAPIError.unavailable }
        return result
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) { revoke() }
    func guestDidStop(_ virtualMachine: VZVirtualMachine) { revoke() }
}

extension ProtectedSessionService {
    public convenience init(access: AccessCoordinator, journal: OperationJournal, worker: PrivateVaultWorker, image: BrowserVMImage) {
        self.init(access: access, journal: journal, workerAlive: { worker.isRunning }, resolve: { account, origin, includeTOTP in
            try await worker.resolveCredential(entry: account.id, revision: account.policy.revision, origin: origin, includeTOTP: includeTOTP)
        }, makeDriver: { adapter in try ProtectedBrowserVM(image: image, adapter: adapter) })
    }

    package convenience init(access: AccessCoordinator, journal: OperationJournal, worker: PrivateVaultWorker, image: BrowserVMImage, fixtureTunnel: @escaping BrowserFixtureTunnel) {
        self.init(access: access, journal: journal, workerAlive: { worker.isRunning }, resolve: { account, origin, includeTOTP in
            try await worker.resolveCredential(entry: account.id, revision: account.policy.revision, origin: origin, includeTOTP: includeTOTP)
        }, makeDriver: { adapter in try ProtectedBrowserVM(image: image, adapter: adapter, fixture: fixtureTunnel) })
    }
}
