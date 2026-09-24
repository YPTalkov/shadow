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
            guard adapter.id == "synthetic-v1", adapter.credentialOrigins == ["https://app.shadow.test"], adapter.resourceOrigins.isSubset(of: ["https://app.shadow.test"]) else { throw AgentAPIError.unavailable }
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

    func authenticate(authorize: @escaping @MainActor (AuthenticationStage) throws -> Void, resolve: @escaping @MainActor () async throws -> PrivateCredential) async throws -> BrowserAuthenticationResult {
        do {
            try await start()
            guard try await receive() == .object(["kind": .string("ready")]) else { throw AgentAPIError.unavailable }
            try await send(.object(["kind": .string("login"), "adapter_id": .string(adapter.id)]))
            for _ in 0..<8 {
                let message = try await receive()
                if let fields = message.object, Set(fields.keys) == ["kind", "stage"], fields["kind"]?.string == "authorize",
                   let stage = fields["stage"]?.string.flatMap(AuthenticationStage.init(rawValue:)) {
                    try authorize(stage)
                    try await send(.object(["kind": .string("authorized"), "stage": .string(stage.rawValue)]))
                } else if message == .object(["kind": .string("resolve")]) {
                    let credential = try await resolve()
                    try await send(.object(["kind": .string("credential"), "username": .string(credential.username), "password": .string(credential.password), "totp": credential.totp.map(JSONValue.string) ?? .null]))
                } else if let fields = message.object, Set(fields.keys) == ["kind", "state"], fields["kind"]?.string == "authentication" {
                    switch fields["state"]?.string {
                    case "succeeded": return .succeeded
                    case "failed": return .failed
                    case "outcome_unknown": return .outcomeUnknown
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
        try await machine.start()
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
                Task {
                    _ = await Task.detached {
                        do {
                            let message = try BoundedJSON.parse(transport.read(timeout: 2), maximumBytes: 512)
                            guard let fields = message.object, Set(fields.keys) == ["host", "port"], fields["port"]?.integer == 443, let host = fields["host"]?.string else { throw EgressError.denied }
                            if let fixture {
                                guard host == "app.shadow.test", let sentinel = destinations.first else { throw EgressError.denied }
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
        self.init(access: access, journal: journal, resolve: { account, origin in
            try await worker.resolveCredential(entry: account.id, revision: account.policy.revision, origin: origin)
        }, makeDriver: { adapter in try ProtectedBrowserVM(image: image, adapter: adapter) })
    }

    package convenience init(access: AccessCoordinator, journal: OperationJournal, worker: PrivateVaultWorker, image: BrowserVMImage, fixtureTunnel: @escaping BrowserFixtureTunnel) {
        self.init(access: access, journal: journal, resolve: { account, origin in
            try await worker.resolveCredential(entry: account.id, revision: account.policy.revision, origin: origin)
        }, makeDriver: { adapter in try ProtectedBrowserVM(image: image, adapter: adapter, fixture: fixtureTunnel) })
    }
}
