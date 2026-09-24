import Foundation
import Virtualization
import RuntimeHost
import BrokerHost
import PolicyCore
import OwnerUI

/// Boots the sealed production image without a fixture CA or egress exception.
@MainActor final class ProductionBrowserProbe {
    private var channels: InstanceChannels?
    private var ready = false
    private var failed = false
    private var connected = false
    private var leaseStarted: TimeInterval = 0
    private var control: FramedChannel?

    func run() async throws {
        guard CommandLine.arguments.count == 3, let bundle = Bundle(path: CommandLine.arguments[2]), let resources = bundle.resourceURL else { throw AgentAPIError.unavailable }
        try InstalledResources.verify(bundle: bundle)
        let image = try BrowserVMImage.packaged(at: resources.appendingPathComponent("browser"))
        let config = try RuntimeVMConfiguration.make(role: .browser, kernel: image.kernel, ramdisk: image.ramdisk, image: image.disk, identity: image.identity)
        guard let boot = config.bootLoader as? VZLinuxBootLoader else { throw AgentAPIError.unavailable }
        boot.commandLine = "console=hvc0 rdinit=/init panic=-1 quiet"
        let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
        serial.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: try FileHandle(forWritingTo: URL(fileURLWithPath: "/dev/null")))
        config.serialPorts = [serial]
        try config.validate()
        let machine = VZVirtualMachine(configuration: config)
        channels = try InstanceChannels(machine: machine, role: .browser) { [weak self] connection, _, role in
            guard let self, !self.connected, role == .browserControl else { connection.close(); return }
            self.connected = true
            Task { @MainActor in
                do {
                    let channel = try FramedChannel(descriptor: connection.fileDescriptor, maximumBytes: 65_536)
                    self.control = channel
                    let hello = try await Task.detached { try BoundedJSON.parse(channel.read(timeout: 3)) }.value
                    guard hello == .object(["kind": .string("supervisor"), "protocol_major": .integer(1)]) else { throw AgentAPIError.unavailable }
                    self.leaseStarted = DeadlineClock.now
                    try channel.write(JSONValue.object(["kind": .string("lease"), "sequence": .integer(1), "ttl_ms": .integer(10000)]).encoded())
                    let message = try await Task.detached { try BoundedJSON.parse(channel.read(timeout: 8)) }.value
                    guard message == .object(["kind": .string("ready")]) else { throw AgentAPIError.unavailable }
                    self.ready = true
                } catch { self.failed = true }
            }
        }
        defer { channels?.revoke(); Task { try? await machine.stop() } }
        try await machine.start()
        let deadline = DeadlineClock.now + 35
        while !failed, DeadlineClock.now < deadline, machine.state != .stopped {
            try await Task.sleep(for: .milliseconds(100))
        }
        // The worker's three-second control-silence limit may close the VM
        // before PID 1's independent ten-second lease deadline.
        guard ready, !failed, machine.state == .stopped, (0...13).contains(DeadlineClock.now - leaseStarted) else {
            print("PRODUCTION_BROWSER_READY=\(ready)")
            print("PRODUCTION_BROWSER_CONTROL_FAILED=\(failed)")
            print("PRODUCTION_BROWSER_STOPPED=\(machine.state == .stopped)")
            print("PRODUCTION_BROWSER_ELAPSED_MS=\(Int((DeadlineClock.now - leaseStarted) * 1000))")
            throw AgentAPIError.unavailable
        }
        print("PRODUCTION_BROWSER_READY=pass")
        print("PRODUCTION_BROWSER_LEASE_STOP=pass")
        print("PRODUCTION_BROWSER_STOP_MS=\(Int((DeadlineClock.now - leaseStarted) * 1000))")
    }
}
