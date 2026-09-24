import Foundation
import Virtualization
import Darwin

public enum VMChannelRole: UInt32, Sendable {
    case agentBroker = 4050
    case agentModel = 4051
    case browserControl = 4052
    case browserEgress = 4053
}

public struct VMInstanceIdentity: Sendable {
    public let instance = UUID()
    public let boot = UUID()
}

@MainActor
public final class InstanceChannels: NSObject, @preconcurrency VZVirtioSocketListenerDelegate {
    public let identity = VMInstanceIdentity()
    private let device: VZVirtioSocketDevice
    private let allowed: Set<VMChannelRole>
    private var listeners: [VMChannelRole: VZVirtioSocketListener] = [:]
    private var connections: [ObjectIdentifier: VZVirtioSocketConnection] = [:]
    private var revoked = false
    private let accept: (VZVirtioSocketConnection, VMInstanceIdentity, VMChannelRole) -> Void

    public init(machine: VZVirtualMachine, role: VMRole, accept: @escaping (VZVirtioSocketConnection, VMInstanceIdentity, VMChannelRole) -> Void) throws {
        guard machine.socketDevices.count == 1, let device = machine.socketDevices.first as? VZVirtioSocketDevice else { throw VMConfigurationError.unsafeImage }
        self.device = device
        self.allowed = role == .agent ? [.agentBroker, .agentModel] : [.browserControl, .browserEgress]
        self.accept = accept
        super.init()
        for channel in allowed {
            let listener = VZVirtioSocketListener()
            listener.delegate = self
            listeners[channel] = listener
            device.setSocketListener(listener, forPort: channel.rawValue)
        }
    }

    public func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection connection: VZVirtioSocketConnection, from socketDevice: VZVirtioSocketDevice) -> Bool {
        guard !revoked, socketDevice === device, connections.count < 8,
              let channel = VMChannelRole(rawValue: connection.destinationPort), allowed.contains(channel),
              listeners[channel] === listener else { return false }
        connections[ObjectIdentifier(connection)] = connection
        DispatchQueue.main.async { [self] in
            guard !revoked, connections[ObjectIdentifier(connection)] != nil else { connection.close(); return }
            accept(connection, identity, channel)
        }
        return true
    }

    public func close(_ connection: VZVirtioSocketConnection) {
        guard connections.removeValue(forKey: ObjectIdentifier(connection)) != nil else { return }
        shutdown(connection.fileDescriptor, SHUT_RDWR)
        connection.close()
    }

    public func revoke() {
        revoked = true
        for channel in allowed { device.removeSocketListener(forPort: channel.rawValue) }
        for connection in connections.values {
            shutdown(connection.fileDescriptor, SHUT_RDWR)
            connection.close()
        }
        connections.removeAll()
        listeners.removeAll()
    }
}
