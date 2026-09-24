import Foundation
import CryptoKit
import Darwin
import Virtualization

extension VZVirtualMachine {
    /// Keep the VM on its main queue across SDKs whose generated async start
    /// method lacks actor isolation. Only the completion result crosses back.
    @MainActor
    public func startOnMainActor() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            start(completionHandler: { continuation.resume(with: $0) })
        }
    }
}

public enum VMRole: Sendable {
    case agent
    case browser
}

public enum VMConfigurationError: Error, Equatable {
    case imageMismatch
    case unsafeImage
}

public struct VMImageIdentity: Sendable {
    public let kernelSHA256: String
    public let ramdiskSHA256: String
    public let imageSHA256: String

    public init(kernelSHA256: String, ramdiskSHA256: String, imageSHA256: String) {
        self.kernelSHA256 = kernelSHA256
        self.ramdiskSHA256 = ramdiskSHA256
        self.imageSHA256 = imageSHA256
    }
}

/// Constructs the only two supported VM device profiles. This type does not
/// launch or qualify an image; callers must verify pinned image hashes first.
public enum RuntimeVMConfiguration {
    public static func make(role: VMRole, kernel: URL, ramdisk: URL, image: URL, identity: VMImageIdentity) throws -> VZVirtualMachineConfiguration {
        guard try hash(kernel) == identity.kernelSHA256,
              try hash(ramdisk) == identity.ramdiskSHA256,
              try hash(image) == identity.imageSHA256 else {
            throw VMConfigurationError.imageMismatch
        }
        let configuration = VZVirtualMachineConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: kernel)
        boot.initialRamdiskURL = ramdisk
        boot.commandLine = "root=/dev/vda ro init=/sbin/init"
        configuration.bootLoader = boot
        configuration.platform = VZGenericPlatformConfiguration()
        configuration.cpuCount = 2
        configuration.memorySize = 4 * 1024 * 1024 * 1024
        configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        configuration.networkDevices = []
        configuration.directorySharingDevices = []
        let disk = try VZDiskImageStorageDeviceAttachment(url: image, readOnly: true)
        configuration.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: disk)]
        if role == .browser {
            let graphics = VZVirtioGraphicsDeviceConfiguration()
            graphics.scanouts = [VZVirtioGraphicsScanoutConfiguration(widthInPixels: 1280, heightInPixels: 800)]
            configuration.graphicsDevices = [graphics]
            configuration.keyboards = [VZUSBKeyboardConfiguration()]
            configuration.pointingDevices = [VZUSBScreenCoordinatePointingDeviceConfiguration()]
        } else {
            configuration.graphicsDevices = []
        }
        return configuration
    }

    private static func hash(_ file: URL) throws -> String {
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { throw VMConfigurationError.unsafeImage }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw VMConfigurationError.unsafeImage
        }
        var digest = SHA256()
        do {
            while let chunk = try handle.read(upToCount: 1024 * 1024), !chunk.isEmpty {
                digest.update(data: chunk)
            }
        } catch {
            throw VMConfigurationError.unsafeImage
        }
        var current = stat()
        guard lstat(file.path, &current) == 0,
              current.st_dev == info.st_dev,
              current.st_ino == info.st_ino,
              current.st_size == info.st_size,
              current.st_mtimespec.tv_sec == info.st_mtimespec.tv_sec,
              current.st_mtimespec.tv_nsec == info.st_mtimespec.tv_nsec else {
            throw VMConfigurationError.unsafeImage
        }
        return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
