import Foundation
import Darwin
import BrokerHost

public enum OwnerConfigurationError: Error {
    case unavailable
    case alreadyRunning
}

@MainActor
public final class OwnerConfiguration {
    public let root: URL
    public let vaultDirectory: URL
    public let vaultID: String
    public let python: URL
    public let browserImage: BrowserVMImage?
    public let agentImage: AgentVMImage?
    private let lock: FileHandle

    public init(root: URL, python: URL, browserImage: BrowserVMImage? = nil, agentImage: AgentVMImage? = nil) throws {
        self.root = root
        self.python = python
        self.browserImage = browserImage
        self.agentImage = agentImage
        vaultDirectory = root.appendingPathComponent("vault", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var info = stat()
        guard lstat(root.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_mode & 0o077 == 0, info.st_uid == getuid() else { throw OwnerConfigurationError.unavailable }
        try Self.syncDirectory(root.deletingLastPathComponent())
        let fd = open(root.appendingPathComponent("owner.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw OwnerConfigurationError.unavailable }
        lock = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o077 == 0,
              info.st_nlink == 1, info.st_uid == getuid() else { throw OwnerConfigurationError.unavailable }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw OwnerConfigurationError.alreadyRunning }
        let identity = root.appendingPathComponent("vault-id")
        let input = open(identity.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if input >= 0 {
            let file = FileHandle(fileDescriptor: input, closeOnDealloc: true)
            var details = stat()
            guard fstat(input, &details) == 0, details.st_mode & S_IFMT == S_IFREG, details.st_size == 36, details.st_mode & 0o077 == 0, details.st_uid == getuid(), details.st_nlink == 1,
                  let data = try file.read(upToCount: 37), let value = String(data: data, encoding: .utf8), UUID(uuidString: value) != nil else { throw OwnerConfigurationError.unavailable }
            vaultID = value
        } else {
            guard errno == ENOENT, !FileManager.default.fileExists(atPath: vaultDirectory.appendingPathComponent("vault.kdbx").path) else { throw OwnerConfigurationError.unavailable }
            let value = UUID().uuidString.lowercased()
            let output = open(identity.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard output >= 0 else { throw OwnerConfigurationError.unavailable }
            let file = FileHandle(fileDescriptor: output, closeOnDealloc: true)
            try file.write(contentsOf: Data(value.utf8))
            guard fsync(output) == 0 else { throw OwnerConfigurationError.unavailable }
            try Self.syncDirectory(root)
            vaultID = value
        }
    }

    private static func syncDirectory(_ url: URL) throws {
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw OwnerConfigurationError.unavailable }
        defer { close(fd) }
        guard fsync(fd) == 0 else { throw OwnerConfigurationError.unavailable }
    }

    public static func local() throws -> OwnerConfiguration {
        let root = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("Shadow", isDirectory: true)
        #if DEBUG
        let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let python = source.appendingPathComponent(".venv/bin/python")
        let browserImage = try? BrowserVMImage.packaged(at: source.appendingPathComponent(".build/guest-cache/browser"))
        let agentImage = try? AgentVMImage.packaged(at: source.appendingPathComponent(".build/guest-cache/agent"))
        #else
        try InstalledResources.verify()
        guard let resources = Bundle.main.resourceURL else { throw OwnerConfigurationError.unavailable }
        let python = resources.appendingPathComponent("python/bin/python3")
        let browserImage = try BrowserVMImage.packaged(at: resources.appendingPathComponent("browser"))
        let agentImage = try AgentVMImage.packaged(at: resources.appendingPathComponent("agent"))
        #endif
        return try OwnerConfiguration(root: root, python: python, browserImage: browserImage, agentImage: agentImage)
    }
}
