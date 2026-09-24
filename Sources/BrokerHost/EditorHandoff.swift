import AppKit
import Foundation
import Darwin
import Security

/// The supervisor holds the ordinary writer lease while the worker is locked
/// for owner editing. The persistent worker journal also gates access on restart.
public final class EditorReservation {
    private var descriptor: Int32

    public init(vaultDirectory: URL) throws {
        let fd = open(vaultDirectory.appendingPathComponent("writer.lock").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw VaultWorkerError.unavailable }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o077 == 0, info.st_nlink == 1, info.st_uid == getuid(),
              flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            throw VaultWorkerError.unavailable
        }
        descriptor = fd
    }

    deinit { release() }

    public func release() {
        if descriptor >= 0 {
            flock(descriptor, LOCK_UN)
            close(descriptor)
            descriptor = -1
        }
    }
}

@MainActor public enum QualifiedEditor {
    public static var isRunning: Bool {
        !NSRunningApplication.runningApplications(withBundleIdentifier: "org.keepassxc.keepassxc").isEmpty
    }

    public static func openCheckout(_ checkout: URL) async throws {
        let application = URL(fileURLWithPath: "/Applications/KeePassXC.app")
        guard let bundle = Bundle(url: application),
              bundle.bundleIdentifier == "org.keepassxc.keepassxc",
              bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String == "2.7.12" else { throw VaultWorkerError.unavailable }
        var code: SecStaticCode?
        var requirement: SecRequirement?
        let expression = "anchor apple generic and identifier \"org.keepassxc.keepassxc\" and certificate leaf[subject.OU] = \"G2S7P7J672\""
        guard SecStaticCodeCreateWithPath(application as CFURL, [], &code) == errSecSuccess,
              SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess,
              let code, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate), requirement) == errSecSuccess else { throw VaultWorkerError.unavailable }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        // Only an encrypted checkout URL is delivered. No secret in arguments,
        // environment, pasteboard, or KeePassXC's stdin.
        _ = try await NSWorkspace.shared.open([checkout], withApplicationAt: application, configuration: configuration)
    }
}
