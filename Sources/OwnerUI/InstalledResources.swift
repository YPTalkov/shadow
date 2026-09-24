import Foundation
import CryptoKit
import Security
import Darwin

/// The local signature seals the inventory; the inventory also excludes extra
/// Python import files and fixes the qualified host and every runtime resource.
public enum InstalledResources {
    private struct Inventory: Decodable {
        let schema: Int
        let macos: String
        let architecture: String
        let files: [String: String]
        let links: [String: String]
    }

    public static func verify(bundle: Bundle = .main) throws {
        guard bundle.bundleIdentifier == "com.yptalkov.shadow", let resources = bundle.resourceURL else { throw OwnerConfigurationError.unavailable }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(bundle.bundleURL as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode), nil) == errSecSuccess else { throw OwnerConfigurationError.unavailable }
        let os = ProcessInfo.processInfo.operatingSystemVersion
        #if arch(arm64)
        let architecture = "arm64"
        #else
        let architecture = "unsupported"
        #endif
        try verifyInventory(at: resources, macos: "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)", architecture: architecture)
    }

    static func verifyInventory(at directory: URL, macos: String, architecture: String) throws {
        let manager = FileManager.default
        let root = URL(fileURLWithPath: try canonicalPath(directory))
        let input = try FileHandle(forReadingFrom: root.appendingPathComponent("installation.json"))
        defer { try? input.close() }
        guard let bytes = try input.read(upToCount: 4 * 1024 * 1024 + 1), bytes.count <= 4 * 1024 * 1024 else { throw OwnerConfigurationError.unavailable }
        let inventory = try JSONDecoder().decode(Inventory.self, from: bytes)
        guard inventory.schema == 1, inventory.macos == macos, inventory.architecture == architecture,
              !inventory.files.isEmpty, inventory.files.count + inventory.links.count <= 20_000,
              Set(inventory.files.keys).isDisjoint(with: inventory.links.keys) else { throw OwnerConfigurationError.unavailable }
        let expected = Set(inventory.files.keys).union(inventory.links.keys)
        for name in expected {
            let parts = name.split(separator: "/", omittingEmptySubsequences: false)
            guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }), !name.contains("\0"), name != "installation.json" else { throw OwnerConfigurationError.unavailable }
        }
        guard let walker = manager.enumerator(at: root, includingPropertiesForKeys: nil, errorHandler: { _, _ in false }) else { throw OwnerConfigurationError.unavailable }
        var found = Set<String>()
        for case let url as URL in walker {
            var info = stat()
            guard lstat(url.path, &info) == 0 else { throw OwnerConfigurationError.unavailable }
            if info.st_mode & S_IFMT == S_IFDIR { continue }
            let name = String(url.path.dropFirst(root.path.count + 1))
            if name == "installation.json" {
                guard info.st_mode & S_IFMT == S_IFREG else { throw OwnerConfigurationError.unavailable }
                continue
            }
            guard found.insert(name).inserted, expected.contains(name) else { throw OwnerConfigurationError.unavailable }
            if let target = inventory.links[name] {
                guard info.st_mode & S_IFMT == S_IFLNK, !target.hasPrefix("/"),
                      try manager.destinationOfSymbolicLink(atPath: url.path) == target,
                      try canonicalPath(url).hasPrefix(root.path + "/"),
                      manager.fileExists(atPath: url.path) else { throw OwnerConfigurationError.unavailable }
            } else {
                guard info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
                      let expectedHash = inventory.files[name], expectedHash.count == 64 else { throw OwnerConfigurationError.unavailable }
                let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { throw OwnerConfigurationError.unavailable }
                let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
                var hash = SHA256()
                while let data = try file.read(upToCount: 1024 * 1024), !data.isEmpty { hash.update(data: data) }
                try file.close()
                guard hash.finalize().map({ String(format: "%02x", $0) }).joined() == expectedHash else { throw OwnerConfigurationError.unavailable }
            }
        }
        guard found == expected else { throw OwnerConfigurationError.unavailable }
    }

    private static func canonicalPath(_ url: URL) throws -> String {
        guard let path = realpath(url.path, nil) else { throw OwnerConfigurationError.unavailable }
        defer { free(path) }
        return String(cString: path)
    }
}
