import CryptoKit
import Darwin
import Foundation
import Security

public enum SourceHostError: String, Error, Sendable {
    case invalidConnector = "invalid_connector"
    case identityChanged = "connector_identity_changed"
    case unavailable = "source_unavailable"
    case notConfigured = "not_configured"
    case cancelled = "cancelled"
}

public struct SourceCandidate: Codable, Sendable {
    public let application: URL
    public let executable: URL
    public let identifier: String
    public let fingerprint: String
    public let requirement: Data
    public let capabilities: SourceCapabilities

    /// Inspect the sealed manifest without executing the selected connector.
    public static func inspect(_ application: URL) throws -> SourceCandidate {
        guard application.isFileURL, application.pathExtension == "app",
              application.standardizedFileURL == application.resolvingSymlinksInPath(),
              let bundle = Bundle(url: application), let executable = bundle.executableURL,
              let identifier = bundle.bundleIdentifier, identifier.utf8.count <= 256,
              executable.path.hasPrefix(application.path + "/") else { throw SourceHostError.invalidConnector }
        var code: SecStaticCode?
        var requirement: SecRequirement?
        var encoded: CFData?
        var signing: CFDictionary?
        guard SecStaticCodeCreateWithPath(application as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate), nil) == errSecSuccess,
              SecCodeCopySigningInformation(code, [], &signing) == errSecSuccess,
              let hash = (signing as? [String: Any])?[kSecCodeInfoUnique as String] as? Data,
              hash.count == 20 else { throw SourceHostError.invalidConnector }
        let expression = "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
        guard SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecRequirementCopyData(requirement, [], &encoded) == errSecSuccess, let encoded else { throw SourceHostError.invalidConnector }
        let manifest = application.appendingPathComponent("Contents/Resources/shadow-source.json")
        let data = try readRegular(manifest, maximum: 16_384, privateOnly: false)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["contract_major", "capabilities"],
              object["contract_major"] as? Int == 1,
              let raw = object["capabilities"] as? [String: Any],
              Set(raw.keys) == ["stable_items", "stable_groups", "complete_scopes", "deletion_evidence", "distinguishes_access_loss", "totp", "collection_mode", "version"] else { throw SourceHostError.invalidConnector }
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        let capabilities = try decoder.decode(SourceCapabilities.self, from: JSONSerialization.data(withJSONObject: raw))
        guard capabilities.version == 1,
              Set(capabilities.completeScopes).isSubset(of: ["account", "group"]),
              Set(capabilities.deletionEvidence).isSubset(of: ["item_tombstone", "group_tombstone"]),
              ["unattended", "owner_unlock_required", "owner_interaction_required"].contains(capabilities.collectionMode) else { throw SourceHostError.invalidConnector }
        return SourceCandidate(application: application, executable: URL(fileURLWithPath: executable.path), identifier: identifier,
                               fingerprint: try executableDigest(executable), requirement: encoded as Data, capabilities: capabilities)
    }

    func verify() throws {
        let current = try Self.inspect(application)
        guard current.executable == executable, current.identifier == identifier,
              current.fingerprint == fingerprint, current.requirement == requirement,
              current.capabilities == capabilities else { throw SourceHostError.identityChanged }
    }

    func verify(process: Process) throws {
        var code: SecCode?
        var requirement: SecRequirement?
        guard process.isRunning,
              SecRequirementCreateWithData(self.requirement as CFData, [], &requirement) == errSecSuccess, let requirement,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: process.processIdentifier] as CFDictionary, [], &code) == errSecSuccess, let code,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw SourceHostError.identityChanged }
        // The requirement pins the running image's CDHash. Looking up its disk
        // path alone would not securely identify the code already executing.
    }

    private static func executableDigest(_ path: URL) throws -> String {
        SHA256.hash(data: try readRegular(path, maximum: 128 * 1024 * 1024, privateOnly: false)).map { String(format: "%02x", $0) }.joined()
    }
}

public struct EnrolledSource: Codable, Identifiable, Sendable {
    public let id: UUID
    public let label: String
    public let candidate: SourceCandidate
    public var enabled: Bool
}

/// Owner-only registry. Digest keys stay in Keychain and never reach a producer.
@MainActor public final class SourceEnrollmentStore {
    private let path: URL
    private let vaultID: String
    private var records: [EnrolledSource]

    public init(root: URL, vaultID: String) throws {
        path = root.appendingPathComponent("sources.json")
        self.vaultID = vaultID
        var info = stat()
        guard lstat(root.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_mode & 0o077 == 0, info.st_uid == getuid() else { throw SourceHostError.unavailable }
        if lstat(path.path, &info) == 0 {
            records = try JSONDecoder().decode([EnrolledSource].self, from: readRegular(path, maximum: 256 * 1024, privateOnly: true))
            guard records.count <= 16, Set(records.map(\.id)).count == records.count else { throw SourceHostError.unavailable }
        } else {
            guard errno == ENOENT else { throw SourceHostError.unavailable }
            records = []
        }
    }

    public var sources: [EnrolledSource] { records }

    public func enroll(_ candidate: SourceCandidate, label: String) throws -> EnrolledSource {
        guard records.count < 16, !label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              label.utf8.count <= 128, !label.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw SourceHostError.invalidConnector }
        try candidate.verify()
        let source = EnrolledSource(id: UUID(), label: label, candidate: candidate, enabled: true)
        var key = Data(count: 32)
        guard key.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else { throw SourceHostError.unavailable }
        var query = keyQuery(source.id)
        query[kSecValueData as String] = key
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw SourceHostError.unavailable }
        do { try persist(records + [source]) }
        catch { SecItemDelete(keyQuery(source.id) as CFDictionary); throw error }
        return source
    }

    public func setEnabled(_ id: UUID, _ enabled: Bool) throws {
        guard let index = records.firstIndex(where: { $0.id == id }) else { throw SourceHostError.notConfigured }
        var updated = records; updated[index].enabled = enabled
        try persist(updated)
    }

    public func remove(_ id: UUID) throws {
        guard records.contains(where: { $0.id == id }) else { throw SourceHostError.notConfigured }
        try persist(records.filter { $0.id != id })
        SecItemDelete(keyQuery(id) as CFDictionary)
    }

    func digestKey(_ id: UUID) throws -> Data {
        guard records.contains(where: { $0.id == id && $0.enabled }) else { throw SourceHostError.notConfigured }
        var query = keyQuery(id)
        query[kSecReturnData as String] = true; query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data, data.count == 32 else { throw SourceHostError.unavailable }
        return data
    }

    private func keyQuery(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.source-digest", kSecAttrAccount as String: vaultID + ":" + id.uuidString.lowercased()]
    }

    private func persist(_ updated: [EnrolledSource]) throws {
        let temporary = path.deletingLastPathComponent().appendingPathComponent(".sources-\(UUID().uuidString)")
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw SourceHostError.unavailable }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? FileManager.default.removeItem(at: temporary) }
        try handle.write(contentsOf: JSONEncoder().encode(updated))
        guard fsync(fd) == 0, rename(temporary.path, path.path) == 0 else { throw SourceHostError.unavailable }
        let parent = open(path.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw SourceHostError.unavailable }
        defer { close(parent) }
        guard fsync(parent) == 0 else { throw SourceHostError.unavailable }
        records = updated
    }
}

private func readRegular(_ path: URL, maximum: Int, privateOnly: Bool) throws -> Data {
    let fd = open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw SourceHostError.invalidConnector }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
          info.st_size > 0, info.st_size <= maximum,
          !privateOnly || (info.st_mode & 0o077 == 0 && info.st_uid == getuid()),
          let data = try handle.read(upToCount: maximum + 1), data.count == info.st_size else { throw SourceHostError.invalidConnector }
    return data
}
