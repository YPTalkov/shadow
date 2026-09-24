import Foundation
import Darwin
import PolicyCore

/// Serializes the independent native restriction ledger. There is no operation
/// for a connector or restored KDBX file to clear a historical event.
public final class NativeRestrictions: @unchecked Sendable {
    private let lock = NSLock()
    private let path: URL
    private let anchor: GenerationAnchor

    public init(vaultDirectory: URL, vaultID: String) {
        path = vaultDirectory.appendingPathComponent("restrictions.sqlite")
        anchor = GenerationAnchor(vaultID: vaultID + ":restrictions")
    }

    public func initializeForEnrollment() throws {
        try lock.withLock {
            let ledger = try RestrictionLedger(path: path, anchor: anchor)
            try ledger.close()
        }
    }

    public func record(account: UUID, kind: RestrictionKind, eventID: UUID) throws {
        try record([RestrictionEvent(id: eventID, account: account, kind: kind)])
    }

    public func record(_ events: [RestrictionEvent]) throws {
        try lock.withLock {
            guard FileManager.default.fileExists(atPath: path.path), try anchor.read() != nil else { throw RestrictionLedgerError.recoveryRequired }
            let ledger = try RestrictionLedger(path: path, anchor: anchor)
            defer { try? ledger.close() }
            try ledger.appendBatch(events)
        }
    }

    public func latest(requireExisting: Bool) throws -> [UUID: RestrictionEvent] {
        try lock.withLock { try readLatest(requireExisting: requireExisting) }
    }

    private func readLatest(requireExisting: Bool) throws -> [UUID: RestrictionEvent] {
        let exists = FileManager.default.fileExists(atPath: path.path), checkpoint = try anchor.read()
        if !exists && checkpoint == nil && !requireExisting { return [:] }
        guard exists, checkpoint != nil else { throw RestrictionLedgerError.recoveryRequired }
        let ledger = try RestrictionLedger(path: path, anchor: anchor)
        defer { try? ledger.close() }
        var latest: [UUID: RestrictionEvent] = [:]
        for event in try ledger.allEvents() { latest[event.account] = event }
        return latest
    }

    public func needsRecoveryReview() -> Bool {
        lock.withLock { (try? readLatest(requireExisting: true)) == nil }
    }

    /// Called only by the private restore handshake after native owner review.
    /// Keep every newer event. Restored observations never establish freshness.
    public func reconcileRestore(mirrored: [UUID], acknowledgeUnknownHistory: Bool) throws {
        try lock.withLock {
            guard mirrored.count <= 50_000, Set(mirrored).count == mirrored.count else { throw RestrictionLedgerError.storageUnavailable }
            if let existing = try? readLatest(requireExisting: true) {
                let ledger = try RestrictionLedger(path: path, anchor: anchor)
                defer { try? ledger.close() }
                let added = mirrored.filter { existing[$0] == nil }.map { RestrictionEvent(id: UUID(), account: $0, kind: .historyUnknown) }
                try ledger.appendBatch(added)
                return
            }
            guard acknowledgeUnknownHistory else { throw RestrictionLedgerError.recoveryRequired }
            let parent = path.deletingLastPathComponent()
            let evidence = parent.appendingPathComponent("restriction-recovery-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(at: evidence, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            var originals: [URL] = []
            for suffix in ["", "-journal", "-wal", "-shm"] {
                let original = URL(fileURLWithPath: path.path + suffix)
                if try Self.preserve(original, to: evidence.appendingPathComponent(original.lastPathComponent)) { originals.append(original) }
            }
            try Self.sync(evidence)
            try Self.sync(parent)
            let candidate = parent.appendingPathComponent(".restriction-restore-\(UUID().uuidString).sqlite")
            let ledger = try RestrictionLedger.recover(at: candidate, anchor: anchor, accounts: mirrored)
            try ledger.close()
            // All history-unknown events are already anchored. Any interruption
            // until publication therefore fails ordinary ledger verification.
            for original in originals where original != path { try FileManager.default.removeItem(at: original) }
            guard rename(candidate.path, path.path) == 0 else { throw RestrictionLedgerError.storageUnavailable }
            try Self.sync(parent)
            _ = try readLatest(requireExisting: true)
        }
    }

    private static func preserve(_ source: URL, to destination: URL) throws -> Bool {
        let input = Darwin.open(source.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if input < 0 && errno == ENOENT { return false }
        guard input >= 0 else { throw RestrictionLedgerError.unsafePath }
        let file = FileHandle(fileDescriptor: input, closeOnDealloc: true)
        var before = stat()
        guard fstat(input, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == getuid(), before.st_nlink == 1, before.st_mode & 0o077 == 0,
              before.st_size <= 128 * 1024 * 1024 else { throw RestrictionLedgerError.unsafePath }
        var data = Data()
        while data.count <= 128 * 1024 * 1024 {
            guard let part = try file.read(upToCount: min(1024 * 1024, 128 * 1024 * 1024 + 1 - data.count)), !part.isEmpty else { break }
            data.append(part)
        }
        var after = stat(), current = stat()
        guard fstat(input, &after) == 0, lstat(source.path, &current) == 0,
              before.st_ino == current.st_ino, before.st_dev == current.st_dev,
              before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              data.count == before.st_size else { throw RestrictionLedgerError.recoveryRequired }
        let output = Darwin.open(destination.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard output >= 0 else { throw RestrictionLedgerError.storageUnavailable }
        let copy = FileHandle(fileDescriptor: output, closeOnDealloc: true)
        try copy.write(contentsOf: data)
        guard fsync(output) == 0 else { throw RestrictionLedgerError.storageUnavailable }
        return true
    }

    private static func sync(_ directory: URL) throws {
        let fd = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RestrictionLedgerError.storageUnavailable }
        defer { Darwin.close(fd) }
        guard fsync(fd) == 0 else { throw RestrictionLedgerError.storageUnavailable }
    }
}
