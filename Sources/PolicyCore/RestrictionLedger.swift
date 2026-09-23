import CryptoKit
import Darwin
import Foundation
import SQLite3

public enum RestrictionLedgerError: Error, Equatable {
    case recoveryRequired
    case unsafePath
    case storageUnavailable
}

public enum RestrictionKind: String, Sendable {
    case deletedAtSource
    case accessLost
    case staleMirror
    case historyUnknown
}

public struct RestrictionEvent: Sendable {
    public let id: UUID
    public let account: UUID
    public let kind: RestrictionKind
    public init(id: UUID, account: UUID, kind: RestrictionKind) { self.id = id; self.account = account; self.kind = kind }
}

/// Append-only restriction history. Its independent Keychain anchor detects an
/// ordinary rollback of this SQLite file, even if the encrypted vault is old.
public final class RestrictionLedger {
    private struct Row {
        let id: UUID
        let account: UUID
        let kind: RestrictionKind
        let previous: String
        let head: String
    }

    private let anchor: GenerationAnchor
    private let file: URL
    private var database: OpaquePointer?
    private var fileIdentity: NSNumber?
    private static let genesis = hash("shadow-restrictions-v1")

    public init(path: URL, anchor: GenerationAnchor) throws {
        self.file = path
        self.anchor = anchor
        let existed = FileManager.default.fileExists(atPath: path.path)
        guard !path.hasDirectoryPath else { throw RestrictionLedgerError.unsafePath }
        let parent = path.deletingLastPathComponent()
        var details = stat()
        guard lstat(parent.path, &details) == 0, details.st_mode & S_IFMT == S_IFDIR,
              details.st_uid == getuid() else { throw RestrictionLedgerError.unsafePath }
        let parentAttributes = try FileManager.default.attributesOfItem(atPath: parent.path)
        guard parentAttributes[.type] as? FileAttributeType == .typeDirectory,
              let parentPermissions = parentAttributes[.posixPermissions] as? Int,
              parentPermissions & 0o077 == 0 else {
            throw RestrictionLedgerError.unsafePath
        }
        if existed {
            guard lstat(path.path, &details) == 0, details.st_mode & S_IFMT == S_IFREG,
                  details.st_uid == getuid(), details.st_nlink == 1 else { throw RestrictionLedgerError.unsafePath }
            let values = try path.resourceValues(forKeys: [.isSymbolicLinkKey])
            guard values.isSymbolicLink != true else { throw RestrictionLedgerError.unsafePath }
            let attributes = try FileManager.default.attributesOfItem(atPath: path.path)
            guard attributes[.type] as? FileAttributeType == .typeRegular,
                  let permissions = attributes[.posixPermissions] as? Int,
                  permissions & 0o077 == 0 else {
                throw RestrictionLedgerError.unsafePath
            }
        } else if try anchor.read() != nil {
            throw RestrictionLedgerError.recoveryRequired
        }
        if !existed {
            let fd = Darwin.open(path.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw RestrictionLedgerError.unsafePath }
            Darwin.close(fd)
        }
        guard let canonical = realpath(path.path, nil) else { throw RestrictionLedgerError.unsafePath }
        defer { free(canonical) }
        guard sqlite3_open_v2(canonical, &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK else {
            throw RestrictionLedgerError.storageUnavailable
        }
        do {
            try execute("PRAGMA synchronous=FULL")
            try execute("PRAGMA journal_mode=DELETE")
            try execute("CREATE TABLE IF NOT EXISTS restriction_event (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, account TEXT NOT NULL, kind TEXT NOT NULL, previous TEXT NOT NULL, head TEXT NOT NULL)")
            if !existed {
                let fd = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { throw RestrictionLedgerError.storageUnavailable }
                let synced = fsync(fd)
                Darwin.close(fd)
                guard synced == 0 else { throw RestrictionLedgerError.storageUnavailable }
                try anchor.advance(expected: nil, to: Self.genesis)
            }
            fileIdentity = try FileManager.default.attributesOfItem(atPath: path.path)[.systemFileNumber] as? NSNumber
            try verify()
        } catch {
            _ = sqlite3_close(database)
            database = nil
            throw error
        }
    }

    deinit {
        if let database { _ = sqlite3_close(database) }
    }

    public func close() throws {
        guard let database else { return }
        guard sqlite3_close(database) == SQLITE_OK else { throw RestrictionLedgerError.storageUnavailable }
        self.database = nil
    }

    public func append(account: UUID, kind: RestrictionKind, id: UUID = UUID()) throws -> RestrictionEvent {
        let event = RestrictionEvent(id: id, account: account, kind: kind)
        try appendBatch([event])
        return event
    }

    public func appendBatch(_ events: [RestrictionEvent]) throws {
        guard events.count <= 256 else { throw RestrictionLedgerError.storageUnavailable }
        let previous = try verify()
        var known = Dictionary(uniqueKeysWithValues: try rows().map { ($0.id, ($0.account, $0.kind)) })
        var inserted: [(RestrictionEvent, String, String)] = []
        var head = previous
        for event in events {
            if let existing = known[event.id] {
                guard existing.0 == event.account, existing.1 == event.kind else { throw RestrictionLedgerError.recoveryRequired }
                continue
            }
            let next = Self.hash("\(head)|\(event.id.uuidString)|\(event.account.uuidString)|\(event.kind.rawValue)")
            inserted.append((event, head, next))
            known[event.id] = (event.account, event.kind)
            head = next
        }
        if inserted.isEmpty { return }
        try execute("BEGIN IMMEDIATE")
        do {
            let statement = try prepare("INSERT INTO restriction_event (id, account, kind, previous, head) VALUES (?, ?, ?, ?, ?)")
            defer { sqlite3_finalize(statement) }
            for (event, prior, next) in inserted {
                sqlite3_reset(statement)
                sqlite3_clear_bindings(statement)
                try bind(event.id.uuidString, at: 1, to: statement)
                try bind(event.account.uuidString, at: 2, to: statement)
                try bind(event.kind.rawValue, at: 3, to: statement)
                try bind(prior, at: 4, to: statement)
                try bind(next, at: 5, to: statement)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw RestrictionLedgerError.storageUnavailable }
            }
            try execute("COMMIT")
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
        // A crash between commit and anchor advance leaves a mismatch and denies use.
        try anchor.advance(expected: previous, to: head)
    }

    public func events(for account: UUID) throws -> [RestrictionEvent] {
        _ = try verify()
        return try rows().filter { $0.account == account }.map {
            RestrictionEvent(id: $0.id, account: $0.account, kind: $0.kind)
        }
    }

    public func allEvents() throws -> [RestrictionEvent] {
        _ = try verify()
        return try rows().map { RestrictionEvent(id: $0.id, account: $0.account, kind: $0.kind) }
    }

    @discardableResult
    private func verify() throws -> String {
        let values = try file.resourceValues(forKeys: [.isSymbolicLinkKey])
        guard values.isSymbolicLink != true,
              let currentIdentity = try FileManager.default.attributesOfItem(atPath: file.path)[.systemFileNumber] as? NSNumber,
              currentIdentity == fileIdentity else {
            throw RestrictionLedgerError.recoveryRequired
        }
        var expected = Self.genesis
        for row in try rows() {
            guard row.previous == expected,
                  row.head == Self.hash("\(expected)|\(row.id.uuidString)|\(row.account.uuidString)|\(row.kind.rawValue)") else {
                throw RestrictionLedgerError.recoveryRequired
            }
            expected = row.head
        }
        guard try anchor.read() == expected else { throw RestrictionLedgerError.recoveryRequired }
        return expected
    }

    private func rows() throws -> [Row] {
        let statement = try prepare("SELECT id, account, kind, previous, head FROM restriction_event ORDER BY seq")
        defer { sqlite3_finalize(statement) }
        var rows: [Row] = []
        while true {
            let result = sqlite3_step(statement)
            if result == SQLITE_DONE { return rows }
            guard result == SQLITE_ROW,
                  let idText = sqlite3_column_text(statement, 0),
                  let accountText = sqlite3_column_text(statement, 1),
                  let kindText = sqlite3_column_text(statement, 2),
                  let previousText = sqlite3_column_text(statement, 3),
                  let headText = sqlite3_column_text(statement, 4),
                  let id = UUID(uuidString: String(cString: idText)),
                  let account = UUID(uuidString: String(cString: accountText)),
                  let kind = RestrictionKind(rawValue: String(cString: kindText)) else {
                throw RestrictionLedgerError.recoveryRequired
            }
            rows.append(Row(id: id, account: account, kind: kind, previous: String(cString: previousText), head: String(cString: headText)))
        }
    }

    private func execute(_ sql: String) throws {
        guard let database, sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
            throw RestrictionLedgerError.storageUnavailable
        }
    }

    private func prepare(_ sql: String) throws -> OpaquePointer {
        guard let database else { throw RestrictionLedgerError.storageUnavailable }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw RestrictionLedgerError.storageUnavailable
        }
        return statement
    }

    private func bind(_ value: String, at index: Int32, to statement: OpaquePointer) throws {
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        guard sqlite3_bind_text(statement, index, value, -1, transient) == SQLITE_OK else {
            throw RestrictionLedgerError.storageUnavailable
        }
    }

    private static func hash(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
