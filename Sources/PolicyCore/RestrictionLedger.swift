import CryptoKit
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
        let parentAttributes = try FileManager.default.attributesOfItem(atPath: parent.path)
        guard parentAttributes[.type] as? FileAttributeType == .typeDirectory,
              let parentPermissions = parentAttributes[.posixPermissions] as? Int,
              parentPermissions & 0o077 == 0 else {
            throw RestrictionLedgerError.unsafePath
        }
        if existed {
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
        guard sqlite3_open_v2(path.path, &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else {
            throw RestrictionLedgerError.storageUnavailable
        }
        do {
            try execute("PRAGMA synchronous=FULL")
            try execute("PRAGMA journal_mode=DELETE")
            try execute("CREATE TABLE IF NOT EXISTS restriction_event (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, account TEXT NOT NULL, kind TEXT NOT NULL, previous TEXT NOT NULL, head TEXT NOT NULL)")
            if !existed {
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
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

    public func append(account: UUID, kind: RestrictionKind) throws -> RestrictionEvent {
        let previous = try verify()
        let event = RestrictionEvent(id: UUID(), account: account, kind: kind)
        let head = Self.hash("\(previous)|\(event.id.uuidString)|\(account.uuidString)|\(kind.rawValue)")
        try execute("BEGIN IMMEDIATE")
        do {
            let statement = try prepare("INSERT INTO restriction_event (id, account, kind, previous, head) VALUES (?, ?, ?, ?, ?)")
            defer { sqlite3_finalize(statement) }
            try bind(event.id.uuidString, at: 1, to: statement)
            try bind(account.uuidString, at: 2, to: statement)
            try bind(kind.rawValue, at: 3, to: statement)
            try bind(previous, at: 4, to: statement)
            try bind(head, at: 5, to: statement)
            guard sqlite3_step(statement) == SQLITE_DONE else { throw RestrictionLedgerError.storageUnavailable }
            try execute("COMMIT")
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
        // A crash between commit and anchor advance leaves a mismatch and denies use.
        try anchor.advance(expected: previous, to: head)
        return event
    }

    public func events(for account: UUID) throws -> [RestrictionEvent] {
        _ = try verify()
        return try rows().filter { $0.account == account }.map {
            RestrictionEvent(id: $0.id, account: $0.account, kind: $0.kind)
        }
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
