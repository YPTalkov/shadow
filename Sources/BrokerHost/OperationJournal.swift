import CryptoKit
import Darwin
import Foundation
import PolicyCore
import SQLite3

public enum OperationJournalError: Error, Equatable {
    case unsafePath, storageUnavailable, capacityExceeded, invalidTransition
}

/// Nonsecret receipts, never authority. One supervisor owns this journal.
/// Callers serialize access on MainActor. A restart closes every unfinished job;
/// the journal cannot recreate a grant, browser, cookie, checkpoint or session.
public final class OperationJournal {
    public struct Receipt {
        public let status: AgentOperationStatus
        public let created: Bool
    }
    private let path: URL
    private let capacity: Int
    private let date: () -> Date
    private var database: OpaquePointer?
    private var descriptor: Int32 = -1
    private var lockDescriptor: Int32 = -1
    private var identity = stat()
    private static let active = "('pending_owner','running','needs_owner_action')"
    private static let operations: Set<String> = ["auth.login", "browser.navigate", "browser.click", "browser.scroll", "browser.fill_nonsecret", "source.request_refresh"]

    public init(path: URL, capacity: Int = 4096, date: @escaping () -> Date = { Date() }) throws {
        self.path = path; self.capacity = capacity; self.date = date
        guard (1...4096).contains(capacity) else { throw OperationJournalError.capacityExceeded }
        let parent = path.deletingLastPathComponent()
        var info = stat()
        guard lstat(parent.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { throw OperationJournalError.unsafePath }
        descriptor = Darwin.open(path.path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw OperationJournalError.unsafePath }
        do {
            guard fstat(descriptor, &identity) == 0 else { throw OperationJournalError.unsafePath }
            try verifyPath()
            // On macOS flock on the database conflicts with SQLite's own
            // locks. Use a separate private supervisor ownership file.
            lockDescriptor = Darwin.open(path.path + ".lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
            var lockInfo = stat()
            guard lockDescriptor >= 0, fstat(lockDescriptor, &lockInfo) == 0,
                  lockInfo.st_mode & S_IFMT == S_IFREG, lockInfo.st_uid == getuid(),
                  lockInfo.st_mode & 0o077 == 0, lockInfo.st_nlink == 1 else { throw OperationJournalError.unsafePath }
            guard flock(lockDescriptor, LOCK_EX | LOCK_NB) == 0 else { throw OperationJournalError.storageUnavailable }
            guard let canonical = realpath(path.path, nil) else { throw OperationJournalError.unsafePath }
            defer { free(canonical) }
            guard sqlite3_open_v2(canonical, &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK else { throw OperationJournalError.storageUnavailable }
            try execute("PRAGMA trusted_schema=OFF")
            try execute("PRAGMA synchronous=FULL")
            try execute("PRAGMA fullfsync=ON")
            try execute("PRAGMA journal_mode=DELETE")
            try execute("PRAGMA max_page_count=1024")
            try execute("CREATE TABLE IF NOT EXISTS operation (reference TEXT PRIMARY KEY, caller TEXT NOT NULL, boot TEXT NOT NULL, request TEXT NOT NULL, fingerprint TEXT NOT NULL, state TEXT NOT NULL, submitted INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, code TEXT, UNIQUE(caller,boot,request))")
            try execute("UPDATE operation SET state=CASE WHEN submitted=1 THEN 'outcome_unknown' ELSE 'cancelled' END, code=NULL WHERE state IN \(Self.active)")
            let parentFD = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard parentFD >= 0 else { throw OperationJournalError.storageUnavailable }
            let synced = fsync(parentFD); Darwin.close(parentFD)
            guard synced == 0 else { throw OperationJournalError.storageUnavailable }
        } catch {
            if let database { sqlite3_close(database) }; database = nil
            Darwin.close(descriptor); descriptor = -1
            if lockDescriptor >= 0 { Darwin.close(lockDescriptor); lockDescriptor = -1 }
            throw error
        }
    }

    deinit {
        if let database { sqlite3_close(database) }
        if descriptor >= 0 { Darwin.close(descriptor) }
        if lockDescriptor >= 0 { Darwin.close(lockDescriptor) }
    }

    public func close() throws {
        if let database {
            guard sqlite3_close(database) == SQLITE_OK else { throw OperationJournalError.storageUnavailable }
            self.database = nil
        }
        if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 }
        if lockDescriptor >= 0 { Darwin.close(lockDescriptor); lockDescriptor = -1 }
    }

    /// Consult this before resolving an expiring account reference or claiming a
    /// one-session retained grant. A retry recovers status, never executes again.
    public func prior(_ request: AgentRequest, caller: EnrolledAgent) throws -> AgentOperationStatus? {
        try verifyPath()
        let statement = try prepare("SELECT reference,fingerprint FROM operation WHERE caller=? AND boot=? AND request=? AND created>=?", [caller.id.uuidString, caller.boot.uuidString, request.id.uuidString, cutoff])
        defer { sqlite3_finalize(statement) }
        let result = sqlite3_step(statement)
        if result == SQLITE_DONE { return nil }
        guard result == SQLITE_ROW else { throw OperationJournalError.storageUnavailable }
        guard try text(statement, 1) == fingerprint(request) else { throw ConsentError.requestConflict }
        return try status(text(statement, 0), caller: caller)
    }

    public func begin(_ request: AgentRequest, caller: EnrolledAgent) throws -> Receipt {
        guard Self.operations.contains(request.operation) else { throw AgentAPIError.invalidRequest }
        if let status = try prior(request, caller: caller) { return Receipt(status: status, created: false) }
        try execute("DELETE FROM operation WHERE created < ? AND state NOT IN \(Self.active)", [cutoff])
        let count = try prepare("SELECT COUNT(*) FROM operation")
        defer { sqlite3_finalize(count) }
        guard sqlite3_step(count) == SQLITE_ROW else { throw OperationJournalError.storageUnavailable }
        guard sqlite3_column_int64(count, 0) < capacity else { throw OperationJournalError.capacityExceeded }
        let reference = try ReferenceRegistry.randomToken()
        try execute("INSERT INTO operation (reference,caller,boot,request,fingerprint,state,created) VALUES (?,?,?,?,?,'running',?)", [reference, caller.id.uuidString, caller.boot.uuidString, request.id.uuidString, try fingerprint(request), String(Int64(date().timeIntervalSince1970))])
        return Receipt(status: AgentOperationStatus(reference: reference, state: .running), created: true)
    }

    public func status(_ reference: String, caller: EnrolledAgent) throws -> AgentOperationStatus {
        try verifyPath()
        let statement = try prepare("SELECT state,code FROM operation WHERE reference=? AND caller=? AND boot=? AND created>=?", [reference, caller.id.uuidString, caller.boot.uuidString, cutoff])
        defer { sqlite3_finalize(statement) }
        let result = sqlite3_step(statement)
        if result == SQLITE_DONE { throw ConsentError.invalidReference }
        guard result == SQLITE_ROW, let state = AgentOperationState(rawValue: try text(statement, 0)) else { throw OperationJournalError.storageUnavailable }
        let code = sqlite3_column_type(statement, 1) == SQLITE_NULL ? nil : AgentAPIError(rawValue: try text(statement, 1))
        return AgentOperationStatus(reference: reference, state: state, error: code)
    }

    /// FULL fsync commits before the browser receives permission to submit.
    public func markSubmitted(_ reference: String, caller: EnrolledAgent) throws {
        let current = try status(reference, caller: caller)
        guard current.state == .running else { throw OperationJournalError.invalidTransition }
        try execute("UPDATE operation SET submitted=1 WHERE reference=?", [reference])
    }

    public func setOwnerAction(_ reference: String, caller: EnrolledAgent, waiting: Bool) throws {
        let current = try status(reference, caller: caller)
        guard current.state == (waiting ? .running : .needsOwnerAction) else { throw OperationJournalError.invalidTransition }
        try execute("UPDATE operation SET state=? WHERE reference=?", [waiting ? "needs_owner_action" : "running", reference])
    }

    public func finish(_ reference: String, caller: EnrolledAgent, state: AgentOperationState, error: AgentAPIError? = nil) throws {
        let current = try status(reference, caller: caller)
        guard [.running, .pendingOwner, .needsOwnerAction].contains(current.state),
              [.succeeded, .failed, .cancelled, .outcomeUnknown].contains(state) else { throw OperationJournalError.invalidTransition }
        // A cancellation or failure after permission to submit is ambiguous.
        try execute("UPDATE operation SET state=CASE WHEN submitted=1 AND ? IN ('cancelled','failed') THEN 'outcome_unknown' ELSE ? END, code=? WHERE reference=?", [state.rawValue, state.rawValue, error?.rawValue, reference])
    }

    private var cutoff: String { String(Int64(date().timeIntervalSince1970) - 7 * 86400) }

    private func fingerprint(_ request: AgentRequest) throws -> String {
        let bytes = try JSONValue.object(["operation": .string(request.operation), "arguments": .object(request.arguments)]).encoded()
        return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    private func verifyPath() throws {
        var current = stat()
        guard descriptor >= 0, lstat(path.path, &current) == 0,
              current.st_mode & S_IFMT == S_IFREG, current.st_uid == getuid(),
              current.st_mode & 0o077 == 0, current.st_nlink == 1,
              current.st_dev == identity.st_dev, current.st_ino == identity.st_ino else { throw OperationJournalError.unsafePath }
    }

    private func prepare(_ sql: String, _ values: [String?] = []) throws -> OpaquePointer {
        guard let database else { throw OperationJournalError.storageUnavailable }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw OperationJournalError.storageUnavailable }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for (index, value) in values.enumerated() {
            let result = value.map { sqlite3_bind_text(statement, Int32(index + 1), $0, -1, transient) } ?? sqlite3_bind_null(statement, Int32(index + 1))
            if result != SQLITE_OK { sqlite3_finalize(statement); throw OperationJournalError.storageUnavailable }
        }
        return statement
    }

    private func execute(_ sql: String, _ values: [String?] = []) throws {
        let statement = try prepare(sql, values); defer { sqlite3_finalize(statement) }
        var result = sqlite3_step(statement)
        while result == SQLITE_ROW { result = sqlite3_step(statement) }
        guard result == SQLITE_DONE else { throw OperationJournalError.storageUnavailable }
    }

    private func text(_ statement: OpaquePointer, _ column: Int32) throws -> String {
        guard let value = sqlite3_column_text(statement, column) else { throw OperationJournalError.storageUnavailable }
        return String(cString: value)
    }
}
