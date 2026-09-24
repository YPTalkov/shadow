import Foundation

/// No call site can supply a title, URL, exception, payload, token or secret.
public enum AuditCode: String, CaseIterable, Sendable {
    case vaultOpened = "vault_opened"
    case lockOwner = "lock_owner", lockScreen = "lock_screen", lockSleep = "lock_sleep", lockWake = "lock_wake"
    case lockSession = "lock_session", lockIdle = "lock_idle", lockQuit = "lock_quit", workerStopped = "worker_stopped"
    case operationSucceeded = "operation_succeeded", operationFailed = "operation_failed"
    case operationCancelled = "operation_cancelled", outcomeUnknown = "outcome_unknown"
    case sourceRefreshed = "source_refreshed", importCompleted = "import_completed"
    case backupCompleted = "backup_completed", restoreCompleted = "restore_completed"
    case consentGranted = "consent_granted", consentDenied = "consent_denied", consentExpired = "consent_expired", grantRevoked = "grant_revoked"

    public init(lock reason: OwnerLockReason) {
        self = switch reason {
        case .owner: .lockOwner
        case .screenLocked: .lockScreen
        case .sleep: .lockSleep
        case .wake: .lockWake
        case .sessionChanged: .lockSession
        case .idle: .lockIdle
        case .quit: .lockQuit
        case .workerStopped: .workerStopped
        }
    }
}

public struct DiagnosticCount: Encodable, Sendable {
    public let day: String
    public let code: String
    public let count: Int64
}

public struct DiagnosticReport: Sendable {
    public let counts: [DiagnosticCount]
    public var text: String { String(decoding: data, as: UTF8.self) }
    public let data: Data

    init(counts: [DiagnosticCount]) throws {
        struct Export: Encodable {
            let schemaVersion = 1
            let retentionDays = 7
            let counts: [DiagnosticCount]
        }
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        data = try encoder.encode(Export(counts: counts))
        guard data.count <= 65536 else { throw OperationJournalError.capacityExceeded }
        self.counts = counts
    }
}
