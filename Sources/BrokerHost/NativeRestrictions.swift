import Foundation
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
        try lock.withLock {
            let exists = FileManager.default.fileExists(atPath: path.path), checkpoint = try anchor.read()
            if !exists && checkpoint == nil && !requireExisting { return [:] }
            guard exists, checkpoint != nil else { throw RestrictionLedgerError.recoveryRequired }
            let ledger = try RestrictionLedger(path: path, anchor: anchor)
            defer { try? ledger.close() }
            var latest: [UUID: RestrictionEvent] = [:]
            for event in try ledger.allEvents() { latest[event.account] = event }
            return latest
        }
    }
}
