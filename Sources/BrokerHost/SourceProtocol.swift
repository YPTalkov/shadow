import Foundation

public struct SourceCapabilities: Codable, Sendable, Equatable {
    public let stableItems: Bool
    public let stableGroups: Bool
    public let completeScopes: [String]
    public let deletionEvidence: [String]
    public let distinguishesAccessLoss: Bool
    public let totp: Bool
    public let collectionMode: String
    public let version: Int

    public init(stableItems: Bool, stableGroups: Bool, completeScopes: [String], deletionEvidence: [String], distinguishesAccessLoss: Bool, totp: Bool, collectionMode: String, version: Int = 1) {
        self.stableItems = stableItems; self.stableGroups = stableGroups; self.completeScopes = completeScopes
        self.deletionEvidence = deletionEvidence; self.distinguishesAccessLoss = distinguishesAccessLoss
        self.totp = totp; self.collectionMode = collectionMode; self.version = version
    }
}

public struct SourceReceipt: Codable, Sendable {
    public let batchId: String
    public let receiptRef: String
    public let generation: UInt64
    public let accepted: Int
    public let conflicted: Int
    public let retained: Int
    public let warnings: [String]
}

public struct SourceFrameResult: Codable, Sendable {
    public let state: String
    public let receipt: SourceReceipt?
}

public struct OwnerSourceSummary: Codable, Identifiable, Sendable {
    public var id: String { instance }
    public let instance: String
    public let label: String
    public let generation: UInt64
    public let lastReceived: String
}

public struct OwnerConflictResult: Codable, Sendable {
    public let state: String
    public let createdLocalCopy: Bool
}
