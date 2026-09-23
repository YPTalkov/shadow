import Foundation
import Security

public enum GenerationAnchorError: Error, Equatable {
    case invalidDigest
    case mismatch
    case unavailable
}

/// Independent anti-rollback digest, kept outside ordinary vault and ledger backups.
/// The supervisor supplies a stable random vault ID and serializes all mutations.
public struct GenerationAnchor: Sendable {
    private let vaultID: String
    private let service = "com.yptalkov.shadow.generation-anchor"

    public init(vaultID: String) {
        self.vaultID = vaultID
    }

    public func read() throws -> String? {
        var query: [String: Any] = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess,
              let data = item as? Data,
              let digest = String(data: data, encoding: .utf8),
              Self.validDigest(digest) else {
            throw GenerationAnchorError.unavailable
        }
        return digest
    }

    public func advance(expected: String?, to digest: String) throws {
        guard Self.validDigest(digest), expected == nil || expected.map(Self.validDigest) == true else {
            throw GenerationAnchorError.invalidDigest
        }
        guard try read() == expected else {
            throw GenerationAnchorError.mismatch
        }
        let value = Data(digest.utf8)
        let status: OSStatus
        if expected == nil {
            var item = baseQuery
            item[kSecValueData as String] = value
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(item as CFDictionary, nil)
        } else {
            status = SecItemUpdate(baseQuery as CFDictionary, [kSecValueData as String: value] as CFDictionary)
        }
        guard status == errSecSuccess else {
            throw GenerationAnchorError.unavailable
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultID,
        ]
    }

    private static func validDigest(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }
    }
}
