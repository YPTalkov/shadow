import Foundation
import Security

protocol CodexTokenStore: Sendable {
    func read() throws -> CodexTokens?
    func write(_ tokens: CodexTokens) throws
    func delete() throws
}

struct CodexKeychainStore: CodexTokenStore {
    let vaultID: String
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "com.yptalkov.shadow.model-oauth",
         kSecAttrAccount as String: vaultID]
    }

    func read() throws -> CodexTokens? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data, data.count <= 65_536,
              let tokens = try? JSONDecoder().decode(CodexTokens.self, from: data) else { throw CodexOAuthError.storageUnavailable }
        do { try tokens.validateStored() } catch { throw CodexOAuthError.storageUnavailable }
        return tokens
    }

    func write(_ tokens: CodexTokens) throws {
        do { try tokens.validateStored() } catch { throw CodexOAuthError.storageUnavailable }
        let data = try JSONEncoder().encode(tokens)
        guard data.count <= 65_536 else { throw CodexOAuthError.storageUnavailable }
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw CodexOAuthError.storageUnavailable }
        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        item[kSecAttrSynchronizable as String] = false
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw CodexOAuthError.storageUnavailable }
    }

    func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw CodexOAuthError.storageUnavailable }
    }
}
