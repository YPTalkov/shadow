import Foundation
import Security
import Testing
@testable import PolicyCore

@Test func keychainAnchorRejectsStaleAdvance() throws {
    let id = "shadow-synthetic-test-\(UUID().uuidString)"
    let service = "com.yptalkov.shadow.generation-anchor"
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: id,
    ]
    defer { SecItemDelete(query as CFDictionary) }

    let anchor = GenerationAnchor(vaultID: id)
    let first = String(repeating: "a", count: 64)
    let second = String(repeating: "b", count: 64)
    #expect(try anchor.read() == nil)
    try anchor.advance(expected: nil, to: first)
    #expect(try anchor.read() == first)
    try anchor.advance(expected: first, to: second)
    #expect(try anchor.read() == second)
    #expect(throws: GenerationAnchorError.mismatch) {
        try anchor.advance(expected: first, to: first)
    }
}
