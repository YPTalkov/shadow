import Foundation

/// A host-private transfer object. Deliberately not Encodable, observable or
/// part of AgentDomainResult; only the private browser driver consumes it.
struct PrivateCredential: Decodable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let username: String
    let password: String
    let totp: String?
    var description: String { "PrivateCredential(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: [:]) }
}
