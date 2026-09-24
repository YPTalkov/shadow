import Foundation
import PolicyCore
import RuntimeHost

public enum AgentAPIError: String, Error, Sendable {
    case invalidRequest = "invalid_request", unsupportedVersion = "unsupported_version", rateLimited = "rate_limited"
    case invalidCursor = "invalid_cursor", invalidReference = "invalid_reference", capabilityUnavailable = "capability_unavailable"
    case responseLimit = "response_limit", unavailable, consentRequired = "account_consent_required"
}

public struct AgentRequest: Sendable {
    public let id: UUID
    public let operation: String
    public let arguments: [String: JSONValue]

    public static func decode(_ data: Data) throws -> AgentRequest {
        let value = try BoundedJSON.parse(data)
        if let version = value["protocol_major"]?.integer, version != 1 { throw AgentAPIError.unsupportedVersion }
        guard ContractValidation.accepts(value, schema: AgentContract.schema),
              let id = value["request_id"]?.string.flatMap(UUID.init(uuidString:)),
              let operation = value["operation"]?.string, let arguments = value["arguments"]?.object else { throw AgentAPIError.invalidRequest }
        return AgentRequest(id: id, operation: operation, arguments: arguments)
    }
}

public enum AgentOperationState: String, Sendable {
    case pendingOwner = "pending_owner", running, needsOwnerAction = "needs_owner_action", succeeded, failed, cancelled, outcomeUnknown = "outcome_unknown"
}

public struct AgentOperationStatus: Sendable {
    public let reference: String
    public let state: AgentOperationState
    public let session: String?
    public let checkpoint: String?
    public let error: AgentAPIError?
    public init(reference: String, state: AgentOperationState, session: String? = nil, checkpoint: String? = nil, error: AgentAPIError? = nil) {
        self.reference = reference; self.state = state; self.session = session; self.checkpoint = checkpoint; self.error = error
    }
    var json: JSONValue {
        .object(["operation_ref": .string(reference), "state": .string(state.rawValue), "session_ref": session.map(JSONValue.string) ?? .null, "checkpoint_ref": checkpoint.map(JSONValue.string) ?? .null, "code": error.map { .string($0.rawValue) } ?? .null])
    }
}

public enum AgentDomainResult: Sendable {
    case operation(AgentOperationStatus)
    case closed
    case completed
    var json: JSONValue {
        switch self {
        case .operation(let status): status.json
        case .closed: .object(["state": .string("closed")])
        case .completed: .object(["state": .string("succeeded")])
        }
    }
}

@MainActor public protocol AgentProtectedService: AnyObject {
    var availableOperations: [String] { get }
    func handle(_ request: AgentRequest, caller: EnrolledAgent) async throws -> AgentDomainResult
}

/// Caller identity comes from the accepted VM instance. Nothing in a request
/// can select another caller, host path, credential field or owner approval.
@MainActor public final class AgentAPI {
    private struct Cursor {
        let caller: EnrolledAgent
        let disclosure: UUID
        let query: String
        let offset: Int
        let expires: TimeInterval
    }
    public weak var protectedService: (any AgentProtectedService)?
    private let access: AccessCoordinator
    private var cursors: [String: Cursor] = [:]
    private var rates: [UUID: [TimeInterval]] = [:]
    private var channels: [UUID: FramedChannel] = [:]

    public init(access: AccessCoordinator) {
        self.access = access
        let previous = access.onRevoke
        access.onRevoke = { [weak self] grant in previous?(grant); self?.invalidateOutputs() }
    }

    public func invalidateOutputs() {
        for channel in channels.values { channel.invalidate() }
        channels.removeAll()
        cursors.removeAll()
    }

    public func serve(_ channel: FramedChannel, caller: EnrolledAgent) async {
        guard access.agents.contains(caller), channels.count < 8 else { channel.invalidate(); return }
        let id = UUID(); channels[id] = channel
        defer { channel.invalidate(); channels.removeValue(forKey: id) }
        do {
            let request = try await Task.detached { try channel.read() }.value
            let reply = await handle(request, caller: caller)
            guard channels[id] != nil, access.agents.contains(caller) else { return }
            try await Task.detached { try channel.write(reply) }.value
        } catch { /* Fixed transport close; no request or exception logging. */ }
    }

    public func handle(_ data: Data, caller: EnrolledAgent) async -> Data {
        var requestID: UUID?
        do {
            guard access.agents.contains(caller) else { throw ConsentError.callerUnavailable }
            let recent = (rates[caller.id] ?? []).filter { $0 > DeadlineClock.now - 60 }
            guard recent.count < 120 else { throw AgentAPIError.rateLimited }
            rates[caller.id] = recent + [DeadlineClock.now]
            let request = try AgentRequest.decode(data); requestID = request.id
            let result = try await dispatch(request, caller: caller)
            let value = envelope(requestID, result: result)
            guard ContractValidation.accepts(value, schema: AgentContract.responseSchema) else { throw AgentAPIError.unavailable }
            let reply = try value.encoded()
            guard reply.count <= 65_536 else { throw AgentAPIError.responseLimit }
            return reply
        } catch {
            let code: String
            if let known = error as? AgentAPIError { code = known.rawValue }
            else if let known = error as? ConsentError { code = known.rawValue }
            else if error is BoundedJSONError { code = "invalid_request" }
            else { code = "unavailable" }
            // Encoding contains only a validated UUID and fixed codes.
            return (try? envelope(requestID, error: code).encoded()) ?? Data("{\"error\":{\"code\":\"unavailable\"}}".utf8)
        }
    }

    private func envelope(_ id: UUID?, result: JSONValue? = nil, error: String? = nil) -> JSONValue {
        var value: [String: JSONValue] = ["protocol_major": .integer(1)]
        if let id { value["request_id"] = .string(id.uuidString.lowercased()) }
        if let result { value["result"] = result }
        if let error { value["error"] = .object(["code": .string(error)]) }
        return .object(value)
    }

    private func dispatch(_ request: AgentRequest, caller: EnrolledAgent) async throws -> JSONValue {
        access.expire()
        let args = request.arguments
        if request.operation == "vault.status" {
            let state = !access.unlocked ? "locked" : access.disclosureIdentity(caller: caller) == nil ? "catalog_consent_required" : "ready"
            let capabilities = ["vault.status", "catalog.search", "access.request", "operation.get", "operation.cancel"] + (protectedService?.availableOperations ?? [])
            return .object(["state": .string(state), "capabilities": .array(capabilities.map(JSONValue.string))])
        }
        guard access.unlocked else { throw ConsentError.vaultLocked }
        switch request.operation {
        case "catalog.search": return try search(args, caller: caller)
        case "access.request":
            let reply: ConsentReply
            if args["kind"]?.string == "catalog" { reply = try access.requestCatalog(caller: caller, requestID: request.id) }
            else {
                reply = try access.requestUse(caller: caller, requestID: request.id, accountRef: args["account_ref"]!.string!, adapterID: args["adapter_id"]!.string!, actions: Set(args["actions"]!.array!.compactMap { $0.string.flatMap(ProtectedAction.init(rawValue:)) }))
            }
            return consent(reply)
        case "operation.get", "operation.cancel":
            let reference = args["operation_ref"]!.string!
            if let reply = try? access.status(reference, caller: caller) {
                return consent(request.operation == "operation.cancel" ? try access.cancelRequest(reference, caller: caller) : reply)
            }
        case "auth.login":
            // The protected service checks durable receipts before resolving
            // expiring account refs or claiming a retained grant a second time.
            if protectedService?.availableOperations.contains("auth.login") == true { break }
            let account = try access.accountForReference(args["account_ref"]!.string!, caller: caller)
            let adapterID = args["adapter_id"]!.string!
            guard let adapter = access.adapter(adapterID), !adapter.credentialOrigins.isEmpty,
                  adapter.credentialOrigins.allSatisfy({ access.authorize(grantRef: args["grant_ref"]!.string!, caller: caller, account: account.id, adapterID: adapterID, origin: $0, action: .login) }) else { throw AgentAPIError.consentRequired }
        default: break
        }
        guard let service = protectedService, service.availableOperations.contains(request.operation) else { throw AgentAPIError.capabilityUnavailable }
        let result = try await service.handle(request, caller: caller)
        guard access.unlocked, access.agents.contains(caller) else { throw ConsentError.vaultLocked }
        if case .operation(let status) = result {
            let references = [status.reference] + [status.session, status.checkpoint].compactMap { $0 }
            guard references.allSatisfy({ $0.utf8.count == 64 && $0.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }) else { throw AgentAPIError.unavailable }
        }
        return result.json
    }

    private func consent(_ reply: ConsentReply) -> JSONValue {
        .object(["operation_ref": .string(reply.requestRef), "state": .string(reply.state.rawValue), "grant_ref": reply.grantRef.map(JSONValue.string) ?? .null])
    }

    private func search(_ args: [String: JSONValue], caller: EnrolledAgent) throws -> JSONValue {
        let disclosed = try access.disclosedAccounts(caller: caller)
        guard let disclosure = access.disclosureIdentity(caller: caller) else { throw ConsentError.consentRequired }
        let query = normalized(args["query"]?.string ?? "")
        let limit = Int(args["limit"]?.integer ?? 50)
        cursors = cursors.filter { $0.value.expires > DeadlineClock.now }
        var offset = 0
        if let token = args["cursor"]?.string {
            guard let cursor = cursors[token], cursor.caller == caller, cursor.disclosure == disclosure, cursor.query == query else { throw AgentAPIError.invalidCursor }
            offset = cursor.offset
        }
        let matches = disclosed.filter { account in
            query.isEmpty || ([account.metadata.title, account.metadata.username] + account.metadata.origins).contains { normalized($0).contains(query) }
        }.sorted { $0.id.uuidString < $1.id.uuidString }
        guard offset <= matches.count else { throw AgentAPIError.invalidCursor }
        var selected: [JSONValue] = []
        for account in matches.dropFirst(offset).prefix(limit) {
            let item = account.metadata
            let projection: JSONValue = .object([
                "account_ref": .string(try access.accountReference(account.id, caller: caller)),
                "title": .string(item.title), "username": .string(item.username), "origins": .array(item.origins.map(JSONValue.string)),
                "group": .string(item.group), "source_kind": .string(item.sourceKind), "presence": .string(item.presence),
                "observed_at": item.observationDate.map { .string(ISO8601DateFormatter().string(from: $0)) } ?? .null,
                "authorization": .string(account.policy.conflicted ? "blocked" : "unapproved"),
                "supported_adapters": .array(access.supportedAdapters(for: account).map(JSONValue.string))
            ])
            // Leave room for the JSON string wrapper used by stdio MCP.
            if try JSONValue.array(selected + [projection]).encoded().count > 28 * 1024 { break }
            selected.append(projection)
        }
        var next: JSONValue = .null
        if offset + selected.count < matches.count {
            guard !selected.isEmpty, cursors.count < 256 else { throw AgentAPIError.responseLimit }
            let token = try ReferenceRegistry.randomToken()
            cursors[token] = Cursor(caller: caller, disclosure: disclosure, query: query, offset: offset + selected.count, expires: DeadlineClock.now + 300)
            next = .string(token)
        }
        return .object(["items": .array(selected), "next_cursor": next])
    }

    private func normalized(_ value: String) -> String {
        value.precomposedStringWithCompatibilityMapping.folding(options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
    }
}
