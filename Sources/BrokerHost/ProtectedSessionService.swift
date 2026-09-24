import Foundation
import PolicyCore

enum AuthenticationStage: String, CaseIterable, Sendable {
    case navigate, resolve, fill, submit, verify, output
}

enum BrowserAuthenticationResult: Sendable { case succeeded, failed, outcomeUnknown }

/// Implementations own their independent worker/egress deadlines. revoke()
/// closes authority synchronously; VM destruction may finish asynchronously.
@MainActor protocol ProtectedBrowserDriver: AnyObject {
    func authenticate(authorize: @escaping @MainActor (AuthenticationStage) throws -> Void, resolve: @escaping @MainActor () async throws -> PrivateCredential) async throws -> BrowserAuthenticationResult
    func renew(sequence: Int) async throws
    func revoke()
}

/// One active protected browser in this release. Every action for that session
/// passes this serial native authority boundary. No client supplies a selector,
/// browser endpoint, origin, credential, VM identity or approval decision.
@MainActor public final class ProtectedSessionService: AgentProtectedService {
    private final class Session {
        let id = UUID()
        let reference: String
        let operation: String
        let caller: EnrolledAgent
        let account: ConsentAccount
        let adapter: QualifiedAdapterPolicy
        let grant: String
        let driver: any ProtectedBrowserDriver
        var task: Task<Void, Never>?
        var stage = 0
        var resolved = false
        var ready = false
        var sequence = 0
        init(reference: String, operation: String, caller: EnrolledAgent, account: ConsentAccount, adapter: QualifiedAdapterPolicy, grant: String, driver: any ProtectedBrowserDriver) {
            self.reference = reference; self.operation = operation; self.caller = caller
            self.account = account; self.adapter = adapter; self.grant = grant; self.driver = driver
        }
    }
    public var availableOperations: [String] { ["auth.login", "operation.get", "operation.cancel", "session.close"] }
    private let access: AccessCoordinator
    private let journal: OperationJournal
    private let resolve: @MainActor (ConsentAccount, String) async throws -> PrivateCredential
    private let makeDriver: @MainActor (QualifiedAdapterPolicy, UUID) throws -> any ProtectedBrowserDriver
    private var active: Session?
    private var monitor: Task<Void, Never>?
    private var closed = false

    init(access: AccessCoordinator, journal: OperationJournal, resolve: @escaping @MainActor (ConsentAccount, String) async throws -> PrivateCredential, makeDriver: @escaping @MainActor (QualifiedAdapterPolicy, UUID) throws -> any ProtectedBrowserDriver) {
        self.access = access; self.journal = journal; self.resolve = resolve; self.makeDriver = makeDriver
        let previous = access.onRevoke
        access.onRevoke = { [weak self] grant in
            // Close browser/egress before any callback can start teardown.
            if let self, let session = self.active, grant == nil || grant == session.grant { self.terminate(session, state: .cancelled) }
            previous?(grant)
        }
        monitor = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(2)) } catch { return }
                await self?.renew()
            }
        }
    }

    deinit { monitor?.cancel() }

    public func shutdown() {
        closed = true; monitor?.cancel(); monitor = nil
        if let active { terminate(active, state: .cancelled) }
    }

    public func handle(_ request: AgentRequest, caller: EnrolledAgent) async throws -> AgentDomainResult {
        guard !closed, access.unlocked, access.agents.contains(caller) else { throw AgentAPIError.unavailable }
        switch request.operation {
        case "auth.login": return .operation(try login(request, caller: caller))
        case "operation.get": return .operation(try status(request.arguments["operation_ref"]!.string!, caller: caller))
        case "operation.cancel":
            let reference = request.arguments["operation_ref"]!.string!
            _ = try journal.status(reference, caller: caller)
            if let session = active, session.operation == reference, session.caller == caller { terminate(session, state: .cancelled) }
            return .operation(try status(reference, caller: caller))
        case "session.close":
            guard let session = active, session.reference == request.arguments["session_ref"]?.string, session.caller == caller else { throw ConsentError.invalidReference }
            terminate(session, state: .cancelled)
            return .closed
        default: throw AgentAPIError.capabilityUnavailable
        }
    }

    public func status(_ reference: String, caller: EnrolledAgent) throws -> AgentOperationStatus {
        let status = try journal.status(reference, caller: caller)
        if let session = active, session.operation == reference, session.caller == caller, session.ready {
            do {
                try check(session)
                return AgentOperationStatus(reference: reference, state: status.state, session: session.reference, error: status.error)
            } catch { terminate(session, state: .cancelled) }
        }
        return status
    }

    private func login(_ request: AgentRequest, caller: EnrolledAgent) throws -> AgentOperationStatus {
        if let prior = try journal.prior(request, caller: caller) { return try status(prior.reference, caller: caller) }
        let account = try access.accountForReference(request.arguments["account_ref"]!.string!, caller: caller)
        let adapterID = request.arguments["adapter_id"]!.string!, grant = request.arguments["grant_ref"]!.string!
        guard let adapter = access.adapter(adapterID), adapter.credentialOrigins.count == 1,
              adapter.credentialOrigins.allSatisfy({ access.authorize(grantRef: grant, caller: caller, account: account.id, adapterID: adapterID, origin: $0, action: .login) }) else { throw AgentAPIError.consentRequired }
        guard active == nil else { throw AgentAPIError.rateLimited }
        let reference = try ReferenceRegistry.randomToken()
        let receipt = try journal.begin(request, caller: caller)
        do {
            let driver = try makeDriver(adapter, caller.boot)
            let session = Session(reference: reference, operation: receipt.status.reference, caller: caller, account: account, adapter: adapter, grant: grant, driver: driver)
            active = session
            try access.claimRetainedSession(grantRef: grant, session: session.id)
            session.task = Task { [weak self] in await self?.authenticate(session) }
        } catch {
            if let active { terminate(active, state: .failed) }
            else { try journal.finish(receipt.status.reference, caller: caller, state: .failed, error: .unavailable) }
        }
        return try status(receipt.status.reference, caller: caller)
    }

    private func check(_ session: Session) throws {
        access.expire()
        guard !closed, active === session, !Task.isCancelled,
              access.accounts.contains(where: { $0.policy == session.account.policy }),
              session.adapter.credentialOrigins.allSatisfy({ access.authorize(grantRef: session.grant, caller: session.caller, account: session.account.id, adapterID: session.adapter.id, origin: $0, action: .login, session: session.id) }) else { throw AgentAPIError.consentRequired }
    }

    private func authorize(_ stage: AuthenticationStage, session: Session) throws {
        try check(session)
        guard session.stage < AuthenticationStage.allCases.count, AuthenticationStage.allCases[session.stage] == stage,
              stage != .fill || session.resolved else { throw AgentAPIError.unavailable }
        if stage == .submit { try journal.markSubmitted(session.operation, caller: session.caller) }
        session.stage += 1
    }

    private func credential(_ session: Session) async throws -> PrivateCredential {
        try check(session)
        guard session.stage == 2, !session.resolved, let origin = session.adapter.credentialOrigins.first else { throw AgentAPIError.unavailable }
        // Reserve before awaiting the worker: even a faulty driver cannot race
        // two resolutions against the same selected account checkpoint.
        session.resolved = true
        let credential = try await resolve(session.account, origin)
        try check(session)
        return credential
    }

    private func authenticate(_ session: Session) async {
        do {
            try check(session)
            session.sequence += 1
            try await session.driver.renew(sequence: session.sequence)
            try check(session)
            let result = try await session.driver.authenticate(authorize: { [weak self] stage in
                guard let self else { throw AgentAPIError.unavailable }
                try self.authorize(stage, session: session)
            }, resolve: { [weak self] in
                guard let self else { throw AgentAPIError.unavailable }
                return try await self.credential(session)
            })
            try check(session)
            if result == .succeeded {
                guard session.stage == AuthenticationStage.allCases.count else { throw AgentAPIError.unavailable }
                try journal.finish(session.operation, caller: session.caller, state: .succeeded)
                session.ready = true
                session.task = nil
            } else { terminate(session, state: result == .outcomeUnknown ? .outcomeUnknown : .failed) }
        } catch { terminate(session, state: .failed) }
    }

    private func renew() async {
        guard let session = active else { return }
        do {
            try check(session)
            session.sequence += 1
            try await session.driver.renew(sequence: session.sequence)
            try check(session)
        } catch { terminate(session, state: .cancelled) }
    }

    private func terminate(_ session: Session, state: AgentOperationState) {
        guard active === session else { return }
        active = nil
        session.driver.revoke()
        session.task?.cancel(); session.task = nil
        do {
            let current = try journal.status(session.operation, caller: session.caller)
            if [.running, .pendingOwner, .needsOwnerAction].contains(current.state) {
                try journal.finish(session.operation, caller: session.caller, state: state, error: state == .failed ? .unavailable : nil)
            }
        } catch {
            // Receipt persistence failed. Close all authority; never retry the
            // action in this process. Restart reconciles the submitted flag.
            closed = true
        }
    }
}
