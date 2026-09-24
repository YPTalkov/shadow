import Foundation
import PolicyCore
import Virtualization

enum AuthenticationStage: String, CaseIterable, Sendable {
    case navigate, resolve, fill, submit, verify, output
    case challengeFill = "challenge_fill", challengeSubmit = "challenge_submit"
    static let primary: [Self] = [.navigate, .resolve, .fill, .submit, .verify, .output]
}

enum BrowserAuthenticationResult: Sendable { case succeeded, failed(AgentAPIError), outcomeUnknown(AgentAPIError) }
enum ProtectedBrowserResult: Sendable { case view(SafeBrowserView), completed }

/// Implementations own their independent worker/egress deadlines. revoke()
/// closes authority synchronously; VM destruction may finish asynchronously.
@MainActor protocol ProtectedBrowserDriver: AnyObject {
    func authenticate(authorize: @escaping @MainActor (AuthenticationStage) throws -> Void, resolve: @escaping @MainActor () async throws -> PrivateCredential, owner: @escaping @MainActor () async throws -> Void) async throws -> BrowserAuthenticationResult
    var ownerMachine: VZVirtualMachine? { get }
    func renew(sequence: Int) async throws
    func checkLease() throws
    func perform(_ operation: String, arguments: [String: JSONValue]) async throws -> ProtectedBrowserResult
    func revoke()
}

extension ProtectedBrowserDriver { var ownerMachine: VZVirtualMachine? { nil } }

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
        var operations = Set<String>()
        var actionBusy = false
        var challengeStage = 0
        var checkpoint: String?
        init(reference: String, operation: String, caller: EnrolledAgent, account: ConsentAccount, adapter: QualifiedAdapterPolicy, grant: String, driver: any ProtectedBrowserDriver) {
            self.reference = reference; self.operation = operation; self.caller = caller
            self.account = account; self.adapter = adapter; self.grant = grant; self.driver = driver
            self.operations = [operation]
        }
    }
    public var availableOperations: [String] { ["auth.login", "operation.get", "operation.cancel", "session.close", "browser.observe", "browser.extract", "browser.navigate", "browser.click"] }
    public let challenges = OwnerChallengeCoordinator()
    private let access: AccessCoordinator
    private let journal: OperationJournal
    private let resolve: @MainActor (ConsentAccount, String, Bool) async throws -> PrivateCredential
    private let makeDriver: @MainActor (QualifiedAdapterPolicy) throws -> any ProtectedBrowserDriver
    private var active: Session?
    private var monitor: Task<Void, Never>?
    private var closed = false
    private var revocationObserver: UUID?
    private let workerAlive: @MainActor () -> Bool

    init(access: AccessCoordinator, journal: OperationJournal, workerAlive: @escaping @MainActor () -> Bool = { true }, resolve: @escaping @MainActor (ConsentAccount, String, Bool) async throws -> PrivateCredential, makeDriver: @escaping @MainActor (QualifiedAdapterPolicy) throws -> any ProtectedBrowserDriver) {
        self.access = access; self.journal = journal; self.resolve = resolve; self.makeDriver = makeDriver
        self.workerAlive = workerAlive
        revocationObserver = access.observeRevocation(owner: self, authority: true) { [weak self] grant in
            // Close browser/egress before any callback can start teardown.
            if let self, let session = self.active, grant == nil || grant == session.grant { self.terminate(session, state: .cancelled) }
        }
        challenges.onCancel = { [weak self] id in
            if let self, let session = self.active, session.id == id { self.terminate(session, state: .cancelled) }
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
        if let revocationObserver { access.removeRevocationObserver(revocationObserver); self.revocationObserver = nil }
        if let active { terminate(active, state: .cancelled) }
    }

    public func handle(_ request: AgentRequest, caller: EnrolledAgent) async throws -> AgentDomainResult {
        guard !closed, access.unlocked, access.agents.contains(caller) else { throw AgentAPIError.unavailable }
        switch request.operation {
        case "auth.login": return .operation(try login(request, caller: caller))
        case "operation.get": return .operation(try status(request.arguments["operation_ref"]!.string!, caller: caller))
        case "operation.cancel":
            let reference = request.arguments["operation_ref"]!.string!
            let current = try journal.status(reference, caller: caller)
            if let session = active, session.operations.contains(reference), session.caller == caller,
               [.running, .pendingOwner, .needsOwnerAction].contains(current.state) { terminate(session, state: .cancelled) }
            return .operation(try status(reference, caller: caller))
        case "browser.observe", "browser.extract": return try await read(request, caller: caller)
        case "browser.navigate", "browser.click": return .operation(try action(request, caller: caller))
        case "session.close":
            guard let session = active, session.reference == request.arguments["session_ref"]?.string, session.caller == caller else { throw ConsentError.invalidReference }
            terminate(session, state: .cancelled)
            return .closed
        default: throw AgentAPIError.capabilityUnavailable
        }
    }

    public func status(_ reference: String, caller: EnrolledAgent) throws -> AgentOperationStatus {
        let status = try journal.status(reference, caller: caller)
        if let session = active, reference == session.operation, session.caller == caller,
           status.state == .needsOwnerAction, let checkpoint = session.checkpoint {
            do {
                challenges.expire()
                try check(session)
                return AgentOperationStatus(reference: reference, state: .needsOwnerAction, checkpoint: checkpoint)
            } catch { terminate(session, state: .cancelled); return try journal.status(reference, caller: caller) }
        }
        if let session = active, session.operations.contains(reference), session.caller == caller, session.ready, !session.actionBusy {
            do {
                try check(session)
                return AgentOperationStatus(reference: reference, state: status.state, session: session.reference, error: status.error)
            } catch { terminate(session, state: .cancelled) }
        }
        return status
    }

    private func sessionForAction(_ request: AgentRequest, caller: EnrolledAgent) throws -> (Session, ProtectedAction) {
        guard let session = active, session.reference == request.arguments["session_ref"]?.string, session.caller == caller else { throw ConsentError.invalidReference }
        guard session.ready else { throw AgentAPIError.sessionClosed }
        guard !session.actionBusy else { throw AgentAPIError.rateLimited }
        guard let action = ProtectedAction(rawValue: String(request.operation.dropFirst("browser.".count))) else { throw AgentAPIError.invalidRequest }
        try checkAction(session, action: action)
        return (session, action)
    }

    private func checkAction(_ session: Session, action: ProtectedAction) throws {
        try check(session)
        guard !session.adapter.resourceOrigins.isEmpty, session.adapter.actions.contains(action),
              session.adapter.resourceOrigins.allSatisfy({ access.authorize(grantRef: session.grant, caller: session.caller, account: session.account.id, adapterID: session.adapter.id, origin: $0, action: action, session: session.id) }) else { throw AgentAPIError.consentRequired }
    }

    private func read(_ request: AgentRequest, caller: EnrolledAgent) async throws -> AgentDomainResult {
        let (session, action) = try sessionForAction(request, caller: caller)
        session.actionBusy = true
        defer { session.actionBusy = false }
        do {
            let result = try await session.driver.perform(request.operation, arguments: request.arguments.filter { $0.key != "session_ref" })
            try checkAction(session, action: action)
            guard case .view(let view) = result else { throw AgentAPIError.unavailable }
            return .view(view)
        } catch {
            terminate(session, state: .cancelled)
            throw error
        }
    }

    private func action(_ request: AgentRequest, caller: EnrolledAgent) throws -> AgentOperationStatus {
        if let prior = try journal.prior(request, caller: caller) { return try status(prior.reference, caller: caller) }
        let (session, action) = try sessionForAction(request, caller: caller)
        guard session.operations.count < 256 else { throw AgentAPIError.rateLimited }
        let receipt = try journal.begin(request, caller: caller)
        session.operations.insert(receipt.status.reference)
        session.actionBusy = true
        session.task = Task { [weak self] in
            guard let self else { return }
            do {
                try checkAction(session, action: action)
                try journal.markSubmitted(receipt.status.reference, caller: caller)
                let result = try await session.driver.perform(request.operation, arguments: request.arguments.filter { $0.key != "session_ref" })
                try checkAction(session, action: action)
                guard case .completed = result else { throw AgentAPIError.unavailable }
                try journal.finish(receipt.status.reference, caller: caller, state: .succeeded)
                session.actionBusy = false
                session.task = nil
            } catch { terminate(session, state: .failed) }
        }
        return receipt.status
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
            let driver = try makeDriver(adapter)
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
        try session.driver.checkLease()
        guard !closed, workerAlive(), active === session, !Task.isCancelled,
              access.accounts.contains(where: { $0.policy == session.account.policy }),
              session.adapter.credentialOrigins.allSatisfy({ access.authorize(grantRef: session.grant, caller: session.caller, account: session.account.id, adapterID: session.adapter.id, origin: $0, action: .login, session: session.id) }) else { throw AgentAPIError.consentRequired }
    }

    private func authorize(_ stage: AuthenticationStage, session: Session) throws {
        try check(session)
        if stage == .challengeFill || stage == .challengeSubmit {
            guard session.stage == 4, session.checkpoint == nil, challengeSpec(session) != nil,
                  (stage == .challengeFill && session.challengeStage == 0) || (stage == .challengeSubmit && session.challengeStage == 1) else { throw AgentAPIError.unsupportedChallenge }
            session.challengeStage += 1
            return
        }
        guard session.stage < AuthenticationStage.primary.count, AuthenticationStage.primary[session.stage] == stage,
              session.challengeStage != 1, session.checkpoint == nil,
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
        let credential = try await resolve(session.account, origin, challengeSpec(session) != nil)
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
            }, owner: { [weak self] in
                guard let self else { throw AgentAPIError.unavailable }
                try await self.ownerChallenge(session)
            })
            try check(session)
            switch result {
            case .succeeded:
                guard session.stage == AuthenticationStage.primary.count else { throw AgentAPIError.unavailable }
                try journal.finish(session.operation, caller: session.caller, state: .succeeded)
                session.ready = true
                session.task = nil
            case .failed(let code): terminate(session, state: .failed, error: code)
            case .outcomeUnknown(let code): terminate(session, state: .outcomeUnknown, error: code)
            }
        } catch { terminate(session, state: .failed) }
    }

    private func renew() async {
        challenges.expire()
        guard let session = active else { return }
        do {
            try check(session)
            session.sequence += 1
            try await session.driver.renew(sequence: session.sequence)
            try check(session)
        } catch { terminate(session, state: .cancelled) }
    }

    private func terminate(_ session: Session, state: AgentOperationState, error: AgentAPIError? = nil) {
        guard active === session else { return }
        active = nil
        session.driver.revoke()
        challenges.cancel(session: session.id)
        session.task?.cancel(); session.task = nil
        do {
            for operation in session.operations {
                let current = try journal.status(operation, caller: session.caller)
                if [.running, .pendingOwner, .needsOwnerAction].contains(current.state) {
                    try journal.finish(operation, caller: session.caller, state: state, error: error ?? (state == .failed ? .unavailable : nil))
                }
            }
        } catch {
            // Receipt persistence failed. Close all authority; never retry the
            // action in this process. Restart reconciles the submitted flag.
            closed = true
        }
    }

    private func challengeSpec(_ session: Session) -> JSONValue? {
        PackagedAdapters.manifests[session.adapter.id]?["login"]?["challenge"]
    }

    private func ownerChallenge(_ session: Session) async throws {
        try check(session)
        guard session.stage == 4, session.challengeStage == 0, session.checkpoint == nil,
              let url = challengeSpec(session)?["url"]?.string,
              let host = URLComponents(string: url)?.host,
              session.adapter.credentialOrigins.contains("https://" + host) else { throw AgentAPIError.unsupportedChallenge }
        session.challengeStage = 2
        let checkpoint = try ReferenceRegistry.randomToken()
        session.checkpoint = checkpoint
        try journal.setOwnerAction(session.operation, caller: session.caller, waiting: true)
        try await challenges.request(session: session.id, checkpoint: checkpoint, account: session.account.metadata.title,
                                     caller: session.caller.displayName, origin: "https://" + host)
        try check(session)
        session.checkpoint = nil
        try journal.setOwnerAction(session.operation, caller: session.caller, waiting: false)
    }

    public func ownerMachine(checkpoint: String) -> VZVirtualMachine? {
        guard let session = active, session.checkpoint == checkpoint, challenges.pending?.id == checkpoint else { return nil }
        do { try check(session); return session.driver.ownerMachine }
        catch { terminate(session, state: .cancelled); return nil }
    }

    public func completeOwnerChallenge(_ checkpoint: String) throws {
        guard let session = active, session.checkpoint == checkpoint else { throw AgentAPIError.invalidReference }
        do { try check(session); try challenges.complete(checkpoint) }
        catch { terminate(session, state: .cancelled); throw error }
    }
}
