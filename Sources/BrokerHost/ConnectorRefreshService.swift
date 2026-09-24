import Foundation
import PolicyCore

/// Catalog permission permits discovery of an enrolled source, never its payload.
/// An accepted refresh is a native import job; entry changes can revoke its old
/// catalog grant without interrupting publication of the encrypted transaction.
@MainActor public final class ConnectorRefreshService: AgentProtectedService {
    private final class Job {
        let reference: String
        let caller: EnrolledAgent
        let source: UUID
        let sourceRef: String
        let deadline: TimeInterval
        var task: Task<Void, Never>?
        var terminal = false
        var submitted = false
        var checkpoint: String?
        var resumed: (checkpoint: String, request: UUID)?
        var resumes = 0
        init(reference: String, caller: EnrolledAgent, source: UUID, sourceRef: String, deadline: TimeInterval) {
            self.reference = reference; self.caller = caller; self.source = source; self.sourceRef = sourceRef; self.deadline = deadline
        }
    }
    public let availableOperations = ["connector.request_refresh", "operation.get", "operation.cancel", "operation.resume"]
    private let access: AccessCoordinator
    private let journal: OperationJournal
    private let isConfigured: @MainActor (UUID) -> Bool
    private let refresh: @MainActor (UUID, @escaping @MainActor () throws -> Void) async throws -> SourceRefreshResult
    private let cancel: @MainActor () -> Void
    private let clock: () -> TimeInterval
    private var jobs: [String: Job] = [:]
    private var lastRefresh: [UUID: TimeInterval] = [:]
    private var active: Job?
    private var closed = false
    private var monitor: Task<Void, Never>?
    private var observer: UUID?

    public init(access: AccessCoordinator, journal: OperationJournal, isConfigured: @escaping @MainActor (UUID) -> Bool,
                refresh: @escaping @MainActor (UUID, @escaping @MainActor () throws -> Void) async throws -> SourceRefreshResult,
                cancel: @escaping @MainActor () -> Void, clock: @escaping () -> TimeInterval = { DeadlineClock.now }) {
        self.access = access; self.journal = journal; self.isConfigured = isConfigured
        self.refresh = refresh; self.cancel = cancel; self.clock = clock
        observer = access.observeRevocation(owner: self, authority: true) { [weak self] grant in
            if grant == nil, let self, let active = self.active { self.finish(active, state: .cancelled) }
        }
        monitor = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: .milliseconds(250)) } catch { return }
                self?.expire()
            }
        }
    }

    deinit { monitor?.cancel() }

    public func shutdown() {
        closed = true
        monitor?.cancel(); monitor = nil
        if let observer { access.removeRevocationObserver(observer); self.observer = nil }
        if let active { finish(active, state: .cancelled) }
    }

    func sourceReference(_ account: ConsentAccount, accountRef: String) -> String? {
        guard !closed, let source = account.metadata.sourceInstance.flatMap(UUID.init(uuidString:)), isConfigured(source) else { return nil }
        return accountRef
    }

    func owns(_ reference: String, caller: EnrolledAgent) -> Bool { jobs[reference]?.caller == caller }

    public func handle(_ request: AgentRequest, caller: EnrolledAgent) async throws -> AgentDomainResult {
        guard !closed, access.unlocked, access.agents.contains(caller) else { throw AgentAPIError.unavailable }
        expire()
        if request.operation == "connector.request_refresh" {
            if let prior = try journal.prior(request, caller: caller) { return .operation(try status(prior.reference, caller: caller)) }
            guard jobs.count < 128, active == nil else { throw AgentAPIError.rateLimited }
            let reference = request.arguments["source_ref"]!.string!
            let source = try resolve(reference, caller: caller)
            guard lastRefresh[source].map({ clock() - $0 >= 60 }) ?? true else { throw AgentAPIError.rateLimited }
            let receipt = try journal.begin(request, caller: caller)
            let job = Job(reference: receipt.status.reference, caller: caller, source: source, sourceRef: reference, deadline: clock() + 300)
            jobs[job.reference] = job
            active = job; lastRefresh[source] = clock()
            launch(job)
            return .operation(receipt.status)
        }
        let reference = request.arguments["operation_ref"]?.string ?? ""
        guard let job = jobs[reference], job.caller == caller else { throw ConsentError.invalidReference }
        switch request.operation {
        case "operation.get": break
        case "operation.cancel": if !job.terminal { finish(job, state: .cancelled) }
        case "operation.resume":
            let checkpoint = request.arguments["checkpoint_ref"]!.string!
            if let resumed = job.resumed, resumed.checkpoint == checkpoint, resumed.request == request.id { break }
            guard !job.terminal, !job.submitted, job.checkpoint == checkpoint, job.task == nil, active === job,
                  try resolve(job.sourceRef, caller: caller) == job.source else { throw ConsentError.staleRequest }
            guard job.resumes < 3 else { throw AgentAPIError.rateLimited }
            try journal.setOwnerAction(reference, caller: caller, waiting: false)
            job.resumes += 1
            job.checkpoint = nil; job.resumed = (checkpoint, request.id)
            launch(job)
        default: throw AgentAPIError.capabilityUnavailable
        }
        return .operation(try status(reference, caller: caller))
    }

    private func resolve(_ reference: String, caller: EnrolledAgent) throws -> UUID {
        let account = try access.accountForReference(reference, caller: caller)
        guard let source = account.metadata.sourceInstance.flatMap(UUID.init(uuidString:)), isConfigured(source) else { throw AgentAPIError.notConfigured }
        return source
    }

    private func status(_ reference: String, caller: EnrolledAgent) throws -> AgentOperationStatus {
        let status = try journal.status(reference, caller: caller)
        return AgentOperationStatus(reference: reference, state: status.state, checkpoint: jobs[reference]?.checkpoint, error: status.error)
    }

    private func launch(_ job: Job) {
        job.task = Task { [weak self] in
            guard let self else { return }
            do {
                try self.check(job)
                let result = try await self.refresh(job.source) { [weak self, weak job] in
                    guard let self, let job else { throw SourceHostError.cancelled }
                    try self.check(job)
                    try self.journal.markSubmitted(job.reference, caller: job.caller)
                    job.submitted = true
                }
                try self.check(job)
                job.task = nil
                switch result.state {
                case "committed": self.finish(job, state: .succeeded)
                case "needs_owner_action":
                    guard !job.submitted else { throw AgentAPIError.outcomeUnknown }
                    job.checkpoint = try ReferenceRegistry.randomToken()
                    try self.journal.setOwnerAction(job.reference, caller: job.caller, waiting: true)
                case "not_configured": self.finish(job, state: .failed, error: .notConfigured)
                case "unsupported": self.finish(job, state: .failed, error: .capabilityUnavailable)
                case "aborted": self.finish(job, state: .cancelled)
                default: self.finish(job, state: .failed, error: .unavailable)
                }
            } catch { self.finish(job, state: .failed, error: .unavailable) }
        }
    }

    private func check(_ job: Job) throws {
        guard !closed, !job.terminal, active === job, access.unlocked, access.agents.contains(job.caller),
              isConfigured(job.source), clock() < job.deadline else { throw SourceHostError.cancelled }
    }

    private func expire() {
        guard let active else { return }
        do { try check(active) } catch { finish(active, state: .cancelled) }
    }

    private func finish(_ job: Job, state: AgentOperationState, error: AgentAPIError? = nil) {
        guard !job.terminal else { return }
        job.terminal = true
        job.checkpoint = nil
        job.task?.cancel(); job.task = nil
        if active === job { active = nil; cancel() }
        do { try journal.finish(job.reference, caller: job.caller, state: state, error: error) }
        catch { access.lock() }
    }
}
