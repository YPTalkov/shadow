import Foundation
import Observation
import BrokerHost
import PolicyCore

@Observable @MainActor
public final class OwnerVaultModel {
    public let configuration: OwnerConfiguration
    public let access = AccessCoordinator()
    public let agentAPI: AgentAPI
    public private(set) var protectedSessions: ProtectedSessionService?
    private var operationJournal: OperationJournal?
    public private(set) var diagnostics: DiagnosticReport?
    public private(set) var diagnosticsAvailable = false
    public private(set) var unlocked = false
    public private(set) var busy = false
    public private(set) var status = "Locked"
    public var message: String?
    public private(set) var accounts: [OwnerCatalogItem] = []
    public private(set) var nextOffset: Int?
    public private(set) var headers: [String] = []
    public private(set) var selectedCSV: URL?
    public private(set) var preview: OwnerImportPreview?
    public var mapping = OwnerCSVMapping(title: "", url: "", username: "", password: "")
    public var validRowsOnly = false
    public private(set) var editor: OwnerEditorStatus?
    public private(set) var editorReview: OwnerEditorReview?
    public private(set) var sources: [EnrolledSource] = []
    public private(set) var sourceSummaries: [OwnerSourceSummary] = []
    public private(set) var sourceCandidate: SourceCandidate?
    private var sourceStore: SourceEnrollmentStore?
    private let sourceRuntime = SourceRuntime()
    private var editorReservation: EditorReservation?
    private var isLocking = false
    private var lockTask: Task<Void, Never>?
    private var worker: PrivateVaultWorker?
    private var epoch = 0
    private var importOperation = UUID()
    private var lastInteraction: TimeInterval
    private var lastMaintenance: TimeInterval
    @ObservationIgnored private let clock: () -> TimeInterval

    public init(configuration: OwnerConfiguration, clock: @escaping () -> TimeInterval = { DeadlineClock.now }) {
        self.configuration = configuration
        self.clock = clock
        lastInteraction = clock()
        lastMaintenance = clock()
        agentAPI = AgentAPI(access: access)
        access.onAudit = { [weak self] code in self?.record(code) }
        for adapter in QualifiedAdapterPolicy.packaged { access.installQualifiedAdapter(adapter) }
        do {
            operationJournal = try OperationJournal(path: configuration.root.appendingPathComponent("operations.sqlite"))
            diagnosticsAvailable = true
        } catch { message = "Local diagnostics and operation receipts are unavailable. Agent sessions cannot start." }
        do {
            let store = try SourceEnrollmentStore(root: configuration.root, vaultID: configuration.vaultID)
            sourceStore = store
            sources = store.sources
        } catch { message = "Connector enrollment is unavailable. Existing encrypted source accounts are preserved." }
    }

    public var vaultExists: Bool {
        FileManager.default.fileExists(atPath: configuration.vaultDirectory.appendingPathComponent("vault.kdbx").path)
    }

    public func noteInteraction() { lastInteraction = clock() }

    public func checkIdle() async {
        access.expire()
        if clock() - lastMaintenance >= 60 {
            lastMaintenance = clock()
            do { try operationJournal?.maintain() }
            catch {
                diagnosticsAvailable = false
                lockImmediately()
                message = "The operation journal is unavailable. Existing encrypted files were preserved."
            }
        }
        if (unlocked || editorReview != nil) && clock() - lastInteraction >= 15 * 60 { lockImmediately(reason: .idle) }
    }

    public func open(password: String, create: Bool) async {
        guard !busy, !unlocked, editor == nil else { return }
        busy = true
        message = nil
        status = create ? "Creating vault…" : "Unlocking…"
        let generation = epoch
        defer { if generation == epoch { busy = false } }
        do {
            let client = try await launchWorker()
            guard generation == epoch else { await client.lock(); return }
            worker = client
            if create { try await client.create(password: password) } else { try await client.unlock(password: password) }
            let items = try await client.catalogSnapshot()
            let summaries = try await client.sources(instances: sources.map(\.id))
            guard generation == epoch else { return }
            accounts = items
            access.openVault(accounts: Self.consentAccounts(items))
            if let image = configuration.browserImage {
                if operationJournal == nil { operationJournal = try OperationJournal(path: configuration.root.appendingPathComponent("operations.sqlite")) }
                if let journal = operationJournal {
                    let service = ProtectedSessionService(access: access, journal: journal, worker: client, image: image)
                    protectedSessions = service
                    agentAPI.protectedService = service
                }
            }
            nextOffset = nil
            sourceSummaries = summaries
            unlocked = true
            status = "Unlocked"
            record(.vaultOpened)
            noteInteraction()
        } catch {
            guard generation == epoch else { return }
            await lock()
            message = Self.explain(error)
            if case VaultWorkerError.reported("editor_active") = error { await refreshEditorStatus() }
        }
    }

    public func lock() async {
        lockImmediately()
        await finishLock()
    }

    public func finishLock() async { await lockTask?.value }

    /// Revoke on the event's current MainActor turn, before scheduling teardown.
    public func lockImmediately(reason: OwnerLockReason = .owner) {
        guard !isLocking else { return }
        isLocking = true
        epoch += 1
        sourceRuntime.stop()
        protectedSessions?.shutdown()
        protectedSessions = nil
        agentAPI.protectedService = nil
        access.lock()
        record(AuditCode(lock: reason))
        let client = worker
        worker = nil
        unlocked = false
        busy = true
        status = "Locked"
        accounts = []
        nextOffset = nil
        headers = []
        selectedCSV = nil
        preview = nil
        editorReview = nil
        sourceCandidate = nil
        sourceSummaries = []
        mapping = OwnerCSVMapping(title: "", url: "", username: "", password: "")
        let generation = epoch
        if reason == .workerStopped { message = "The vault worker stopped. Unlock again before continuing." }
        lockTask = Task { [weak self] in
            await client?.lock()
            guard let self, generation == self.epoch else { return }
            self.isLocking = false; self.busy = false
            self.lockTask = nil
            if self.editor != nil {
                self.status = "Editing checkout active"
                self.reserveEditor()
            }
        }
    }

    public func refreshEditorStatus() async {
        guard !busy, !unlocked, worker == nil else { return }
        busy = true
        let generation = epoch
        defer { if generation == epoch { busy = false } }
        do {
            let client = try await launchWorker()
            let state = try await client.editorStatus()
            await client.lock()
            guard generation == epoch else { return }
            editor = state.state == "editing" ? state : nil
            if editor != nil { status = "Editing checkout active"; reserveEditor() }
        } catch {
            guard generation == epoch else { return }
            message = Self.explain(error)
        }
    }

    public func beginEditing() async {
        guard unlocked, !busy, let client = worker else { return }
        access.lock()
        busy = true
        let generation = epoch
        do {
            let state = try await client.beginEditor()
            guard generation == epoch else { return }
            editor = state
            await lock()
            message = "An encrypted editing copy is ready. Unlock it independently in KeePassXC, then close KeePassXC and review your changes here."
        } catch {
            guard generation == epoch else { return }
            await lock()
            message = Self.explain(error)
            await refreshEditorStatus()
        }
    }

    public func openEditor() async {
        guard !busy, let path = editor?.checkoutPath, editorReservation != nil else { return }
        do { try await QualifiedEditor.openCheckout(URL(fileURLWithPath: path)) }
        catch { message = "The qualified KeePassXC 2.7.12 app could not open. Your encrypted checkout is preserved." }
    }

    public func previewEditing(password: String) async {
        await editingOperation { client in
            let review = try await client.previewEditor(password: password)
            return { self.editorReview = review; self.status = "Review editor changes" }
        }
    }

    public func applyEditing() async {
        guard let review = editorReview else { return }
        await editingOperation { client in
            let result = try await client.commitEditor(reviewID: review.reviewId)
            return {
                self.editor = nil; self.editorReview = nil
                self.message = result.lateChange
                    ? "Reviewed changes were applied. The editing copy changed again and was preserved; review that copy separately."
                    : "Reviewed changes were applied. The encrypted editing copy is preserved; later editor saves cannot change your active vault. Unlock to continue."
            }
        }
        if editor == nil { await lock() }
    }

    public func cancelEditing(discard: Bool) async {
        await editingOperation { client in
            _ = try await client.cancelEditor(discard: discard)
            return {
                self.editor = nil; self.editorReview = nil
                self.message = discard ? "Editing cancelled and the checkout discarded. The active vault was preserved." : "Editing cancelled. The encrypted checkout was preserved in the vault's editor folder."
            }
        }
        if editor == nil { await lock() }
    }

    private func launchWorker() async throws -> PrivateVaultWorker {
        let generation = epoch
        return try await PrivateVaultWorker.launch(python: configuration.python, vaultDirectory: configuration.vaultDirectory, vaultID: configuration.vaultID, onInvalidate: { [weak access] ids in
            for id in ids { access?.invalidate(account: id) }
        }, onTermination: { [weak self] in
            guard let self, self.epoch == generation else { return }
            self.lockImmediately(reason: .workerStopped)
        })
    }

    private func reserveEditor() {
        guard editorReservation == nil else { return }
        do { editorReservation = try EditorReservation(vaultDirectory: configuration.vaultDirectory) }
        catch { message = "The editing lease could not be reserved. Keep the checkout; vault access remains closed." }
    }

    private func editingOperation(_ operation: (PrivateVaultWorker) async throws -> (() -> Void)) async {
        guard editor != nil, !busy, !unlocked else { return }
        guard !QualifiedEditor.isRunning else { message = "Close KeePassXC before reviewing, applying or cancelling this checkout."; return }
        busy = true
        message = nil
        editorReservation = nil
        noteInteraction()
        let generation = epoch
        defer { if generation == epoch { busy = false } }
        do {
            let client: PrivateVaultWorker
            if let existing = worker { client = existing } else { client = try await launchWorker() }
            guard generation == epoch else { await client.lock(); return }
            worker = client
            let publish = try await operation(client)
            guard generation == epoch else { return }
            publish()
        } catch {
            guard generation == epoch else { return }
            await lock()
            message = Self.explain(error)
        }
    }

    public func loadMore() async {
        guard let offset = nextOffset else { return }
        await perform { client in
            let page = try await client.catalog(offset: offset)
            return { self.accounts += page.items; self.nextOffset = page.nextOffset; self.access.updateAccounts(Self.consentAccounts(page.items)) }
        }
    }

    public func selectCSV(_ path: URL) async {
        await perform { client in
            let headers = try await client.csvHeaders(path: path)
            return {
                self.selectedCSV = path
                self.headers = headers
                self.preview = nil
                func match(_ candidates: [String]) -> String { headers.first { candidates.contains($0.lowercased()) } ?? "" }
                self.mapping = OwnerCSVMapping(title: match(["title", "name"]), url: match(["url", "website"]), username: match(["username", "user", "login"]), password: match(["password"]))
                self.mapping.notes = headers.first { $0.lowercased() == "notes" }
                self.validRowsOnly = false
            }
        }
    }

    public func previewCSV() async {
        guard let path = selectedCSV else { return }
        let selection = mapping
        await perform { client in
            let preview = try await client.previewCSV(path: path, mapping: selection)
            return { self.preview = preview; self.importOperation = UUID() }
        }
    }

    public func commitCSV() async {
        guard preview != nil, !busy else { return }
        access.lock()
        let operation = importOperation, validOnly = validRowsOnly
        await perform { client in
            let result = try await client.commitCSV(operationID: operation, validRowsOnly: validOnly)
            let items = try await client.catalogSnapshot()
            try await client.cancelCSV()
            return {
                self.accounts = items
                self.access.openVault(accounts: Self.consentAccounts(items))
                self.record(.importCompleted)
                self.nextOffset = nil
                self.preview = nil
                self.selectedCSV = nil
                self.headers = []
                self.message = "Imported \(result.accepted) accounts. The original CSV is still plaintext; manage its export, download and cloud copies separately."
            }
        }
        // A recoverable import error must not leave the owner UI open while
        // authority is closed. Reopening creates a fresh consent scope.
        if unlocked && !access.unlocked { await lock() }
    }

    public func inspectSource(_ application: URL) async {
        guard unlocked, !busy else { return }
        busy = true
        let generation = epoch
        defer { if generation == epoch { busy = false } }
        do {
            let candidate = try await Task.detached { try SourceCandidate.inspect(application) }.value
            guard generation == epoch else { return }
            sourceCandidate = candidate
        } catch {
            guard generation == epoch else { return }
            message = "Choose a signed connector app with a valid Shadow source manifest. The app has not been enrolled."
        }
    }

    public func cancelSourceEnrollment() { sourceCandidate = nil }

    public func enrollSource(label: String) {
        guard unlocked, !busy, let candidate = sourceCandidate, let store = sourceStore else { return }
        do {
            _ = try store.enroll(candidate, label: label)
            sources = store.sources
            sourceCandidate = nil
            message = "Connector enrolled. Refresh is manual; periodic collection is off."
        } catch { message = "The connector could not be enrolled. Verify its identity and try again." }
    }

    public func setSourceEnabled(_ id: UUID, _ enabled: Bool) {
        guard unlocked, !busy, let store = sourceStore else { return }
        do { try store.setEnabled(id, enabled); sources = store.sources }
        catch { message = "The connector setting could not be saved." }
    }

    public func removeSource(_ id: UUID) {
        guard unlocked, !busy, let store = sourceStore else { return }
        do {
            try store.remove(id); sources = store.sources
            message = "Connector removed. Its encrypted accounts and source history are preserved."
        } catch { message = "The connector could not be removed." }
    }

    public func refreshSource(_ id: UUID) async {
        guard unlocked, !busy, let source = sources.first(where: { $0.id == id }), let store = sourceStore else { return }
        access.lock()
        await perform { client in
            let result = try await self.sourceRuntime.refresh(source, store: store, worker: client)
            let items = try await client.catalogSnapshot()
            let summaries = try await client.sources(instances: self.sources.map(\.id))
            return {
                self.accounts = items; self.nextOffset = nil
                self.access.openVault(accounts: Self.consentAccounts(items))
                self.sourceSummaries = summaries
                if result.state == "committed" { self.record(.sourceRefreshed) }
                switch result.state {
                case "committed": self.message = "Source updated: \(result.receipt?.accepted ?? 0) accepted, \(result.receipt?.conflicted ?? 0) conflicts, \(result.receipt?.retained ?? 0) retained."
                case "needs_owner_action": self.message = "The connector needs your attention. Open its app to sign in or unlock the source, then refresh again."
                case "aborted": self.message = "The connector cancelled its update. Existing accounts are preserved."
                default: self.message = "This connector cannot refresh its configured source."
                }
            }
        }
        if unlocked && !access.unlocked { await lock() }
    }

    public func resolveSourceConflict(_ item: OwnerCatalogItem, choice: String) async {
        guard unlocked, !busy, let entry = UUID(uuidString: item.id), item.conflicted else { return }
        access.lock()
        await perform { client in
            _ = try await client.resolveConflict(entry: entry, revision: item.revision, choice: choice, operationID: UUID())
            let items = try await client.catalogSnapshot()
            return {
                self.accounts = items; self.nextOffset = nil
                // A resolution can archive an unlinked candidate. Reset the
                // consent scope so removed entries cannot remain discoverable.
                self.access.openVault(accounts: Self.consentAccounts(items))
                self.message = "Conflict resolved. Request fresh access before using the account."
            }
        }
        if unlocked && !access.unlocked { await lock() }
    }

    private static func consentAccounts(_ items: [OwnerCatalogItem]) -> [ConsentAccount] {
        items.compactMap { item in
            guard let id = UUID(uuidString: item.id) else { return nil }
            let local = item.sourceKind == "local"
            let presence: SourcePresence = switch item.presence {
            case "present": .present
            case "deleted_at_source": .deletedAtSource
            case "access_lost": .accessLost
            default: .unknown
            }
            let policy = AccountPolicy(id: id, revision: item.revision, source: local ? .local : .mirrored, presence: presence, lastObserved: item.observationDate, restrictionEvent: item.restrictionEvent.flatMap(UUID.init(uuidString:)), conflicted: item.conflicted)
            return ConsentAccount(metadata: item, policy: policy)
        }
    }

    public func reviseMapping() async {
        await perform { client in
            try await client.cancelCSV()
            return { self.preview = nil }
        }
    }

    public func cancelCSV() async {
        await perform { client in
            try await client.cancelCSV()
            return { self.preview = nil; self.selectedCSV = nil; self.headers = [] }
        }
    }

    public func prepareDiagnostics() {
        diagnostics = nil
        do {
            guard let operationJournal else { throw OperationJournalError.storageUnavailable }
            diagnostics = try operationJournal.diagnosticReport()
            diagnosticsAvailable = true
        } catch {
            diagnosticsAvailable = false
            message = "The diagnostic report could not be read. Existing encrypted files were preserved."
        }
    }

    public func exportDiagnostics(to destination: URL) {
        guard let diagnostics else { return }
        do {
            try diagnostics.data.write(to: destination, options: .atomic)
            message = "The reviewed diagnostic report was exported."
        } catch { message = "The diagnostic report could not be saved." }
    }

    private func record(_ code: AuditCode) {
        do {
            guard let operationJournal else { throw OperationJournalError.storageUnavailable }
            try operationJournal.record(code)
        } catch { diagnosticsAvailable = false }
    }

    private func perform(_ operation: (PrivateVaultWorker) async throws -> (() -> Void)) async {
        guard unlocked, !busy, let client = worker else { return }
        busy = true
        message = nil
        let generation = epoch
        noteInteraction()
        defer { if generation == epoch { busy = false } }
        do {
            let publish = try await operation(client)
            guard generation == epoch else { return }
            publish()
        } catch {
            guard generation == epoch else { return }
            if case VaultWorkerError.reported(let code) = error {
                if ["recovery_required", "external_modification", "invalid_credentials", "vault_locked", "unsafe_path", "vault_unavailable"].contains(code) { await lock() }
                message = Self.explain(error)
            } else {
                await lock()
                message = "The operation was interrupted. Unlock the vault to check the result before trying again."
            }
        }
    }

    private static func explain(_ error: any Error) -> String {
        guard case VaultWorkerError.reported(let code) = error else { return "The vault worker is unavailable. Your encrypted files were preserved." }
        switch code {
        case "invalid_credentials": return "The master password was not accepted."
        case "recovery_required", "external_modification": return "This vault needs recovery before access can resume. Its encrypted files were preserved."
        case "already_exists": return "A vault already exists here. Unlock it to continue."
        case "invalid_mapping": return "Choose a different column for each field and include all required fields."
        case "invalid_rows": return "Some rows are invalid. Review the preview before importing only valid rows."
        case "source_changed": return "The selected CSV changed. Select it again to review a fresh preview."
        case "invalid_csv", "unsafe_source": return "This CSV cannot be imported. Check its encoding, headers and format."
        case "limit_exceeded": return "The selected file exceeds the import limits."
        case "unsupported_profile", "kdf_limit_exceeded": return "This encrypted file uses settings that have not been qualified."
        case "editor_active": return "An encrypted editing checkout is active. Finish or cancel it before unlocking the vault."
        case "editor_changed": return "The editing copy changed after review. Close KeePassXC and review the new version before applying."
        case "editor_unavailable": return "The editing copy is missing or unavailable. Its existing recovery files were preserved."
        case "unsafe_path": return "The vault's file permissions or location need attention before access can resume."
        default: return "The operation could not be completed. Your encrypted files were preserved."
        }
    }
}
