import Foundation
import Observation
import BrokerHost

@Observable @MainActor
public final class OwnerVaultModel {
    public let configuration: OwnerConfiguration
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
    private var editorReservation: EditorReservation?
    private var isLocking = false
    private var worker: PrivateVaultWorker?
    private var epoch = 0
    private var importOperation = UUID()
    private var lastInteraction = Date()

    public init(configuration: OwnerConfiguration) { self.configuration = configuration }

    public var vaultExists: Bool {
        FileManager.default.fileExists(atPath: configuration.vaultDirectory.appendingPathComponent("vault.kdbx").path)
    }

    public func noteInteraction() { lastInteraction = Date() }

    public func checkIdle() async {
        if (unlocked || editorReview != nil) && Date().timeIntervalSince(lastInteraction) >= 15 * 60 { await lock() }
    }

    public func open(password: String, create: Bool) async {
        guard !busy, !unlocked, editor == nil else { return }
        busy = true
        message = nil
        status = create ? "Creating vault…" : "Unlocking…"
        let generation = epoch
        defer { if generation == epoch { busy = false } }
        do {
            let client = try await PrivateVaultWorker.launch(python: configuration.python, vaultDirectory: configuration.vaultDirectory, vaultID: configuration.vaultID)
            guard generation == epoch else { await client.lock(); return }
            worker = client
            if create { try await client.create(password: password) } else { try await client.unlock(password: password) }
            let page = try await client.catalog()
            guard generation == epoch else { return }
            accounts = page.items
            nextOffset = page.nextOffset
            unlocked = true
            status = "Unlocked"
            noteInteraction()
        } catch {
            guard generation == epoch else { return }
            await lock()
            message = Self.explain(error)
            if case VaultWorkerError.reported("editor_active") = error { await refreshEditorStatus() }
        }
    }

    public func lock() async {
        guard !isLocking else { return }
        isLocking = true
        defer { isLocking = false; busy = false }
        epoch += 1
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
        mapping = OwnerCSVMapping(title: "", url: "", username: "", password: "")
        await client?.lock()
        if editor != nil {
            status = "Editing checkout active"
            reserveEditor()
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
        try await PrivateVaultWorker.launch(python: configuration.python, vaultDirectory: configuration.vaultDirectory, vaultID: configuration.vaultID)
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
            return { self.accounts += page.items; self.nextOffset = page.nextOffset }
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
        guard preview != nil else { return }
        let operation = importOperation, validOnly = validRowsOnly
        await perform { client in
            let result = try await client.commitCSV(operationID: operation, validRowsOnly: validOnly)
            let page = try await client.catalog()
            try await client.cancelCSV()
            return {
                self.accounts = page.items
                self.nextOffset = page.nextOffset
                self.preview = nil
                self.selectedCSV = nil
                self.headers = []
                self.message = "Imported \(result.accepted) accounts. The original CSV is still plaintext; manage its export, download and cloud copies separately."
            }
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
