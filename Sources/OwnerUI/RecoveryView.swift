import SwiftUI
import AppKit
import UniformTypeIdentifiers
import BrokerHost

struct RecoveryView: View {
    @Bindable var model: OwnerVaultModel
    @State private var selection: URL?
    @State private var password = ""
    @State private var acknowledgeUnknown = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Encrypted recovery files").font(.title2.bold())
                Text("Keep the master password separately. Encrypted copies can be opened independently in KeePassXC.").foregroundStyle(.secondary)
                if let backup = model.backupStatus {
                    Text("Last daily backup: \(backup.lastDay ?? "None") · Daily copies: \(backup.dailyCount)")
                }
                HStack {
                    Button("Verify daily backup") { Task { await model.backupNow() } }
                        .disabled(model.busy || model.editor != nil || !model.vaultExists || model.restoreReview != nil)
                    Button("Export encrypted copy…") { exportBackup() }.disabled(!model.unlocked || model.busy)
                    Button("Show vault folder") { NSWorkspace.shared.open(model.configuration.vaultDirectory) }
                }
                Text("Shadow keeps the previous generation and 30 days of daily backups while it runs. Unlock to export the current encrypted vault. Exports use a new filename.").font(.callout).foregroundStyle(.secondary)
                Divider()
                Text("Restore an encrypted file").font(.headline)
                if let review = model.restoreReview {
                    Text("Accounts in the selected snapshot: \(review.accounts) · Mirrored entries: \(review.mirrored)")
                    Text("Current files will be preserved. Newer restrictions remain in force. Restored mirrors require retained-copy review; local accounts need new approval.")
                    if review.historyUnknown {
                        Text("Restriction history is missing or cannot be verified. Shadow cannot determine which source restrictions were lost.").foregroundStyle(.orange)
                        Toggle("I understand the history is uncertain; treat every restored mirror as unknown.", isOn: $acknowledgeUnknown)
                    }
                    HStack {
                        Button("Restore reviewed snapshot") { Task { await model.commitRestore(acknowledgeUnknownHistory: acknowledgeUnknown) } }
                            .disabled(model.busy || (review.historyUnknown && !acknowledgeUnknown))
                        Button("Cancel restore") { model.lockImmediately() }.disabled(model.busy)
                    }
                } else {
                    Text("Reviewing a file ends all agent sessions and locks the current vault. Restore never reactivates previous grants.").foregroundStyle(.secondary)
                    Button(selection == nil ? "Choose encrypted file…" : "Choose another file…") { chooseRestore() }
                        .disabled(model.busy || model.editor != nil)
                    if let selection {
                        Text(selection.lastPathComponent).font(.callout)
                        SecureField("Selected file's master password", text: $password).textFieldStyle(.roundedBorder)
                        Button("Check and review restore") {
                            let submitted = password
                            password = ""
                            acknowledgeUnknown = false
                            Task { await model.previewRestore(path: selection, password: submitted) }
                        }.disabled(password.isEmpty || model.busy)
                    }
                }
                Divider()
                Text("Local diagnostics").font(.headline)
                Text("Review seven days of event codes and counts before exporting. The report contains no account names, websites or credential values.").foregroundStyle(.secondary)
                Button("Review diagnostic report") { model.prepareDiagnostics() }
                if let report = model.diagnostics {
                    ScrollView { Text(report.text).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }.frame(maxHeight: 160)
                    Button("Export reviewed report…") {
                        let panel = NSSavePanel()
                        panel.allowedContentTypes = [.json]
                        panel.nameFieldStringValue = "shadow-diagnostics.json"
                        Task { @MainActor in
                            if await panel.begin() == .OK, let url = panel.url { model.exportDiagnostics(to: url) }
                        }
                    }
                } else if !model.diagnosticsAvailable {
                    Text("Diagnostics are unavailable.").font(.callout).foregroundStyle(.secondary)
                }
            }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func chooseRestore() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "kdbx") ?? .data]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        Task { @MainActor in
            if await panel.begin() == .OK, let url = panel.url { selection = url; password = "" }
        }
    }

    private func exportBackup() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "kdbx") ?? .data]
        panel.nameFieldStringValue = "shadow-\(String(ISO8601DateFormatter().string(from: Date()).prefix(10))).kdbx"
        Task { @MainActor in
            if await panel.begin() == .OK, let url = panel.url { await model.exportBackup(to: url) }
        }
    }
}
