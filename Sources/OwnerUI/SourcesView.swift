import AppKit
import SwiftUI
import UniformTypeIdentifiers
import BrokerHost

public struct SourcesView: View {
    @Bindable private var model: OwnerVaultModel
    @State private var sourceLabel = ""
    @State private var filter = ""
    @State private var removal: EnrolledSource?

    public init(model: OwnerVaultModel) { self.model = model }

    public var body: some View {
        if !model.unlocked {
            ContentUnavailableView("Unlock to manage sources", systemImage: "lock", description: Text("Your retained accounts stay encrypted when a connector is disabled or removed."))
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 20) {
                    Text("Sources & Retained Items").font(.title2.bold())
                    Text("Connectors provide updates. Account access is approved separately in Agent Access.").foregroundStyle(.secondary)
                    Button("Choose connector app…") { chooseConnector() }.disabled(model.busy)
                    if let candidate = model.sourceCandidate {
                        GroupBox("Review connector enrollment") {
                            VStack(alignment: .leading, spacing: 12) {
                                Text(candidate.identifier).font(.headline).textSelection(.enabled)
                                Text(candidate.application.path).font(.caption).textSelection(.enabled)
                                Text("Executable SHA-256: \(candidate.fingerprint)").font(.caption.monospaced()).textSelection(.enabled)
                                capabilitySummary(candidate.capabilities)
                                Text("This connector runs locally and handles source credentials. Enroll only an app you trust. An executable update requires a new enrollment.").foregroundStyle(.secondary)
                                TextField("Your source label", text: $sourceLabel).textFieldStyle(.roundedBorder)
                                HStack {
                                    Button("Enroll connector") { model.enrollSource(label: sourceLabel); sourceLabel = "" }.buttonStyle(.borderedProminent).disabled(model.busy || sourceLabel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                                    Button("Cancel") { model.cancelSourceEnrollment() }
                                }
                            }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    if model.sources.isEmpty { Text("No connectors enrolled. CSV accounts work independently.").foregroundStyle(.secondary) }
                    ForEach(model.sources) { source in
                        GroupBox {
                            VStack(alignment: .leading, spacing: 12) {
                                HStack {
                                    Text(source.label).font(.headline)
                                    Spacer()
                                    Toggle("Enabled", isOn: Binding(get: { source.enabled }, set: { model.setSourceEnabled(source.id, $0) })).toggleStyle(.switch).fixedSize()
                                }
                                Text(source.candidate.identifier).font(.caption).foregroundStyle(.secondary)
                                capabilitySummary(source.candidate.capabilities)
                                if let status = model.sourceSummaries.first(where: { $0.instance == source.id.uuidString.lowercased() }) {
                                    Text("Last received: \(status.lastReceived) · Generation \(status.generation)").font(.caption).foregroundStyle(.secondary)
                                } else { Text("No completed refresh yet").font(.caption).foregroundStyle(.secondary) }
                                HStack {
                                    Button("Refresh now") { Task { await model.refreshSource(source.id) } }.disabled(!source.enabled)
                                    Button("Remove connector…") { removal = source }
                                    Text("Periodic refresh is off").font(.caption).foregroundStyle(.secondary)
                                }
                            }.padding(8)
                        }.disabled(model.busy)
                    }
                    Divider()
                    Text("Retained items and conflicts").font(.headline)
                    Text("A source removal, lost access, stale observation or uncertain history never deletes your encrypted copy. Reappearance still needs a fresh retained-copy approval. Inspect password values with the KeePassXC editing workflow.").foregroundStyle(.secondary)
                    TextField("Filter by account or username", text: $filter).textFieldStyle(.roundedBorder)
                    let items = model.accounts.filter { item in
                        (item.restrictionEvent != nil || item.conflicted || item.diverged) && (filter.isEmpty || item.title.localizedCaseInsensitiveContains(filter) || item.username.localizedCaseInsensitiveContains(filter))
                    }
                    if items.isEmpty { Text("No matching retained items or conflicts").foregroundStyle(.secondary) }
                    ForEach(items) { item in
                        GroupBox {
                            VStack(alignment: .leading, spacing: 10) {
                                Text(item.title).font(.headline)
                                Text(item.username).foregroundStyle(.secondary)
                                Text(item.group).font(.caption).foregroundStyle(.secondary)
                                Text(presence(item)).font(.callout)
                                if let observed = item.observationDate { Text("Last observed: \(observed.formatted())").font(.caption) }
                                if item.conflicted {
                                    Text("Source and local edits conflict. Credential use is blocked until you choose a resolution.").foregroundStyle(.orange)
                                    HStack {
                                        Button("Keep local") { Task { await model.resolveSourceConflict(item, choice: "keep_local") } }
                                        Button("Accept incoming") { Task { await model.resolveSourceConflict(item, choice: "accept_incoming") } }
                                        Button("Keep both") { Task { await model.resolveSourceConflict(item, choice: "keep_both") } }
                                    }.disabled(model.busy)
                                } else if item.diverged { Text("Local changes retained; this copy differs from its source.").font(.caption) }
                            }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }.padding(24)
            }
            .confirmationDialog("Remove this connector?", isPresented: Binding(get: { removal != nil }, set: { if !$0 { removal = nil } }), titleVisibility: .visible) {
                Button("Remove connector", role: .destructive) { if let source = removal { model.removeSource(source.id) }; removal = nil }
                Button("Cancel", role: .cancel) { removal = nil }
            } message: { Text("Its encrypted accounts and source history will remain in your vault.") }
        }
    }

    private func capabilitySummary(_ capabilities: SourceCapabilities) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Stable items: \(capabilities.stableItems ? "Yes" : "No — owner reconciliation required") · Stable groups: \(capabilities.stableGroups ? "Yes" : "No")")
            Text("Complete coverage: \(capabilities.completeScopes.isEmpty ? "None" : capabilities.completeScopes.joined(separator: ", ")) · Access loss: \(capabilities.distinguishesAccessLoss ? "Distinguished" : "Unknown")")
            Text("Collection: \(capabilities.collectionMode.replacingOccurrences(of: "_", with: " ")) · Credentials: \(capabilities.totp ? "Password and TOTP" : "Password")")
        }.font(.caption).foregroundStyle(.secondary)
    }

    private func presence(_ item: OwnerCatalogItem) -> String {
        switch item.presence {
        case "deleted_at_source": "Retained local copy · Deleted at source"
        case "access_lost": "Retained local copy · Source access lost"
        case "unknown": "Retained local copy · Source presence uncertain"
        default: item.restrictionEvent != nil ? "Retained local copy · Historical restriction or stale observation" : "Present at source"
        }
    }

    private func chooseConnector() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.applicationBundle]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        Task { @MainActor in
            if await panel.begin() == .OK, let application = panel.url { await model.inspectSource(application) }
        }
    }
}
