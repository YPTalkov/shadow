import SwiftUI
import AppKit
import UniformTypeIdentifiers
import BrokerHost

public struct OwnerPanel: View {
    @Bindable private var model: OwnerVaultModel
    @State private var destination: Destination? = .vault
    @State private var password = ""
    @State private var confirmation = ""

    public init(model: OwnerVaultModel, initialDestination: Destination = .vault) {
        self.model = model
        _destination = State(initialValue: initialDestination)
    }

    public enum Destination: String, CaseIterable, Identifiable {
        case vault = "Vault", importCSV = "Import", access = "Agent Access", sources = "Sources & Retained Items", recovery = "Recovery"
        public var id: Self { self }
        var icon: String {
            switch self {
            case .vault: "lock.shield"
            case .importCSV: "square.and.arrow.down"
            case .access: "person.crop.circle.badge.checkmark"
            case .sources: "arrow.triangle.2.circlepath"
            case .recovery: "clock.arrow.circlepath"
            }
        }
    }

    public var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                Text("SHADOW").font(.caption.weight(.semibold)).foregroundStyle(.secondary).padding([.horizontal, .top], 12).padding(.bottom, 8)
                ForEach(Destination.allCases) { item in
                    Button { destination = item } label: {
                        Label(item.rawValue, systemImage: item.icon)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                            .background(destination == item ? Color.accentColor.opacity(0.15) : .clear, in: RoundedRectangle(cornerRadius: 8))
                            .contentShape(Rectangle())
                    }.buttonStyle(.plain)
                }
                Spacer()
            }.padding(10).frame(width: 205).frame(maxHeight: .infinity).background(.quaternary.opacity(0.3))
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 10) {
                    Image(systemName: model.unlocked ? "lock.open.fill" : "lock.fill").foregroundStyle(model.unlocked ? .green : .secondary)
                    Text(model.status).fontWeight(.semibold)
                    if model.busy { ProgressView().controlSize(.small) }
                    Spacer()
                    if model.unlocked || model.busy {
                        Button(model.busy ? "Cancel and lock" : "Lock vault") { Task { await model.lock() } }
                            .accessibilityLabel("Lock vault and end access")
                    }
                }.padding()
                Divider()
                Group {
                    switch destination ?? .vault {
                    case .vault: vault
                    case .importCSV: importView
                    case .access: ContentUnavailableView("Agent access is closed", systemImage: "lock.shield", description: Text("Credential use will remain unavailable until this build completes its runtime qualification."))
                    case .sources: ContentUnavailableView("No sources enrolled", systemImage: "arrow.triangle.2.circlepath", description: Text("CSV imports work independently. An optional connector can be enrolled after its consumer is qualified."))
                    case .recovery: recovery
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
                if let message = model.message {
                    Divider()
                    HStack(alignment: .top) {
                        Image(systemName: "info.circle")
                        Text(message).textSelection(.enabled)
                        Spacer()
                        Button { model.message = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain).accessibilityLabel("Dismiss message")
                    }.padding().background(.quaternary.opacity(0.3))
                }
                Divider()
                Label("Development build · Synthetic credentials only", systemImage: "hammer")
                    .font(.caption).foregroundStyle(.secondary).padding(12)
            }
        }
        .navigationTitle("Shadow")
        .onChange(of: model.unlocked) { _, unlocked in if !unlocked { password = ""; confirmation = "" } }
    }

    private var vault: some View {
        Group {
            if model.unlocked {
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Your accounts").font(.title2.bold())
                            Text("Account metadata is visible here. Password inspection belongs in KeePassXC.").font(.callout).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Import CSV") { destination = .importCSV }
                    }.padding([.top, .horizontal])
                    if model.accounts.isEmpty {
                        ContentUnavailableView("Your vault is empty", systemImage: "tray", description: Text("Import a synthetic CSV to add your first accounts."))
                    } else {
                        Table(model.accounts) {
                            TableColumn("Account", value: \.title)
                            TableColumn("Username", value: \.username)
                            TableColumn("Website") { item in Text(item.origins.joined(separator: ", ")) }
                            TableColumn("Group", value: \.group)
                        }.padding(.horizontal)
                    }
                    if model.nextOffset != nil {
                        Button("Load more accounts") { Task { await model.loadMore() } }.disabled(model.busy).padding([.horizontal, .bottom])
                    }
                }
            } else {
                VStack(alignment: .leading, spacing: 18) {
                    Image(systemName: "lock.shield").font(.system(size: 42)).foregroundStyle(.tint)
                    Text(model.vaultExists ? "Unlock your vault" : "Create your local vault").font(.largeTitle.bold())
                    Text("Your master password protects an encrypted KDBX file that you can recover with KeePassXC. Shadow does not save the master password.")
                        .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    SecureField("Master password", text: $password).textFieldStyle(.roundedBorder).accessibilityLabel("Master password")
                    if !model.vaultExists { SecureField("Confirm master password", text: $confirmation).textFieldStyle(.roundedBorder) }
                    Button(model.vaultExists ? "Unlock vault" : "Create vault") {
                        let value = password, create = !model.vaultExists
                        password = ""; confirmation = ""
                        Task { await model.open(password: value, create: create) }
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.busy || password.isEmpty || (!model.vaultExists && password != confirmation))
                }.frame(maxWidth: 460).padding(32)
            }
        }
    }

    private var importView: some View {
        Group {
            if !model.unlocked {
                ContentUnavailableView("Unlock to import", systemImage: "lock", description: Text("Choose and review a CSV after unlocking your vault."))
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        Text("Import accounts").font(.title2.bold())
                        Text("The source CSV is already plaintext. Importing encrypts the vault copy; the original file and any export, download or cloud copies remain your responsibility.")
                            .foregroundStyle(.secondary)
                        HStack {
                            Button("Choose CSV…") { chooseCSV() }.disabled(model.busy)
                            if let file = model.selectedCSV { Text(file.lastPathComponent).lineLimit(1).foregroundStyle(.secondary) }
                        }
                        if !model.headers.isEmpty {
                            GroupBox("Column mapping") {
                                Form {
                                    columnPicker("Account title", value: $model.mapping.title)
                                    columnPicker("Website URL", value: $model.mapping.url)
                                    columnPicker("Username", value: $model.mapping.username)
                                    columnPicker("Password", value: $model.mapping.password)
                                    optionalPicker("Notes", value: $model.mapping.notes)
                                    optionalPicker("TOTP", value: $model.mapping.totp)
                                    optionalPicker("Group", value: $model.mapping.group)
                                }.padding(8).disabled(model.busy || model.preview != nil)
                            }
                            if let preview = model.preview {
                                HStack {
                                    Text("\(preview.accepted) valid · \(preview.rejected) rejected").font(.headline)
                                    Spacer()
                                    Button("Change mapping") { Task { await model.reviseMapping() } }.disabled(model.busy)
                                }
                                ForEach(Array(preview.rows.enumerated()), id: \.offset) { _, row in
                                    HStack {
                                        VStack(alignment: .leading) { Text(row.title).fontWeight(.medium); Text(row.username).foregroundStyle(.secondary) }
                                        Spacer()
                                        Text(row.origin).font(.callout).foregroundStyle(.secondary)
                                    }.padding(.vertical, 4)
                                }
                                if preview.accepted > preview.rows.count { Text("Showing the first \(preview.rows.count) valid rows.").font(.caption).foregroundStyle(.secondary) }
                                if preview.rejected > 0 { Toggle("Import only the valid rows", isOn: $model.validRowsOnly) }
                                HStack {
                                    Button("Import \(preview.accepted) accounts") { Task { await model.commitCSV() } }
                                        .buttonStyle(.borderedProminent)
                                        .disabled(model.busy || preview.accepted == 0 || (preview.rejected > 0 && !model.validRowsOnly))
                                    Button("Cancel import") { Task { await model.cancelCSV() } }.disabled(model.busy)
                                }
                            } else {
                                Button("Review import") { Task { await model.previewCSV() } }
                                    .buttonStyle(.borderedProminent)
                                    .disabled(model.busy || [model.mapping.title, model.mapping.url, model.mapping.username, model.mapping.password].contains(""))
                            }
                        }
                    }.padding(24)
                }
            }
        }
    }

    private var recovery: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Encrypted recovery files").font(.title2.bold())
            Text("The vault and its retained backups remain local. An older file cannot restore previous agent authority.").foregroundStyle(.secondary)
            Button("Show encrypted vault folder") { NSWorkspace.shared.open(model.configuration.vaultDirectory) }
            Text("The guided restore workflow is still under implementation. This development build must contain synthetic credentials only.").font(.callout).foregroundStyle(.secondary)
            Spacer()
        }.padding(24)
    }

    private func columnPicker(_ label: String, value: Binding<String>) -> some View {
        Picker(label, selection: value) {
            Text("Choose a column").tag("")
            ForEach(model.headers, id: \.self) { Text($0).tag($0) }
        }
    }

    private func optionalPicker(_ label: String, value: Binding<String?>) -> some View {
        Picker(label, selection: value) {
            Text("Not imported").tag(String?.none)
            ForEach(model.headers, id: \.self) { Text($0).tag(Optional($0)) }
        }
    }

    private func chooseCSV() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.commaSeparatedText]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        Task { @MainActor in
            if await panel.begin() == .OK, let url = panel.url { await model.selectCSV(url) }
        }
    }
}
