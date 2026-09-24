import SwiftUI
import BrokerHost
import PolicyCore

public struct AgentAccessView: View {
    @Bindable private var access: AccessCoordinator
    public init(access: AccessCoordinator) { self.access = access }

    public var body: some View {
        if !access.unlocked {
            ContentUnavailableView("Agent access is closed", systemImage: "lock.shield", description: Text("Unlock the vault to review access. Locking ends every permission."))
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    Text("Agent Access").font(.title2.bold())
                    Text("Catalog access reveals only the accounts you select. Using a credential requires a separate approval for its destinations and actions.").foregroundStyle(.secondary)
                    if access.agents.isEmpty {
                        Label("No isolated agent is running", systemImage: "desktopcomputer")
                        Text("Requests appear here when an enrolled agent asks for access.").foregroundStyle(.secondary)
                    } else {
                        ForEach(access.agents) { caller in
                            HStack { Label(caller.displayName, systemImage: "desktopcomputer"); Spacer(); Text("Isolated agent").foregroundStyle(.secondary) }
                        }
                    }
                    if !access.pending.isEmpty {
                        Text("Waiting for you").font(.headline)
                        ForEach(access.pending) { request in
                            NativeConsentCard(access: access, request: request)
                        }
                    }
                    Divider()
                    Text("Current permissions").font(.headline)
                    if access.grants.isEmpty { Text("No active permissions").foregroundStyle(.secondary) }
                    ForEach(access.grants) { grant in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 6) {
                                Text(grant.caller.displayName).fontWeight(.semibold)
                                Text(grant.kind == .catalog ? "Catalog · \(grant.accountIDs.count) selected accounts" : "Credential use · \(grant.adapter?.id ?? "")")
                                Text("Expires \(grant.expiresAt.formatted(date: .omitted, time: .shortened))").font(.caption).foregroundStyle(.secondary)
                                if grant.retainedEvent != nil { Text("Retained copy · One session").font(.caption) }
                            }
                            Spacer()
                            Button("Revoke") { access.revoke(grant.id) }.accessibilityLabel("Revoke \(grant.kind == .catalog ? "catalog" : "credential use") permission for \(grant.caller.displayName)")
                        }.padding().background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
                    }
                }.padding(24)
            }
            .task {
                while !Task.isCancelled {
                    access.expire()
                    try? await Task.sleep(for: .seconds(1))
                }
            }
        }
    }
}

private struct NativeConsentCard: View {
    @Bindable var access: AccessCoordinator
    let request: ConsentRequest
    @State private var selected: Set<UUID> = []
    @State private var duration: TimeInterval = 3600
    @State private var retained = false
    @State private var error: String?

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 16) {
                Label(request.kind == .catalog ? "Choose visible accounts" : "Approve credential use", systemImage: "person.crop.circle.badge.checkmark").font(.headline)
                Text("Caller: \(request.caller.displayName)")
                if request.kind == .catalog {
                    Text("Select each account this agent may discover. No accounts are selected by default.").foregroundStyle(.secondary)
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 10) {
                            ForEach(access.accounts.filter { request.availableAccountIDs.contains($0.id) }) { account in
                                Toggle(isOn: Binding(get: { selected.contains(account.id) }, set: { if $0 { selected.insert(account.id) } else { selected.remove(account.id) } })) {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(account.metadata.title).fontWeight(.medium)
                                        Text([account.metadata.username, account.metadata.group].filter { !$0.isEmpty }.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(maxHeight: 240)
                } else if let account = request.account, let adapter = request.adapter {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(account.metadata.title).fontWeight(.semibold)
                        Text(account.metadata.username).foregroundStyle(.secondary)
                        Text("Credential destinations").font(.caption.weight(.semibold))
                        ForEach(adapter.credentialOrigins.sorted(), id: \.self) { Text($0).textSelection(.enabled) }
                        if !adapter.resourceOrigins.isEmpty {
                            Text("Additional resource destinations").font(.caption.weight(.semibold))
                            ForEach(adapter.resourceOrigins.sorted(), id: \.self) { Text($0).textSelection(.enabled) }
                        }
                        Text("Allowed actions: \(request.actions.map(\.rawValue).sorted().joined(separator: ", "))")
                    }
                    if account.policy.restrictionEvent != nil {
                        Text("This is a retained copy. Its source is deleted, unavailable, stale, or its history is uncertain. Approval applies to this revision for one session.").foregroundStyle(.orange)
                        Toggle("I approve use of this retained copy", isOn: $retained)
                    }
                }
                Picker("Permission duration", selection: $duration) {
                    Text("5 minutes").tag(TimeInterval(300))
                    Text("15 minutes").tag(TimeInterval(900))
                    Text("1 hour").tag(TimeInterval(3600))
                }.frame(maxWidth: 300)
                if let error { Text(error).foregroundStyle(.red) }
                HStack {
                    Button("Deny") { access.deny(request.id) }
                    Button(request.kind == .catalog ? "Allow selected accounts" : "Approve credential use") {
                        do {
                            if request.kind == .catalog { try access.approveCatalog(request.id, selected: selected, duration: duration) }
                            else { try access.approveUse(request.id, duration: duration, approveRetained: retained) }
                        } catch { self.error = "This request expired or its account changed. Ask the agent to request access again." }
                    }.buttonStyle(.borderedProminent)
                        .disabled((request.kind == .catalog && selected.isEmpty) || (request.account?.policy.restrictionEvent != nil && !retained))
                }
                Text("Request expires \(request.expiresAt.formatted(date: .omitted, time: .shortened)). Denying or ignoring it grants no access.").font(.caption).foregroundStyle(.secondary)
            }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
