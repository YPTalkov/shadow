// Synthetic native API harness. Never bundled in the production application.
import Foundation
import BrokerHost
import PolicyCore
import RuntimeHost

let approve = CommandLine.arguments.contains("--synthetic-approve")
Task { @MainActor in
    do {
        let channel = try FramedChannel(descriptor: 0)
        let authority = AccessCoordinator()
        let api = AgentAPI(access: authority)
        let caller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Synthetic protocol probe")
        authority.enroll(caller)
        let accounts = (0..<61).map { index -> ConsentAccount in
            let id = UUID()
            let title = index < 55 ? "Synthetic Account \(index)" : "Undisclosed canary \(index)"
            return ConsentAccount(metadata: OwnerCatalogItem(id: id.uuidString.lowercased(), title: title, username: "fixture@example.invalid", origins: ["https://example.invalid"], group: "Synthetic"), policy: AccountPolicy(id: id, revision: 1, source: .local, presence: .present, lastObserved: nil, restrictionEvent: nil))
        }
        authority.openVault(accounts: accounts)
        authority.installQualifiedAdapter(QualifiedAdapterPolicy(id: "synthetic-v1", credentialOrigins: ["https://example.invalid"], resourceOrigins: [], actions: [.login, .observe]))
        for _ in 0..<128 {
            let data = try await Task.detached { try channel.read(timeout: 180) }.value
            let response = await api.handle(data, caller: caller)
            // Simulate the separate native owner action after returning pending.
            for pending in authority.pending {
                if !approve { authority.deny(pending.id) }
                else if pending.kind == .catalog { try authority.approveCatalog(pending.id, selected: Set(accounts.prefix(55).map(\.id)), duration: 300) }
                else { try authority.approveUse(pending.id, duration: 300, approveRetained: false) }
            }
            try await Task.detached { try channel.write(response) }.value
        }
    } catch { /* No input or exception text on either stream. */ }
    exit(0)
}
dispatchMain()
