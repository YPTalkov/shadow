import SwiftUI
import Virtualization
import BrokerHost

/// This view exists only in the native owner process. The guest agent has no
/// graphics device or API for obtaining the browser's pixels or input events.
public struct PrivateBrowserView: View {
    let service: ProtectedSessionService
    let challenge: OwnerChallenge
    @State private var failed = false

    public init(service: ProtectedSessionService, challenge: OwnerChallenge) { self.service = service; self.challenge = challenge }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Complete sign-in privately", systemImage: "lock.shield").font(.title2.bold())
            Text("\(challenge.account) · Requested by \(challenge.caller)")
            Text(challenge.origin).font(.body.monospaced()).textSelection(.enabled)
            Text("Complete the website's verification below, then choose Continue. This window expires after two minutes.")
                .font(.callout).foregroundStyle(.secondary)
            if let machine = service.ownerMachine(checkpoint: challenge.id) {
                MachineView(machine: machine).frame(minWidth: 900, minHeight: 530)
                    .accessibilityLabel("Private website verification")
            } else {
                ContentUnavailableView("Session closed", systemImage: "lock")
            }
            if failed { Text("The checkpoint is no longer available. Request a new sign-in.").foregroundStyle(.red) }
            HStack {
                Button("Cancel sign-in", role: .cancel) { service.challenges.cancel(challenge.id) }
                Spacer()
                Button("Continue") {
                    do { try service.completeOwnerChallenge(challenge.id) }
                    catch { failed = true }
                }.buttonStyle(.borderedProminent)
            }
        }.padding(20).interactiveDismissDisabled()
    }
}

private struct MachineView: NSViewRepresentable {
    let machine: VZVirtualMachine
    func makeNSView(context: Context) -> VZVirtualMachineView {
        let view = VZVirtualMachineView()
        view.capturesSystemKeys = false
        view.automaticallyReconfiguresDisplay = false
        view.virtualMachine = machine
        return view
    }
    func updateNSView(_ view: VZVirtualMachineView, context: Context) { view.virtualMachine = machine }
    static func dismantleNSView(_ view: VZVirtualMachineView, coordinator: ()) { view.virtualMachine = nil }
}
