import SwiftUI
import AppKit

struct ModelSignInView: View {
    @Bindable var owner: OwnerVaultModel
    private var model: ModelSignInModel { owner.modelSignIn }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Codex model access").font(.headline)
            switch model.phase {
            case .checking:
                ProgressView("Checking sign-in…").controlSize(.small)
            case .signedOut:
                Text("Sign in with your ChatGPT subscription. Shadow keeps the sign-in in this Mac's Keychain.").foregroundStyle(.secondary)
                Button("Sign in with ChatGPT") { model.start() }.disabled(!owner.unlocked || owner.busy)
            case .signingIn:
                if let prompt = model.prompt {
                    Text("Open the sign-in page, then enter this code yourself at auth.openai.com.")
                    Text(prompt.userCode).font(.system(.title2, design: .monospaced).bold()).accessibilityLabel("Sign-in code \(prompt.userCode)")
                    HStack {
                        Button("Open ChatGPT sign-in page") { NSWorkspace.shared.open(prompt.verificationURL) }
                        Button("Cancel sign-in") { model.cancelImmediately() }
                    }
                    Text("Expires \(prompt.expiresAt.formatted(date: .omitted, time: .shortened)). Keep this code private.").font(.caption).foregroundStyle(.secondary)
                } else {
                    HStack { ProgressView("Requesting sign-in code…").controlSize(.small); Button("Cancel") { model.cancelImmediately() } }
                }
            case .signedIn:
                HStack {
                    Label("ChatGPT connected", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    Spacer()
                    Button("Sign out and end access") { owner.signOutModel() }
                }
            case .unavailable:
                Text("Model sign-in is unavailable.").foregroundStyle(.secondary)
                Button("Check Keychain again") { model.refreshStatus() }
            }
            if let message = model.message { Text(message).font(.callout).foregroundStyle(.secondary) }
        }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
    }
}
