import SwiftUI
import BrokerHost

struct AgentTaskView: View {
    @Bindable var owner: OwnerVaultModel
    @State private var prompt = ""
    @State private var selectedModel = "gpt-6-sol"
    @State private var maximumRequests = 30
    @State private var controlsExpanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Run a task").font(.headline)
                Spacer()
                if let runtime = owner.agentRuntime, runtime.active { Button("Stop task") { runtime.stop() } }
            }
            if let runtime = owner.agentRuntime {
                DisclosureGroup("Task description and limits", isExpanded: $controlsExpanded) {
                    taskForm(runtime)
                }
                Text(status(runtime.state)).font(.caption).foregroundStyle(.secondary)
                if !runtime.output.isEmpty {
                    GroupBox("Agent output · untrusted text") {
                        ScrollView { Text(verbatim: runtime.output).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }.frame(maxHeight: 100)
                    }
                }
            } else {
                Text("The isolated Codex image is unavailable.").foregroundStyle(.secondary)
            }
        }.padding(.horizontal, 24).padding(.vertical, 12)
        .onChange(of: owner.unlocked) { _, unlocked in if !unlocked { prompt = "" } }
        .onChange(of: owner.access.pending.count, initial: true) { _, count in if count > 0 { controlsExpanded = false } }
    }

    private func taskForm(_ runtime: AgentRuntime) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Describe the task without passwords or sign-in codes. Codex runs for up to 15 minutes. Account discovery and credential use need your separate approval below.")
                .font(.callout).foregroundStyle(.secondary)
            Text("Website support: synthetic qualification sites only. Real-site access needs a reviewed site adapter.")
                .font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $prompt).font(.body).frame(minHeight: 60, maxHeight: 90)
                .border(.quaternary).accessibilityLabel("Task for isolated Codex")
                .disabled(runtime.active)
            HStack {
                Picker("Model", selection: $selectedModel) {
                    ForEach(AgentRuntime.models, id: \.self) { Text($0).tag($0) }
                }.frame(maxWidth: 240).disabled(runtime.active)
                Picker("Request limit", selection: $maximumRequests) {
                    Text("30").tag(30)
                    Text("60").tag(60)
                    Text("120").tag(120)
                }.frame(maxWidth: 155).disabled(runtime.active)
                Spacer()
                if !runtime.active {
                    Button("Start task") {
                        let task = prompt
                        prompt = ""
                        Task { await owner.startAgent(prompt: task, model: selectedModel, maximumRequests: maximumRequests) }
                    }.buttonStyle(.borderedProminent)
                        .disabled(!owner.unlocked || owner.busy || !owner.diagnosticsAvailable || owner.modelSignIn.phase != .signedIn || prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || prompt.utf8.count > 8192)
                }
            }
        }.padding(.top, 8)
    }

    private func status(_ state: AgentRuntime.State) -> String {
        switch state {
        case .idle: "Ready when signed in and unlocked."
        case .starting: "Starting isolated Codex…"
        case .running: "Task running. Review access requests below."
        case .succeeded: "Task finished. Its permissions and isolated environment are closed."
        case .failed: "Task could not finish. Its access is closed; check sign-in and try again."
        case .stopped: "Task stopped. Its permissions and isolated environment are closed."
        }
    }
}
