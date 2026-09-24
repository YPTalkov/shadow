import SwiftUI
import AppKit
import OwnerUI
import BrokerHost
import Darwin

@main
struct ShadowApp: App {
    @NSApplicationDelegateAdaptor(OwnerLifecycle.self) private var lifecycle
    private let model: OwnerVaultModel?
    private let startupMessage: String?

    init() {
        do {
            var coreLimit = rlimit(rlim_cur: 0, rlim_max: 0)
            guard setrlimit(RLIMIT_CORE, &coreLimit) == 0 else { throw OwnerConfigurationError.unavailable }
            model = OwnerVaultModel(configuration: try OwnerConfiguration.local())
            startupMessage = nil
        } catch OwnerConfigurationError.alreadyRunning {
            model = nil
            startupMessage = "Shadow is already running for this vault."
        } catch {
            model = nil
            startupMessage = "The vault configuration needs attention. Existing encrypted files were preserved."
        }
    }

    var body: some Scene {
        Window("Shadow", id: "vault") {
            Group {
                if let model {
                    OwnerPanel(model: model)
                        .task { lifecycle.attach(model) }
                } else {
                    ContentUnavailableView("Shadow could not open", systemImage: "lock.shield", description: Text(startupMessage ?? "Configuration unavailable"))
                }
            }.frame(minWidth: 850, minHeight: 580)
        }
        .defaultSize(width: 1040, height: 720)
        .commands {
            CommandMenu("Vault") {
                Button("Lock Vault") { model?.lockImmediately() }
                    .keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }
    }
}

@MainActor
final class OwnerLifecycle: NSObject, NSApplicationDelegate {
    private var model: OwnerVaultModel?
    private var monitor: OwnerLifecycleMonitor?

    func attach(_ model: OwnerVaultModel) {
        guard self.model == nil else { return }
        self.model = model
        monitor = OwnerLifecycleMonitor(model: model)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        monitor?.stop()
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        monitor?.stop()
        model?.lockImmediately(reason: .quit)
        Task {
            await model?.finishLock()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
