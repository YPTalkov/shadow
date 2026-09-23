import SwiftUI
import AppKit
import OwnerUI

@main
struct ShadowApp: App {
    @NSApplicationDelegateAdaptor(OwnerLifecycle.self) private var lifecycle
    private let model: OwnerVaultModel?
    private let startupMessage: String?

    init() {
        do {
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
                Button("Lock Vault") { Task { await model?.lock() } }
                    .keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }
    }
}

@MainActor
final class OwnerLifecycle: NSObject, NSApplicationDelegate {
    private var model: OwnerVaultModel?
    private var observers: [NSObjectProtocol] = []
    private var idleTask: Task<Void, Never>?
    private var activity: Any?

    func attach(_ model: OwnerVaultModel) {
        guard self.model == nil else { return }
        self.model = model
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { _ in
                Task { @MainActor in await model.lock() }
            })
        }
        activity = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel]) { event in
            MainActor.assumeIsolated { model.noteInteraction() }
            return event
        }
        idleTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                await model.checkIdle()
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        idleTask?.cancel()
        Task {
            await model?.lock()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
