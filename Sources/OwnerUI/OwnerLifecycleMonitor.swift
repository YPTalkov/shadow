import AppKit
import CoreGraphics
import BrokerHost

@MainActor public final class OwnerLifecycleMonitor {
    private let model: OwnerVaultModel
    private let workspace: NotificationCenter
    private let distributed: NotificationCenter
    private let sessionAvailable: @MainActor () -> Bool
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private var timer: Task<Void, Never>?
    private var activity: Any?

    public init(model: OwnerVaultModel, workspace: NotificationCenter? = nil, distributed: NotificationCenter? = nil, sessionAvailable: (@MainActor () -> Bool)? = nil) {
        self.model = model
        self.workspace = workspace ?? NSWorkspace.shared.notificationCenter
        self.distributed = distributed ?? DistributedNotificationCenter.default()
        self.sessionAvailable = sessionAvailable ?? Self.activeSession
        let events: [(Notification.Name, OwnerLockReason)] = [
            (NSWorkspace.willSleepNotification, .sleep), (NSWorkspace.didWakeNotification, .wake),
            (NSWorkspace.screensDidSleepNotification, .screenLocked),
            (NSWorkspace.sessionDidResignActiveNotification, .sessionChanged),
            (NSWorkspace.sessionDidBecomeActiveNotification, .sessionChanged)
        ]
        for (name, reason) in events { observe(self.workspace, name: name, reason: reason) }
        // This additional macOS signal is qualified per supported OS release.
        observe(self.distributed, name: Notification.Name("com.apple.screenIsLocked"), reason: .screenLocked)
        activity = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel]) { [weak model] event in
            MainActor.assumeIsolated { model?.noteInteraction() }
            return event
        }
        timer = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(1)) } catch { return }
                if let self { await self.check() } else { return }
            }
        }
    }

    private func observe(_ center: NotificationCenter, name: Notification.Name, reason: OwnerLockReason) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak model] _ in
            MainActor.assumeIsolated { model?.lockImmediately(reason: reason) }
        }
        observers.append((center, token))
    }

    public func check() async {
        if (model.unlocked || model.busy || model.access.unlocked) && !sessionAvailable() { model.lockImmediately(reason: .screenLocked) }
        await model.checkIdle()
    }

    public func stop() {
        timer?.cancel(); timer = nil
        for (center, token) in observers { center.removeObserver(token) }
        observers = []
        if let activity { NSEvent.removeMonitor(activity); self.activity = nil }
    }

    private static func activeSession() -> Bool {
        guard let state = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return state[kCGSessionOnConsoleKey as String] as? Bool == true && state[kCGSessionLoginDoneKey as String] as? Bool == true && state["CGSSessionScreenIsLocked"] as? Bool != true
    }
}
