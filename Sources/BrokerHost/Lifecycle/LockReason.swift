public enum OwnerLockReason: String, Sendable, CaseIterable {
    case owner, screenLocked = "screen_locked", sleep, wake
    case sessionChanged = "session_changed", idle, quit, workerStopped = "worker_stopped"
}
