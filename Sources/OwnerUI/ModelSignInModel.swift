import Foundation
import Observation
import ModelRelay

@Observable @MainActor
public final class ModelSignInModel {
    public enum Phase { case checking, signedOut, signingIn, signedIn, unavailable }
    public private(set) var phase: Phase = .checking
    public private(set) var prompt: CodexSignInPrompt?
    public private(set) var message: String?
    public let authentication: CodexAuthentication
    private var operation: Task<Void, Never>?
    private var generation = 0

    public init(authentication: CodexAuthentication) {
        self.authentication = authentication
        refreshStatus()
    }

    public func refreshStatus() {
        guard phase != .signingIn else { return }
        generation += 1
        let epoch = generation
        phase = .checking
        operation = Task { [weak self, authentication] in
            do {
                let signedIn = try await authentication.isSignedIn()
                guard let self, epoch == self.generation else { return }
                self.phase = signedIn ? .signedIn : .signedOut
            } catch {
                guard let self, epoch == self.generation else { return }
                self.phase = .unavailable
                self.message = "Model sign-in could not be read from Keychain."
            }
        }
    }

    public func start() {
        guard phase == .signedOut else { return }
        generation += 1
        let epoch = generation
        phase = .signingIn
        prompt = nil
        message = nil
        operation = Task { [weak self, authentication] in
            do {
                let prompt = try await authentication.begin()
                guard let self, epoch == self.generation else { return }
                self.prompt = prompt
                while !Task.isCancelled {
                    try await Task.sleep(for: .seconds(1))
                    if try await authentication.poll() {
                        guard epoch == self.generation else { return }
                        self.prompt = nil
                        self.phase = .signedIn
                        self.operation = nil
                        return
                    }
                }
            } catch {
                guard let self, epoch == self.generation else { return }
                await authentication.cancelPending()
                guard epoch == self.generation else { return }
                self.prompt = nil
                self.phase = .signedOut
                self.message = Self.explain(error)
                self.operation = nil
            }
        }
    }

    public func cancelImmediately() {
        generation += 1
        let epoch = generation
        operation?.cancel()
        prompt = nil
        phase = .checking
        operation = Task { [weak self, authentication] in
            await authentication.cancelPending()
            let signedIn = try? await authentication.isSignedIn()
            guard let self, epoch == self.generation else { return }
            self.phase = signedIn == true ? .signedIn : (signedIn == false ? .signedOut : .unavailable)
            self.operation = nil
        }
    }

    public func signOut() async {
        generation += 1
        let epoch = generation
        operation?.cancel()
        operation = nil
        prompt = nil
        phase = .checking
        do {
            try await authentication.signOut()
            guard epoch == generation else { return }
            phase = .signedOut
            message = "Shadow's ChatGPT sign-in was removed from Keychain."
        } catch {
            guard epoch == generation else { return }
            phase = .unavailable
            message = "Sign-out could not update Keychain. Agent access remains closed."
        }
    }

    private static func explain(_ error: any Error) -> String {
        guard let error = error as? CodexOAuthError else { return "Sign-in was interrupted. Start again when ready." }
        switch error {
        case .deviceLoginDisabled:
            return "Enable device-code login in your ChatGPT security settings or ask your workspace administrator, then try again."
        case .expired: return "The sign-in code expired. Request a new code."
        case .storageUnavailable: return "Sign-in could not be saved in Keychain."
        case .cancelled: return "Sign-in was cancelled."
        case .accountChanged: return "The provider returned a different account. Sign in again."
        default: return "ChatGPT sign-in could not complete. Check your connection and device-login setting, then try again."
        }
    }
}
