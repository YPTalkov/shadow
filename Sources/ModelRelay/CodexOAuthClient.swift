import Foundation
import PolicyCore

public enum CodexOAuthError: String, Error, Sendable {
    case unavailable, invalidResponse, deviceLoginDisabled, expired, cancelled
    case signInRequired, storageUnavailable, accountChanged, busy
}

struct CodexDeviceChallenge: Sendable, CustomStringConvertible, CustomReflectable {
    let deviceID: String
    let userCode: String
    let interval: TimeInterval
    let verificationURL = URL(string: "https://auth.openai.com/codex/device")!
    var description: String { "CodexDeviceChallenge(redacted)" }
    var customMirror: Mirror { Mirror(self, children: [:]) }
}

struct CodexTokens: Codable, Sendable, CustomStringConvertible, CustomReflectable {
    let access: String
    let refresh: String
    let accountID: String
    let expiresAt: Date
    var credential: CodexCredential { CodexCredential(accessToken: access, accountID: accountID, expiresAt: expiresAt) }
    var description: String { "CodexTokens(redacted)" }
    var customMirror: Mirror { Mirror(self, children: [:]) }

    static func parse(_ data: Data, now: Date) throws -> CodexTokens {
        guard let object = try? BoundedJSON.parse(data).object,
              let access = object["access_token"]?.string, safeToken(access),
              let refresh = object["refresh_token"]?.string, safeToken(refresh),
              let seconds = object["expires_in"]?.integer, (31...2_592_000).contains(seconds) else { throw CodexOAuthError.invalidResponse }
        let claims = try accountClaims(access)
        let expires = min(now.addingTimeInterval(TimeInterval(seconds)), claims.expires)
        guard expires.timeIntervalSince(now) > 30 else { throw CodexOAuthError.invalidResponse }
        return CodexTokens(access: access, refresh: refresh, accountID: claims.account, expiresAt: expires)
    }

    func validateStored() throws {
        let claims = try Self.accountClaims(access)
        guard Self.safeToken(refresh), claims.account == accountID, expiresAt.timeIntervalSince1970.isFinite,
              expiresAt <= claims.expires else { throw CodexOAuthError.storageUnavailable }
    }

    private static func accountClaims(_ access: String) throws -> (account: String, expires: Date) {
        guard safeToken(access) else { throw CodexOAuthError.invalidResponse }
        let parts = access.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, parts.allSatisfy({ !$0.isEmpty }) else { throw CodexOAuthError.invalidResponse }
        var payload = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        payload += String(repeating: "=", count: (4 - payload.count % 4) % 4)
        guard let data = Data(base64Encoded: payload), let claims = try? BoundedJSON.parse(data),
              let account = claims["https://api.openai.com/auth"]?["chatgpt_account_id"]?.string,
              safeToken(account), account.utf8.count <= 256,
              let expiry = claims["exp"]?.integer, (1...253_402_300_799).contains(expiry) else { throw CodexOAuthError.invalidResponse }
        // Claims are routing metadata from the TLS-authenticated token response,
        // not an independent proof that a caller may authenticate as this user.
        return (account, Date(timeIntervalSince1970: TimeInterval(expiry)))
    }

    static func safeToken(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 16_384 && value.utf8.allSatisfy { (33...126).contains($0) }
    }
}

struct OAuthHTTPReply: Sendable { let status: Int; let body: Data }
protocol CodexOAuthTransport: Sendable {
    func post(_ request: URLRequest) async throws -> OAuthHTTPReply
}

private struct ProviderOAuthTransport: CodexOAuthTransport {
    func post(_ request: URLRequest) async throws -> OAuthHTTPReply {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.connectionProxyDictionary = [:]
        configuration.timeoutIntervalForResource = 30
        configuration.waitsForConnectivity = false
        let session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse else { throw CodexOAuthError.unavailable }
            if http.statusCode == 200 {
                guard http.value(forHTTPHeaderField: "Content-Type")?.lowercased().split(separator: ";").first == "application/json" else { throw CodexOAuthError.invalidResponse }
            }
            var body = Data()
            for try await byte in bytes {
                guard body.count < 65_536 else { throw CodexOAuthError.invalidResponse }
                body.append(byte)
            }
            return OAuthHTTPReply(status: http.statusCode, body: body)
        } catch is CancellationError { throw CodexOAuthError.cancelled }
        catch let error as CodexOAuthError { throw error }
        catch { throw Task.isCancelled ? CodexOAuthError.cancelled : .unavailable }
    }
}

enum CodexDevicePoll: Sendable { case pending, slowDown, complete(CodexTokens) }

struct CodexOAuthClient: Sendable {
    private static let clientID = "app_EMoamEEZ73f0CkXaXp7hrann"
    private let transport: any CodexOAuthTransport
    init() { transport = ProviderOAuthTransport() }
    init(transport: any CodexOAuthTransport) { self.transport = transport }

    func start() async throws -> CodexDeviceChallenge {
        let reply = try await post("/api/accounts/deviceauth/usercode", json: ["client_id": Self.clientID])
        if reply.status == 404 { throw CodexOAuthError.deviceLoginDisabled }
        guard reply.status == 200 else { throw CodexOAuthError.unavailable }
        guard let object = try? BoundedJSON.parse(reply.body),
              let id = object["device_auth_id"]?.string, CodexTokens.safeToken(id), id.utf8.count <= 4096,
              let code = object["user_code"]?.string, (4...32).contains(code.utf8.count),
              code.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) || $0 == 45 }) else { throw CodexOAuthError.invalidResponse }
        let interval: Int64?
        if let text = object["interval"]?.string, text.count <= 3, text.utf8.allSatisfy({ (48...57).contains($0) }) { interval = Int64(text) }
        else { interval = object["interval"]?.integer }
        guard let interval, (0...60).contains(interval) else { throw CodexOAuthError.invalidResponse }
        return CodexDeviceChallenge(deviceID: id, userCode: code, interval: TimeInterval(max(1, interval)))
    }

    func poll(_ challenge: CodexDeviceChallenge, now: Date) async throws -> CodexDevicePoll {
        let reply = try await post("/api/accounts/deviceauth/token", json: ["device_auth_id": challenge.deviceID, "user_code": challenge.userCode])
        if [403, 404].contains(reply.status) { return .pending }
        guard let object = try? BoundedJSON.parse(reply.body) else { throw CodexOAuthError.invalidResponse }
        if reply.status != 200 {
            let error = object["error"]?.string ?? object["error"]?["code"]?.string
            if error == "deviceauth_authorization_pending" { return .pending }
            if error == "slow_down" { return .slowDown }
            throw CodexOAuthError.unavailable
        }
        guard let code = object["authorization_code"]?.string, CodexTokens.safeToken(code),
              let verifier = object["code_verifier"]?.string, CodexTokens.safeToken(verifier) else { throw CodexOAuthError.invalidResponse }
        let tokens = try await token([
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "redirect_uri": "https://auth.openai.com/deviceauth/callback",
        ], now: now)
        return .complete(tokens)
    }

    func refresh(_ previous: CodexTokens, now: Date) async throws -> CodexTokens {
        let tokens = try await token(["grant_type": "refresh_token", "refresh_token": previous.refresh], now: now)
        guard tokens.accountID == previous.accountID else { throw CodexOAuthError.accountChanged }
        return tokens
    }

    private func token(_ parameters: [String: String], now: Date) async throws -> CodexTokens {
        var values = parameters
        values["client_id"] = Self.clientID
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        let body = values.keys.sorted().map { key in "\(key)=\(values[key]!.addingPercentEncoding(withAllowedCharacters: allowed)!)" }.joined(separator: "&")
        let reply = try await transport.post(request("/oauth/token", body: Data(body.utf8), contentType: "application/x-www-form-urlencoded"))
        if [400, 401, 403].contains(reply.status) { throw CodexOAuthError.signInRequired }
        guard reply.status == 200 else { throw CodexOAuthError.unavailable }
        return try CodexTokens.parse(reply.body, now: now)
    }

    private func post(_ path: String, json: [String: String]) async throws -> OAuthHTTPReply {
        try await transport.post(request(path, body: JSONEncoder().encode(json), contentType: "application/json"))
    }

    private func request(_ path: String, body: Data, contentType: String) -> URLRequest {
        var request = URLRequest(url: URL(string: "https://auth.openai.com" + path)!)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("shadow/0.1", forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 30
        return request
    }
}
