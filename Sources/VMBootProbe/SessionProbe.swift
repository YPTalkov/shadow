import Foundation
import BrokerHost
import PolicyCore
import RuntimeHost
import Security
import Darwin

/// Synthetic-only end-to-end use of the native authority and production driver.
@MainActor enum SessionProbe {
    static func run() async throws {
        guard CommandLine.arguments.count == 8, let rootPath = ProcessInfo.processInfo.environment["SHADOW_PROBE_ROOT"],
              let port = ProcessInfo.processInfo.environment["SHADOW_FIXTURE_PORT"].flatMap(UInt16.init) else { throw AgentAPIError.unavailable }
        let args = CommandLine.arguments
        let image = BrowserVMImage(kernel: URL(fileURLWithPath: args[2]), ramdisk: URL(fileURLWithPath: args[3]), disk: URL(fileURLWithPath: args[4]), identity: VMImageIdentity(kernelSHA256: args[5], ramdiskSHA256: args[6], imageSHA256: args[7]))
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-session-probe-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let vaultID = "synthetic-session-\(UUID())"
        defer {
            try? FileManager.default.removeItem(at: directory)
            SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: vaultID] as CFDictionary)
        }
        let access = AccessCoordinator(), api = AgentAPI(access: access)
        let worker = try await PrivateVaultWorker.launch(python: URL(fileURLWithPath: rootPath).appendingPathComponent(".venv/bin/python"), vaultDirectory: directory.appendingPathComponent("vault"), vaultID: vaultID, onInvalidate: { ids in ids.forEach { access.invalidate(account: $0) } })
        do {
            try await worker.create(password: "synthetic-master-canary")
            let csv = directory.appendingPathComponent("fixture.csv")
            try Data("Title,URL,Username,Password\nSynthetic,https://app.shadow.test,synthetic-user,synthetic-atomic-auth-canary\n".utf8).write(to: csv)
            _ = try await worker.previewCSV(path: csv, mapping: OwnerCSVMapping(title: "Title", url: "URL", username: "Username", password: "Password"))
            _ = try await worker.commitCSV(operationID: UUID(), validRowsOnly: false)
            guard let item = try await worker.catalog().items.first, let accountID = UUID(uuidString: item.id) else { throw AgentAPIError.unavailable }
            access.openVault(accounts: [ConsentAccount(metadata: item, policy: AccountPolicy(id: accountID, revision: item.revision, source: .local, presence: .present, lastObserved: nil, restrictionEvent: nil))])
            let caller = EnrolledAgent(id: UUID(), boot: UUID(), displayName: "Synthetic VM client")
            access.enroll(caller)
            let actions: Set<ProtectedAction> = [.login, .observe, .extract, .navigate, .click]
            access.installQualifiedAdapter(QualifiedAdapterPolicy(id: "synthetic-v1", credentialOrigins: ["https://app.shadow.test"], resourceOrigins: ["https://app.shadow.test"], actions: actions))
            let service = ProtectedSessionService(access: access, journal: try OperationJournal(path: directory.appendingPathComponent("operations.sqlite")), worker: worker, image: image) { descriptor, channel, authorize in
                try FixtureTunnel.run(guest: descriptor, port: port, transport: channel, authorize: authorize)
            }
            defer { service.shutdown() }
            api.protectedService = service
            let disclosure = try access.requestCatalog(caller: caller, requestID: UUID())
            try access.approveCatalog(disclosure.requestRef, selected: [accountID], duration: 300)
            let reference = try access.accountReference(accountID, caller: caller)
            let use = try access.requestUse(caller: caller, requestID: UUID(), accountRef: reference, adapterID: "synthetic-v1", actions: actions)
            try access.approveUse(use.requestRef, duration: 300, approveRetained: false)
            guard let grant = try access.status(use.requestRef, caller: caller).grantRef else { throw AgentAPIError.unavailable }
            func call(_ operation: String, _ arguments: [String: JSONValue], id: UUID = UUID()) async throws -> JSONValue {
                let request = try JSONValue.object(["protocol_major": .integer(1), "request_id": .string(id.uuidString.lowercased()), "operation": .string(operation), "arguments": .object(arguments)]).encoded()
                let reply = try BoundedJSON.parse(await api.handle(request, caller: caller))
                guard let result = reply["result"] else { throw AgentAPIError.unavailable }
                return result
            }
            let loginID = UUID(), arguments: [String: JSONValue] = ["account_ref": .string(reference), "grant_ref": .string(grant), "adapter_id": .string("synthetic-v1")]
            let interruption = ProcessInfo.processInfo.environment["SHADOW_PROBE_INTERRUPT"] ?? ""
            signal(SIGUSR1, SIG_IGN)
            let revokeSignal = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .main)
            revokeSignal.setEventHandler { access.revoke(grant) }
            revokeSignal.resume()
            defer { revokeSignal.cancel() }
            let initial = try await call("auth.login", arguments, id: loginID)
            guard let operation = initial["operation_ref"]?.string else { throw AgentAPIError.unavailable }
            let started = DeadlineClock.now
            var status = initial
            while status["state"]?.string == "running", DeadlineClock.now - started < 50 {
                try await Task.sleep(for: .milliseconds(500))
                status = try await call("operation.get", ["operation_ref": .string(operation)])
            }
            if interruption == "revoke" {
                guard status["state"]?.string == "outcome_unknown", status["session_ref"] == .null,
                      try await call("auth.login", arguments, id: loginID) == status else { throw AgentAPIError.unavailable }
                print("BROWSER_NATIVE_REVOKE=pass")
                await worker.lock()
                return
            }
            guard status["state"]?.string == "succeeded", let session = status["session_ref"]?.string else { throw AgentAPIError.unavailable }
            print("BROWSER_NATIVE_AUTH=pass")
            if interruption == "suspend" {
                print("BROWSER_NATIVE_SUSPEND=ready")
                fflush(nil)
                try await Task.sleep(for: .seconds(13))
                guard try await call("operation.get", ["operation_ref": .string(operation)])["session_ref"] == .null else { throw AgentAPIError.unavailable }
                print("BROWSER_NATIVE_SUSPEND=pass")
                await worker.lock()
                return
            }
            guard try await call("auth.login", arguments, id: loginID) == status else { throw AgentAPIError.unavailable }
            print("BROWSER_NATIVE_RETRY=pass")
            let list = try await call("browser.observe", ["session_ref": .string(session), "view_id": .string("items")])
            guard let row = list["records"]?.array?.first, row["fields"]?.array?.first?["value"]?.string == "Example report",
                  let element = row["actions"]?.array?.first?["element_ref"]?.string else { throw AgentAPIError.unavailable }
            func finishAction(_ value: JSONValue) async throws {
                guard let reference = value["operation_ref"]?.string else { throw AgentAPIError.unavailable }
                for _ in 0..<40 {
                    let result = try await call("operation.get", ["operation_ref": .string(reference)])
                    if result["state"]?.string == "succeeded" { return }
                    guard result["state"]?.string == "running" else { throw AgentAPIError.unavailable }
                    try await Task.sleep(for: .milliseconds(500))
                }
                throw AgentAPIError.unavailable
            }
            try await finishAction(call("browser.click", ["session_ref": .string(session), "element_ref": .string(element)]))
            let detail = try await call("browser.extract", ["session_ref": .string(session), "schema_id": .string("item_detail")])
            guard detail["records"]?.array?.first?["fields"]?.array?.contains(where: { $0["name"]?.string == "status" && $0["value"]?.string == "Ready" }) == true else { throw AgentAPIError.unavailable }
            try await finishAction(call("browser.navigate", ["session_ref": .string(session), "route_id": .string("items")]))
            guard try await call("browser.observe", ["session_ref": .string(session), "view_id": .string("items")])["records"]?.array?.count == 1 else { throw AgentAPIError.unavailable }
            print("BROWSER_SAFE_WORKFLOW=pass")
            _ = try await call("session.close", ["session_ref": .string(session)])
            guard try await call("operation.get", ["operation_ref": .string(operation)])["session_ref"] == .null else { throw AgentAPIError.unavailable }
            print("BROWSER_NATIVE_CLOSE=pass")
            await worker.lock()
        } catch {
            await worker.lock()
            throw error
        }
    }
}
