import Foundation
import BrokerHost
import PolicyCore
import RuntimeHost
import ModelRelay
import Security

/// Synthetic owner and provider around the production agent/browser drivers.
@MainActor enum TwoVMProbe {
    static func run() async throws {
        guard CommandLine.arguments.count == 8, let rootPath = ProcessInfo.processInfo.environment["SHADOW_PROBE_ROOT"],
              let port = ProcessInfo.processInfo.environment["SHADOW_FIXTURE_PORT"].flatMap(UInt16.init) else { throw AgentAPIError.unavailable }
        let args = CommandLine.arguments, root = URL(fileURLWithPath: rootPath)
        let removeSource = ProcessInfo.processInfo.environment["SHADOW_PROBE_INTERRUPT"] == "source"
        let browserImage = BrowserVMImage(kernel: URL(fileURLWithPath: args[2]), ramdisk: URL(fileURLWithPath: args[3]), disk: URL(fileURLWithPath: args[4]), identity: VMImageIdentity(kernelSHA256: args[5], ramdiskSHA256: args[6], imageSHA256: args[7]))
        let agentImage = try AgentVMImage.packaged(at: root.appendingPathComponent(".build/guest-cache/agent"))
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shadow-two-vm-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let vaultID = "synthetic-two-vm-\(UUID())"
        defer {
            try? FileManager.default.removeItem(at: directory)
            for account in [vaultID, vaultID + ":restrictions"] {
                SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yptalkov.shadow.generation-anchor", kSecAttrAccount as String: account] as CFDictionary)
            }
        }
        let access = AccessCoordinator(), api: AgentAPI
        api = AgentAPI(access: access)
        let worker = try await PrivateVaultWorker.launch(python: root.appendingPathComponent(".venv/bin/python"), vaultDirectory: directory.appendingPathComponent("vault"), vaultID: vaultID) { ids in
            ids.forEach { access.invalidate(account: $0) }
        }
        let source = UUID(), sourceEpoch = UUID()
        do {
            try await worker.create(password: "synthetic-master-canary")
            if removeSource {
                let capabilities = SourceCapabilities(stableItems: true, stableGroups: true, completeScopes: ["account"], deletionEvidence: ["item_tombstone"], distinguishesAccessLoss: true, totp: false, collectionMode: "unattended")
                try await worker.configureSource(instance: source, label: "Synthetic source", epoch: sourceEpoch, capabilities: capabilities, digestKey: Data(repeating: 23, count: 32))
                try await snapshot(worker, source: source, epoch: sourceEpoch, generation: 0, includeItem: true)
            } else {
                let csv = directory.appendingPathComponent("fixture.csv")
                try Data("Title,URL,Username,Password\nSynthetic,https://app.shadow.test,synthetic-user,synthetic-atomic-auth-canary\n".utf8).write(to: csv)
                _ = try await worker.previewCSV(path: csv, mapping: OwnerCSVMapping(title: "Title", url: "URL", username: "Username", password: "Password"))
                _ = try await worker.commitCSV(operationID: UUID(), validRowsOnly: false)
            }
            guard let item = try await worker.catalog().items.first, let account = UUID(uuidString: item.id) else { throw AgentAPIError.unavailable }
            access.openVault(accounts: [ConsentAccount(metadata: item, policy: AccountPolicy(id: account, revision: item.revision, source: removeSource ? .mirrored : .local, presence: .present, lastObserved: item.observationDate, restrictionEvent: nil))])
            let actions: Set<ProtectedAction> = [.login, .observe, .extract, .navigate, .click]
            access.installQualifiedAdapter(QualifiedAdapterPolicy(id: "synthetic-v1", credentialOrigins: ["https://app.shadow.test"], resourceOrigins: ["https://app.shadow.test"], actions: actions))
            let journal = try OperationJournal(path: directory.appendingPathComponent("operations.sqlite"))
            let browser = ProtectedSessionService(access: access, journal: journal, worker: worker, image: browserImage) { descriptor, channel, authorize in
                try FixtureTunnel.run(guest: descriptor, port: port, transport: channel, authorize: authorize)
            }
            defer { browser.shutdown() }
            api.protectedService = browser
            let model = TwoVMModel(removeSource: removeSource)
            let runtime = AgentRuntime(image: agentImage, access: access, api: api) { request, send in try await model.respond(request, send: send) }
            defer { runtime.stop(); access.lock() }
            await runtime.start(prompt: "Read the status of Example report using Shadow. Request separate native permission for discovery and credential use. Close the protected session when finished.", model: "gpt-6-sol", maximumRequests: 120)
            let deadline = DeadlineClock.now + 100
            var disclosures = 0, uses = 0
            var removed = false
            while runtime.active, DeadlineClock.now < deadline {
                for request in access.pending {
                    guard request.caller == access.agents.first else { throw AgentAPIError.unavailable }
                    if request.kind == .catalog {
                        guard disclosures == 0, request.availableAccountIDs == [account] else { throw AgentAPIError.unavailable }
                        try access.approveCatalog(request.id, selected: [account], duration: 300)
                        disclosures += 1
                    } else {
                        guard uses == 0, request.account?.id == account, request.actions == actions,
                              request.adapter?.credentialOrigins == ["https://app.shadow.test"] else { throw AgentAPIError.unavailable }
                        try access.approveUse(request.id, duration: 300, approveRetained: false)
                        uses += 1
                    }
                }
                if removeSource, !removed, await model.waitingForRemoval {
                    try await snapshot(worker, source: source, epoch: sourceEpoch, generation: 1, includeItem: false)
                    guard let retained = try await worker.catalog().items.first, retained.id == item.id,
                          retained.presence == "deleted_at_source", retained.restrictionEvent != nil, access.grants.isEmpty else { throw AgentAPIError.unavailable }
                    removed = true
                    await model.releaseAfterRemoval()
                }
                try await Task.sleep(for: .milliseconds(50))
            }
            guard runtime.state == .succeeded, runtime.output == (removeSource ? "Source changed; access ended" : "Example report: Ready"), await model.complete,
                  !removeSource || removed,
                  disclosures == 1, uses == 1, access.agents.isEmpty, access.grants.isEmpty else {
                print("TWO_VM_STATE=\(runtime.state)")
                print("TWO_VM_STEP=\(await model.step)")
                throw AgentAPIError.unavailable
            }
            print("TWO_VM_SEPARATE_CONSENT=pass")
            print(removeSource ? "TWO_VM_SOURCE_REMOVAL=pass" : "TWO_VM_AUTHENTICATED_READ=pass")
            print("TWO_VM_MODEL_CANARIES=absent")
            print("TWO_VM_TEARDOWN=pass")
            await worker.lock()
        } catch { await worker.lock(); throw error }
    }

    private static func snapshot(_ worker: PrivateVaultWorker, source: UUID, epoch: UUID, generation: Int, includeItem: Bool) async throws {
        let batch = UUID().uuidString.lowercased(), time = ISO8601DateFormatter().string(from: Date())
        var frames: [(String, [String: Any])] = [
            ("begin", ["previous_generation": generation, "started_at": time, "mode": "snapshot"]),
            ("group", ["id": "fixture-group", "parent_id": NSNull(), "name": "Synthetic", "relationship": "member", "observation": "present"])
        ]
        if includeItem {
            frames.append(("item", ["id": "fixture-item", "source_revision": "revision_unknown", "title": "Synthetic", "username": "synthetic-user", "urls": ["https://app.shadow.test"], "groups": ["fixture-group"], "credential_kind": "password", "secret": ["password": "synthetic-atomic-auth-canary"]]))
        }
        frames.append(("coverage", ["scope": "account", "id": "account", "state": "complete", "basis": "enumeration_complete", "capability_version": 1]))
        frames.append(("commit", ["finished_at": time, "final_sequence": frames.count, "coverage_count": 1]))
        for (sequence, frame) in frames.enumerated() {
            let data = try JSONSerialization.data(withJSONObject: ["contract_major": 1, "source_instance_id": source.uuidString.lowercased(), "channel_epoch": epoch.uuidString.lowercased(), "producer_sequence": sequence, "kind": frame.0, "batch_id": batch, "payload": frame.1])
            let result = try await worker.sourceFrame(instance: source, frame: data)
            guard result.state == (frame.0 == "commit" ? "committed" : "collecting") else { throw AgentAPIError.unavailable }
        }
    }
}

private actor TwoVMModel {
    enum Step: String { case initial, status, catalog, disclosure, search, use, permission, login, authenticated, blockedRead, observe, click, clicked, extract, close, done }
    private(set) var step = Step.initial
    private(set) var complete = false
    private var operation = "", account = "", grant = "", session = ""
    private var requests = 0
    private let removeSource: Bool
    private(set) var waitingForRemoval = false
    private var removed = false

    init(removeSource: Bool) { self.removeSource = removeSource }
    func releaseAfterRemoval() { removed = true }

    func respond(_ request: AgentModelRequest, send: @escaping @Sendable (Data) async throws -> Void) async throws {
        requests += 1
        guard requests <= 110 else { throw AgentAPIError.rateLimited }
        let text = String(decoding: request.body, as: UTF8.self)
        for canary in ["synthetic-master-canary", "synthetic-atomic-auth-canary", "synthetic-http-only-canary"] {
            guard !text.contains(canary), !text.contains(Data(canary.utf8).base64EncodedString()) else { throw AgentAPIError.unavailable }
        }
        _ = try CodexRelayPolicy(models: ["gpt-6-sol"]).request(method: request.method, path: request.path, headers: request.headers, body: request.body,
            credential: CodexCredential(accessToken: "host-only-synthetic-canary", accountID: "host-only-synthetic-account", expiresAt: Date().addingTimeInterval(120)))
        try request.lease.reserve(instance: request.instance, boot: request.boot, bytes: request.body.count)
        let body = try JSONSerialization.jsonObject(with: request.body) as? [String: Any] ?? [:]
        let input = body["input"] as? [[String: Any]] ?? []
        let result = try latestResult(input)
        let call: (String, [String: Any], Bool)?
        switch step {
        case .initial: step = .status; call = ("vault_status", [:], false)
        case .status:
            guard result["state"] as? String == "catalog_consent_required" else { throw AgentAPIError.unavailable }
            step = .catalog; call = ("access_request", ["kind": "catalog"], false)
        case .catalog:
            operation = try reference(result, "operation_ref")
            step = .disclosure; call = ("operation_get", ["operation_ref": operation], true)
        case .disclosure:
            if result["state"] as? String == "pending_owner" { call = ("operation_get", ["operation_ref": operation], true) }
            else {
                guard result["state"] as? String == "granted" else { throw AgentAPIError.unavailable }
                step = .search; call = ("catalog_search", ["query": "Synthetic"], false)
            }
        case .search:
            guard let entries = result["items"] as? [[String: Any]], entries.count == 1 else { throw AgentAPIError.unavailable }
            account = try reference(entries[0], "account_ref")
            step = .use; call = ("access_request", ["kind": "account_use", "account_ref": account, "adapter_id": "synthetic-v1", "actions": ["login", "observe", "extract", "navigate", "click"]], false)
        case .use:
            operation = try reference(result, "operation_ref")
            step = .permission; call = ("operation_get", ["operation_ref": operation], true)
        case .permission:
            if result["state"] as? String == "pending_owner" { call = ("operation_get", ["operation_ref": operation], true) }
            else {
                guard result["state"] as? String == "granted" else { throw AgentAPIError.unavailable }
                grant = try reference(result, "grant_ref")
                step = .login; call = ("auth_login", ["account_ref": account, "grant_ref": grant, "adapter_id": "synthetic-v1"], false)
            }
        case .login:
            operation = try reference(result, "operation_ref")
            step = .authenticated; call = ("operation_get", ["operation_ref": operation], true)
        case .authenticated:
            if result["state"] as? String == "running" { call = ("operation_get", ["operation_ref": operation], true) }
            else {
                guard result["state"] as? String == "succeeded" else { throw AgentAPIError.unavailable }
                session = try reference(result, "session_ref")
                if removeSource {
                    waitingForRemoval = true
                    while !removed {
                        try request.lease.check(instance: request.instance, boot: request.boot)
                        try await Task.sleep(for: .milliseconds(100))
                    }
                }
                step = removeSource ? .blockedRead : .observe
                call = ("browser_observe", ["session_ref": session, "view_id": "items"], false)
            }
        case .blockedRead:
            guard let error = result["error"] as? [String: Any], ["invalid_reference", "session_closed", "account_consent_required"].contains(error["code"] as? String ?? "") else { throw AgentAPIError.unavailable }
            step = .done; complete = true; call = nil
        case .observe:
            guard let row = (result["records"] as? [[String: Any]])?.first,
                  let action = (row["actions"] as? [[String: Any]])?.first else { throw AgentAPIError.unavailable }
            let element = try reference(action, "element_ref")
            step = .click; call = ("browser_click", ["session_ref": session, "element_ref": element], false)
        case .click:
            operation = try reference(result, "operation_ref")
            step = .clicked; call = ("operation_get", ["operation_ref": operation], true)
        case .clicked:
            if result["state"] as? String == "running" { call = ("operation_get", ["operation_ref": operation], true) }
            else {
                guard result["state"] as? String == "succeeded" else { throw AgentAPIError.unavailable }
                step = .extract; call = ("browser_extract", ["session_ref": session, "schema_id": "item_detail"], false)
            }
        case .extract:
            guard let row = (result["records"] as? [[String: Any]])?.first, let fields = row["fields"] as? [[String: Any]],
                  fields.contains(where: { $0["name"] as? String == "status" && $0["value"] as? String == "Ready" }),
                  fields.contains(where: { $0["name"] as? String == "title" && $0["value"] as? String == "Example report" }) else { throw AgentAPIError.unavailable }
            step = .close; call = ("session_close", ["session_ref": session], false)
        case .close:
            guard result["state"] as? String == "closed" else { throw AgentAPIError.unavailable }
            step = .done; complete = true; call = nil
        case .done: throw AgentAPIError.unavailable
        }
        let item: [String: Any]
        if let call {
            let arguments = try JSONSerialization.data(withJSONObject: ["request_id": UUID().uuidString.lowercased(), "arguments": call.1], options: [.sortedKeys])
            let delay = call.2 ? "await new Promise(resolve => setTimeout(resolve, 500)); " : ""
            item = ["type": "custom_tool_call", "id": "ctc_\(requests)", "call_id": "call_\(requests)", "name": "exec", "namespace": "functions", "status": "completed",
                    "input": delay + "text(await tools.mcp__shadow__shadow_\(call.0)(\(String(decoding: arguments, as: UTF8.self))));"]
        } else {
            item = ["type": "message", "id": "msg_final", "role": "assistant", "status": "completed", "content": [["type": "output_text", "text": removeSource ? "Source changed; access ended" : "Example report: Ready", "annotations": []]]]
        }
        let response: [String: Any] = ["id": "resp_\(requests)", "object": "response", "status": "completed", "output": [item], "usage": ["input_tokens": 1, "output_tokens": 1, "total_tokens": 2]]
        for event: [String: Any] in [
            ["type": "response.created", "response": ["id": "resp_\(requests)", "status": "in_progress", "output": []]],
            ["type": "response.output_item.added", "output_index": 0, "item": item],
            ["type": "response.output_item.done", "output_index": 0, "item": item],
            ["type": "response.completed", "response": response]
        ] {
            let data = try JSONSerialization.data(withJSONObject: event)
            try await send(Data("event: \(event["type"]!)\ndata: \(String(decoding: data, as: UTF8.self))\n\n".utf8))
        }
    }

    private func reference(_ object: [String: Any], _ key: String) throws -> String {
        guard let value = object[key] as? String, value.count == 64, value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw AgentAPIError.unavailable }
        return value
    }

    private func latestResult(_ input: [[String: Any]]) throws -> [String: Any] {
        if step == .initial { return [:] }
        guard let output = input.last(where: { $0["type"] as? String == "custom_tool_call_output" })?["output"] else { throw AgentAPIError.unavailable }
        let parts = output as? [[String: Any]] ?? [["text": output]]
        for part in parts.reversed() {
            guard let text = part["text"] as? String, let data = text.data(using: .utf8),
                  let mcp = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  mcp["isError"] as? Bool == (step == .blockedRead),
                  let content = mcp["content"] as? [[String: Any]], let payload = content.first?["text"] as? String,
                  let result = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any] else { continue }
            return result
        }
        throw AgentAPIError.unavailable
    }
}
