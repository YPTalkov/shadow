// Synthetic conformance producer. This executable is never bundled in Shadow.
import Foundation
import RuntimeHost

do {
    let channel = try FramedChannel(descriptor: 0, maximumBytes: 1024 * 1024)
    let command = try JSONSerialization.jsonObject(with: channel.read(timeout: 15)) as? [String: Any]
    guard let command, command["kind"] as? String == "refresh",
          let instance = command["source_instance_id"] as? String,
          let epoch = command["channel_epoch"] as? String,
          let generation = command["previous_generation"] as? Int else { exit(1) }
    let batch = UUID().uuidString.lowercased()
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let messages: [(String, [String: Any])] = [
        ("begin", ["previous_generation": generation, "started_at": timestamp, "mode": "snapshot"]),
        ("group", ["id": "fixture-group", "parent_id": NSNull(), "name": "Synthetic fixture", "relationship": "owner", "observation": "present"]),
        ("item", ["id": "fixture-item", "source_revision": "revision_unknown", "title": "Synthetic source account", "username": "fixture@example.invalid", "urls": ["https://example.invalid"], "groups": ["fixture-group"], "credential_kind": "password", "secret": ["password": "synthetic-fixture-password-canary"]]),
        ("coverage", ["scope": "account", "id": "account", "state": "complete", "basis": "enumeration_complete", "capability_version": 1]),
        ("commit", ["finished_at": timestamp, "final_sequence": 4, "coverage_count": 1])
    ]
    for (sequence, message) in messages.enumerated() {
        let data = try JSONSerialization.data(withJSONObject: ["contract_major": 1, "source_instance_id": instance, "channel_epoch": epoch, "producer_sequence": sequence, "kind": message.0, "batch_id": batch, "payload": message.1])
        try channel.write(data)
        _ = try channel.read(timeout: 15)
    }
} catch { exit(1) }
