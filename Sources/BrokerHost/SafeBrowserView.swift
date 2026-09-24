import Foundation
import PolicyCore

/// Only a packaged view schema can construct an agent-visible browser result.
public struct SafeBrowserView: Sendable {
    let json: JSONValue

    init(_ value: JSONValue, adapterID: String) throws {
        func reference(_ value: JSONValue?) -> Bool {
            guard let text = value?.string else { return false }
            return text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        }
        guard let object = value.object, Set(object.keys) == ["view_id", "document_ref", "records"], reference(object["document_ref"]),
              let viewID = object["view_id"]?.string,
              let manifest = PackagedAdapters.manifests[adapterID]?["views"]?.array?.first(where: { $0["id"]?.string == viewID }),
              let fields = manifest["fields"]?.object, fields.count <= 8,
              let actions = manifest["actions"]?.object, actions.count <= 4,
              let records = object["records"]?.array, records.count <= 50 else { throw AgentAPIError.unsupportedView }
        for record in records {
            guard let row = record.object, Set(row.keys) == ["fields", "actions"],
                  let values = row["fields"]?.array, values.count == fields.count,
                  Set(values.compactMap { $0["name"]?.string }) == Set(fields.keys),
                  let buttons = row["actions"]?.array, buttons.count <= actions.count else { throw AgentAPIError.unsupportedView }
            for field in values {
                guard let item = field.object, Set(item.keys) == ["name", "value"],
                      let text = item["value"]?.string, text.unicodeScalars.count <= 256 else { throw AgentAPIError.unsupportedView }
            }
            var names = Set<String>()
            for button in buttons {
                guard let item = button.object, Set(item.keys) == ["id", "element_ref"],
                      let name = item["id"]?.string, actions[name] != nil, names.insert(name).inserted,
                      reference(item["element_ref"]) else { throw AgentAPIError.unsupportedView }
            }
        }
        guard try value.encoded().count <= 28 * 1024 else { throw AgentAPIError.responseLimit }
        json = value
    }
}
