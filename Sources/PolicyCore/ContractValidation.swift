import Foundation

/// Validates the bounded subset used by the pinned, embedded agent contract.
/// No remote schemas, references, coercion, defaults, or executable expressions.
public enum ContractValidation {
    public static func accepts(_ value: JSONValue, schema: JSONValue) -> Bool {
        if let constant = schema["const"], constant != value { return false }
        if let values = schema["enum"]?.array, !values.contains(value) { return false }
        if let choices = schema["oneOf"]?.array, choices.filter({ accepts(value, schema: $0) }).count != 1 { return false }
        if let type = schema["type"]?.string {
            let matches: Bool = switch (type, value) {
            case ("object", .object), ("array", .array), ("string", .string), ("integer", .integer), ("boolean", .bool), ("null", .null): true
            default: false
            }
            if !matches { return false }
        }
        if case .object(let object) = value {
            let properties = schema["properties"]?.object ?? [:]
            if schema["additionalProperties"] == .bool(false), !Set(object.keys).isSubset(of: Set(properties.keys)) { return false }
            if let required = schema["required"]?.array, !required.allSatisfy({ $0.string.map { object[$0] != nil } ?? false }) { return false }
            for (key, rule) in properties {
                if let field = object[key], !accepts(field, schema: rule) { return false }
            }
        }
        if case .array(let array) = value {
            if let minimum = schema["minItems"]?.integer, array.count < minimum { return false }
            if let maximum = schema["maxItems"]?.integer, array.count > maximum { return false }
            if schema["uniqueItems"] == .bool(true) {
                for index in array.indices where array[..<index].contains(array[index]) { return false }
            }
            if let items = schema["items"], !array.allSatisfy({ accepts($0, schema: items) }) { return false }
        }
        if case .string(let string) = value {
            if let maximum = schema["maxLength"]?.integer, string.unicodeScalars.count > maximum { return false }
            if let minimum = schema["minLength"]?.integer, string.unicodeScalars.count < minimum { return false }
            if let pattern = schema["pattern"]?.string, string.range(of: pattern, options: .regularExpression) != string.startIndex..<string.endIndex { return false }
            if schema["format"]?.string == "uuid", UUID(uuidString: string)?.uuidString.lowercased() != string { return false }
        }
        if case .integer(let integer) = value {
            if let minimum = schema["minimum"]?.integer, integer < minimum { return false }
            if let maximum = schema["maximum"]?.integer, integer > maximum { return false }
        }
        return true
    }
}
