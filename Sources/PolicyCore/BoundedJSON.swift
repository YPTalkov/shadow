import Foundation

public enum JSONValue: Equatable, Sendable, Encodable {
    case object([String: JSONValue]), array([JSONValue]), string(String), integer(Int64), bool(Bool), null

    public var object: [String: JSONValue]? { if case .object(let value) = self { value } else { nil } }
    public var array: [JSONValue]? { if case .array(let value) = self { value } else { nil } }
    public var string: String? { if case .string(let value) = self { value } else { nil } }
    public var integer: Int64? { if case .integer(let value) = self { value } else { nil } }
    public subscript(_ key: String) -> JSONValue? { object?[key] }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }

    public func encoded() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}

public enum BoundedJSONError: Error { case invalid }

/// One interpretation at the untrusted boundary: duplicate keys, floats,
/// trailing bytes, malformed Unicode and excessive depth/size are rejected.
public enum BoundedJSON {
    public static func parse(_ data: Data, maximumBytes: Int = 65_536, maximumDepth: Int = 8, maximumNodes: Int = 4096) throws -> JSONValue {
        guard !data.isEmpty, data.count <= maximumBytes else { throw BoundedJSONError.invalid }
        var parser = Parser(bytes: Array(data), depthLimit: maximumDepth, nodesRemaining: maximumNodes)
        let result = try parser.value(depth: 0)
        parser.whitespace()
        guard parser.position == data.count else { throw BoundedJSONError.invalid }
        return result
    }

    private struct Parser {
        let bytes: [UInt8]
        let depthLimit: Int
        var nodesRemaining: Int
        var position = 0
        var current: UInt8? { position < bytes.count ? bytes[position] : nil }

        mutating func whitespace() {
            while let byte = current, [9, 10, 13, 32].contains(byte) { position += 1 }
        }

        mutating func value(depth: Int) throws -> JSONValue {
            nodesRemaining -= 1
            guard depth <= depthLimit, nodesRemaining >= 0 else { throw BoundedJSONError.invalid }
            whitespace()
            guard let next = current else { throw BoundedJSONError.invalid }
            switch next {
            case 123:
                position += 1; whitespace()
                var object: [String: JSONValue] = [:]
                if current == 125 { position += 1; return .object(object) }
                while true {
                    whitespace()
                    let key = try string()
                    guard object[key] == nil else { throw BoundedJSONError.invalid }
                    whitespace(); try consume(58)
                    object[key] = try value(depth: depth + 1)
                    whitespace()
                    if current == 125 { position += 1; return .object(object) }
                    try consume(44)
                }
            case 91:
                position += 1; whitespace()
                var array: [JSONValue] = []
                if current == 93 { position += 1; return .array(array) }
                while true {
                    array.append(try value(depth: depth + 1)); whitespace()
                    if current == 93 { position += 1; return .array(array) }
                    try consume(44)
                }
            case 34: return .string(try string())
            case 116: try literal("true"); return .bool(true)
            case 102: try literal("false"); return .bool(false)
            case 110: try literal("null"); return .null
            case 45, 48...57:
                let start = position
                if current == 45 { position += 1 }
                guard let first = current, (48...57).contains(first) else { throw BoundedJSONError.invalid }
                position += 1
                if first != 48 { while let byte = current, (48...57).contains(byte) { position += 1 } }
                guard position - start <= 20, let number = Int64(String(decoding: bytes[start..<position], as: UTF8.self)) else { throw BoundedJSONError.invalid }
                return .integer(number)
            default: throw BoundedJSONError.invalid
            }
        }

        mutating func string() throws -> String {
            let start = position
            try consume(34)
            while let byte = current {
                position += 1
                if byte == 34 {
                    let raw = Data(bytes[start..<position])
                    guard raw.count <= 16_384, String(data: raw, encoding: .utf8) != nil,
                          let value = try? JSONDecoder().decode(String.self, from: raw) else { throw BoundedJSONError.invalid }
                    return value
                }
                guard byte >= 32 else { throw BoundedJSONError.invalid }
                if byte == 92 {
                    guard current != nil else { throw BoundedJSONError.invalid }
                    position += 1
                }
            }
            throw BoundedJSONError.invalid
        }

        mutating func consume(_ byte: UInt8) throws {
            guard current == byte else { throw BoundedJSONError.invalid }
            position += 1
        }

        mutating func literal(_ value: String) throws {
            for byte in value.utf8 { try consume(byte) }
        }
    }
}
