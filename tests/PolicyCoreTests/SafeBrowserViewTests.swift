import Foundation
import Testing
@testable import BrokerHost
import PolicyCore

@Test func nativeBrowserViewRejectsFieldsOutsideThePackagedManifest() throws {
    func view(field: String = "title", extra: Bool = false, action: String = "open") -> JSONValue {
        var row: [String: JSONValue] = ["fields": .array([.object(["name": .string(field), "value": .string("Example report")])]), "actions": .array([.object(["id": .string(action), "element_ref": .string(String(repeating: "a", count: 64))])])]
        if extra { row["cookie"] = .string("synthetic-cookie-canary") }
        return .object(["view_id": .string("items"), "document_ref": .string(String(repeating: "b", count: 64)), "records": .array([.object(row)])])
    }
    #expect(try SafeBrowserView(view(), adapterID: "synthetic-v1").json == view())
    for invalid in [view(field: "password"), view(extra: true), view(action: "export")] {
        #expect(throws: AgentAPIError.unsupportedView) { _ = try SafeBrowserView(invalid, adapterID: "synthetic-v1") }
    }
    #expect(throws: AgentAPIError.unsupportedView) { _ = try SafeBrowserView(view(), adapterID: "unqualified-v1") }
}
