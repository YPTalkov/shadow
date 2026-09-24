"""Programmatic tool calling with ordinary opaque-reference variables."""

from .client import ShadowClient


class Shadow(ShadowClient):
    def status(self):
        return self.call("vault.status")

    def request_catalog(self, *, request_id=None):
        return self.call("access.request", {"kind": "catalog"}, request_id=request_id)

    def search(self, query="", *, cursor=None, limit=50):
        arguments = {"query": query, "limit": limit}
        if cursor is not None:
            arguments["cursor"] = cursor
        return self.call("catalog.search", arguments)

    def request_account(self, account_ref, adapter_id, actions, *, request_id=None):
        return self.call("access.request", {"kind": "account_use", "account_ref": account_ref, "adapter_id": adapter_id, "actions": actions}, request_id=request_id)

    def login(self, account_ref, grant_ref, adapter_id, *, request_id):
        return self.call("auth.login", {"account_ref": account_ref, "grant_ref": grant_ref, "adapter_id": adapter_id}, request_id=request_id)

    def operation(self, operation_ref):
        return self.call("operation.get", {"operation_ref": operation_ref})

    def cancel(self, operation_ref):
        return self.call("operation.cancel", {"operation_ref": operation_ref})

    def close(self, session_ref):
        return self.call("session.close", {"session_ref": session_ref})
