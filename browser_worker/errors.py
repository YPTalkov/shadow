"""Only these literal codes can cross the private browser protocol."""
from enum import StrEnum


class Code(StrEnum):
    OUTPUT_CLOSED = "output_closed"
    DOCUMENT_CHANGED = "document_changed"
    LEASE_EXPIRED = "lease_expired"
    INVALID_LEASE = "invalid_lease"
    SESSION_CLOSED = "session_closed"
    UNSUPPORTED_VIEW = "unsupported_view"
    UNSUPPORTED_CHALLENGE = "unsupported_challenge"
    INVALID_REQUEST = "invalid_request"
    AUTHENTICATION_FAILED = "authentication_failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    UNAVAILABLE = "unavailable"


class BrowserFailure(Exception):
    def __init__(self, code: Code):
        if not isinstance(code, Code):
            code = Code.UNAVAILABLE
        self.code = code
        super().__init__(code.value)
