import base64
import html
from urllib.parse import quote

import pytest

from browser_worker.observations import project_records
from browser_worker.errors import BrowserFailure

PASSWORD = "synthetic /password&canary"
COOKIE = "synthetic-session-cookie-canary"
SPEC = {"id": "items", "fields": ["title"], "actions": ["open"]}


def row(value, **extra):
    return {"fields": {"title": value}, "actions": [], **extra}


def test_safe_projection_filters_known_secrets_and_never_returns_extra_fields():
    variants = [PASSWORD, quote(PASSWORD, safe=""), base64.b64encode(PASSWORD.encode()).decode(), html.escape(PASSWORD), COOKIE]
    result = project_records([row(value) for value in variants], SPEC, [PASSWORD, COOKIE])
    assert all(record["fields"] == [{"name": "title", "value": "[withheld]"}] for record in result)
    for records in ([row("safe", hidden="token")], [row("safe") | {"fields": {"password": "secret"}}], [row("safe") | {"actions": [{"id": "export", "index": 0}]}]):
        with pytest.raises(BrowserFailure, match="unsupported_view"):
            project_records(records, SPEC, [PASSWORD])


def test_safe_projection_bounds_rows_fields_and_opaque_navigation():
    assert project_records([row("Example report")], SPEC, [PASSWORD]) == [{"fields": [{"name": "title", "value": "Example report"}], "actions": []}]
    for records in ([row("x" * 257)], [row("safe")] * 51, [row({"script": "value"})]):
        with pytest.raises(BrowserFailure, match="unsupported_view"):
            project_records(records, SPEC, [PASSWORD])
