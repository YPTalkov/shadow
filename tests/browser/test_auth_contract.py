import pytest

from browser_worker.auth import Credential, LoginSpec
from browser_worker.errors import BrowserFailure, Code


def test_credentials_never_have_a_value_bearing_representation():
    value = Credential("synthetic-user", "synthetic-password", "synthetic-seed")
    assert "synthetic" not in repr(value)
    assert "synthetic" not in str(value)


def test_failure_vocabulary_cannot_echo_an_exception_or_page_value():
    assert str(BrowserFailure("synthetic-error-canary")) == "unavailable"
    assert str(BrowserFailure(Code.DOCUMENT_CHANGED)) == "document_changed"


@pytest.mark.parametrize("url", ["http://login.example.com/", "https://user:secret@login.example.com/", "https://login.example.com/?token=secret", "https://login.example.com/#secret", "https://127.0.0.1/"])
def test_packaged_login_spec_rejects_ambiguous_or_insecure_locations(url):
    with pytest.raises(BrowserFailure, match="invalid_request"):
        LoginSpec(url=url, action="https://login.example.com/session", success="https://login.example.com/items",
                  username="#username", password="#password", submit="#submit", success_selector="main[data-view=items]")
