from copy import deepcopy
import pytest

from browser_worker.errors import BrowserFailure
from site_adapters import manifest, login_spec
from site_adapters.validation import validate


@pytest.mark.parametrize("adapter", ["synthetic-v1", "synthetic-sso-v1"])
def test_packaged_manifests_pass_cross_origin_contract(adapter):
    value = manifest(adapter)
    validate(value)
    assert login_spec(adapter).challenge is not None


@pytest.mark.parametrize("change", ["extra", "origin", "route", "view_duplicate", "field_limit", "action_extra", "challenge_origin", "id"])
def test_adapter_drift_is_rejected_before_browser_launch(change):
    value = deepcopy(manifest("synthetic-v1"))
    if change == "extra": value["script"] = "unreviewed"
    if change == "origin": value["origin"] = "https://other.shadow.test"
    if change == "route": value["routes"]["items"] += "?token=unreviewed"
    if change == "view_duplicate": value["views"].append(value["views"][0])
    if change == "field_limit": value["views"][0]["fields"] = {str(i): "span" for i in range(9)}
    if change == "action_extra": value["views"][0]["actions"]["open"]["script"] = "unreviewed"
    if change == "challenge_origin": value["login"]["challenge"]["url"] = "https://other.shadow.test/verify"
    if change == "id": value["id"] = "../../unreviewed"
    with pytest.raises(BrowserFailure): validate(value)
