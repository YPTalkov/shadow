"""Packaged, versioned site definitions. No agent-provided selectors or scripts."""
import json
from pathlib import Path

from browser_worker.auth import LoginSpec
from browser_worker.errors import BrowserFailure, Code
from .validation import validate


def manifest(adapter_id: str) -> dict:
    # Qualification installs explicit IDs here. User paths never reach a loader.
    paths = {"synthetic-v1": "synthetic", "synthetic-sso-v1": "synthetic_sso"}
    if adapter_id not in paths:
        raise BrowserFailure(Code.UNSUPPORTED_VIEW)
    value = json.loads((Path(__file__).parent / paths[adapter_id] / "manifest.json").read_text())
    validate(value)
    return value


def login_spec(adapter_id: str) -> LoginSpec:
    return LoginSpec(**manifest(adapter_id)["login"])
