"""Packaged, versioned site definitions. No agent-provided selectors or scripts."""
import json
from pathlib import Path

from browser_worker.auth import LoginSpec
from browser_worker.errors import BrowserFailure, Code


def login_spec(adapter_id: str) -> LoginSpec:
    # Qualification installs explicit IDs here. User paths never reach a loader.
    if adapter_id != "synthetic-v1":
        raise BrowserFailure(Code.UNSUPPORTED_VIEW)
    manifest = json.loads((Path(__file__).parent / "synthetic/manifest.json").read_text())
    return LoginSpec(**manifest["login"])
