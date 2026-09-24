"""Synthetic provider, production agent image and native supervisor; no sign-in."""

import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / ".build/guest-cache/agent"
BINARY = ROOT / ".build/arm64-apple-macosx/debug/vm-boot-probe"
CHECKS = ("AGENT_CODEX_SHELL_MCP", "AGENT_TASK_TEARDOWN", "AGENT_LOCK_REJECTS_OLD_BOOT", "AGENT_RUNTIME")


def main():
    results = []
    for model in ("gpt-6-sol", "gpt-6-luna", "gpt-6-astra"):
        run = subprocess.run([str(BINARY), "agent-runtime", str(IMAGE), model], capture_output=True, timeout=90)
        lines = run.stdout.decode(errors="replace").splitlines()
        checks = {check: check + "=pass" in lines for check in CHECKS}
        passed = run.returncode == 0 and all(checks.values())
        results.append({"model": model, "checks": checks, "passed": passed})
        print(model + ": " + ("pass" if passed else "failed"), flush=True)
    result = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "macos": platform.mac_ver()[0], "architecture": platform.machine(),
        "binary_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(),
        "image": json.loads((IMAGE / "manifest.json").read_text()),
        "live_provider": False, "real_credentials": False, "results": results,
    }
    (IMAGE / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    if not all(item["passed"] for item in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
