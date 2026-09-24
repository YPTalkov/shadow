"""Run both synthetic VM profiles and fail unless root's boundary checks pass."""

import json
import argparse
import hashlib
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / ".build/guest-cache/probe"
EXECUTABLE = ROOT / ".build/arm64-apple-macosx/debug/vm-boot-probe"
EXPECTED = {
    "UID": "0",
    "NETWORK_DEVICES": "lo",
    "SWAP_DEVICES": "0",
    "HOST_HOME_PRESENT": "no",
    "SHARED_MOUNTS": "0",
    "IP_ROUTE_COUNT": "0",
    "VSOCK_ROLE_BOUNDARY": "pass",
    "DIRECT_EGRESS": "denied",
    "BASE_DISK": "readonly",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", action="append", choices=("agent", "browser"))
    roles = parser.parse_args().role or ["agent", "browser"]
    manifest = json.loads((IMAGE / "manifest.json").read_text())
    results = {}
    for role in roles:
        command = [str(EXECUTABLE), role]
        command += [str(IMAGE / name) for name in ("kernel", "initrd", "disk")]
        command += [manifest["files"][name] for name in ("kernel", "initrd", "disk")]
        console = IMAGE / f"{role}-console.txt"
        with console.open("wb") as log:
            run = subprocess.run(command, stdout=log, stderr=subprocess.DEVNULL, timeout=75)
        output = console.read_text(errors="replace").replace("\r", "")
        lines = dict(line.split("=", 1) for line in output.splitlines() if "=" in line and not line.startswith("["))
        passed = run.returncode == 0 and all(lines.get(k) == v for k, v in EXPECTED.items())
        passed = passed and hashlib.sha256((IMAGE / "disk").read_bytes()).hexdigest() == manifest["files"]["disk"]
        if role == "agent":
            passed = passed and all(lines.get(key) == "pass" for key in ("LINUX_CODEX_RELAY", "CODEX_TOOL_RESULT", "CODEX_MCP_RESULT", "GUEST_AGENT_API"))
        # Only this synthetic probe's output is recorded; production guests have no console log.
        checks = {key: lines.get(key) for key in EXPECTED}
        if role == "agent":
            checks.update({key: lines.get(key) for key in ("LINUX_CODEX_RELAY", "CODEX_TOOL_RESULT", "CODEX_MCP_RESULT", "GUEST_AGENT_API")})
        if role == "browser" and os.environ.get("SHADOW_LIVE_EGRESS") == "1":
            checks.update({key: lines.get(key) for key in ("HTTPS_EGRESS", "EGRESS_DESTINATIONS")})
            passed = passed and checks["HTTPS_EGRESS"] == "pass" and checks["EGRESS_DESTINATIONS"] == "denied"
        results[role] = {"passed": passed, "checks": checks}
    report = {"manifest": manifest, "profiles": results}
    name = "results.json" if set(roles) == {"agent", "browser"} else "results-" + "-".join(roles) + ".json"
    (IMAGE / name).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    if not all(result["passed"] for result in results.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
