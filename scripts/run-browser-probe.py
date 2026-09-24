"""Boot the synthetic Chromium engine check using the production VM device profile."""
import json
from pathlib import Path
import subprocess
import importlib.util
import os
import threading
import argparse
import signal
import time
import hashlib
import platform
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / ".build/guest-cache/browser"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", action="store_true")
    parser.add_argument("--agent", action="store_true")
    parser.add_argument("--app", type=Path, help="qualify this sealed bundle's worker and agent image")
    parser.add_argument("--binary", type=Path, default=ROOT / ".build/arm64-apple-macosx/debug/vm-boot-probe")
    parser.add_argument("--interrupt", choices=("revoke", "suspend", "worker", "source"))
    parser.add_argument("--flow", choices=("totp", "owner", "sso", "unsupported", "owner_cancel", "owner_timeout"))
    arguments = parser.parse_args()
    if arguments.app and not arguments.agent:
        parser.error("--app currently requires --agent")
    if arguments.agent and (arguments.interrupt not in (None, "source") or arguments.flow):
        parser.error("--agent supports the basic task and source removal")
    if arguments.interrupt == "source" and not arguments.agent:
        parser.error("source removal requires --agent")
    session = arguments.agent or arguments.session or arguments.interrupt is not None or arguments.flow is not None
    manifest = json.loads((IMAGE / ("qualification-manifest.json" if session else "runtime-manifest.json")).read_text())
    executable = arguments.binary.resolve()
    command = [str(executable), "two-vm" if arguments.agent else "browser-session" if session else "browser"]
    command += [str(IMAGE / name) for name in ("kernel", "initrd-qualification" if session else "initrd", "disk")]
    command += [manifest["files"][name] for name in ("kernel", "initrd", "disk")]
    module_spec = importlib.util.spec_from_file_location("https_fixture", ROOT / "tests/sites/https_fixture.py")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    fixture = module.Fixture(IMAGE / "fixture")
    fixture.flow = arguments.flow or ""
    if arguments.interrupt == "revoke":
        fixture.hold_response = threading.Event()
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    try:
        console_path = IMAGE / ("session-console.txt" if session else "console.txt")
        with console_path.open("wb") as console:
            environment = {**os.environ, "SHADOW_FIXTURE_PORT": str(fixture.server_port), "SHADOW_PROBE_ROOT": str(ROOT), "SHADOW_PROBE_INTERRUPT": arguments.interrupt or "", "SHADOW_PROBE_FLOW": arguments.flow or ""}
            if arguments.app:
                environment["SHADOW_QUALIFY_APP"] = str(arguments.app.resolve())
            else:
                environment.pop("SHADOW_QUALIFY_APP", None)
            with subprocess.Popen(command, stdout=console, stderr=subprocess.DEVNULL, env=environment) as run:
                try:
                    if arguments.interrupt in {"revoke", "suspend"}:
                        deadline = time.monotonic() + 50
                        while run.poll() is None and time.monotonic() < deadline:
                            ready = fixture.submissions == 1 if arguments.interrupt == "revoke" else "BROWSER_NATIVE_SUSPEND=ready" in console_path.read_text()
                            if ready:
                                os.kill(run.pid, signal.SIGUSR1 if arguments.interrupt == "revoke" else signal.SIGSTOP)
                                if arguments.interrupt == "suspend":
                                    time.sleep(12)
                                    os.kill(run.pid, signal.SIGCONT)
                                break
                            time.sleep(0.05)
                    run.wait(timeout=180 if arguments.flow == "owner_timeout" else 120 if arguments.agent else 75)
                except BaseException:
                    run.kill()
                    run.wait(timeout=5)
                    raise
    finally:
        if fixture.hold_response is not None:
            fixture.hold_response.set()
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=1)
    output = console_path.read_text(errors="replace").replace("\r", "")
    lines = dict(line.split("=", 1) for line in output.splitlines() if line.startswith(("BROWSER_", "TWO_VM_")))
    expected = {"BROWSER_ENGINE": "pass", "BROWSER_PRIVATE_DISPLAY": "ready", "BROWSER_UID": "1001", "BROWSER_NETWORK_DEVICES": "lo", "BROWSER_ATOMIC_AUTH": "pass", "BROWSER_AUTH_SCENARIOS": "10"}
    passed = run.returncode == 0 and all(lines.get(key) == value for key, value in expected.items())
    if session:
        required = ("BROWSER_SESSION", "BROWSER_NATIVE_AUTH", "BROWSER_NATIVE_RETRY", "BROWSER_NATIVE_CLOSE", "BROWSER_SAFE_WORKFLOW")
        if arguments.agent:
            required = ("TWO_VM_SEPARATE_CONSENT", "TWO_VM_SOURCE_REMOVAL" if arguments.interrupt == "source" else "TWO_VM_AUTHENTICATED_READ", "TWO_VM_TEARDOWN", "TWO_VM_RESULT")
        elif arguments.interrupt:
            required = ("BROWSER_SESSION", "BROWSER_NATIVE_" + arguments.interrupt.upper())
        if arguments.flow in {"unsupported", "owner_cancel", "owner_timeout"}:
            required = ("BROWSER_SESSION", "BROWSER_NATIVE_CHALLENGE")
        passed = run.returncode == 0 and all(lines.get(key) == "pass" for key in required)
    else:
        passed = passed and int(lines.get("BROWSER_INPUT_DEVICES", "0")) >= 2
        passed = passed and lines.get("BROWSER_HTTPS_AUTH") == "pass" and lines.get("BROWSER_CRASH_DUMPS") == "absent"
        passed = passed and lines.get("BROWSER_SAFE_VIEWS") == "pass" and lines.get("BROWSER_SAFE_VIEW_SCENARIOS") == "18"
        passed = passed and lines.get("BROWSER_CHALLENGES") == "pass" and lines.get("BROWSER_CHALLENGE_SCENARIOS") == "9"
    passed = passed and fixture.submissions == 1
    lines["BROWSER_HTTPS_SUBMISSIONS"] = str(fixture.submissions)
    if arguments.flow:
        passed = passed and fixture.challenges == (0 if arguments.flow in {"unsupported", "owner_cancel", "owner_timeout"} else 1)
        lines["BROWSER_HTTPS_CHALLENGES"] = str(fixture.challenges)
    leaked = any(value in output for value in ("synthetic-atomic-auth-canary", "synthetic-http-only-canary", "synthetic-browser-bootstrap-canary", "synthetic-view/password&canary", "synthetic-view-cookie-canary"))
    lines["BROWSER_CONSOLE_CANARIES"] = "absent" if not leaked else "fail"
    passed = passed and not leaked
    with executable.open("rb") as file:
        executable_hash = hashlib.file_digest(file, "sha256").hexdigest()
    report = {
        "passed": passed, "exit_code": run.returncode, "manifest": manifest, "checks": lines,
        "tested_at": datetime.now(timezone.utc).isoformat(),
        "host": {"macos": platform.mac_ver()[0], "architecture": platform.machine()},
        "executable_sha256": executable_hash,
    }
    filename = "session-results.json" if session else "results.json"
    if arguments.agent:
        filename = "two-vm-results.json"
        agent_manifest = arguments.app / "Contents/Resources/agent/manifest.json" if arguments.app else ROOT / ".build/guest-cache/agent/manifest.json"
        report["agent_manifest"] = json.loads(agent_manifest.read_text())
        if arguments.app:
            report["package_inventory_sha256"] = hashlib.sha256((arguments.app / "Contents/Resources/installation.json").read_bytes()).hexdigest()
        passed = passed and lines.get("TWO_VM_MODEL_CANARIES") == "absent"
        report["passed"] = passed
    if arguments.interrupt:
        filename = ("two-vm-" if arguments.agent else "") + arguments.interrupt + "-results.json"
    if arguments.flow:
        filename = arguments.flow + "-results.json"
    (IMAGE / filename).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
