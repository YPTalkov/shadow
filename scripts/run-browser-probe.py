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

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / ".build/guest-cache/browser"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", action="store_true")
    parser.add_argument("--interrupt", choices=("revoke", "suspend"))
    parser.add_argument("--flow", choices=("totp", "owner", "sso", "unsupported", "owner_cancel", "owner_timeout"))
    arguments = parser.parse_args()
    session = arguments.session or arguments.interrupt is not None or arguments.flow is not None
    manifest = json.loads((IMAGE / ("qualification-manifest.json" if session else "runtime-manifest.json")).read_text())
    executable = ROOT / ".build/arm64-apple-macosx/debug/vm-boot-probe"
    command = [str(executable), "browser-session" if session else "browser"]
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
            with subprocess.Popen(command, stdout=console, stderr=subprocess.DEVNULL, env=environment) as run:
                try:
                    if arguments.interrupt:
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
                    run.wait(timeout=180 if arguments.flow == "owner_timeout" else 75)
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
    lines = dict(line.split("=", 1) for line in output.splitlines() if line.startswith("BROWSER_"))
    expected = {"BROWSER_ENGINE": "pass", "BROWSER_PRIVATE_DISPLAY": "ready", "BROWSER_UID": "1001", "BROWSER_NETWORK_DEVICES": "lo", "BROWSER_ATOMIC_AUTH": "pass", "BROWSER_AUTH_SCENARIOS": "10"}
    passed = run.returncode == 0 and all(lines.get(key) == value for key, value in expected.items())
    if session:
        required = ("BROWSER_SESSION", "BROWSER_NATIVE_AUTH", "BROWSER_NATIVE_RETRY", "BROWSER_NATIVE_CLOSE", "BROWSER_SAFE_WORKFLOW")
        if arguments.interrupt:
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
    report = {"passed": passed, "exit_code": run.returncode, "manifest": manifest, "checks": lines}
    filename = "session-results.json" if session else "results.json"
    if arguments.interrupt:
        filename = arguments.interrupt + "-results.json"
    if arguments.flow:
        filename = arguments.flow + "-results.json"
    (IMAGE / filename).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
