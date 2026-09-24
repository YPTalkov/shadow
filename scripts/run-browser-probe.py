"""Boot the synthetic Chromium engine check using the production VM device profile."""
import json
from pathlib import Path
import subprocess
import importlib.util
import os
import threading

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / ".build/guest-cache/browser"


def main():
    manifest = json.loads((IMAGE / "runtime-manifest.json").read_text())
    executable = ROOT / ".build/arm64-apple-macosx/debug/vm-boot-probe"
    command = [str(executable), "browser"]
    command += [str(IMAGE / name) for name in ("kernel", "initrd", "disk")]
    command += [manifest["files"][name] for name in ("kernel", "initrd", "disk")]
    module_spec = importlib.util.spec_from_file_location("https_fixture", ROOT / "tests/sites/https_fixture.py")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    fixture = module.Fixture(IMAGE / "fixture")
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    try:
        with (IMAGE / "console.txt").open("wb") as console:
            run = subprocess.run(command, stdout=console, stderr=subprocess.DEVNULL, timeout=75,
                                 env={**os.environ, "SHADOW_FIXTURE_PORT": str(fixture.server_port)})
    finally:
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=1)
    output = (IMAGE / "console.txt").read_text(errors="replace").replace("\r", "")
    lines = dict(line.split("=", 1) for line in output.splitlines() if line.startswith("BROWSER_"))
    expected = {"BROWSER_ENGINE": "pass", "BROWSER_PRIVATE_DISPLAY": "ready", "BROWSER_UID": "1001", "BROWSER_NETWORK_DEVICES": "lo", "BROWSER_ATOMIC_AUTH": "pass", "BROWSER_AUTH_SCENARIOS": "10"}
    passed = run.returncode == 0 and all(lines.get(key) == value for key, value in expected.items())
    passed = passed and int(lines.get("BROWSER_INPUT_DEVICES", "0")) >= 2
    passed = passed and lines.get("BROWSER_HTTPS_AUTH") == "pass" and lines.get("BROWSER_CRASH_DUMPS") == "absent" and fixture.submissions == 1
    lines["BROWSER_HTTPS_SUBMISSIONS"] = str(fixture.submissions)
    leaked = any(value in output for value in ("synthetic-atomic-auth-canary", "synthetic-http-only-canary", "synthetic-browser-bootstrap-canary"))
    lines["BROWSER_CONSOLE_CANARIES"] = "absent" if not leaked else "fail"
    passed = passed and not leaked
    report = {"passed": passed, "manifest": manifest, "checks": lines}
    (IMAGE / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
