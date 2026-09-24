"""Relocation and tamper checks against the actual locally signed executable."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("app", type=Path)
    parser.add_argument("--output", type=Path, default=Path("dist/package-checks.json"))
    arguments = parser.parse_args()
    checks = {}
    with tempfile.TemporaryDirectory(prefix="shadow-package-") as temporary:
        directory = Path(temporary)
        app = directory / "Relocated Shadow.app"
        shutil.copytree(arguments.app, app, symlinks=True)
        executable = app / "Contents/MacOS/Shadow"
        resources = app / "Contents/Resources"
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(directory), "LANG": "C.UTF-8"}

        def verify():
            run = subprocess.run([executable, "--verify-installation"], cwd=directory, env=environment, capture_output=True, timeout=30)
            return run.returncode == 0 and run.stdout.strip() == b"SHADOW_INSTALLATION=pass"

        def resign():
            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", app], check=True, capture_output=True)

        checks["relocated_signature_inventory"] = verify()
        code = "import sys,pykeepass,vault_worker.ipc; assert sys.version_info[:3] == (3,12,13); assert pykeepass.__version__ == '4.2.0'; print('WORKER_IMPORT=pass')"
        imported = subprocess.run([resources / "python/bin/python3", "-I", "-B", "-c", code], cwd=directory, env=environment, capture_output=True, timeout=15)
        checks["relocated_python"] = imported.returncode == 0 and imported.stdout.strip() == b"WORKER_IMPORT=pass"
        for label, name in {"worker": "python/lib/python3.12/site-packages/vault_worker/ipc.py", "agent_image": "agent/disk", "browser_image": "browser/initrd-runtime", "adapter": "adapters/synthetic.json"}.items():
            path = resources / name
            original = path.read_bytes()
            path.write_bytes(original + b"tamper")
            checks[label + "_signature_rejected"] = not verify()
            resign()
            checks[label + "_inventory_rejected_after_resign"] = not verify()
            path.write_bytes(original)
            resign()
        injected = resources / "python/lib/python3.12/site-packages/sitecustomize.py"
        injected.write_text("raise RuntimeError('must never load')\n")
        resign()
        checks["added_python_file_rejected"] = not verify()
        injected.unlink()
        manifest = resources / "installation.json"
        original = manifest.read_bytes()
        for key, value in (("macos", "0.0.0"), ("architecture", "x86_64")):
            document = json.loads(original)
            document[key] = value
            manifest.write_text(json.dumps(document))
            resign()
            checks["unqualified_" + key + "_rejected"] = not verify()
        manifest.write_bytes(original)
        python = resources / "python/bin/python3"
        target = os.readlink(python)
        python.unlink()
        python.symlink_to("/usr/bin/python3")
        resign()
        checks["external_interpreter_rejected"] = not verify()
        python.unlink()
        python.symlink_to(target)
        resign()
        checks["restored_bundle_valid"] = verify()
        checks["no_runtime_bytecode_written"] = not any(resources.rglob("*.pyc"))
    inventory = arguments.app / "Contents/Resources/installation.json"
    report = {"time_utc": datetime.now(timezone.utc).isoformat(), "inventory_sha256": hashlib.sha256(inventory.read_bytes()).hexdigest(), "checks": checks, "passed": all(checks.values())}
    arguments.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
