"""Build the signed synthetic producer bundle for local UI qualification only."""

import json
import plistlib
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
application = root / ".build/fixtures/SyntheticSource.app"
contents = application / "Contents"
(contents / "MacOS").mkdir(parents=True, exist_ok=True)
(contents / "Resources").mkdir(exist_ok=True)
shutil.copy2(root / ".build/debug/source-fixture", contents / "MacOS/source-fixture")
(contents / "Info.plist").write_bytes(plistlib.dumps({
    "CFBundleIdentifier": "com.yptalkov.shadow.synthetic-source",
    "CFBundleExecutable": "source-fixture", "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
}))
(contents / "Resources/shadow-source.json").write_text(json.dumps({
    "contract_major": 1, "capabilities": {
        "stable_items": True, "stable_groups": True, "complete_scopes": ["account", "group"],
        "deletion_evidence": ["item_tombstone"], "distinguishes_access_loss": True,
        "totp": False, "collection_mode": "unattended", "version": 1,
    },
}))
subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(application)], check=True)
print(application)
