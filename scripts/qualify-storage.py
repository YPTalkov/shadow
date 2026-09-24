"""Synthetic storage, leakage and performance rehearsal with bundled Python."""
from datetime import datetime, timezone
import base64
import csv
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

from vault_worker.catalog import Catalog, CatalogItem
from vault_worker.csv_import import CSVMapping, SelectedCSV
from vault_worker.store import MemoryAnchor, VaultStore


def main():
    output = Path(sys.argv[1])
    checks = {}
    timings = {}
    password = "synthetic-package-master"
    canaries = [password, "synthetic-package-password", "synthetic-package-notes", "JBSWY3DPEHPK3PXP", "synthetic-package-token", "synthetic-package-recovery"]
    with tempfile.TemporaryDirectory(prefix="shadow-storage-") as temporary:
        root = Path(temporary)
        store = VaultStore(root / "vault", MemoryAnchor())
        start = time.perf_counter()
        store.create(password)
        timings["create_seconds"] = time.perf_counter() - start
        source = root / "fixture.csv"
        with source.open("w") as file:
            writer = csv.writer(file)
            writer.writerow(["Title", "URL", "Username", "Password", "Notes", "TOTP"])
            writer.writerows([f"Fixture {index}", "https://app.shadow.test", "synthetic-user", canaries[1], canaries[2], canaries[3]] for index in range(5000))
        start = time.perf_counter()
        with SelectedCSV(source, CSVMapping("Title", "URL", "Username", "Password", notes="Notes", totp="TOTP")) as selected:
            preview = selected.preview()
            receipt = selected.commit(store, password, operation_id="synthetic-package-import")
        timings["import_5000_seconds"] = time.perf_counter() - start
        source.unlink()
        checks["import_5000"] = receipt["accepted"] == 5000 and preview.rejected == 0
        start = time.perf_counter()
        vault = store.open(password)
        timings["unlock_seconds"] = time.perf_counter() - start
        def reflect(vault):
            entries = vault.entries
            entries[0].set_custom_property("api_token", canaries[4], protect=True)
            entries[0].set_custom_property("recovery_codes", canaries[5], protect=True)
            for index, canary in enumerate(canaries):
                entries[index].title = "Reflected " + canary
        store.commit(password, reflect)
        vault = store.open(password)
        catalog = Catalog.from_vault(vault)
        result = catalog.search("", approved_ids={str(e.uuid) for e in vault.entries}, ref_factory=lambda _: "a" * 64)
        projected = json.dumps(result)
        checks["all_secret_classes_withheld"] = sum(item["title"] == "[withheld]" for item in result["items"]) == 6 and all(value not in projected and base64.b64encode(value.encode()).decode() not in projected for value in canaries)
        # Encrypted files are independently readable, using stdin for the key.
        run = subprocess.run(["/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli", "ls", "-q", str(root / "vault/vault.kdbx"), "Imports"], input=(password + "\n").encode(), capture_output=True, timeout=30)
        checks["keepassxc_independent_read"] = run.returncode == 0 and b"Fixture 4999" in run.stdout
        checks["persistent_canaries_absent"] = True
        for path in root.rglob("*"):
            if path.is_file():
                contents = path.read_bytes()
                checks["persistent_canaries_absent"] &= all(canary.encode() not in contents for canary in canaries)
    entries = [CatalogItem(str(index), f"Fixture {index:05}", "synthetic-user", ("https://app.shadow.test",), "") for index in range(10_000)]
    catalog = Catalog(entries)
    approved = {entry.id for entry in entries}
    samples = []
    for index in range(100):
        start = time.perf_counter()
        catalog.search(str(index), approved_ids=approved, ref_factory=lambda _: "a" * 64)
        samples.append((time.perf_counter() - start) * 1000)
    timings["catalog_10000_p95_ms"] = statistics.quantiles(samples, n=20)[18]
    checks["import_budget"] = timings["import_5000_seconds"] < 30
    checks["search_budget"] = timings["catalog_10000_p95_ms"] < 300
    report = {"time_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(), "macos": platform.mac_ver()[0],
              "hardware": subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.model"]).decode().strip(), "timings": timings, "checks": checks, "passed": all(checks.values())}
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
