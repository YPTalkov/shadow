from pathlib import Path
import json


ROOT = Path(__file__).resolve().parents[2]


def test_public_and_private_protocols_have_explicit_major_versions():
    for name in ("agent-api-v1.schema.json", "internal-ipc-v1.schema.json"):
        schema = json.loads((ROOT / "contracts" / name).read_text())
        assert schema["$id"].endswith("/v1")
        assert schema["properties"]["protocol_major"]["const"] == 1
        assert schema["additionalProperties"] is False


def test_guest_packages_have_no_vault_dependency():
    for package in ("agent_tools", "guest_transport"):
        for path in (ROOT / package).rglob("*.py"):
            source = path.read_text()
            assert "from vault_worker" not in source
            assert "import vault_worker" not in source
            assert "import pykeepass" not in source
