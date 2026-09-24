"""Guest CLI/PTC smoke test through the actual instance-bound native API."""
import io
import json

from agent_tools import cli
from agent_tools.protocol import AgentError
from agent_tools.ptc import Shadow

try:
    output = io.BytesIO()
    code = cli.main(["vault.status"], stdout=output)
    assert code == 0 and json.loads(output.getvalue())["result"]["state"] == "catalog_consent_required"
    assert Shadow().status()["state"] == "catalog_consent_required"
    try:
        Shadow().search()
        raise AssertionError
    except AgentError as error:
        assert error.code == "catalog_consent_required"
    print("GUEST_AGENT_API=pass")
except Exception:
    print("GUEST_AGENT_API=fail")
