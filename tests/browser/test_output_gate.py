import pytest

from browser_worker.output_gate import OutputGate, Phase, BrowserFailure
from browser_worker.watchdog import WorkerLease


def test_output_requires_verified_document_and_live_lease():
    now = [10.0]
    lease = WorkerLease(clock=lambda: now[0])
    gate = OutputGate(lease)
    lease.renew(sequence=1, ttl_ms=2000)
    with pytest.raises(BrowserFailure, match="output_closed"):
        gate.output_checkpoint("doc-a")
    gate.transition(Phase.NAVIGATING)
    gate.transition(Phase.RESOLVING)
    gate.transition(Phase.AUTHENTICATING)
    gate.transition(Phase.VERIFYING)
    gate.ready("doc-a")
    checkpoint = gate.output_checkpoint("doc-a")
    gate.validate_output(checkpoint, "doc-a")
    with pytest.raises(BrowserFailure, match="document_changed"):
        gate.validate_output(checkpoint, "doc-b")
    now[0] = 12.0
    with pytest.raises(BrowserFailure, match="lease_expired"):
        gate.validate_output(checkpoint, "doc-a")


@pytest.mark.parametrize("phase", [Phase.NAVIGATING, Phase.RESOLVING, Phase.AUTHENTICATING, Phase.OWNER, Phase.VERIFYING])
def test_authentication_and_owner_challenges_never_open_output(phase):
    lease = WorkerLease()
    lease.renew(sequence=1, ttl_ms=10000)
    gate = OutputGate(lease)
    gate.transition(phase)
    with pytest.raises(BrowserFailure, match="output_closed"):
        gate.output_checkpoint("doc")


def test_revocation_and_document_change_invalidate_captured_output():
    lease = WorkerLease()
    lease.renew(sequence=1, ttl_ms=10000)
    gate = OutputGate(lease)
    gate.transition(Phase.VERIFYING)
    gate.ready("doc")
    checkpoint = gate.output_checkpoint("doc")
    gate.transition(Phase.NAVIGATING)
    gate.transition(Phase.VERIFYING)
    gate.ready("doc")
    with pytest.raises(BrowserFailure, match="output_closed"):
        gate.validate_output(checkpoint, "doc")
    gate.close()
    with pytest.raises(BrowserFailure, match="session_closed"):
        gate.transition(Phase.VERIFYING)


def test_lease_cannot_be_replayed_extended_past_bounds_or_revived():
    now = [100.0]
    lease = WorkerLease(clock=lambda: now[0])
    lease.renew(sequence=1, ttl_ms=10000)
    for sequence, duration in [(1, 10000), (2, 10001), (True, 10000), (2, True)]:
        with pytest.raises(BrowserFailure, match="invalid_lease"):
            lease.renew(sequence=sequence, ttl_ms=duration)
    now[0] = 111.0
    with pytest.raises(BrowserFailure, match="lease_expired"):
        lease.renew(sequence=2, ttl_ms=10000)
    now[0] = 100.0
    with pytest.raises(BrowserFailure, match="lease_expired"):
        lease.check()


def test_explicit_revocation_cannot_be_renewed():
    lease = WorkerLease()
    lease.renew(sequence=1, ttl_ms=10000)
    lease.revoke()
    with pytest.raises(BrowserFailure, match="lease_expired"):
        lease.renew(sequence=2, ttl_ms=10000)


def test_closed_output_can_report_fixed_failure_before_control_teardown():
    lease = WorkerLease()
    lease.renew(sequence=1, ttl_ms=10000)
    gate = OutputGate(lease)
    gate.close()
    lease.check()
    with pytest.raises(BrowserFailure, match="output_closed"):
        gate.output_checkpoint("doc")
    with pytest.raises(BrowserFailure, match="session_closed"):
        gate.transition(Phase.VERIFYING)
