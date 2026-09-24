"""No browser observation is available during authentication or owner action."""
from dataclasses import dataclass
from enum import StrEnum

from .errors import BrowserFailure, Code
from .watchdog import WorkerLease


class Phase(StrEnum):
    NEW = "new"
    NAVIGATING = "navigating"
    RESOLVING = "resolving"
    AUTHENTICATING = "authenticating"
    OWNER = "owner"
    VERIFYING = "verifying"
    READY = "ready"
    CLOSED = "closed"


@dataclass(frozen=True)
class Checkpoint:
    epoch: int
    document: str


class OutputGate:
    def __init__(self, lease: WorkerLease):
        self.lease = lease
        self.phase = Phase.NEW
        self._epoch = 0
        self._document = None

    def transition(self, phase: Phase):
        if self.phase == Phase.CLOSED:
            raise BrowserFailure(Code.SESSION_CLOSED)
        if phase in {Phase.READY, Phase.CLOSED}:
            raise BrowserFailure(Code.INVALID_REQUEST)
        self.lease.check()
        self._epoch += 1
        self._document = None
        self.phase = phase

    def ready(self, document: str):
        self.lease.check()
        if self.phase != Phase.VERIFYING or not document:
            raise BrowserFailure(Code.OUTPUT_CLOSED)
        self._epoch += 1
        self._document = document
        self.phase = Phase.READY

    def output_checkpoint(self, document: str) -> Checkpoint:
        self.lease.check()
        if self.phase != Phase.READY:
            raise BrowserFailure(Code.OUTPUT_CLOSED)
        if document != self._document:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        return Checkpoint(self._epoch, document)

    def validate_output(self, checkpoint: Checkpoint, document: str):
        current = self.output_checkpoint(document)
        if current != checkpoint:
            raise BrowserFailure(Code.OUTPUT_CLOSED)

    def close(self):
        # Seal observations immediately. The controller still needs its live
        # private channel to send one fixed terminal code before teardown.
        self.phase = Phase.CLOSED
        self._epoch += 1
        self._document = None
