"""Independent deadlines: an event-loop stall cannot preserve browser authority."""
from collections.abc import Callable
import threading
import time

from .errors import BrowserFailure, Code


def boot_time() -> float:
    if hasattr(time, "CLOCK_BOOTTIME"):
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    return time.monotonic()


class WorkerLease:
    def __init__(self, *, clock: Callable[[], float] = boot_time):
        self._clock = clock
        self._lock = threading.Lock()
        self._sequence = 0
        self._deadline = 0.0
        self._revoked = False

    def _check(self):
        if self._revoked or self._sequence == 0 or self._clock() >= self._deadline:
            self._revoked = True
            raise BrowserFailure(Code.LEASE_EXPIRED)

    def renew(self, *, sequence: int, ttl_ms: int):
        with self._lock:
            if type(sequence) is not int or sequence <= self._sequence or type(ttl_ms) is not int or not 1 <= ttl_ms <= 10000:
                raise BrowserFailure(Code.INVALID_LEASE)
            if self._revoked or self._sequence:
                self._check()
            self._sequence = sequence
            self._deadline = self._clock() + ttl_ms / 1000

    def check(self):
        with self._lock:
            self._check()

    def revoke(self):
        with self._lock:
            self._revoked = True


class Watchdog:
    """Start only after the initial lease; terminate must kill the worker group."""
    def __init__(self, lease: WorkerLease, terminate: Callable[[], None]):
        self._lease = lease
        self._terminate = terminate
        self._stopped = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="browser-watchdog")

    def start(self):
        self._lease.check()
        self._thread.start()

    def _run(self):
        while not self._stopped.wait(0.1):
            try:
                self._lease.check()
            except BrowserFailure:
                self._terminate()
                return

    def stop(self):
        self._stopped.set()
        self._thread.join(timeout=1)
