import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

from browser_worker.control import Frames, encode
from browser_worker.errors import BrowserFailure
from browser_worker.supervisor import relay


def test_control_frames_are_bounded_unambiguous_and_incremental():
    frames = Frames()
    data = encode({"kind": "lease", "sequence": 1, "ttl_ms": 1000})
    assert frames.feed(data[:5]) == []
    assert frames.feed(data[5:]) == [{"kind": "lease", "sequence": 1, "ttl_ms": 1000}]
    for bad in [b'{"kind":"lease","kind":"login"}', b'{"value":NaN}', b'[]', b'{"a":"\\ud800"}']:
        with pytest.raises(BrowserFailure):
            Frames().feed(struct.pack("!I", len(bad)) + bad)
    with pytest.raises(BrowserFailure):
        Frames().feed(struct.pack("!I", 2 * 1024 * 1024 + 1))


def test_root_monitor_kills_stalled_worker_independently():
    host, root = socket.socketpair()
    child, monitor = socket.socketpair()
    worker = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    deadline = time.monotonic()
    host.sendall(encode({"kind": "lease", "sequence": 1, "ttl_ms": 150}))
    thread = threading.Thread(target=relay, args=(root, monitor, worker.pid))
    thread.start()
    try:
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert worker.wait(timeout=1) != 0
        assert time.monotonic() - deadline < 1
    finally:
        for channel in (host, root, child, monitor):
            channel.close()
        if worker.poll() is None:
            worker.kill()
            worker.wait()


def test_root_monitor_rejects_replayed_lease_and_closes_channels():
    host, root = socket.socketpair()
    child, monitor = socket.socketpair()
    worker = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    thread = threading.Thread(target=relay, args=(root, monitor, worker.pid))
    thread.start()
    try:
        lease = encode({"kind": "lease", "sequence": 1, "ttl_ms": 10000})
        host.sendall(lease)
        assert child.recv(len(lease)) == lease
        host.sendall(lease)
        thread.join(timeout=2)
        assert not thread.is_alive() and worker.wait(timeout=1) != 0
    finally:
        for channel in (host, root, child, monitor):
            channel.close()
        if worker.poll() is None:
            worker.kill()
            worker.wait()
