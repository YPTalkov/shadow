"""Root PID 1 owns a deadline independent of the browser worker's event loop."""
import ctypes
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import time

from .control import Frames, encode, renew
from .watchdog import WorkerLease

ENVIRONMENT = {
    "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/home/pwuser",
    "PYTHONPATH": "/opt/shadow:/opt/shadow-deps", "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright",
    "PYTHONDONTWRITEBYTECODE": "1", "XDG_CONFIG_HOME": "/opt/shadow/config",
    "XDG_CACHE_HOME": "/home/pwuser/.cache", "XDG_DATA_HOME": "/home/pwuser/.local/share", "DISPLAY": ":0",
}


def relay(host, child, worker_pid):
    """Bounded relay with a root-owned lease, even if the worker is SIGSTOPed."""
    lease = WorkerLease()
    started = time.monotonic()
    leased = False
    channels = {host: (child, Frames()), child: (host, Frames())}
    for channel in channels:
        channel.settimeout(0.1)
    try:
        while True:
            if leased:
                lease.check()
            elif time.monotonic() - started > 10:
                return
            for _, frames in channels.values():
                frames.check_deadline()
            ready, _, _ = select.select(list(channels), [], [], 0.05)
            for channel in ready:
                data = channel.recv(65536)
                if not data:
                    return
                destination, frames = channels[channel]
                for message in frames.feed(data):
                    if channel is host and message.get("kind") == "lease":
                        renew(lease, message)
                        leased = True
                    else:
                        lease.check()
                    destination.sendall(encode(message))
    except BaseException:
        pass  # Never print messages, raw exceptions or tracebacks from this path.
    finally:
        lease.revoke()
        for channel in channels:
            try:
                channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        try:
            os.killpg(worker_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def display():
    for command in (["/usr/lib/systemd/systemd-udevd", "--daemon", "--resolve-names=never"],
                    ["/usr/bin/udevadm", "trigger", "--action=add"],
                    ["/usr/bin/udevadm", "settle", "--timeout=5"]):
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    process = subprocess.Popen(["/usr/lib/xorg/Xorg", ":0", "-config", "/opt/shadow/xorg.conf",
                                "-logfile", "/dev/null", "-nolisten", "tcp", "-noreset", "-ac", "vt1"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if Path("/tmp/.X11-unix/X0").exists():
            return process
        if process.poll() is not None:
            break
        time.sleep(0.1)
    raise RuntimeError("display_unavailable")


def main():
    os.umask(0o077)
    try:
        display()
        host = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        host.settimeout(5)
        host.connect((socket.VMADDR_CID_HOST, 4052))
        host.sendall(encode({"kind": "supervisor", "protocol_major": 1}))
        parent, child = socket.socketpair()
        worker = subprocess.Popen(["/usr/bin/python3", "-m", "browser_worker.controller"], stdin=child,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env=ENVIRONMENT, user=1001, group=1001, extra_groups=[], start_new_session=True)
        child.close()
        relay(host, parent, worker.pid)
        worker.wait(timeout=2)
    except BaseException:
        pass
    finally:
        # PID 1 stops the entire guest, including a descendant that has changed
        # its process group. No writable browser state survives VM destruction.
        ctypes.CDLL(None).reboot(0x4321FEDC)


if __name__ == "__main__":
    main()
