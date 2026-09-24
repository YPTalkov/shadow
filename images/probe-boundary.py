import json
import os
import socket
import errno
from guest_transport.model_bridge import send, receive

role = "browser" if "shadow.role=browser" in open("/proc/cmdline").read() else "agent"
allowed = {4052, 4053} if role == "browser" else {4050, 4051}
channel_results = {}
for port in (4050, 4051, 4052, 4053, 80, 443, 22):
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        try:
            connection.connect((socket.VMADDR_CID_HOST, port))
            send(connection, {"probe": "role"})
            reply = receive(connection)
            channel_results[port] = port in allowed and reply == {"kind": "probe", "channel": port}
        except OSError:
            channel_results[port] = port not in allowed
egress_denied = []
for family, destination in [
    (socket.AF_INET, ("1.1.1.1", 443)),
    (socket.AF_INET, ("10.0.2.2", 443)),
    (socket.AF_INET, ("169.254.169.254", 80)),
    (socket.AF_INET, ("127.0.0.1", 4052)),
    (socket.AF_INET6, ("::1", 4052)),
    (socket.AF_INET6, ("fe80::1", 443)),
]:
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        try:
            with socket.socket(family, kind) as connection:
                connection.settimeout(0.2)
                if kind == socket.SOCK_DGRAM:
                    # Loopback is guest-owned; only external UDP destinations must fail.
                    if destination[0] in ("127.0.0.1", "::1"):
                        continue
                    connection.sendto(b"synthetic-egress-probe", destination)
                else:
                    connection.connect(destination)
                egress_denied.append(False)
        except OSError:
            egress_denied.append(True)
disk_readonly = False
disk = os.open("/dev/vda", os.O_WRONLY | os.O_SYNC)
try:
    os.write(disk, b"synthetic-write-probe".ljust(512, b"\0"))
    os.fsync(disk)
except OSError as error:
    disk_readonly = error.errno in (errno.EROFS, errno.EIO, errno.EPERM)
finally:
    os.close(disk)
print("VSOCK_ROLE_BOUNDARY=" + ("pass" if all(channel_results.values()) else "fail"))
print("DIRECT_EGRESS=" + ("denied" if all(egress_denied) else "reachable"))
print("BASE_DISK=" + ("readonly" if disk_readonly else "writable"))
print("PYTHON_RUNTIME=" + os.sys.version.split()[0])
