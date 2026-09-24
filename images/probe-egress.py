import socket
import ssl
from guest_transport.model_bridge import send, receive

denied = []
for destination in ("127.0.0.1", "169.254.169.254", "example.net", "example.com@other.com"):
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as channel:
        channel.settimeout(3)
        channel.connect((socket.VMADDR_CID_HOST, 4053))
        send(channel, {"host": destination, "port": 443})
        try:
            denied.append(receive(channel) != {"kind": "connected"})
        except (OSError, ValueError):
            denied.append(True)
print("EGRESS_DESTINATIONS=" + ("denied" if all(denied) else "fail"))
try:
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as channel:
        channel.settimeout(10)
        channel.connect((socket.VMADDR_CID_HOST, 4053))
        send(channel, {"host": "example.com", "port": 443})
        if receive(channel) != {"kind": "connected"}:
            raise ValueError("not_connected")
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        with context.wrap_socket(channel, server_hostname="example.com") as tls:
            tls.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            data = tls.recv(4096)
            passed = data.startswith(b"HTTP/1.1 200 ")
    print("HTTPS_EGRESS=" + ("pass" if passed else "fail"))
except (OSError, ValueError):
    print("HTTPS_EGRESS=fail")
