import socket

import pytest

from browser_worker.egress import ConnectProxy, authority_from_header
from browser_worker.errors import BrowserFailure
from browser_worker.watchdog import WorkerLease


@pytest.mark.parametrize("header", [
    b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"CONNECT example.com:80 HTTP/1.1\r\n\r\n",
    b"CONNECT user:secret@example.com:443 HTTP/1.1\r\n\r\n",
    b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nHost: other.com:443\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nAuthorization: synthetic-canary\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nHost: example.com:443\r\n\r\n",
])
def test_connect_rejects_routing_and_header_confusion(header):
    with pytest.raises(BrowserFailure, match="invalid_request"):
        authority_from_header(header)


def test_proxy_forwards_only_after_private_approval_and_stops_on_revoke():
    lease = WorkerLease()
    lease.renew(sequence=1, ttl_ms=10000)
    host, bridge = socket.socketpair()
    opened = []

    def connect(hostname):
        opened.append(hostname)
        return bridge

    proxy = ConnectProxy(lease, connect=connect)
    proxy.start()
    try:
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=2) as browser:
            browser.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            assert browser.recv(1024) == b"HTTP/1.1 200 Connection Established\r\n\r\n"
            browser.sendall(b"synthetic-tls-data")
            host.settimeout(2)
            assert host.recv(1024) == b"synthetic-tls-data"
            host.sendall(b"synthetic-reply")
            assert browser.recv(1024) == b"synthetic-reply"
            lease.revoke()
            assert browser.recv(1024) == b""
            assert opened == ["example.com"]
    finally:
        proxy.close()
        host.close()
