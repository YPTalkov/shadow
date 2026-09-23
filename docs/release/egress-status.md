# HTTPS egress component evidence

The native gateway accepts exact canonical ASCII hostnames on port 443, bound to a host-created VM instance, boot, session and expiring lease. It resolves on the host, rejects an entire DNS answer containing any prohibited address, and connects directly to a validated numeric address. It never resolves that name again during connection establishment. Each new connection resolves and validates again.

The address checks conservatively exclude local, private, link-local, shared, multicast, documentation, translation and reserved ranges, based on the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) registries. Invalid hostname syntax, userinfo, IP literals, encoded IPv4 forms, trailing-dot aliases, and non-443 ports fail closed.

Forwarding uses bounded buffers, a 16 MiB total transfer limit, nonblocking I/O, and authorization checks between polling and forwarding. Idle connections recheck leases every 100 ms. Expiry/revocation closes the host tunnel; VM channel revocation also shuts down its duplicated descriptors. Shared deadline handling uses macOS continuous monotonic time, which advances during sleep. This implementation choice is not a completed real sleep/resume qualification test.

The native suite exercises special addresses, mixed public/private DNS answers, wrong boot/session/destination, expiry, bidirectional forwarding, no forwarding after revocation, and expiry without incoming traffic. The initial target test failed before implementation. A test read initially waited for 1024 bytes from a short socket message; bounding the read to the message length fixed the test harness.

The actual no-NIC browser VM rejected private addresses and an unapproved public domain, then completed a certificate-verified HTTP/1.1 HEAD request to example.com over its role-bound host socket. The response body and TLS session state were not captured. To repeat this network test, set SHADOW_LIVE_EGRESS=1 when running scripts/run-vm-probe.py. Results and exact artifact hashes are in vm-probe-results.json.

U2/U9 remain open. The gateway carries opaque TLS; it does not inspect HTTP authority inside an established tunnel. Qualification still requires the browser's origin checks, disabled HTTP/2 coalescing and QUIC, redirect/WebSocket/popup tests, controlled DNS rebinding, independent crash/watchdog tests, connection budgeting in the supervisor, and production packaging. No credential has been sent through it.
