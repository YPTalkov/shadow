# Threat model

The agent and website page content are untrusted. The owner, native control panel, host supervisor, host-private KDBX worker, and protected browser worker are trusted for their narrow roles. A source connector is trusted with the source plaintext but cannot grant agent authority. An attacker with host administrator or kernel control is outside the product claim.

The agent may run arbitrary code **inside its isolated VM**. The supported design gives that VM no NIC, host-home mount, browser automation channel, or vault-worker channel. It receives only the public broker protocol and a restricted model relay. Installing these tools into an unrestricted macOS user session does not enforce the secrecy claim.

Protected values include passwords, vault keys, TOTP seeds and codes, recovery codes, cookies, bearer tokens, and authenticated browser state. Catalog metadata is intentionally visible after separate owner consent. Authenticated work must remain in the protected browser; ordinary crawler/browser tools cannot inherit its session.

The private source protocol uses length-prefixed UTF-8 JSON over a supervisor-created inherited channel, with a 1 MiB frame cap and a 64 MiB transaction cap. Version negotiation happens before payload handling. Secrets never appear in diagnostic responses. This encoding does not make an unauthenticated socket safe; process identity and channel custody are required.

No real data may be imported until the packaged runtime, VM/network boundary, canary leakage suite, KDBX editor round trip, recovery drill, and independent security review pass. Synthetic-only development is the current status.
