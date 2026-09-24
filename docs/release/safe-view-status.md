# Safe view qualification

The synthetic adapter supports a permitted list, link navigation to its detail,
designated field extraction and a packaged route back to the list. It returns
bounded fields and opaque document-bound element references. Native validation
uses the same packaged manifest as the browser worker, and all three agent
transports use the same result schema.

Real-VM evidence:

- Native encrypted-vault login → observe list → opaque link → extract detail
  status → return to list → close. Exactly one login submission across a retry.
- Eighteen real Chromium view cases: permitted content; plain, URL, base64 and
  HTML credential echoes; cookie echo; hidden/image content; password input;
  iframe; settings route; token-bearing link; popup; replaced link; changed href;
  navigation generation; history-only route change; route and root replacement
  during output preparation.
- The history-only case failed before the fix. Views now retain a native-world
  snapshot and recheck URL, root, row/field identities, field values and links
  before output or navigation. Old references do not follow replacement nodes.
- Ten prior atomic-auth scenarios, real HTTPS login and forced-crash dump
  suppression also pass with the new worker code.

Commands: `uv run --frozen python scripts/run-browser-probe.py --session` and the
same command without `--session`, after building/signing the probe and constructing
the `qualification` and `probe` image profiles. Exact hashes are in the adjacent
`safe-view-*-results.json` records.

Additional verification: 61 Python browser/protocol tests; four native
session/public-API/view tests; Python compilation; Swift build; both schema
generation checks. No Python lint or static type checker is configured.

Supported actions are explicit. Arbitrary URLs, selectors, script execution,
screenshots, downloads, raw DOM, headers, cookies and storage are absent from the
agent result surface. Unknown routes or views close the session. Automated
challenge completion and private owner interaction are not qualified yet.

Known-value suppression is defense in depth. A malicious destination can encode
or transform information in ways that no text filter can generally recognize.
These results do not claim that arbitrary websites or arbitrary page text are safe.
