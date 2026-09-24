# Protected connector refresh jobs

The native agent API now routes `connector.request_refresh`, polling, cancellation and owner-action resume to the enrolled connector runtime. Catalog discovery supplies a nullable `source_ref` only for approved entries belonging to an enabled connector. This extends the unreleased v1 result schema; native, CLI, MCP and PTC schema copies were regenerated together.

A source reference reuses the entry's opaque catalog reference and resolves through the same caller/boot/grant/revision checks. It cannot choose an executable, source UUID, path, digest key or IPC channel. The source registry and running-code signature remain native authority. Entry changes during a refresh invalidate affected catalog/use grants and protected sessions before encrypted publication; they do not undo the accepted native import itself.

Each job has a durable, caller-bound receipt. The supervisor records potential commit before passing the connector's commit frame to the vault worker. Cancellation before that point is `cancelled`; interruption afterward is `outcome_unknown`. Retrying the original request returns its receipt and never repeats the import. Owner-action resume requires the exact transient checkpoint and a still-valid source reference; it is unavailable after any attempted commit.

Limits: one active job, five-minute continuous deadline, 128 recorded jobs per service lifetime, one new refresh per source per minute, and three owner-action resumes. Lock closes jobs synchronously. A 250 ms monitor also closes jobs whose VM caller disappears. Only fixed states and opaque references cross the agent boundary.

## Evidence

- 10 native test functions pass: source disclosure, source-identity exclusion, exact retry, checkpoint binding, cancellation before/after commit, disabled source, expiry, catalog reset, shared API policy, journal recovery and native source retention.
- 60 Python protocol/connector tests pass. All three transport frontends consume the regenerated response schema.
- The native UI probe enrolls the signed synthetic connector, imports its first generation, obtains a catalog-scoped source reference through the agent API, completes generation two through a connector job, and retries the same request without another import. Four encrypted catalog entries remain; no secret or connector receipt appears in the agent result. The probe then continues through removal, editor handoff and recovery.

```sh
bash scripts/test-swift.sh --filter 'connectorJob|connectorSource|connectorOwner|connectorCancellation|connectorDisabled|nativeSource|publicAPI|operationJournal'
uv run --frozen pytest tests/protocol tests/connector -q
.build/arm64-apple-macosx/debug/owner-ui-probe
```

Remaining: combined agent/browser VM tasks, source-update interruption of a live browser, packaged fault qualification and independent review. Rebuild the agent image after contract generation so its embedded result schema matches the native host.

## Scoped cleanup

The CE reuse, quality and efficiency rubrics were applied serially to this slice. Connector frames are parsed once before checking terminal status and the commit boundary. Existing opaque reference checks, `OperationJournal` transitions, native source runtime and API result projection are reused. The connector service survives temporary catalog resets; explicit owner shutdown disposes it. Native manual refresh still resets all grants, while an accepted agent refresh preserves the VM and invalidates only the affected accounts through the existing worker callbacks. Those different publication rules remain explicit.

This is implementation evidence and scoped cleanup, not a final security review.
