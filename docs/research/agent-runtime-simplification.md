# Agent runtime simplification receipt

Scope: the uncommitted native agent supervisor, guest runner/image, owner task controls, relay compatibility changes and their tests, following `9f29914`. The reviewed plan's settled isolation, custody and native-consent decisions were preserved. The three CE simplification rubrics were applied serially in the main thread under the workspace instructions.

## Reuse

- Agent tool connections now reuse `AgentAPI.serve` after the supervisor reads the initial frame. This preserves the existing revocation-driven output-channel invalidation and rate policy. An authorization callback checks the runtime lease before dispatch and output.
- Framing, VM device profiles, monotonic clocks, identity binding and Keychain authentication reuse the existing components.
- Browser and agent launch logic remains separate: browser control carries private credentials and leased egress; agent control carries owner tasks and untrusted text. Combining their state machines would obscure different authority rules.

## Quality

- Removed an unused image output constant and duplicate heartbeat counter state.
- Kept the model relay's protocol variant explicit. The Responses Lite header is a validated literal; it does not weaken routing or credential rules.
- Native task fields are grouped in a collapsible form. Incoming consent collapses it; Stop remains outside the collapsed form. Untrusted agent output uses verbatim text.
- Temporary diagnostic prints were removed. Synthetic probe failures carry fixed result labels.

## Efficiency and cleanup

- Rejected connections are closed through their owning channel registry, releasing the connection slot.
- Request, input, output, frame, connection and lifetime limits are bounded. Model I/O and framing run off the main actor; native revocation happens synchronously before asynchronous VM destruction.
- Image hashing remains synchronous during start, matching the current browser driver. Packaged startup and UI responsiveness still need the U13 measurements.

This is a scoped cleanup receipt, not the final CE code review or independent security review. New behavior was verified separately: 12 native test functions, 42 Python tests, the actual production-image Codex probe and native UI capture.
