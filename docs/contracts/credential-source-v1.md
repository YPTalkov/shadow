---
title: Credential Source Ingestion Contract v1
date: 2026-09-23
contract: credential-source/v1
---

# Credential Source Ingestion Contract v1

This is the private ingestion seam between the standalone vault and optional source connectors. It is not an agent tool. The [standalone plan](../plans/2026-09-23-2139-feat-standalone-agent-credential-vault-plan.md), especially R11–R13/R19 and KTD5/KTD7/KTD8, owns product authority and retention behavior. This document owns wire and reconciliation semantics. Normative terms below describe the implementation to build, not an existing service.

## Ownership and versioning

The standalone app owns this contract and its synthetic conformance suite. The Apple project implements a producer against it without changing the consumer's authority rules. Copy this document into the new standalone repository at U1 with provenance. The copy there becomes the implementation authority; record its commit/hash when integrating the connector. A breaking change needs a new major contract version and tests on both sides; no silent compatibility fallback.

## Trust and enrollment

The native owner UI enrolls a connector executable identity and assigns an opaque `source_instance_id`. That ID identifies one source/account enrollment, not an Apple email address. Reenrolling a different account creates a new namespace. Connector identity plus a host-created private channel authenticates the producer; an ID string in a message does not.

The supervisor launches an approved local connector and gives it an inherited framed channel. Use a bounded typed encoding shared with the consumer; pin the encoding in U1. Do not expose a TCP/HTTP listener, shell export command, agent-accessible socket, or generic “run this connector executable” tool. Production may later use an equivalent authenticated launch service only after matching security tests.

The connector is trusted to handle source plaintext; it receives no vault master key, existing vault secret dump, agent grant, or policy-writing capability. Disable inherited debug/trace environments and raw stderr capture. Its reporting interface returns fixed codes/counts only. Any connector requiring clipboard or plaintext export files needs a separately approved collection design; this contract does not authorize those mechanisms.

## Envelope and lifecycle

Every message includes major contract version, source instance, host-assigned channel epoch, producer sequence, message kind, and a random batch ID. Unknown fields that could affect interpretation fail validation. A maximum frame is 1 MiB, a string/secret field 64 KiB, a transaction 64 MiB uncompressed/50,000 items/10,000 groups. Stream large transactions through encrypted staging or bounded trusted memory; never plaintext disk spooling. Limit decompression/XML/JSON nesting independently.

Transactions follow `begin → zero or more group/item/coverage events → commit`, with `abort` available before commit. Begin names the previously acknowledged source generation, collection start time, and mode (`snapshot` or `delta`). Commit names collection end time, final sequence, and coverage summary. The host records observation/receipt time itself; source clocks are informational and cannot extend grants or freshness beyond host policy.

The consumer acknowledges success only after KDBX and ledger publication completes under KTD5. It returns an opaque receipt with batch ID, new generation, accepted/conflicted/retained counts, and fixed warning codes. It never echoes secret values or complete input records. Uncommitted batches have no absence/deletion effect; a disconnect discards them or leaves encrypted recoverable staging that is not visible to agents.

Repeated committed batch ID plus identical content returns the same receipt. Reusing a batch ID with changed content fails. Compare using a host-keyed digest of the envelope in private storage, not a public password hash. A generation mismatch returns `generation_conflict`; the producer must recollect/rebase through an explicit new batch. Out-of-order/duplicate frames are either recognized exact retries or rejected, never partially applied twice.

## Source capabilities

Enrollment reports and the owner can inspect:

- Stable item identity available or unavailable.
- Stable group identity available or unavailable.
- Full enumeration supported scopes, including whether permission loss can be distinguished.
- Explicit deletion evidence supported or unsupported.
- Credential types actually collectable: password, optional TOTP, and unsupported types.
- Metadata fields observable and whether group ownership/membership can be established.
- Collection mode: unattended, owner unlock required, or owner interaction required.

Capabilities constrain interpretation; they are not evidence that a particular batch is complete. Do not infer an Apple ID, hidden group members, unobservable password values, or passkeys from UI labels. If no stable source item ID exists, use a connector-private mapping only if ambiguity can be detected. Otherwise ingest as a new unlinked candidate and ask for owner reconciliation; never merge by title/URL/username. Absence-based deletion is disabled for identities/scopes that cannot be tracked reliably.

## Group and item records

Groups have a stable source-group ID when supported, optional parent-group ID, display name, last-observed relationship (`owner`, `member`, `unknown`), and observation state. Do not transmit other members' personal details unless a later contract requires them. The relationship is provenance, not authorization in the local app.

Items have a stable source-item ID when supported; source revision or explicit `revision_unknown`; display title; username; website URLs; source-group memberships; credential kind; and a restricted secret payload. A password item may include password, notes, and optional TOTP material. Other secret-bearing attributes are preserved only under an explicitly supported encrypted field definition; they are never passed through as catalog metadata. URLs are untrusted data, not grants or navigation instructions.

The consumer assigns the KDBX entry UUID and local revision. Source IDs are namespaced by source instance. One stable source item in several groups maps to one local entry with all memberships in encrypted provenance and a deterministic primary display group. Separate source IDs with matching content stay separate; the protocol does not deduplicate credentials by password equality.

Local structure starts under `Sources/<owner-chosen source label>/…` using source hierarchy where observable. CSV/native entries use separate local groups. Duplicate group display names remain distinguishable by identity. A rename updates the displayed path while preserving history; a move changes current membership without rewriting historical observations.

## Coverage and deletion evidence

Each transaction declares coverage for explicit stable group/account scopes: `complete`, `partial`, `unavailable`, or `access_lost`. It includes a machine-readable basis code and collection capability version. A complete group snapshot applies only to that group, not to the entire source. Missing coverage means unknown, not empty.

The consumer may infer source deletion from absence only when all of these hold:

1. The scope and previously observed items have stable identities.
2. The producer supports authoritative full enumeration for that scope.
3. The batch completed successfully and explicitly declares that scope complete.
4. There is no conflicting permission/error/partial marker in that scope.
5. The item is not positively observed elsewhere in the same covered source transaction.

If an item's membership in a group disappears but the item is still observed elsewhere, record a membership removal, not global item deletion. If the producer cannot determine whether the item moved to an inaccessible scope, mark presence `unknown` or `access_lost`, not confirmed global deletion. The owner-visible note must state the scope of the evidence.

An explicit deletion event names source item/group identity, source revision if known, observed deletion time, and a supported evidence code. `not_found_in_search`, pagination interruption, locked source, failed export, or a missing group label are not deletion evidence. Unsupported evidence is a rejected event or uncertainty state, never a guessed tombstone.

Confirmed removal creates an immutable removal event and the R11 retained annotation. Access loss creates a distinct restriction event and note. Group removal retains the group/provenance and marks affected memberships; it does not recursively erase KDBX entries. A failed/partial scan only updates coverage/freshness unless it carries a separately supported restriction event.

## Reconciliation and authority

For a known source ID with an unchanged local mirror, a new source revision updates supported mirrored fields transactionally and increments the local revision if credential/authority-relevant data changed. Keep encrypted history according to the managed profile. Merely observing an unchanged item refreshes observation time without manufacturing a new credential revision.

Owner-edited fields are tracked against the last accepted encrypted source baseline. An incoming incompatible change produces an encrypted conflict record and blocks affected use. The owner chooses keep local, accept incoming, or keep both as distinct local entries. No secret values are displayed in the app's conflict summary; inspection uses the KeePassXC handoff. Concurrent owner edits or stale file identity fail the batch instead of overwriting them.

Restrictions and agent grants follow KTD7, not producer instructions. A connector cannot mark an item “approved,” clear a removal event, extend freshness with a future timestamp, suppress a revocation, request permanent deletion, or make a local copy look upstream-current. Reappearance after removal updates presence only; fresh native approval remains necessary. Enrollment/uninstall never deletes entries.

If the vault is locked or in editor handoff, return `vault_unavailable` and do not accept plaintext data for indefinite queuing. The connector should collect again after availability returns. A source-side action already performed is not retried automatically by the consumer.

## Refresh and scheduling

The app may ask an enrolled connector to refresh with a nonsecret request ID and bounded scope. The response is `queued`, `running`, `needs_owner_action`, `not_configured`, `unsupported`, or a completed receipt. An agent can request this operation through the app but cannot approve source access or see its channel.

The connector owns its schedule and acquisition method. The owner enables periodic collection; no schedule is assumed merely because the connector exists. Failed or missed refreshes affect freshness under KTD7, never data retention. Connector authentication/Apple account changes require native reenrollment, not agent-provided credentials.

## Required conformance cases

The consumer and producer must pass a common synthetic suite for:

- Version/identity/channel mismatch, unknown fields, size/nesting limits, and malformed secret payloads without echo.
- Complete, partial, unavailable, and access-lost scope updates, including contradictory coverage declarations.
- Batch retry, changed-payload replay, stale generation, interrupted commit, disk full, and vault locked/editor-active states.
- Stable rename/move, duplicate names, absent stable IDs, ambiguous rematches, and one item with multiple memberships.
- Source deletion, group removal, permission loss, reappearance, source password update, and local-owner conflict.
- Retention across restart and backup restore; no policy elevation from connector-supplied fields.
- No secret in receipts, logs, status, metadata projections, diagnostic errors, or agent refresh responses.

Apple-specific live evidence belongs to the connector project. Passing this suite proves protocol behavior, not Apple's completeness, source identity stability, export support, or entitlement availability.
