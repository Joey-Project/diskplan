---
id: 20260828-7ac314
title: Descriptor-Bound Optional Artifacts
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/runtime-safe-artifacts
pr:
supersedes: []
superseded_by:
---

# Descriptor-Bound Optional Artifacts

## Summary

- Add an optional safe writer for canonical evidence, proposed-plan, decision, history, and
  execution-record JSON artifacts.
- Add a concrete bounded `ExecutionAuditSink` whose persistence failures remain nonfatal and are
  reported after the shell/TUI event stream.

## Current State

- Disabled persistence performs no policy installation, directory creation, or file write.
- Enabled admission is module-internal until the authoritative engine composition can derive a
  complete active scan/provider root set from the immutable-plan capture. It traverses the
  destination with no-follow descriptor-relative operations, rejects every symlink and
  File Provider/dataless uncertainty, and creates one exclusive owner-private task directory.
- Sticky or other group/world-writable ancestors fail closed in v1. Stable extended deny ACLs are
  retained in the access-policy seal; allow ACLs are rejected.
- Object identity is protected by device, inode, generation, and type across the held descriptor
  and its parent slot. Content stability is protected by two bounded held-descriptor reads that
  must agree in size, bytes, and SHA-256 while identity and access seals remain exact.
  Access policy is protected separately by owner, group, mode, mutation-authorization flags, and
  ACL digest. Timestamp, presentation/archive flags, and unrelated child-entry churn are
  deliberately not compared.
- Writes use an exclusive owner-private temporary file, optional durability sync, exact readback,
  final-chain revalidation, and atomic `RENAME_EXCL` publication in the held task directory.
  Existing final names are never overwritten. A failed write retains its exclusive temporary
  object instead of risking a check-then-unlink replacement race.
- Recovery locators bind parent and leaf identities, raw leaf, size, and digest, and explicitly
  require revalidation before use. A pathname is only a point-in-time hint after the final slot
  still names the bound object.
- History records carry independent `first_seen`, `last_seen`, `last_seen_open`, and
  `last_seen_process_reference` observations. Spill remains capability-off because no
  descriptor-bound stable SQLite VFS exists.
- The audit sink is bound to one expected execution epoch, and the coordinator supplies that epoch
  on every audit record. Its exact full-document budget includes metadata, envelope, events, and
  separators; cumulative iterative depth/node/collection limits run before recursive canonical
  encoding. After the first optional sink failure in an apply epoch, the coordinator disables
  further persistence attempts while keeping shell/TUI delivery and the first typed failure intact.
- File Provider identifier absence is not treated as affirmative local-origin evidence. Production
  admission fails closed until the system probe can supply positive non-materializing local proof.
  Held-descriptor readback and final locator verification preserve distinct unreadable, failed,
  identity, content, and access-policy outcomes. Owner-private admission requires the effective UID
  and exact type-specific permissions: `0700` for directories and `0600` for regular files.

## Task List

- [x] Add canonical JSON values and fixed artifact document kinds.
- [x] Add descriptor-bound admission, exclusion-root checks, no-clobber publication, and typed
  warning/locator outcomes.
- [x] Add the bounded canonical execution audit sink and preserve nonfatal apply semantics.
- [x] Add direct fixtures for disabled mode, symlink/provider/dataless rejection, exclusion roots,
  ancestor and leaf replacement, access-policy drift, collisions, storage failures, distinct
  revalidation outcomes, history, and audit publication.
- [x] Address static-review hardening findings: close the public exclusion bypass, gate each path
  access, require exact final bytes and access policy, eliminate unsafe cleanup, complete the
  durability chain, narrow authorization flags, freeze audit publication, and reject duplicate
  history IDs.
- [x] Address second-review findings: use double-read content stability, include Data Vault,
  restricted-write, and no-unlink authorization flags, bind one audit sink per epoch without
  discarding the owner transcript, and account for the complete canonical audit document budget.
- [x] Address third-review findings: bind every audit event to its producer epoch, accumulate final
  document structural limits before every append, and expose only throwing public canonical
  encoders so structural rejection cannot trap.
- [x] Complete the fourth narrow static review with no remaining high-confidence findings.
- [x] Address final-review findings for File Provider absence, epoch-scoped audit failure latching,
  typed readback/locator outcomes, and type-specific owner-private permissions; complete the exact
  follow-up static review with no remaining findings.
- [x] Run formatting, parser validation, journal validation, and diff whitespace checks.
- [x] Run the real target build, focused artifact/audit tests, complete execution suite, and one
  serial full Swift gate in the assigned dynamic slot.
- [ ] Prepare the signed landing commit after dynamic validation and final review.

## Handoff

- Phase: implementation, exact static rereview, and refreshed local dynamic validation complete.
- Next step: prepare the signed landing commit when the parent workstream requests it.
- Blocker: none in this slice.

## Evidence

- Accepted contract: `docs/design/accepted-plan.md`, section 17.
- Apply sink contract: `docs/design/best-effort-apply.md`, “Event and audit sinks”.
- `swift-format lint --strict` passed for all changed Swift files.
- `swiftc -frontend -parse` passed for all changed Swift files.
- `git diff --check` passed.
- The fourth narrow read-only static review reported no remaining high-confidence findings.
- The final exact read-only rereview reported no findings after typed locator-stage propagation and
  its directed unreadable/failed/identity/content/access-policy tests were added.
- Apple Swift 6.3.3 built the `DiskplanExecution` target successfully on arm64 macOS 26.
- The final hardening contract gate passed 5/5 for File Provider absence, audit-failure latching,
  typed temporary and locator readback, and type-specific owner-private modes.
- Focused artifact/audit gate passed 37/37, including real full-durability directory fsync,
  last-moment `RENAME_EXCL` collision, live no-materialization policy rejection, same-inode
  double-read mutation, ENOSPC/EROFS/EACCES, epoch, cumulative-budget, and throwing-encoder cases.
- Complete `DiskplanExecutionTests` passed 97/97.
- One refreshed `swift test --no-parallel -q` full gate passed 375/375.
