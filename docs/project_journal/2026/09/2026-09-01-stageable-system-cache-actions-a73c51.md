---
id: 20260901-a73c51
title: Stageable System Cache Actions
status: completed
created: 2026-09-01
updated: 2026-09-01
branch: wip/stageable-cache-actions
pr:
supersedes: []
superseded_by:
---

# Stageable System Cache Actions

## Summary

- Add the first production-safe executable classification: a direct child directory of the
  Foundation-discovered user cache root.
- Keep every other cache, build, temporary, versioned-artifact, Git, and provider candidate on the
  existing report-only route.
- Bind immutable rules, root discovery, root identity, effective UID, access policy, activity,
  provider, mount, and release-topology evidence before constructing a generic-remove action.

## Current State

- `ScanRootOrigin` distinguishes Engine-owned Foundation cache-root discovery from explicit client
  roots without adding a client-controlled IPC field. Matching raw paths, root IDs, or object
  identities cannot upgrade an explicit root.
- `RuntimeStageableActionAuthority` discovers the user cache root through Foundation, opens it with
  `O_NOFOLLOW`, binds the descriptor identity and effective UID, loads only canonical
  `DiskplanRules`, and contributes the effective rules digest to immutable plan provenance.
- The bounded authority accumulator retains arbitrary direct child directories only under the
  exact root ID whose package-private origin and raw path match the Foundation authority. A
  descriptor-identical `Library/Caches` alias under a home scan root is deduplicated before overlap
  analysis. Names remain report-only hints. A root or nested `.git` directory/file creates
  structural Git evidence and therefore prevents generic removal.
- Owner-private namespace evidence requires the effective UID, no group/other write, owner
  write/execute on every directory in the parent chain, safe typed ACL grants, clear protection
  flags, local provider evidence, and the root mount. Unknown, unreadable, and failed evidence stay
  distinct and fail closed.
- Scanner subtree preflight aggregates owner scope, group/other write, unsafe ACL grants,
  restricted flags, directory access, and prompt-style unwritable entries. Ordinary removal is the
  default. `requiresForceWithWarning` is emitted only for a completely enumerated otherwise-safe
  subtree containing an unwritable entry; `rm -rf` is not used to mask unsafe or missing evidence.
- Report-only candidates are projected as `REPORT_ONLY`, `NOT_STAGEABLE`, keep-informational rows
  with authority-authored blockers and no mutation preview. Their action/target pairs are bounded
  by the 100,000-record wire limit; a truncated projection is explicitly marked incomplete, while
  zero available pair capacity is a typed failure rather than silent omission.
- The authority/session API is ready for production injection. The runtime controller still needs
  the separately owned composition change that loads canonical bundled/user rules and passes the
  configured authority into the scan session before traversal.

## Protected Properties

- Root authority is the conjunction of Foundation discovery origin, raw root bytes, descriptor
  device/file ID/type, effective UID, adapter identity, and effective rules digest. Client root IDs
  and explicit paths are presentation/input fields, not authority.
- Access policy binds UID, GID, mode, flags, ACL digest, and typed ACL grant safety. An unknown ACL
  classification is hashed as unknown for determinism but cannot establish owner-private access.
- Subtree removability requires complete bounded enumeration. Missing, unreadable, failed, or
  contradictory subtree evidence cannot request force and cannot produce an action.
- Storage ownership remains the complete hardlink/clone/release-set graph. Nested candidates and
  repositories remain explicit overlap blockers, so removing one apparent owner cannot claim
  shared-block release.

## Task List

- [x] Add Engine-owned user-cache discovery and explicit-versus-system root origin.
- [x] Bind effective rules configuration and protections into immutable provenance.
- [x] Add typed ACL grant safety and bounded subtree removal preflight to scanner evidence.
- [x] Gate owner-private namespace and force requirements with one-vote fail-closed evidence.
- [x] Preserve report-only candidates and nested Git/overlap/release-topology blockers.
- [x] Add deterministic production policy and scanner fixtures for the accepted safety matrix.
- [x] Complete India-host build, targeted/full tests, strict changed-file formatting, and journal
  validation.
- [x] Complete read-only review with no remaining findings.
- [x] Prepare the signed landing commit and task-root cleanup handoff.

## Handoff

- Phase: the production-safe authority slice is implemented and dynamically validated.
- Next step: hand the signed exact head to the integration owner.
- Integration seam: runtime composition must load canonical rule bytes and construct both the
  authority session and plan from the same configured `RuntimePolicyAuthority`; the default remains
  capability-off/report-only.

## Evidence

- Architecture: `docs/design/accepted-plan.md`.
- Parent authority workstream:
  `docs/project_journal/2026/08/2026-08-28-runtime-policy-authority-3e91ad.md`.
- India `swift test` passed 724/724 under the process-group supervisor; receipt SHA-256:
  `835ca74c4a536b0127efc5be405faf9d9dd9d5fb57f1a8facfe52a5f869da412`.
- India `swift build` passed under the process-group supervisor after the final source and journal
  update; receipt output SHA-256:
  `ed89852dd688def9669c96f6c686a57f372e97e33e731033b798403f034fce64`.
- Exact stageable/rules/access/topology/multi-root/report-only tests passed under the India
  supervisor; final focused receipt SHA-256:
  `cfe28bdfbd76421fd61eb1daa7a4a918533741ec1e4330606560b55fb0f06b85`.
- Strict changed-file `swift format lint` passed under the India supervisor. Repository-wide strict
  lint still reports unrelated pre-existing files, so this workstream records the changed-file
  gate rather than claiming a clean whole-repository lint.
- The journal validator passed under the India supervisor; receipt output SHA-256:
  `ecfd18f6c477ebb9e15212d643aa0ab8fbca4e3b008aca0f5514adaccb253e45`.
- A fresh read-only review found and closed public origin minting, report-only semantics and wire
  capacity, root/nested Git, descendant protection, and standard-profile cache-root alias issues;
  the final review returned no findings.
