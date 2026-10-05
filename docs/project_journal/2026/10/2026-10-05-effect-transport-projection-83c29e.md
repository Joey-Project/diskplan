---
id: 20261005-83c29e
title: Checked Effect Transport Projection
status: active
created: 2026-10-05
updated: 2026-10-05
branch: wip/effect-permission-integration
pr: https://github.com/Joey-Project/diskplan/pull/30
supersedes: []
superseded_by:
---

# Checked Effect Transport Projection

## Boundary

Primary author: OpenAI Codex (GPT-6.1 Sol Extra High), with a separate GPT-6 Luna
internal audit. This slice maps checked raw Swift v2 records to the frozen
protocol 1.7 requirement and acknowledged-consent records. It neither issues
permission nor checks plan/action references. Production callers must still
derive consent from authoritative plan/actions, admit exact references, and
obtain live one-use execution credentials. Live negotiation remains 1.6.

The mapper writes both enums explicitly, retains every opaque/digest reference,
and emits the consent's checked canonical digest. Policy/schema UTF-8 bytes are
not normalized; the opaque event ID is not interpreted as text or a path.
No scanner, Provider probe, Rules source, filesystem access, or mutation changes
are introduced. The parent [integration workstream](2026-10-05-effect-permission-integration-c6hbgn.md)
owns production activation and full acceptance.

## Tasks

- [x] Add closed raw-record projections and field-by-field wire round-trip tests.
- [x] Validate formatting and two selected tests on India.
- [x] Complete separate fixed-source internal audit.
- [ ] Wire authoritative plan/overlay callers at the coherent 1.7 checkpoint.

## India Receipt

Staged tree: `6d7a4fd77ba2cc9fc63ab287a0830f1234155a51`; source archive SHA-256:
`686be65dc0f2ffd82d3faee9667be016c4e8395a1c22fbc5bf097eb57638ed08`.
India verified this upload before extraction into
`/private/tmp/diskplan-release-baseline-20261005.NlIPngd0/effect-projection-source-v1`.
The main task root remains owner-private, UID 501 / mode 0700.

The task runner passed `bash -n` and shellcheck on India. India formatted and
strict-linted both Swift files, then ran package-lock-guarded
`swift test --disable-automatic-resolution --scratch-path
/private/tmp/diskplan-release-baseline-20261005.NlIPngd0/swift-build --jobs 4
--filter 'runtimeEffectRequirementProjection|runtimeEffectConsentProjection'`.
Two Swift Testing tests executed and passed. The separate XCTest zero-test
summary is not the selected-test count. Three valid operation/permission
combinations and both consent permissions are checked inside those tests.

The 900-second / 1-MiB runner exited 0 after 27,557 ms, with verified process
group and quiescent termination. Log: 19,306 bytes, SHA-256
`589dcf1b3da31102989e8b85d152ddd9fc24c0c2116a3b28e30289a7c2fbd83a`.
Formatted sources were copied back mechanically and matched India:

- `RuntimeEffectBindingProjection.swift`:
  `72042d60cd71a4378469c8b748fb5fbb5acacfc85d0ceecc720d5492d1ddd30a`.
- `RuntimeEffectBindingProjectionTests.swift`:
  `7519afa81be956a73b400c05c810c6a6da9062692076e906dedb8f7ceccdce26`.
- `Package.resolved` unchanged:
  `9c858ad2ab85466112834e09bfa270f01d0835e028244ee6a8e2e5b4ca677e98`.

These are transport-mechanism receipts, not production reference admission,
Provider/platform-positive acceptance, a full suite, or a formal review.

A separate GPT-6 Luna read-only audit checked both exact formatted source
hashes, their raw v2 and generated protocol declarations, and the India log
tail. It found no concrete mapping or byte-fidelity issue and confirmed the
two actual Swift Testing executions. It also confirmed that only tests call
the mapper; production reference admission and activation remain unfinished.
