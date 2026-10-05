# Effect Permission Bindings V2

This is the implementation interface for the accepted
[action-effect contract](locality-and-provider-actions.md), not a claim that the
runtime implements it. The [accepted plan](accepted-plan.md) remains authoritative.
`proto/diskplan/v1/ipc.proto` is the source of truth for wire types. Swift owns
classification; Rust verifies closed bindings and references, not safety policy.

## Domain Interface

`ActionEffectPermission: UInt8` has exactly `localRemoveOnly = 1` and
`mayDeleteAcrossDevices = 2`. Domain builders default to local-only for new plan
intent. Missing execution bindings, zero, unknown values and legacy overlays
never supply permission. Unknown ownership remains an observation, not local.

`ActionEffectOperation: UInt8` has `ordinaryRemove = 1` and
`providerEvictLocalCopy = 2`. The former binds the exact declared removal adapter,
not arbitrary commands; unsupported adapters remain unsupported. Eviction can
only require local-only and is not an ordinary removal fallback.

`ActionPrototype.build(request:evidence:effectPermission:)` carries the permission
into a closed `ActionEffectRequirementBindingV2`. A cross-device ordinary variant
is initially supported only for generic removal with a generic scope and no Git
scope. Dedicated adapters retain all independent requirements. OneVote input
accepts the same permission and binds it into its evaluation source. It relaxes
only the ownership/propagation veto for that otherwise eligible variant; explicit
protection and every other gate are unchanged. The access-policy baseline binds
`Observation<ProviderState>`, including unknown, separately from access/ACL/mount
facts. It must not promote missing markers to no-propagation authority.

The immutable requirement contains version 2, operation, permission, variant
group ID, target-scope digest and operation-contract digest. Its digest must not
include an action ID: action IDs already include the requirement, so doing both
would create a hash cycle. The target-scope digest binds the protected namespace;
the operation-contract digest binds the exact adapter, protected properties and
postcondition without the effect requirement. Variants for the same exact scope
share a 32-byte group ID; selected variants are mutually exclusive. Unsupported
eviction remains guided/report-only rather than being advertised as executable.

`EffectConsentCore.create(plan:action:permission:consentEventID:)` constructs a
typed `EffectConsentBindingV2` exclusively from that plan and action. The event is
1...256 raw bytes. It cannot accept caller-provided target paths or authoritative
digests. Its fields are version, permission, requirement digest, action ID,
lineage ID, target-scope digest, plan digest, evidence digest, policy version,
schema version (a byte-preserving string), and consent event ID. The explicit
permission argument must equal the action's immutable requirement; mismatch
throws rather than upgrading or downgrading it.

`DecisionOverlay.currentBindingVersion` becomes `decision-overlay-v2` and gains
`effectConsents`. Every selected executable action has exactly one matching
consent; no unselected action retains one. Both local and cross-device consent
are explicit in new execution bindings. UI default local-only does not make
missing fields valid. Consent is per action, not a transferable group grant.

`EffectEpochRequirement` is separate from waiver requirements. Execution binds
the consent, action/lineage, requirement/permission, original plan/evidence,
policy/schema, target scope, overlay hash/revision and current
`ExecutionEpochContext` (epoch ID, semantic reference, issue and deadline seconds).
It also binds the authenticated fresh revalidation receipt's exact SHA-256 and
typed receipt reference for the corresponding stage, epoch, action, target and
time window. Minting and whole-plan/JIT checks verify that provenance through the
live authority. Whole-plan and JIT are distinct fresh receipts, not assumed to
have equal digests; neither a caller-supplied digest nor a replayed receipt can
replace the required stage's authenticated collection. A new capture ID
alone is not a protected-property change; revalidation compares object identity,
content and access policy deliberately, retaining benign metadata transitions.
`EffectEpochCredential` is engine-issued opaque runtime state, verified against
the live one-use execution authority. It is neither persisted in overlays nor
sent through IPC. Whole-plan and JIT checks independently reject stale, missing,
wrong-action or replayed credentials. Waiver credentials cannot substitute.

## Canonical Bytes And Digest Domains

Encode unsigned version 2 as eight-byte big-endian `u64`; encode closed enums as
one byte. `blob` is an eight-byte big-endian byte length followed by those bytes.
Strings use raw UTF-8 bytes without normalization. Every digest and variant group
is exactly 32 bytes. Policy/schema strings are nonempty valid UTF-8, at most 256
bytes each, and must match the supported frozen versions. Event IDs are 1...256
bytes. Requirement and consent records are capped at 4096 bytes. Reject trailing
bytes, missing/empty values, invalid UTF-8, overlong data and noncanonical forms;
protobuf defaults alone never satisfy these validations.

Requirement field order:

```text
u64(2), u8(operation), u8(permission), blob(variant_group_id),
blob(target_scope_sha256), blob(operation_contract_sha256)
```

Consent field order:

```text
u64(2), u8(permission), blob(requirement_sha256), blob(action_id),
blob(action_lineage_id), blob(target_scope_sha256), blob(plan_sha256),
blob(evidence_sha256), blob(policy_version_utf8), blob(schema_version_utf8),
blob(consent_event_id)
```

Digests are SHA-256 of the exact domain prefix plus canonical bytes:
`diskplan/effect-requirement/v2\0` and `diskplan/effect-consent/v2\0`.
Existing action-lineage, action, plan and decision-overlay domains advance to v2;
unchanged evidence/global-fact binding formats stay v1. Protobuf serialization is
transport, not canonical digest input. Do not claim EvidenceBinding V1 covers
the complete policy plan.

Rust independently re-encodes and verifies both typed records, then compares
their exact references with the validated action and manifest. It does not
recompute the full Swift plan or infer ownership. Golden vectors cover each
field's tampering, unknown/missing enums, conflicts, and cross-language equality.

## IPC 1.7 Additions

Append fields without changing historical tags or fixture bytes:

- `ActionEffectRequirementBindingV2`: version=1, optional operation=2, optional
  permission=3, variant group=4, target-scope digest=5, operation-contract digest=6.
- `EffectConsentBindingV2`: version=1, optional permission=2, requirement digest=3,
  action ID=4, lineage ID=5, target-scope digest=6, plan digest=7, evidence digest=8,
  policy string=9, schema string=10, raw event ID=11.
- `PlanActionProjection`: requirement=26, requirement digest=27, variant group=28.
  Executable 1.7 actions require all three and consistent references.
- `PlanProjectionManifest`: action-effect binding schema version=29, exactly 2.
- `DecisionEditKind`: `SET_EFFECT_CONSENT = 7`; overlay edit body=16. Its new
  message has action ID=1, optional permission=2, event ID=3, requirement digest=4.
  Leave shared stage/unstage payloads unchanged. Edit batches validate atomically.
- `AcknowledgedEffectConsent`: binding=1, consent digest=2. Overlay acknowledgement
  appends records=23, maximum count=24, actual count=25.
- `ApplyReviewActionProjection`: optional permission=4, requirement digest=5,
  consent digest=6; these participate in its review binding and displayed warning.
- Append overlay rejection codes 11 for invalid/missing effect consent and 12 for
  conflicting variants. Zero and unknown enum values are never permissions.

Protocols 1.4-1.6 retain historical decoding/fixture compatibility but cannot
grant new mutation authority; live engine mutation requests require 1.7. Preserve
old golden bytes and add dedicated runtime 1.7 and canonical-effect-v2 fixtures.
No dehydration result selects removal automatically: rescan/replan and a new
per-action consent are required. Force confirmation stays separate.
