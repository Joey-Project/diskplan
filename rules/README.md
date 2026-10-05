# Declarative Rules

`builtin-v1.json` and `user-policy-default-v1.json` use Diskplan canonical JSON. A document is
UTF-8, ends in exactly one LF, contains no insignificant whitespace, orders object keys by decoded
UTF-8 bytes, and uses only shortest string escapes and signed 64-bit decimal integers. Arrays whose
meaning is a set have a schema-specific canonical sort order. The strict bounded parser rejects
duplicate or unsorted keys before constructing an object, and rejects floats, non-minimal integers,
unknown fields, over-limit values, and noncanonical escapes.

Each digest purpose has a separate `diskplan/<binding-kind>/v1\0` domain. Bundled assets, user
policy assets, effective configuration, frozen Rules inputs, candidate hints, disclosed agent
metadata, agent invocations, and agent cache keys cannot alias merely because their framed field
bytes happen to have the same shape.

The shipped default policy enables only `generic-remove`. This makes an ordinary-removal adapter
available for independently admitted engine actions; it does not make declarative hints stageable,
grant arbitrary path or command authority, or permit deletion to propagate across devices. The
Swift engine still applies each action's evidence gates and explicit effect consent.

`scripts/generate-rule-assets.py` compiles the exact canonical bytes of both shipped JSON assets
into `DiskplanRules`. Runtime code consumes these embedded bytes and does not locate files beside
the executable or in a resource bundle. Run the generator in write mode after changing either JSON
asset; `--check` compares the exact generated Swift source. The Python generator only converts
bounded bytes to literals; the Swift canonical loaders and shipped-asset tests validate their
format and schema.

`FrozenRulesPolicyInputs` freezes the verified built-in and shipped-default baseline together with
explicit overlay intent. An unrequested overlay is a valid `none` state. A requested missing,
unreadable, malformed, or oversized overlay is `policy-unverified`: read-only planning may use the
validated baseline, while mutation configuration is unavailable. This state remains distinct from
no overlay. Disabling a broken overlay creates a new input snapshot and binding, so it cannot
upgrade an existing plan or review. The digest binds the baseline asset and input digests, overlay
intent, bounded raw source identity, closed failure state or verified overlay digest, and effective
configuration digest. The source identity is provenance data, not permission to read a path. Each
canonical input is limited to one MiB before parsing or hashing; oversized content is represented
by a fixed failure code and byte count, without claiming a content digest.

The built-in schema version is `diskplan.rules.v1`. Its root contains `rules` and
`schema_version`. Each rule contains `candidate_kind`, `handling`, `id`, `managed_action`, and
`matcher`. Matchers operate on raw name bytes encoded as lowercase hexadecimal. Declarative matches
produce report-only hints; they do not assert recoverability, static rebuild evidence, adapter
registration, or stageability.

The restricted user schema version is `diskplan.user-policy.v1`. Its root contains only
`adapter_enablement`, `agent`, `budgets`, `profile`, `protections`, `schema_version`, and
`thresholds`. A protection path binds an exact 32-byte root digest and a bounded sequence of raw
root-relative components. No user-policy field accepts an executable, shell, argv, environment,
download, plugin, or arbitrary command.

Agent mode is `off`, `ask`, or `auto`; the shipped default is `ask`. Disclosure values are a fixed
metadata allowlist. Agent results and unavailable-agent outcomes remain report-only, and cache keys
bind model, schema, prompt, policy, disclosure profile, exact typed disclosed metadata, and evidence
identities. A single immutable invocation owns the metadata used by both the transport and cache
authority seams, so callers cannot independently select payload and binding. These files configure
no provider, transport, credentials, or persistent cache implementation.

An ordinary invocation is not transport-capable. Transport accepts only a sealed authorized value:
validated `auto` policy may authorize deterministically, while `ask` remains unavailable until a
candidate-bound user-consent authority can supply a receipt. Mode `off` cannot construct an
invocation.

Model, schema, and prompt identifiers are 1–256 ASCII bytes, begin and end with an alphanumeric
byte, allow only alphanumerics plus `._/-` internally, and pass the same credential-shape screen as
disclosed metadata. They remain data-only identifiers and grant no argv, environment, executable,
path, or transport authority.

The retained disclosed-metadata object owns the exact canonical JSON bytes that a future transport
may send; its cache digest derives from those same bytes. Constructors reject credential-shaped
root aliases, raw names, manifest names, and tokens before payload construction. All metadata array
variants are capped at 4,096 entries and one MiB, and all JSON integer variants are limited to
`0...Int64.max` to match the canonical parser.
