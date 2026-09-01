# Protocol 1.4 runtime fixtures

`fixtures.json` is the human-readable source for Swift-authored, framed
protobuf vectors. `empty-batch-dry-run` proves that a zero-selection overlay
still produces an authoritative plan, overlay, dry-run proof, apply review,
and zero-unit execution record. `force-action-execution` covers a two-chunk
plan, raw non-UTF-8 path projection, exact force warning, revalidation binding,
bounded namespace/ACL/content safety evidence, apply review, successful
adapter/post-verification event, and sealed terminal.
`git-evidence-action`, `codex-scope-action`, and `version-survivor-action`
exercise the bounded Git counters/coverage, configured Codex provenance, and
raw-selector/survivor projection variants without exporting path or version
record collections.

Each non-empty line in a generated `*.frames.hex` file is one complete
framing-v1 record: a four-byte big-endian payload length followed by the exact
canonical `diskplan.v1.Envelope` bytes. Swift authors every digest. Swift and
Rust independently decode, validate, and byte-for-byte re-encode the vectors.
The protocol 1.3 fixture directory remains unchanged and is checked separately.

```sh
scripts/protocol14-fixtures.sh check
scripts/protocol14-fixtures.sh generate
```
