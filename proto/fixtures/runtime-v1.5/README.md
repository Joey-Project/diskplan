# Protocol 1.5 runtime fixtures

These vectors extend the protocol 1.4 runtime chain with byte-exact working
directory provenance and a closed path-race projection on every execution
preview. Mutation previews carry an absolute raw working-directory byte string;
non-mutating previews carry a present empty byte string. Rust validates these
bytes and escapes them for display without joining, normalizing, resolving, or
opening the path.

Each non-empty line in a generated `*.frames.hex` file is one complete
framing-v1 record: a four-byte big-endian payload length followed by the exact
canonical `diskplan.v1.Envelope` bytes. The plan, dry-run, apply-review,
force-warning, execution-record, and terminal hashes bind the exact preview
bytes. Swift authors every digest. Swift and Rust independently decode,
validate, and byte-for-byte re-encode the vectors.

Protocol 1.4 fixtures remain byte-identical. When a 1.5 endpoint negotiates
minor 1.4 it omits preview tags 7 and 8, and the Rust frontend rejects mutation
previews because an exact raw working directory is unavailable.

```sh
scripts/protocol15-fixtures.sh check
scripts/protocol15-fixtures.sh generate
```
