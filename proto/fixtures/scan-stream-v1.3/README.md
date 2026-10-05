# Protocol 1.3 scan-stream fixtures

`fixtures.json` is the human-readable source for the checked-in framed protobuf
vectors. `zero-ready`, `single-ready`, and `multi-finalized` cover zero, one,
and multiple retained-node chunks plus both checkpoint-ready and finalized
terminal envelopes. Each non-empty line in a generated `*.frames.hex` file is
one complete framing-v1 record: a four-byte big-endian payload length followed
by the exact canonical `diskplan.v1.Envelope` bytes.

The Swift authority generates the vectors with a deliberately small legal
chunk target for the multi-chunk case; the manifest continues to advertise the
protocol's 4 MiB maximum. Swift and Rust tests decode, semantically validate,
and byte-for-byte re-encode every frame. They also mutate the vectors to prove
fail-closed handling for truncation and mismatched count, digest, and frontier
metadata.

```sh
scripts/protocol13-fixtures.sh check
scripts/protocol13-fixtures.sh generate
```
