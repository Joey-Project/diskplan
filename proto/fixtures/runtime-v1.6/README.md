# Protocol 1.6 runtime fixtures

These vectors retain the protocol 1.5 execution-preview contract and add the
fail-closed `ExecutionStreamFailureProjection` terminal. The failure fixture
ends immediately after a valid `apply_started`, while its accepted review
contains a force-required action. This proves that a failure terminal binds the
execution, apply review, emitted prefix, count, byte budget, and digest without
claiming a complete force-warning list or a trustworthy unit summary.

The failure terminal is valid only at protocol 1.6. Protocol 1.4 and 1.5
fixtures remain byte-identical, and both older negotiated minors reject tag 21.
Positive apply also requires protocol 1.6 so the frontend can distinguish a
trustworthy `apply_finished` from a fail-closed post-start projection failure.

Each non-empty line in a generated `*.frames.hex` file is one complete
framing-v1 record: a four-byte big-endian payload length followed by the exact
canonical `diskplan.v1.Envelope` bytes. Swift authors every digest. Swift and
Rust independently decode, validate, and byte-for-byte re-encode the vectors.

```sh
scripts/protocol16-fixtures.sh check
scripts/protocol16-fixtures.sh generate
```
