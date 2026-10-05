# Canonical effect binding v2 vectors

These shared vectors pin the frozen v2 requirement and consent canonical bytes
and SHA-256 domains. Rust recomputes the canonical encoding and hashes; Swift
consumers may independently verify the same bytes without adding another shared
encoder implementation.

```sh
scripts/effect-canonical-fixture.sh check
scripts/effect-canonical-fixture.sh generate
```

The separate runtime-v1.7 vectors cover additive protobuf binding validation.
Neither fixture set enables the live protocol default or claims that the
production engine execution chain is integrated.
