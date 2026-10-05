# Protocol 1.7 effect-binding component vectors

This fixture set covers presence, closed-enum, size, and cross-field validation
for the additive protocol 1.7 effect-binding protobuf components. It is not a
complete framed runtime chain and does not establish live negotiation or
production mutation support.

```sh
scripts/protocol17-fixtures.sh check
scripts/protocol17-fixtures.sh generate
```

The 1.4 through 1.6 framed golden vectors remain unchanged. Protocol 1.7 stays
an explicit validator support point until the engine and frontend integration
land together.
