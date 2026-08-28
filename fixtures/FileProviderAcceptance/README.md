# Controlled File Provider Fixture

This fixture is the macOS 26 acceptance oracle for Diskplan's metadata-only File Provider
boundary. It contains a hidden `LSUIElement` host app and one embedded replicated
`com.apple.fileprovider-nonui` extension. The project intentionally has no File Provider
testing-mode entitlement and creates domains with empty testing modes.

Use `scripts/fileprovider-fixture.sh build-unsigned` for compile-only validation. The signed
`accept` lifecycle is reserved for the controlled India host and is documented in
`docs/design/file-provider-fixture.md`.

The fixture is not sample user storage. It exposes exactly two root items:

- a 64 KiB dataless `sentinel.txt` whose `fetchContents` implementation writes real fixed
  bytes into the domain manager's temporary directory; and
- a dataless `sealed-dir` whose enumerator returns a hidden child only if Diskplan descends
  incorrectly.

The App Group oracle records metadata and dangerous callbacks as bounded JSONL. An acceptance
window fails if it sees content fetch, upload/create, modify, delete,
`materializedItemsDidChange`, or sealed-directory enumeration.

This is a probe-level fixture, not the eventual full scanner acceptance. A passing result proves
the macOS File Provider evidence primitive against controlled placeholders and explicitly reports
that scanner acceptance was not run. The real scanner hook will run `scan -> plan` inside the
same bounded callback window once that engine entrypoint is available.

Control records are read through owner-private no-follow descriptors with explicit size and
stability checks. Cleanup atomically isolates only the manifest-bound UUID run directory and
rejects symlinks, special objects, identity replacement, or access-policy changes while keeping
the manifest recoverable on ordinary failures.
