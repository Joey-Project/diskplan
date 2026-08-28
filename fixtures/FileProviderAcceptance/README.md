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
`materializedItemsDidChange`, or sealed-directory enumeration. Both provider probes and a
postflight extension-liveness signal run inside the open window. Closure requires two continuous
seconds without a new event within a 30-second total bound; assertion after closure reads only
sealed control/oracle data.

Every append first durably writes run-scoped poison evidence while holding the recorder lock,
then durably appends its JSONL event, and clears the poison marker only after that success. An
append or poison-storage error therefore remains fail-closed across recreated extension
instances instead of masquerading as callback-zero.
Teardown persistently seals the recorder before domain removal, and append never recreates a
missing run directory. File Provider callbacks and `pluginkit` mutation/query steps have bounded
monotonic deadlines and discard late completions. Recorder and JSONL locks use nonblocking
acquisition under the same 30-second absolute deadline. Exact-bundle registry records require
strict UTF-8, a recognized header, and one absolute path; malformed text that mentions the exact
bundle fails closed.

This is a probe-level fixture, not the eventual full scanner acceptance. A passing result proves
the macOS File Provider evidence primitive against controlled placeholders and explicitly reports
that scanner acceptance was not run. The real scanner hook will run `scan -> plan` inside the
same bounded callback window once that engine entrypoint is available.

Control records are read through owner-private no-follow descriptors with explicit size and
stability checks. Cleanup atomically isolates only the manifest-bound UUID run directory and
rejects symlinks, special objects, identity replacement, or access-policy changes while keeping
the manifest recoverable on ordinary failures. It also rejects the run root or any descendant
directory on a different device, and unregister cleanup proceeds only after the registry no
longer references the exact embedded extension path. A validated recovery copy prevents
manifest restoration failures from being silently discarded; even a final directory-removal
failure recreates and directly validates `manifest.json` at the deterministic UUID recovery path.
