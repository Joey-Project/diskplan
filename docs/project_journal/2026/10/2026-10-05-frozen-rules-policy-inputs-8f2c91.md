---
id: 20261005-8f2c91
title: Frozen Rules Policy Inputs
status: active
created: 2026-10-05
updated: 2026-10-05
branch: wip/rules-input-state
pr:
supersedes: []
superseded_by:
---

# Frozen Rules Policy Inputs

## Summary
- Added an immutable interpretation of required Rules baselines and explicit optional-overlay intent. A broken requested overlay keeps a verified baseline available for read-only planning and removes mutation configuration.
- Embedded exact canonical asset bytes in generated Swift literals. The shipped default enables only `generic-remove`; action evidence and effect consent remain engine-owned.

## Current State
- The Rules API and focused tests are implemented on `wip/rules-input-state`. Runtime input custody and caller wiring remain with the main integration task.
- Canonical inputs are capped at 1 MiB before parsing or hashing. Oversized input binds a closed failure code and byte count without a claimed content digest. Source identity preserves validated raw bytes up to 4 KiB and grants no path-reading authority.
- Validation ran only on `India-mac-mini-m4-hoteng` (UID 501), macOS 26 arm64, Swift 6.3.3. The private task root was `/private/tmp/diskplan-rules-input-state.jhdXi0`, verified real path, owner 501, mode 0700. It is isolated build state, not a checkout; it can be removed after this checkpoint because source and terminal evidence are recorded here.
- The task root began from base commit `368ba199a3b8b7e8eecff160f39cf0ea80df23e4`, tree `4a02b12ac03918d9fd0d454da20d2045fbf72179`; the streamed `git archive --format=tar HEAD` was 7,495,680 bytes with SHA-256 `2a9aef593c633c57a8556ff8da479d25c3034a6f2b494fcb0fa04120f87cb296`. Changed files were overlaid in that private snapshot before generation, formatting, and tests.
- The failed first combined-filter attempt was split by the remote shell at `|`; its supervisor result was lost to a broken pipe and it is expressly not counted as a gate. After that process ended, a scoped `pgrep` found no task-root process. Separate reruns below returned terminal `result=passed`, `quiescent=true`, and exit status 0. A later scoped `pgrep -fl diskplan-rules-input-state.jhdXi0` returned no matching process.
- The exact seven-file implementation snapshot was identical locally and on India: hash each file with `shasum -a 256` in the listed order, concatenate the seven checksum lines, then hash that manifest with `shasum -a 256`; resulting manifest SHA-256: `2ad42bc8f7cbd6676e3e63b07efc34c76c77275db3f41c64f1a2d6be6ec1383e`.

| Source file | SHA-256 |
| --- | --- |
| `rules/README.md` | `786beef95e0912b9c2b6a0d3b7d1180e2e6e87ae68a6596730292dbf0801058c` |
| `rules/user-policy-default-v1.json` | `598ef77aa49c3774442fa7d080407db284f5f25944b1dcaf50dc69a6e679c062` |
| `swift/Tests/DiskplanRulesTests/RulesLoaderTests.swift` | `7e2b39cef81825be43ec919087dec5faaaa0b5b817c1ff1172de00e2bc61dfda` |
| `scripts/generate-rule-assets.py` | `64b4ff449fdf16e40acb72dbb909a2cec8ee77019d18fb4e350e9a99c6efee4c` |
| `swift/Sources/DiskplanRules/BundledRuleAssets.generated.swift` | `b0c95f8b6a805981be00c4e909e07d853a5f544dbdc129924b908dec458e691e` |
| `swift/Sources/DiskplanRules/FrozenRulesPolicyInputs.swift` | `6e16941a929ddc4c5fa767b38600d3f1292a17e952078224b38d336944bb6125` |
| `swift/Tests/DiskplanRulesTests/FrozenRulesPolicyInputsTests.swift` | `57356065daf176861787774fc91bbdf8acfce7cea7e9335f1512daf377523f67` |

## Next Steps
- Main integration supplies caller-bound raw input/failure state, carries `bindingDigest` into plan and execution binding, and wires the separate planning and mutation configurations.
- CI should run the generator with `--check` after source asset changes.

## Evidence
- `Package.resolved` was guarded before each bounded operation and remained byte-identical; SHA-256 was `9c858ad2ab85466112834e09bfa270f01d0835e028244ee6a8e2e5b4ca677e98`.
- Generator write mode and `--check` passed on India. The two canonical JSON assets remain source-of-truth: Python reads at most 1 MiB from each and renders fixed hexadecimal byte arrays; `--check` compares the exact generated Swift bytes. It does not claim to validate canonical JSON or schema. The Swift loaders and shipped-asset test own that validation; the test compares both embedded `Data` values byte-for-byte with the shipped files.
- Swift formatting and strict lint passed on India. Both Swift test invocations returned terminal `result=passed`, process-group `quiescent=true`, exit status 0, timeout 900 seconds, and retained-output cap 1,048,576 bytes; their final captured output files and measured results are recorded below.
- Exact validation commands (all sent over SSH to the stated host; bounded operations used a pollable PTY):

```text
python3 /private/tmp/diskplan-rules-input-state.jhdXi0/scripts/generate-rule-assets.py
python3 /private/tmp/diskplan-rules-input-state.jhdXi0/scripts/generate-rule-assets.py --check
swift format format --in-place /private/tmp/diskplan-rules-input-state.jhdXi0/swift/Sources/DiskplanRules/FrozenRulesPolicyInputs.swift /private/tmp/diskplan-rules-input-state.jhdXi0/swift/Tests/DiskplanRulesTests/FrozenRulesPolicyInputsTests.swift /private/tmp/diskplan-rules-input-state.jhdXi0/swift/Tests/DiskplanRulesTests/RulesLoaderTests.swift
swift format lint --strict /private/tmp/diskplan-rules-input-state.jhdXi0/swift/Sources/DiskplanRules/FrozenRulesPolicyInputs.swift /private/tmp/diskplan-rules-input-state.jhdXi0/swift/Sources/DiskplanRules/BundledRuleAssets.generated.swift /private/tmp/diskplan-rules-input-state.jhdXi0/swift/Tests/DiskplanRulesTests/FrozenRulesPolicyInputsTests.swift /private/tmp/diskplan-rules-input-state.jhdXi0/swift/Tests/DiskplanRulesTests/RulesLoaderTests.swift
swift test --package-path /private/tmp/diskplan-rules-input-state.jhdXi0 --filter FrozenRulesPolicyInputsTests
swift test --package-path /private/tmp/diskplan-rules-input-state.jhdXi0 --filter shippedRuleAssetsAreCanonicalAndUseConservativeDefaults
```

- Each command above was invoked as `scripts/ci/package-resolved-guard.sh run Package.resolved -- python3 scripts/release/run_bounded.py --timeout-seconds 900 --max-output-bytes 1048576 --output <task-root-output> -- <command...>` except generator `--check`, which also used that wrapper. The first unwrapped generator and check calls passed before they were repeated under the guard.
- The final Rules-input test filter passed all 7 tests in 11,245 ms. `swift-tests-rules-final-output.bin` contains 2,610 bytes; SHA-256 `e79a53df0738d31beeb921bf03a9b150b53dca4d3a70349862eb69e75c59c855`.
- The final shipped-default test filter passed its 1 test in 5,429 ms. `swift-tests-shipped-final-output.bin` contains 930 bytes; SHA-256 `d49f008abeebca051c22148c29a669bf7489efa45f3fb1cafd08f3dcb9488989`.
- A preceding combined filter containing `|` is excluded from gate evidence despite partial output. The separate terminal receipts, process-group quiescence, source snapshot match, and unchanged lock digest are the checkpoint evidence.
- The task root contains only this workstream's private archive, source snapshot, captured outputs, and SwiftPM `.build`; those become recyclable after this checkpoint.
