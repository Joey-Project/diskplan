---
id: 20260827-41f0a2
title: Phase 0 Shared Foundation
status: active
created: 2026-08-27
updated: 2026-08-28
branch: wip/phase0-foundation
pr:
supersedes: []
superseded_by:
---

# Phase 0 Shared Foundation

## Summary

- 建立 Swift engine、Rust frontend 和 versioned Protobuf IPC 的共同基础。
- 本 workstream 只冻结跨语言 contract、handshake、canonical binding fixtures 和 build/test harness；APFS、File Provider 与完整 TUI 分别在后续 Phase 0 workstream 实现。

## Current State

- Base commit：`0ee3ed5555fec42ffc5e9b8e718024fcbb686d71`。
- Branch：`wip/phase0-foundation`，位于 linked worktree。
- Toolchain preflight：Swift 6.3.3、Rust 1.95.0、Protobuf 35.1，target 为 `arm64-apple-macosx26.0`。
- Shared foundation implementation and Tier 1 validation are complete. The first frozen-range review found four process/publisher issues, fixed in signed commit `b6a26faa5191e1c8872f63380f3a14d818be8296`. A second full-range review found five follow-up race, cleanup, ACL, and source-binding issues; those fixes are included in this branch and await fresh full-range review before the pull request.
- The Swift engine remains the evidence authority. Rust exposes only strict canonical verification and a supervised live IPC session.

## Task List

- [x] 建立 Swift Package 与 Cargo workspace。
- [x] 定义 versioned Protobuf envelopes 和 length-delimited stdio handshake。
- [x] 建立 deterministic canonical binding 与跨语言 golden vectors。
- [x] 添加 Swift/Rust unit、compatibility 和 smoke tests。
- [ ] 完成本地 delivery gate、独立 review 和 PR readiness。

## Handoff

- Phase：Phase 0 foundation delivery gate。
- Next step：冻结新的 `base_sha..head_sha`，完成 fresh independent review 和 PR readiness。
- Blockers：当前没有已知 blocker。

## Evidence

- Accepted design：`docs/design/accepted-plan.md`。
- Design baseline：`0ee3ed5555fec42ffc5e9b8e718024fcbb686d71`。
- Active task：`codex://threads/01a04386-7151-7b11-98c6-b7c805e66b03`。
- `swift build` and `swift test` (11 tests).
- `cargo fmt --all -- --check`.
- `cargo check --locked --workspace --all-targets`.
- `cargo test --locked --workspace` (2 cleanup unit tests, 8 process tests, 2 explicit cross-language ignores, 8 core tests, 5 canonical tests, and 17 publisher tests).
- `cargo clippy --locked --workspace --all-targets -- -D warnings`.
- `scripts/proto-codegen.sh check` and `scripts/canonical-fixture.sh check`.
- `scripts/test-cross-language.sh` (2 real Swift/Rust process tests plus canonical drift check).
- `scripts/test-deployment-target.sh` (`aarch64-apple-darwin`, Mach-O `minos 14.0`).
- `bash -n`, ShellCheck 0.11.0, and `git diff --check`.
- Frozen review of `0ee3ed5555fec42ffc5e9b8e718024fcbb686d71..dfd1561513755d836bda945a6f71badefebac1ca` found four issues: unbounded stdout queueing, unbounded post-`SIGKILL` wait, unbound rejection sequence, and insufficient rollback-backup validation. The subsequent fix set adds bounded backpressure/reaping and descriptor-held identity/content/access seals with adversarial tests.
- Full-range rereview through `8fa904c8d22aaadfef69c0247f4c716db98f73c3` found five follow-up issues: pathname cleanup remained validate-then-use, escaped direct children were not directly killed, ACL changes were not sealed, early stage failures could leave files, and source reads were path-racy. The subsequent fix set adds trusted-exclusive directory leases, atomic quarantine-before-delete, descriptor-captured ACL/source seals, provisional-stage cleanup, and direct-child kill/reap tests.
