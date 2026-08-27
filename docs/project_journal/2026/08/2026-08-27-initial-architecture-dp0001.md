---
id: 20260827-dp0001
title: Initial Architecture And Delivery Plan
status: active
created: 2026-08-27
updated: 2026-08-27
branch: main
pr:
supersedes: []
superseded_by:
---

# Initial Architecture And Delivery Plan

## Summary

- 产品设计已经确认并记录在 `docs/design/accepted-plan.md`。
- 本 workstream 完成空 canonical repository 的首次 bootstrap，并建立 project journal、linked worktree 和 PR 工作流。
- 产品实现尚未开始；下一个 delivery gate 是 Phase 0 capability slice。

## Current State

- Canonical repository：`/Users/hoteng/Program/GitHub/diskplan`。
- GitHub repository：`Joey-Project/diskplan`。
- 必须验收的 release environment：Apple Silicon 和 macOS 26。
- 首选真实主机验证目标：`India-mac-mini-m4-hoteng`。
- 架构：Swift safety/execution engine、Rust/Ratatui frontend，以及基于 stdio 的 versioned Protobuf。

## Task List

- [x] 恢复并分析原始人工磁盘清理 workflow。
- [x] 对齐 classification、activity、recoverability、APFS、File Provider、UI、execution、persistence、testing 和 platform 决策。
- [x] 确认完整 product/delivery plan。
- [x] 建立 repository guidance、README、ignore rules、accepted design 和 project journal。
- [ ] Phase 0：验证 APFS attributes、File Provider metadata-only access、Swift/Rust Protobuf IPC 和最小 scan TUI。
- [ ] Phase 1：实现只读 scan-to-evidence。
- [ ] Phase 2：实现 deterministic classification、policy、dependency graph 和 immutable plan。
- [ ] Phase 3：实现 plan-first TUI。
- [ ] Phase 4：实现 revalidation 和 dry-run。
- [ ] Phase 5：启用经过 fixture apply tests 的 best-effort adapters。
- [ ] Phase 6：完成 macOS 26 真实主机 release acceptance。

## Handoff

- Phase：从设计进入实现。
- Summary：Phase 0 所需的架构和安全 contract 已冻结；共享 schema 稳定后，独立模块可以并行开发。
- Next step：为 Phase 0 capability slice 创建 linked worktree 和 `wip/<topic>` 分支，并通过 pull request 落地。
- Blockers：当前没有已知 blocker。

## Evidence

- Accepted design：`docs/design/accepted-plan.md`。
- 原始清理 task：`codex://threads/019e4f9b-d3cb-7c92-9637-722ebb48c3db`。
- 设计对齐 task：`codex://threads/01a04386-7151-7b11-98c6-b7c805e66b03`。
