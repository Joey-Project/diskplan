# Diskplan Accepted Design Plan

## 1. 目标与边界

`diskplan` 将已有的人工磁盘清理流程产品化为确定性、可审计的 macOS 工具。工具不直接判断文件对用户是否“有用”，而是把结果表达为：

```text
evidence -> deterministic classification -> recommendation -> uncertainty
```

只有证据足够的对象才能得到可执行建议；语义未知、证据不完整或运行状态不安全的对象保留为 review/blocked 状态。

首版是可执行产品，但严格分成两个阶段：

1. `scan -> plan`：完全只读。
2. 用户显式选择或编辑计划后，执行 `revalidate -> dry-run/apply`。

## 2. 结果模型

基础结果状态包括：

- `safe-to-clean`
- `safe-after-exit`
- `likely-rebuildable`
- `needs-semantic-review`
- `managed-by-provider`
- `keep`
- `scan-incomplete`
- `classification-conflict`

状态由 policy engine 统一计算。collector、recognizer、adapter 和 agent 都不能自行宣布最终安全等级。

### 2.1 分类优先级

分类按以下优先级执行：

1. Explicit user overrides.
2. Authoritative tool adapters.
3. Structural recognizers.
4. Path conventions.
5. Generic unknown fallback.

同一优先级发生冲突时返回 `classification-conflict`。agent 可以提出候选类型、缺失证据和新规则建议，但其输出必须标记为 `agent-assisted`，不能覆盖 explicit/authoritative evidence，也不能单独产生 `safe-to-clean`。

## 3. Recommendation Policy

安全决策采用 one-vote reject（任一强否决证据即可阻止清理）。以下维度分别保留，不聚合成安全分数：

- Explicit protection and provider boundaries.
- Evidence completeness.
- Current activity.
- Object identity and access policy.
- Semantic uniqueness or uncertainty.
- Recoverability strength.
- Dependency/release-set completeness.

大小、年龄和回收成本只用于同一安全层级内排序。建议排序可以使用：

```text
(tier, immediate_reclaim desc, inactive_duration desc,
 rebuild_cost asc, cleanup_cost asc, canonical_path)
```

但该顺序不代表安全真值。

## 4. Activity Evidence

工具不合成虚假的单一 `last_used_at`。activity evidence 分为：

- Current positive activity: open files, process cwd, mapped binaries, active provider operations.
- Observed history: `first_seen`, `last_seen`, `last_seen_open`, `last_seen_process_reference`.
- Filesystem times with explicit trust levels.
- Managed references: Git worktree, active version, current update operation.

强正面 activity 阻止清理。没有观察到 open handle 只是弱负面证据。全局 process snapshot 使用一次 bounded `lsof -nP`，再映射到 candidate ancestors；不对每个目录运行无界 `lsof +D`。

history 是可选增强。缺失时标记 `history_unavailable`，不能伪造长期不活跃结论。

## 5. Recoverability

恢复能力分为：

1. Tool contracts.
2. Static rebuild evidence.
3. Lightweight recovery-source verification.
4. Optional dynamic build/download/round-trip verification.

常规扫描禁止 build、install、download、大规模 hash 和无界 LFS enumeration。动态验证只用于 deep audit、高风险 action 或 adapter 开发。

建议必须区分：

- Provider-owned reclaimable storage.
- Exactly recoverable data.
- Statically rebuildable output.
- Probably rebuildable output.
- Duplicate data with a designated survivor.
- Unique or unknown content.

## 6. Scan Profiles And Determinism

确定性契约是：相同文件系统状态、相同进程/权限可见性、相同配置和相同 policy version，产生相同分类、action、stable ID、依赖图和排序。

实现要求：

- 按文件系统原始名称字节排序，不依赖 locale。
- collector/adapters 的并发完成顺序不影响最终输出。
- 外部工具先解析为 typed records，再 canonical sort。
- 时间戳等非语义字段不进入 evidence hash。
- 扫描中发生真实身份、内容或 access-policy 变化的 candidate 标记 `unstable-during-scan`。

Profiles：

| Profile | Scope | Default structural budget |
| --- | --- | --- |
| `quick` | Volume/APFS/VM/swap/snapshot probes, process snapshot, known adapter roots | No generic traversal |
| `standard` | `quick` plus current local home, `/private/tmp`, `$TMPDIR`, readable cache roots | 2,000,000 entries per root, depth 64 |
| `deep <path...>` | Explicit roots | 10,000,000 entries per root, depth 128 |
| `full-audit` | Visible local writable data volumes | 100,000,000 entries per volume, depth 128 |

默认不使用 wall-clock 总时限，因为机器负载会改变截断点。可能挂起的外部 collector 使用 deadline；用户可以显式指定 `--max-duration`，此时结果标记 `time-bounded`。

## 7. Interactive Scan

扫描界面显示：

- Profile and elapsed time.
- Entries/directories/candidates.
- Allocated bytes observed and current reclaim estimate.
- Complete and partial roots.
- Current rate, root, and structural budget.

不显示无法证明的完成百分比。扫描阶段快捷键：

- `q`: cancel and exit without a plan.
- `Space`: pause/resume scanning.
- `p`: pause and build a provisional plan.
- `r`: return from the provisional plan and resume.
- `?`: show contextual hotkeys.

provisional plan（基于当前已完整证据生成的临时计划）只能为完整 candidate 给出正常建议。继续扫描会使临时 plan 失效；waiver 不能跨 evidence hash 保留。选择 dry-run/apply 时，用户必须先把当前 partial scan 固化为正式 immutable partial plan。

## 8. Storage Metrics And APFS Dependency Graph

不能把 APFS 占用压缩成一个“准确目录大小”。每个 candidate 分别记录：

- `logical_bytes`
- `nominal_allocated_bytes`
- `immediate_private_reclaim_bytes`
- `conditional_group_reclaim_bytes`
- snapshot/shared/partial unknowns

release set（释放一组共享块所必须移除的完整 owner 集合）使用依赖图表示：

```text
candidate/path nodes
  -> file-object nodes
  -> allocation-group nodes
  -> clone/hardlink/snapshot owners
```

规则：

- 删除一个 clone 可以释放它的 private bytes；共享部分只有 release set 完成后才计入条件释放量。
- `clone_refcnt` 大于 observed owners 时，group 不完整，不给 shared reclaim credit。
- 任一 owner 不安全时，不产生 grouped cleanup recommendation；安全成员仍保留其 private reclaim。
- hardlink 只有 observed link count 等于 `st_nlink` 时才完整。
- snapshot 是 blocker，不自动成为清理目标。
- partial clone 只使用 private-size lower bound。
- apply 前重新验证所有 owner、refcount、link count 和 snapshot blockers。

## 9. File Provider Contract

不维护 provider 名称/path 排除表。系统能力和 filesystem flags 用于发现 provider boundaries：

- `EF_IS_SYNC_ROOT`
- `SF_DATALESS`
- provider identifier/capability probes when available

本地 walker 使用 fd-relative `getattrlistbulk/getattrlistat`，不读取文件内容、不跟随 symlink、不跨 mount。provider root 使用 `NSFileCoordinator` immediate metadata only 和 `URLResourceValues`。

可报告 user-visible materialized footprint；public API 无法获得的 hidden backing/staging 明确记录：

```text
provider_hidden_footprint: unavailable-via-public-api
```

首版不执行 provider eviction、unpin、reset 或 hidden backing cleanup。

## 10. Coverage And Permissions

首版始终使用当前用户身份，不调用 `sudo`，不安装 privileged helper。Full Disk Access 由用户自行授予。

每个 collector/root/candidate 使用 typed coverage：

- `complete`
- `partial`
- `permission_denied`
- `tcc_denied`
- `budget_exhausted`
- `timed_out`
- `mount_boundary`
- `provider_metadata_only`
- `collector_failed`
- `not_requested_by_profile`

“没有发现”只有在对应范围完整时才是负面证据。root-owned 或其他用户拥有且无法完整检查的对象可以报告，但首版不可 stage。TUI 提供 Coverage view；`doctor` 只做只读能力探测，不修改 TCC、SIP 或系统设置。

## 11. Runtime Architecture

### 11.1 Swift Engine

Swift 是唯一的 safety/execution authority，负责：

- macOS/APFS/File Provider/process evidence.
- Classification and policy.
- Release-set graph.
- Immutable plan generation.
- Decision overlay validation.
- Revalidation, dry-run, apply, and post-verify.
- Optional history and execution records.

### 11.2 Rust Frontend

Rust + Ratatui 负责：

- Plan-first TUI.
- Progress, filtering, expansion, columns, and hotkeys.
- Decision overlay editing.
- Revalidation/execution presentation.

Rust 不重新分类，不构造 engine 未提供的 path/action/argv。

### 11.3 IPC

首版使用 length-delimited Protobuf over stdin/stdout：

```text
diskplan (Rust)
  <-> versioned Protobuf envelopes
diskplan-engine (Swift)
```

协议包括 `Hello`、request/response envelopes、progress events、decision overlay、revalidation result 和 execution events。stdout 只承载 binary frames，stderr 承载 diagnostics。major mismatch 拒绝运行；minor 通过 capability negotiation 兼容。

Swift 使用 SwiftProtobuf，Rust 首版使用 `prost`。`.proto` 是权威 schema；生成代码和 cross-language golden frames 必须一起验证。

落盘 artifacts 仍使用可审计 JSON，不用 Protobuf 取代：

- `evidence.json`
- `proposed-plan.json`
- `decision.json`
- `execution-record.json`

## 12. Plan-First TUI

顶层信息架构按 plan 状态和 action type 展开，不按 directory 展开：

1. Ready.
2. Conditional.
3. Needs review.
4. Blocked.
5. Keep/informational.

directory/path 只在单条 action 的 Targets view 中展开。主列包括：

- Decision.
- Plan/action.
- Immediate reclaim.
- Shared unlock.
- Activity.
- Recoverability.
- Status/blocker.

Views 包括 Summary、Targets、Evidence、Dependencies、Revalidation 和 Execution Preview。主要快捷键：

- `j/k` or arrows: move.
- `Enter/l`: expand.
- `h`: collapse.
- `Space`: stage.
- `e`: evidence.
- `t`: targets.
- `g`: dependencies.
- `c`: columns.
- `s`: sort within the current group.
- `/`: filter.
- `p`: plan.
- `D`: dry-run.
- `A`: apply review.
- `?`: hotkey list.
- `q`: quit.

## 13. Immutable Plan And Decision Overlay

scanner facts、classification 和 action definitions 属于 immutable plan。decision overlay 只包含：

- Selected action IDs.
- Allowed policy waivers.
- Waiver reasons.
- User notes.
- Referenced plan/evidence hash.

overlay 不能增加 arbitrary path、argv 或 action ID。evidence hash 变化会使 waiver 失效。

不可 override：

- Object identity/type/device mismatch.
- Symlink or mount escape.
- Access-policy change.
- Collector failure or required incomplete evidence.
- New open/cwd/mapped/provider activity.
- Adapter/tool mismatch.
- Action touching paths outside the plan.
- Release-set owner/refcount/link/snapshot changes.
- Unsynced provider data eviction.

可显式 waiver：

- Recency/age policy.
- Static-only rebuild evidence.
- Unknown rebuild cost.
- Agent-assisted classification.
- Task-semantic completion.
- Duplicate survivor choice.
- Fully observed local Git work discard.
- Normal keep policy.

dirty/untracked Git 内容必须使用专门的 `discard-local-work` action，不得伪装成普通删除。

## 14. Execution Semantics

apply 是 best effort：

- 整体预检后，每个 action 在执行前进行 just-in-time revalidation。
- 某 action 失败时跳过其依赖项，继续完全独立的 action。
- 无法限定影响范围的 protocol、plan hash 或 path escape 错误才停止整个 batch。
- 取消后不启动新 action；当前调用是否能即时中断不作强保证。
- 不承诺 rollback；下次普通 scan 应重新发现残留。
- post-verify 以对象结果为准，卷 free-space delta 只作参考。

generic remove 固定调用 `/bin/rm`，不经 shell、不展开 glob：

| Target | Command shape |
| --- | --- |
| File/symlink | `/bin/rm -- path` |
| Forced file/symlink | `/bin/rm -f -- path` |
| Directory | `/bin/rm -Rx -- path` |
| Forced directory | `/bin/rm -Rfx -- path` |

`requires_force` 必须在 stage 时和 apply review 中提醒。普通失败后不能自动升级为 `-f`、提权或重试。

默认输出为 shell/TUI event stream。history、plan、audit、execution record 和 spill 均可选；`ENOSPC`、只读目录或日志失败不能阻止清理。

## 15. First-Version Scope

### 15.1 Executable Types

- Ordinary local cache/build outputs such as `.venv`, `target`, `build`, DerivedData, and `node_modules` when evidence is sufficient.
- `/private/tmp` and project temporary products.
- Git worktrees through `git worktree remove`.
- `.codex-tmp`, preferring `codex-clean-tmp` when applicable.
- Versioned CLI/app artifacts through a generic versioned-install adapter.
- Complete APFS release sets.
- App-exit cache cleanup after the user exits the app.
- Generic local file/tree removal when the object is understood but no specialized cleanup protocol exists.

### 15.2 Execution Adapters

- `generic-remove`
- `git-worktree-remove`
- `codex-clean-tmp`
- `versioned-artifact-remove`
- `complete-release-set-remove`

### 15.3 Report-Only Types

- File Provider eviction/unpin/reset and hidden backing cleanup.
- APFS snapshot deletion.
- CoreSpotlight rebuild.
- SQLite VACUUM.
- App process close/restart/kill.
- Archive/upload/migration.
- Git GC/LFS prune.
- Package-manager/container prune.

这些项目可以显示为 `managed-action` 或 `future-adapter`，但首版不能 stage。

## 16. Rules And Agent

知识来源分三层：

1. Built-in Swift adapters for authoritative tool/lifecycle behavior.
2. Canonical JSON declarative recognizers for ordinary cache/build/temp patterns.
3. Restricted user policy for protection, adapter enablement, thresholds, profile, budget, and agent mode.

declarative rules 不能执行 shell、下载、创建任意 argv 或绕过 one-vote reject。外部 executable plugins 不进入首版；内部保留 future adapter protocol/capability boundaries。

agent modes：

- `off`
- `ask` (default)
- `auto`

agent 默认只接收 minimal metadata，例如 root alias、relative names、counts/types/sizes/time buckets、manifest names、Git counts 和失败规则。禁止发送 file contents、session history、diff/commit bodies、credential-shaped values、SQLite contents、整个 cloud tree 或 home tree。结果按 model、schema/prompt/policy version、disclosure profile 和 evidence hash 缓存。

## 17. Streaming And Retention

walker 在目录关闭时聚合并分类，普通逐文件信息随后丢弃。必须跨目录保留的索引包括 candidates、clone/hardlink owners、process references 和 incomplete ranges。

默认 retention budgets：

```text
candidate summaries       250,000
shared-object keys      2,000,000
owner references        5,000,000
encoded retained data     768 MiB
```

达到预算后继续扫描 aggregate/progress，但相应 dependency evidence 标记不完整。candidate 使用稳定 top-K，优先保留 immediate reclaim 大的对象，相同时按 canonical path 排序。

可选：

```text
--spill-dir <path>
--spill-max-bytes <size>
```

spill 使用 disposable SQLite，默认关闭，失败只降级 evidence。异常遗留应在后续 scan 中成为清理候选。

## 18. Testing And Acceptance

### 18.1 Test Tiers

- Tier 0: affected targeted tests during development.
- Tier 1: checkpoint/PR builds, core policy fixtures, Protobuf compatibility, TUI snapshots, temp-tree dry-run/apply tests.
- Tier 2: real macOS/APFS/File Provider/bounded full-audit validation on `India-mac-mini-m4-hoteng`.
- Tier 3: reproducible CI on GitHub public macOS runners.

不要求每次运行完整测试。真实 user data 只允许 scan/dry-run；actual mutation tests 只能位于 test-created task-scoped temporary APFS roots。

关键验收：

- one-vote reject and ordering fixtures.
- Clone/hardlink/release-set fixtures.
- Open FD/cwd/mapped activity.
- Scan race and identity/access-policy changes.
- Dry-run mutation guard.
- Force warning and generic remove isolation.
- Best-effort independent-action continuation.
- Optional persistence failures including simulated `ENOSPC`.
- Swift/Rust Protobuf golden frames.
- Ratatui snapshots, resize, and hotkeys.
- Real File Provider non-materialization when capability exists.
- Synthetic million-entry streaming and deterministic retention cutoff.

## 19. Platform And Installation

- Required release gate: Apple Silicon, macOS 26.
- macOS 27+ remains runtime-probed best effort until promoted to the required validation set.
- Deployment target remains macOS 14 initially; macOS 14/15 are best effort and do not block release.
- Each new macOS release can be promoted to required validation while older releases are downgraded to best effort.
- APFS is the complete-capability filesystem; other filesystems degrade by capability.

首版使用无 `sudo` 的 versioned local install：

```text
~/.local/bin/diskplan
  -> ~/.local/libexec/diskplan/<version>/diskplan

~/.local/libexec/diskplan/<version>/
  diskplan
  diskplan-engine
  rules/
  protocol-version
```

Rust launcher 只从自己的 versioned directory 定位 engine。升级通过安装新目录并切换 symlink；installer 不修改 TCC。signed/notarized app bundle、Homebrew packaging 和 universal binaries 后置。

## 20. Implementation Gates And Parallel Work

六个 Phase 表示依赖与验收 gate，不要求严格串行。共享 schema 稳定后，允许独立模块同步开发和验证。

### Phase 0: High-Risk Capability Slice

- APFS/getattrlist probes.
- File Provider metadata-only/non-materialization probe.
- SwiftProtobuf/Rust `prost` stdio handshake.
- Minimal Ratatui scan screen and control keys.
- macOS 26 validation.

### Phase 1: Read-Only Scan To Evidence

- Profiles, deterministic walker, budgets, streaming aggregation.
- Coverage and process/activity snapshot.
- APFS/VM/swap/snapshot baseline.
- Protobuf progress and shell structured output.

### Phase 2: Classify To Plan

- Adapters, recognizers, one-vote policy, recoverability.
- Agent interface/cache contract.
- Release-set graph.
- Immutable plan and overlay.

### Phase 3: Plan-First TUI

- Plan hierarchy/views/columns/filtering.
- Provisional plan and staging.
- Force warnings and large-plan virtualization.

### Phase 4: Revalidate To Dry-Run

- Identity/activity/provider/dependency revalidation.
- Adapter dry-run and generic command preview.
- Best-effort result stream and no-persistence mode.

### Phase 5: Apply

- Enable tested adapters incrementally.
- Fixture-only actual mutation tests.
- Partial failure, cancellation, and post-verify.

### Phase 6: Real-Host Release Acceptance

- `India-mac-mini-m4-hoteng` standard and bounded full-audit.
- APFS/File Provider/activity/performance validation.
- Real candidates remain dry-run during automated acceptance.

并行约束：

- `.proto`/core JSON changes must update both languages and fixtures together.
- Rust TUI can develop against golden plans/fake engine.
- APFS, File Provider, and process collectors can develop behind one `Collector` contract.
- Policy can develop against evidence fixtures without waiting for every collector.
- Execution adapters share one reference revalidation contract; no adapter bypasses it.

## 21. Deferred Decisions

以下内容不阻塞 Phase 0，并在出现真实需求时重新打开：

- Formal product branding beyond the `diskplan` working name.
- Developer ID signing/notarization and public distribution.
- Intel/universal support.
- Privileged helper.
- External executable adapter protocol.
- gRPC/Unix-socket transport or background daemon.
- Provider mutation, system index rebuild, database maintenance, process control, and package/container cleanup adapters.
