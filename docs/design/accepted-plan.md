# Diskplan Accepted Design Plan

## 1. 目标与边界

`diskplan` 将已有的人工磁盘清理流程产品化为确定性、可审计的 macOS 工具。工具不直接判断文件对用户是否“有用”，而是把结果表达为：

```text
evidence -> deterministic classification -> recommendation -> uncertainty
```

只有证据足够的对象才能得到可执行建议；语义未知、证据不完整或运行状态不安全的对象保留为 review/blocked 状态。

首版是可执行产品，但严格分成两个阶段：

1. `scan -> plan`：对扫描目标完全只读。默认模式不产生持久写入；用户显式启用的 history、artifact 或 spill 属于 tool-owned side effects，并且必须位于所有活动扫描 root 之外。
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

1. Explicit protection and type-hint routing.
2. Authoritative tool adapters.
3. Structural recognizers.
4. Path conventions.
5. Generic unknown fallback.

第一级是非对称的：explicit protection 只能阻止或降低建议；explicit type hint 只能选择需要运行的 recognizer 或补充语义，不能覆盖 authoritative evidence、提升最终安全等级或绕过 hard gate。所有放宽必须通过当前 plan 中明确列举的 waiver，并绑定 evidence hash。同一有效优先级发生冲突时返回 `classification-conflict`。agent 可以提出候选类型、缺失证据和新规则建议，但其输出必须标记为 `agent-assisted`，不能覆盖 explicit/authoritative evidence，也不能单独产生 `safe-to-clean`。

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

动态验证不属于默认 scan。用户显式启用后，它只能在所有 scan/provider roots 之外的 task-scoped disposable copy 中运行，并使用隔离的 cache、temporary directory、home/config 和 package-manager state；不允许写回扫描目标或隐式使用全局可写状态。复制前必须以 metadata-only 方式检查整个 source coverage；任何 provider-bound、dataless 或可能因读取而 materialize 的 source 在首版拒绝动态验证，未来只能通过单独且明确确认的 materialization action 进入。无法证明隔离或 non-materialization 的 build、install、download、copy 或 round-trip verification 必须作为另行确认的有副作用 action，不能参与只读 `scan -> plan`。

建议必须区分：

- Provider-owned reclaimable storage.
- Exactly recoverable data.
- Statically rebuildable output.
- Probably rebuildable output.
- Duplicate data with a designated survivor.
- Unique or unknown content.

## 6. Scan Profiles And Determinism

确定性契约是：相同文件系统状态、相同进程/权限可见性、相同配置、相同 policy version 和相同冻结的 semantic time inputs，产生相同分类、action、stable ID、依赖图和排序。

实现要求：

- 按文件系统原始名称字节排序，不依赖 locale。
- collector/adapters 的并发完成顺序不影响最终输出。
- 外部工具先解析为 typed records，再 canonical sort。
- scan 开始时冻结 `scan_reference_time`；age、recency 和 `inactive_duration` 只相对该值计算。影响分类、排序、action 或 agent cache 的 filesystem/history time 与冻结 reference time 进入 plan provenance。稳定的 waiver consent core 只绑定 action lineage、policy version、被 waive 的 exact predicate/value bucket、其语义 evidence subset 和用户理由；纯粹时钟推进但未改变这些语义值时，不撤销 consent core。它不是执行凭证。
- report 生成时间、UI 刷新时间等纯展示字段不进入 evidence hash。
- apply review 前的整体 revalidation 创建有 deadline 的 `execution_epoch`，冻结一个新的 `execution_reference_time` 并重新计算 plan/evidence/policy binding。engine 只有在 action lineage、waived predicate/value bucket、其 semantic evidence subset 均相同，全部 non-waived gates 通过、受保护属性未变化且用户未撤销时，才可从 consent core 为当前 epoch 签发新的 execution credential；否则用户必须基于新结果重新确认。随后同一 execution epoch 内的 JIT revalidation 复用该冻结语义时间，但仍实时检查 identity、content、access policy、activity、provider 和 dependency evidence。credential 在 epoch/deadline、plan/action/evidence ID 任一不匹配时立即拒绝，不能跨 epoch 重放；跨过相关 policy threshold 时 consent 必须重新确认，旧 agent cache 也不能继续命中。
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
- clone group 只有 `clone_refcnt == observed owners` 时才完整；任一方向不相等都标记 incomplete/conflict，不给 shared reclaim credit。
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

所有位于 File Provider boundary 内、带 provider ownership/capability evidence，或标记 dataless 的 path 在首版都是 non-stageable hard gate，包括已经 materialized 的普通文件。它们只能得到 `managed-by-provider`/report-only 结果；`generic-remove`、Git、release-set 和其他删除 adapter 都必须 fail closed，不能让 cache/path recognizer 绕过 provider boundary。未来任何可能传播为 cloud delete、eviction、unpin 或 materialization 的动作都需要专用 provider adapter 和独立确认。

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

overlay 不能增加 arbitrary path、argv 或 action ID。overlay 保存用户 consent core；由 engine 派生的 epoch-scoped execution credential 不可编辑。evidence/plan/action hash 变化始终使旧 execution credential 失效，但只有满足 6 节完整续签条件时才允许复用 consent core，无条件 remap 或重放都 fail closed。

explicit protection/type hint 同样受这个边界约束：protection 可以直接阻止 action；type hint 只能补充 classification input。任何提升风险容忍度的用户决定必须落在下方明确允许的 waiver 集合中。

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
- Normal keep policy.

v1 的 dirty/untracked Git 内容及其 dependent remove chain 固定为 report-only：plan 可保留专门的 `discard-local-work` action、完整证据和 successor baseline 用于解释，但该 action 不可 stage、不可 waiver，apply preparation 不得为它签发 capability。只有 clean worktree 的 descriptor-bound quarantine remove 可执行。

### 13.1 Canonical IDs And Bindings

所有用于执行授权或 cache 命中的 ID/hash 都来自 versioned closed typed binding schema，不能由各模块临时选择字段。权威 schema 与 `.proto` 同仓维护，但摘要输入使用独立的 `canonical-binary-v1` 编码，避免依赖未保证 canonical 的普通 Protobuf serialization：

- record 使用固定 field order；整数为 fixed-width big-endian；bytes/path 使用 length prefix 并保留 filesystem raw name bytes；timestamp 使用 UTC seconds+nanos；禁止 map；具有集合语义的 repeated field 按其 canonical byte key 排序；absent、unknown、unreadable、failed 和 empty 使用不同 typed variants；
- digest 使用 SHA-256，并以 `diskplan/<binding-kind>/v1\0` 做 domain separation；不同 kind 至少包括 evidence、action-lineage、action、plan、waiver-consent、waiver-credential 和 agent-cache；
- evidence binding 封闭纳入 root/candidate object identity、raw relative path、coverage、collector success/failure、activity、provider/dataless state、recoverability、content/access-policy facts、APFS owner/dependency evidence、profile/config/policy/schema version 和所有 policy-relevant semantic time values；
- action lineage ID 封闭纳入 policy/schema version、adapter/action type、typed arguments、target object identity/raw path、protected-property contract、expected postcondition 和有方向的 prerequisite lineage IDs，但排除 reference time、epoch 和可重新计算的 evidence ID；action ID 再封闭纳入当前 evidence ID 与 prerequisite action IDs；plan hash 纳入 canonical ordered actions、release sets、global coverage/config/schema/policy versions；
- waiver consent binding 封闭纳入 action lineage ID、policy version、被 waive 的 exact predicate/value bucket、其 semantic evidence subset、用户理由和 consent event ID；waiver credential 再纳入 consent hash、当前 plan/action/evidence ID、execution epoch/reference time/deadline。agent cache 另外纳入 model、prompt/schema/policy version、disclosure profile 与实际 disclosed metadata binding。

schema 未知字段、缺少 required variant 或 canonical decode/round-trip 不一致时，execution fail closed，最多 report-only。任何安全相关字段增删都必须 bump binding version，并同时更新 Swift/Rust golden vectors；不能通过忽略新字段维持旧 waiver、ID 或 cache hit。

## 14. Execution Semantics

apply 是 best effort：

- 整体预检后，每个 action 在执行前进行 just-in-time revalidation。
- action DAG 的边固定为 `prerequisite -> dependent`。prerequisite 发生 failed、skipped、cancelled 或 partial outcome 时，所有 downstream dependents 转为 `blocked-by-prerequisite`；它所依赖的 upstream prerequisites 不受反向影响，完全独立的 action 继续。
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

### 14.1 Protected Properties And Path-Race Boundary

revalidation 必须为每类 action 分别声明：从 plan 到 use 必须成立的 preconditions、调用期间需要维持的 invariants，以及成功/失败后的 postconditions。成功删除的正常 postcondition 是目标 slot absent 或 adapter 明确声明的 expected residual，而不是要求被删 object 的 identity/content 继续存在。

可作为 precondition 或 invocation invariant 的受保护属性包括：

- Object identity: no-follow `st_dev`, `st_ino`, file type，以及 filesystem 可用时的 generation/birth identity。
- Content stability: 仅在 recoverability/action contract 依赖内容时比较 size、content digest 或其他明确内容信号；普通 `mtime` 变化只触发重新读取，不能单独宣称内容变化。
- Access policy: owner、group、mode、ACL、immutable/restricted flags 和 mount/device boundary。

directory child-entry churn、directory size/link-count/mtime 变化只有在 action contract 选择 subtree content stability 时才是阻断信号；否则它们是需要重新枚举的 generation hint。unreadable/revalidation failure、missing、identity mismatch、content mismatch 和 access-policy mismatch 必须保持不同状态。

`/bin/rm` 是 pathname-based，无法原子关闭“最后一次 revalidation 到 rm 使用路径”之间的竞态。因此 generic remove 只能用于明确标记为 `path-slot-removal` 的 action：用户授权清理的是受约束 parent 下的 exact pathname slot，包括 revalidation 后仍可能出现的 occupant/children；adapter 还必须证明整个 parent namespace 在调用期间只由受信任主体控制，或该 slot 的每一种可能 occupant 都属于同一 disposable class。它必须在 spawn 前最后一次 revalidate 已固定的 parent chain、mount boundary、exact basename 和 no-follow root semantics；计划和 TUI 同时显示 `path_race_residual: true`，并明确它不能保证删除的是此前观察到的 object。

如果 action 的安全性要求“只能删除此前验证的那个 object”、完整 subtree content stability，或 parent namespace 可能被不受信任主体并发修改，它不能使用 generic `/bin/rm` fallback；首版必须使用持有已验证 parent descriptor 并通过 `unlinkat`/descriptor-relative traversal 等方式维持 object/namespace binding 的专用 native adapter，先原子 quarantine 到同一受控 filesystem 后再删除，或者降级为 report-only。one-vote reject 只保证阻止 revalidation 时已经可见的新增 path、path escape、mount crossing 或不合格 replacement；generic path-slot action 对检查后的变化只依赖其显式 slot authorization 和 trust precondition，不能声称 engine 会再次观察并否决。

### 14.2 Git Worktree Removal Completeness

`git-worktree-remove` 和 `discard-local-work` 不能把普通 `git status` 视为完整观察。允许 stage 之前必须同时证明：

- engine 对 worktree filesystem 做 no-follow 完整 traversal，覆盖 tracked、untracked、ignored/excluded entries，并对 unreadable、budget exhaustion、mount crossing 或 scan race fail closed；
- Git adapter 记录 HEAD/index、staged/unstaged/unmerged state、worktree registration 和 administrative metadata，并验证 worktree root identity；
- nested repositories、submodules、linked worktrees 和 sparse-checkout state 被显式识别；其本地内容必须分别证明 recoverable 或作为用户可见的 unique/local changes 进入同一 action；
- action 执行前重新验证 filesystem coverage、Git state 和所有已声明 local-change entries，任何新增或未观察项目都阻止 stage/apply。

上述 coverage 在 v1 只用于解释 dirty worktree、冻结 future adapter contract 与拒绝理由；它不启用 destructive waiver。所有 dirty discard/remove action 都是 report-only，adapter 不得因 Git porcelain 未报告 ignored data 就推断目录可安全删除。未来若引入可执行 discard，必须作为新的专用 adapter/waiver 版本重新验收，不能复用当前 plan 或 consent。

point-in-time coverage 仍不足以授权 pathname-based forced removal。所有会移除 worktree root 的 Git action 都必须把 namespace binding 延续到 use。mutation 前必须证明 source parent chain 是 owner-private、无 group/other writer、无 provider/mount boundary，并且 activity snapshot 没有其他 process reference；adapter 将它标记为 `trusted-exclusive-namespace`。同一用户的恶意或不可观测并发 namespace mutation不在首版可安全执行的 threat model 内；无法满足该 trust precondition 时必须 report-only，不能先移动后判断。

满足 trust precondition 后，revalidation 通过已验证 parent descriptor no-follow 打开 root 并固定 object identity，再用 exclusive/no-clobber `renameatx_np` 将 exact slot 原子移入同一 filesystem 上 engine-owned、owner-private 的 quarantine namespace。quarantine 后必须从 held descriptor 与 destination descriptor 双向确认是同一 object，并在受控 namespace 中重新完成 no-follow subtree coverage；token 分别绑定每个目录、普通文件和 symlink 的 identity、content 与 access policy（含 descriptor-bound ACL）。pre/post token 必须在任何 post-rename 取消或超时恢复之前比较。任一受保护属性差异都禁止删除；只有 typed recovery policy 明确允许的验证失败才可尽力原子恢复原 slot，且恢复路径必须先为当前 quarantine 建立稳定 descriptor-bound snapshot，再在 recovery hook/准备完成后、`renameatx_np` 提交前完整复验 identity、content 与 access policy。access-policy drift 必须保留 quarantine 供人工恢复，否则在 event stream 报告可恢复 locator 或 unverified binding。递归删除在每次 `unlinkat` 前重新以 descriptor-relative 方式验证该 exact node 的 identity、content 与 access policy；子节点已按 token 删除后不把目录 size/mtime churn 当作目录 content drift，新出现的 child 则由 non-empty removal fail closed。之后再 best-effort 清理 Git administrative state。overlay 必须显示 namespace trust、quarantine 与 Git metadata cleanup 是同一 action 的 prerequisite/dependent steps。普通 `git worktree remove` 不能作为绕过该规则的强制删除 fallback。

默认输出为 shell/TUI event stream。history、plan、audit、execution record 和 spill 均可选；`ENOSPC`、只读目录或日志失败不能阻止清理。

## 15. First-Version Scope

### 15.1 Executable Types

- Ordinary local cache/build outputs such as `.venv`, `target`, `build`, DerivedData, and `node_modules` when evidence is sufficient.
- `/private/tmp` and project temporary products.
- Git worktrees through the dedicated `git-worktree-remove` adapter: descriptor-bound atomic quarantine removes the root; Git commands may only perform subsequent administrative metadata cleanup, whose failure is recorded as partial/expected residual.
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

启用 spill 时，`--spill-dir` 必须证明位于所有活动 scan roots 和 provider roots 之外，并从本次扫描视图中按已绑定的 device/inode root 排除；无法证明隔离时拒绝启用 spill。engine 必须 no-follow 创建 owner-private task directory，持有并持续验证其 parent/directory descriptor、identity 和 access policy；每次 SQLite open/write 都必须通过 descriptor-relative custom VFS 或等价的 stable binding，不能重新信任未经绑定的 pathname。任一 ancestor replacement、symlink redirection 或 access-policy mismatch 都 fail closed；平台 SQLite 接口无法维持该保证时禁用 spill。TUI 必须把该次运行标记为 `scan_write_mode: spill-enabled`，不得继续显示为默认 no-persistence read-only mode。

history、saved plan、audit 和 execution artifacts 使用同一安全 writer：扫描结束后在所有 scan roots 和 provider roots 之外 no-follow 创建 owner-private task directory；destination 及完整 ancestor chain 必须没有 provider boundary、provider capability 或 dataless evidence。writer 以 descriptor-relative open 和 exclusive/no-clobber temporary name 写入，再原子发布且绝不覆盖已有用户文件。任何 identity、ancestor、symlink、provider 或 access-policy mismatch 都停止该可选写入；首版不提供 provider-write fallback。失败不改变 scan/plan/apply 结果。若失败发生在创建 artifact 之后，event stream 尽力报告 retained recovery locator；无法安全发布或报告时允许留下后续 scan 可发现的 task-scoped artifact。

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

七个 Phase（Phase 0 至 Phase 6）表示依赖与验收 gate，不要求严格串行。共享 schema 稳定后，允许独立模块同步开发和验证。

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
- The authoritative implementation contract is documented in
  [`revalidation-and-dry-run.md`](revalidation-and-dry-run.md).
- Best-effort result stream and no-persistence mode.

### Phase 5: Apply

- Enable tested adapters incrementally.
- Fixture-only actual mutation tests.
- Partial failure, cancellation, and post-verify.
- The authoritative implementation contract is documented in
  [`best-effort-apply.md`](best-effort-apply.md).

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
