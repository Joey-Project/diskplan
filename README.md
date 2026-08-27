# diskplan

`diskplan` 是一个面向 macOS/APFS 的确定性磁盘清理规划工具。它不会把“是否有用”伪装成可计算真值，而是根据可审计证据生成保守建议，让用户先检查、编辑计划，再显式执行。

当前仓库已有 Phase 0 shared-foundation slice，包括 Swift engine、Rust CLI、
versioned Protobuf handshake 和跨语言 canonical binding golden vectors；尚未实现扫描或删除能力。

## 核心流程

```text
read-only scan
  -> typed evidence
  -> deterministic classification
  -> dependency graph
  -> immutable proposed plan
  -> user decision overlay
  -> revalidation
  -> dry-run or best-effort apply
  -> post-scan report
```

核心原则：

- 默认的第一阶段 `scan -> plan` 对被扫描目标完全只读；可选 history、artifact 或 spill 写入必须显式启用并位于扫描范围之外。
- 安全决策采用 one-vote reject（任一强否决证据即可阻止清理），不把多维风险混成一个分数。
- APFS clone、hardlink 和 snapshot 通过共享块依赖图计算立即释放量与条件释放量。
- File Provider 扫描只读取立即可用 metadata，不主动 materialize 文件内容。
- 用户必须显式选择或编辑 decision overlay，之后才进入 `revalidate -> dry-run/apply`。
- 日志、history 和审计文件均可选；磁盘空间不足不能阻止 best-effort 清理。

完整的已确认计划见 [docs/design/accepted-plan.md](docs/design/accepted-plan.md)。当前实施状态见 [project journal](docs/project_journal/2026/08/2026-08-27-phase0-foundation-41f0a2.md)。

## 开发工作流

这个仓库的默认分支 checkout 是 canonical mirror（作为创建和同步 worktree 的干净基线）。首次 bootstrap 后，功能开发应使用 linked worktree、`wip/<topic>` 分支和 pull request。

普通构建和测试只使用已入库的 protobuf generated sources，不要求安装 `protoc`：

```sh
swift build
swift test
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
scripts/test-deployment-target.sh
scripts/test-cross-language.sh
```

只有显式检查或更新 schema/generated sources 时才需要
`proto/toolchain.lock` 中固定版本的工具：

```sh
scripts/proto-codegen.sh check
scripts/proto-codegen.sh generate
scripts/canonical-fixture.sh check
scripts/canonical-fixture.sh generate
```

IPC 与 canonical binary contract 见 [proto/README.md](proto/README.md)。
