# diskplan

`diskplan` 是一个面向 macOS/APFS 的确定性磁盘清理规划工具。它不会把“是否有用”伪装成可计算真值，而是根据可审计证据生成保守建议，让用户先检查、编辑计划，再显式执行。

当前仓库已有 Phase 0 shared foundation 与最小 Ratatui frontend shell，包括
Swift engine、versioned Protobuf handshake、scan control/event stream、响应式 scan/provisional-plan
界面和跨语言 canonical binding golden vectors。Phase 0 scan facts 是完全只读且不访问文件系统的
deterministic fixture（确定性测试夹具）；真正的只读 scanner 和任何删除能力尚未实现。

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

完整的已确认计划见 [docs/design/accepted-plan.md](docs/design/accepted-plan.md)。当前 TUI workstream
状态见 [project journal](docs/project_journal/2026/08/2026-08-28-phase0-tui-shell-7c0a91.md)。

## Phase 0 TUI

先构建两个进程，再把 Swift engine 路径交给 Rust frontend：

```sh
swift build --product diskplan-engine
cargo build --locked -p diskplan
cargo run --locked -p diskplan -- "$(swift build --show-bin-path)/diskplan-engine"
```

扫描界面支持 `q`、`Space`、`p`、`r`、`?`，并仅在 scan screen 把 `/` 作为帮助别名。
状态只有在 Swift engine 回应 control acknowledgement 后才变化；`q` 只发送一次取消请求并等待
engine terminal event 与进程回收。engine driver 对 acknowledgement、state、plan 和 terminal event
使用有界无损队列；连续 `ScanProgress` 只保留最新值，但每一个 wire event 仍会先完成严格序列验证。
任何 control acknowledgement 语义不一致都会终止当前 session 并触发 engine cleanup。`--handshake`
保留为无 TUI 的协议诊断入口。

## 开发工作流

这个仓库的默认分支 checkout 是 canonical mirror（作为创建和同步 worktree 的干净基线）。首次 bootstrap 后，功能开发应使用 linked worktree、`wip/<topic>` 分支和 pull request。

普通构建和测试只使用已入库的 protobuf generated sources，不要求安装 `protoc`：

```sh
swift build
swift test
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
INSTA_UPDATE=no cargo test --locked --workspace
scripts/test-deployment-target.sh
scripts/test-cross-language.sh
scripts/test-tui-pty.sh
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

## Release packaging

Apple Silicon macOS 26 的 versioned archive、无 `sudo` 本地安装、升级/回滚、
package lifecycle tests 与 India 主机 dry-run 验收入口见
[docs/release.md](docs/release.md)。release bundle 中的 `diskplan` 默认只解析
同一个 versioned directory 里的 sibling `diskplan-engine`；开发命令仍可显式传入
engine 路径。
