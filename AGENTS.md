# Diskplan Repository Guidelines

- Treat `/Users/hoteng/Program/GitHub/diskplan` as the canonical checkout of the default branch.
- The initial bootstrap commit is the only direct setup exception. Perform subsequent feature work in linked worktrees on `wip/<topic>` branches and land it through pull requests.
- Keep the canonical checkout clean and suitable for creating or updating worktrees.
- Project journaling is adopted. Keep ordinary workstream state in `docs/project_journal/YYYY/MM/*.md`; do not commit the generated `docs/project_journal/INDEX.md`.
- Keep stable architecture decisions in `docs/design/accepted-plan.md` and link to them from journals instead of duplicating them.
- The Swift engine is authoritative for evidence collection, policy, planning, revalidation, and execution. The Rust frontend must not duplicate safety classification.
- Treat `proto/` as the source of truth for Swift/Rust IPC schemas. Schema changes must update both generated sides and compatibility fixtures together.
- Phase-one scanning is read-only. Never add a scan-path mutation as an optimization or probe.
- Tests may mutate only test-created task-scoped temporary roots. Existing user data is limited to scanning and dry-run validation.
- Default to targeted tests during development. Run broader local, remote macOS, and GitHub runner gates only at the checkpoints defined in the accepted plan.
- macOS 26 on Apple Silicon is the release gate. Older supported deployment targets and newer unverified macOS releases are best effort through runtime capability checks.
