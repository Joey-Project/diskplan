---
id: 20261004-macos15-ci-runner
title: Move macOS 14 deployment compatibility CI to macOS 15 runner
status: completed
created: 2026-10-04
updated: 2026-10-04
branch: wip/macos15-runners
pr:
supersedes: []
superseded_by:
---

# Move macOS 14 deployment compatibility CI to macOS 15 runner

## Summary

- Move the non-blocking deployment compatibility job to the `macos-15` arm64 runner.
- Keep the product deployment target at macOS 14; the job checks that target while running on macOS 15.

## Current State

- The workflow job, runner assertion, and CI reference document use `macos-15` for the best-effort runner.
- The required macOS 26 release gate is unchanged.

## Validation

- Repository CI will validate the workflow and journal. The first PR run must confirm GitHub runner provisioning and the pinned Xcode path.

## Evidence

- `.github/workflows/foundation-ci.yml`
- `.github/CI.md`
