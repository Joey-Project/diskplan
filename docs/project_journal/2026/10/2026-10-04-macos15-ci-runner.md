---
id: 20261004-macos15-ci-runner
title: Raise best-effort macOS deployment target to 15
status: completed
created: 2026-10-04
updated: 2026-10-04
branch: wip/macos15-runners
pr:
supersedes: []
superseded_by:
---

# Raise best-effort macOS deployment target to 15

## Summary

- Set the minimum product deployment target to macOS 15.
- Use the `macos-15` runner for non-blocking deployment-target metadata verification.

## Current State

- SwiftPM, Cargo, and the Rust deployment assertion use macOS 15 as the minimum target.
- The best-effort CI job verifies the Rust binary's macOS 15 minimum-target metadata; it does not run the CLI.
- The required macOS 26 release gate is unchanged.

## Validation

- Repository CI will validate the workflow and journal. The first PR run must confirm GitHub runner provisioning and the pinned Xcode path.

## Evidence

- `.github/workflows/foundation-ci.yml`
- `.github/CI.md`
