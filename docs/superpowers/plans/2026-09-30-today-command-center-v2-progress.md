# SDD ledger — plan: docs/superpowers/plans/2026-09-30-today-command-center-v2.md

Base: f4df9d6f9f7ae72456dc7cef90f6c9beeb1b402a

Ruling: No local worktree is available because the container cannot resolve GitHub and the only connected computer is the shared family PC, which lacks fresh task-specific authorization. Use the isolated GitHub feature branch `agent/gpt/today-command-center-v2` as the workspace; do not use the shared PC.

Pre-flight interface: Task 1 defines the executable shell contract consumed by Task 2; Task 3 adds browser-level coverage for the same behavior if the pre-existing `tests/` lock clears. Task 4 verifies the exact resulting head; Task 5 integrates only that verified head.

Pre-flight constraint: `pushward-live-test-ui.lock` currently covers `app.js`, `index.html`, and `tests/`. Those paths are excluded from Tasks 1–2. `modern-shell.js` requires a separate same-task SHARED lock before modification.
