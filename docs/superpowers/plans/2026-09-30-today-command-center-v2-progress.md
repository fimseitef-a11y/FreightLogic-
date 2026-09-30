# SDD ledger — plan: docs/superpowers/plans/2026-09-30-today-command-center-v2.md

Base: f4df9d6f9f7ae72456dc7cef90f6c9beeb1b402a

Ruling: No local worktree is available because the container cannot resolve GitHub and the only connected computer is the shared family PC, which lacks fresh task-specific authorization. Use the isolated GitHub feature branch `agent/gpt/today-command-center-v2` as the workspace; do not use the shared PC.

Pre-flight interface: Task 1 defines the executable shell contract consumed by Task 2; Task 3 adds browser-level coverage for the same behavior if the pre-existing `tests/` lock clears. Task 4 verifies the exact resulting head; Task 5 integrates only that verified head.

Pre-flight constraint: `pushward-live-test-ui.lock` currently covers `app.js`, `index.html`, and `tests/`. Those paths are excluded from Tasks 1–2. `modern-shell.js` requires a separate same-task SHARED lock before modification.

Task 1: complete. RED observed with `node scripts/test-today-command-center-v2.mjs` against the exact base `modern-shell.js` behavior: assertion failed because `installTodayCommandCenter` was `undefined`. The contract was committed as `5bb7f707760e70b857d2c3018243e845178f8cbc` and later strengthened with executable fuel-route assertions.

Task 2 lock: claimed and fresh-read verified on `agent-coordination` as `.agents/locks/today-command-center-v2.lock`, owner `gpt`, token `54c09d42-db16-4f40-855a-d95ace8417fd`, path `modern-shell.js` only.

Task 2 Ruling: The plan originally put scoped presentation rules in `styles.css`. The available GitHub write connector replaces whole files rather than patching, and `styles.css` is ~111 KB. A new external CSS runtime asset would require service-worker/precache integration on another SHARED path, expanding scope while an unrelated lock is active. Keep the complete Today-v2 presentation style block atomically inside `modern-shell.js` as an injected self-hosted `<style>` element. This preserves offline behavior, CSP compatibility (`style-src 'unsafe-inline'` already governs existing inline styles), and the one-locked-seam boundary. Cost if wrong: presentation code is less physically separated until a later governed extraction.

Task 2 local GREEN: `node scripts/test-today-command-center-v2.mjs` → `Today command center v2 contract: PASS`. The strengthened contract additionally verified that Fuel Update routes to `#insights`, expands All Settings, scrolls the Money & Accounting section, focuses `#fuelPrice`, and reveals the field. Branch/CI verification is still required before Task 2 is called integrated.

Task 3 constraint rechecked after implementation: the prior `pushward-live-test-ui.lock` still exists and still covers `tests/`; it is not yet eligible for protocol reaping. No `tests/` edit has been made.
