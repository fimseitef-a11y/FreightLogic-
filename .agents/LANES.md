# FreightLogic Path Ownership

Ownership is physical-path based. Conceptual ownership does not authorize an edit outside the paths below. `SHARED` means serialized through the lock protocol in `/AGENTS.md`.

This map reflects the post-extraction v24.1 repository. The CSS presentation seam is now real; JavaScript UI/core code inside `app.js` remains serialized until a separately approved extraction creates additional physical paths.

**UI redesign takeover (2026-09-14, operator-directed).** The operator explicitly directed GPT to take over and handle the approved FreightLogic reference-image redesign. `styles.css` is therefore reassigned to `gpt` for the presentation implementation. All other non-`SHARED` paths remain `claude`; this is a targeted presentation takeover, not a blanket ownership transfer.

`SHARED` paths — `app.js`, `index.html`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js`, `manifest.json`, `.agents/`, `AGENTS.md`, `.gitignore`, `.assetsignore` — stay SHARED and still require a held lock, because that serialization protects against concurrent sessions, not just different agents. Commit-prefix discipline, the full-suite gate and release-marker discipline are unchanged. A path with no row still fails closed.

**OMEGA continuation closed (2026-09-15).** The bounded GPT task — app.js economics/math, market-classifier collision and release-generation discipline — **landed in `fb408a0` (PR #200)**, so its six exact-file exceptions are retired and their parent rows own those paths again. Deleted rather than flipped back: a redundant narrower row is just another thing to go stale. The task did not close physical iPhone A1–A10 or M6 raw-data certification, and nothing here does.

**Post-PR-210 full-repair continuation (2026-09-15, operator-directed).** `main` advanced through PR #210 while GPT's reviewed repair PR #209 was in flight. PR #210's zero-token onboarding is authoritative and supersedes the older admin-handler repair; GPT must not restore that old path. The still-confirmed bounded repair is rebased onto current `main` as v24.0.14 / Worker v19: stable internal trip identity (DB16), UNKNOWN payment semantics, explicit-speed-only Profit/Hour, share-target filename hardening, proactive cleanup of reachable legacy v7 plaintext-token residue, the already-approved GPT-owned CSS contribution, and only the regression/release/evidence files required to prove and ship those changes. These exact exceptions expire when the reviewed successor PR lands. Physical iPhone A1–A11 and authentic M6 remain open evidence gates.

| Top-level path | Owner | Notes |
|---|---|---|
| `cloud-backup-worker.js` | gpt | Temporary Worker v19 legacy plaintext-token cleanup exception; preserve PR #210 zero-token onboarding. |
| `tests/integration/full-repair-regressions.spec.mjs` | gpt | Temporary regressions for the bounded post-PR-210 repair. |
| `tests/integration/omega-economics.spec.mjs` | gpt | Temporary DB16 fixture adapter; assertions unchanged. |
| `tests/integration/tax-export-csv-corruption.spec.mjs` | gpt | Temporary DB16 fixture adapter; assertions unchanged. |
| `tests/integration/toctou-concurrent-edit.spec.mjs` | gpt | Temporary DB16 fixture adapter; concurrency assertions unchanged. |
| `tests/integration/field-resilience.spec.mjs` | gpt | Temporary DB16 fixture adapter; resilience assertions unchanged. |
| `tests/integration/backup-restore-parity.spec.mjs` | gpt | Temporary DB16 fixture adapter; restore-parity assertions unchanged. |
| `tests/unit/worker-invite-claim.spec.mjs` | gpt | Temporary Worker v19 health-generation assertion update; onboarding assertions unchanged. |
| `tests/unit/worker-token-rotation.spec.mjs` | gpt | Temporary legacy-token cleanup regression exception. |
| `tests/unit/cache-generation.spec.mjs` | gpt | Temporary DB16/app-generation invariant update. |
| `tests/run-all.mjs` | gpt | Temporary regression-registration exception; preserve PR #210 test registrations. |
| `scripts/verify-cloudflare-parity.mjs` | gpt | Temporary app/Worker parity marker update. |
| `midwest-stack-config.json` | gpt | Temporary appTarget release-marker update only. |
| `midwest-stack-authority.js` | gpt | Temporary release-marker update only. |
| `voice-load.js` | gpt | Temporary release-marker update only. |
| `CLAUDE.md` | gpt | Temporary current-release/evidence documentation exception; preserve zero-token onboarding documentation. |
| `FIELD_TEST_CHECKLIST.md` | gpt | Temporary release/evidence documentation exception; A1–A11 stay open. |
| `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` | gpt | Temporary parity-evidence documentation exception. |
| `docs/BACKUP_CONTRACT.md` | gpt | Temporary DB16 stable-identity migration/restore contract amendment. |
| `.assetsignore` | SHARED | Repository/deployment metadata; coordinate changes. |
| `.github/` | claude | Consolidated to the Claude completion lane on 2026-09-14; release/certification workflows. |
| `.githooks/` | claude | Lane-guard git hooks; enforcement tooling for this map. |
| `.gitignore` | SHARED | Repository-wide behavior. |
| `.agents/` | SHARED | Durable protocol on `main`; live state on `agent-coordination`. Do not edit another agent's live lock/inbox entry except per protocol. |
| `AGENTS.md` | SHARED | Coordination contract. |
| `AUDIT_REPORT.md` | claude | Core audit record; findings are recorded with their reproduction and their live production status. |
| `README.txt` | claude | General/non-core documentation. |
| `RECON_24_0_2.md` | claude | Read-only core reconciliation/audit artifact; maintained with the Claude core/audit lane. |
| `_headers` | claude | CSP/security/deployment headers. |
| `admin-driver-ui.js` | claude | PR #210 zero-token onboarding makes this module explicitly stand down; do not restore the superseded GPT admin-handler patch. |
| `app.js` | SHARED | **Serialized until split. Any edit requires `lock/app-js` and full suite.** Decision/runtime/core behavior remains serialized. |
| `dat-rateview.js` | claude | Freight-rate source client. Frozen/dormant and non-authoritative per the completion plan; may not influence canonical cargo-van pricing without operator re-authorization. |
| `docs/` | claude | Certification, backup/tax/authority contracts, completion plan and release documentation except exact temporary rows above. |
| `favicon16.png` | claude | Visual asset. |
| `favicon32.png` | claude | Visual asset. |
| `icon1024.png` | claude | Visual asset. |
| `icon120.png` | claude | Visual asset. |
| `icon128.png` | claude | Visual asset. |
| `icon152.png` | claude | Visual asset. |
| `icon167.png` | claude | Visual asset. |
| `icon180.png` | claude | Visual asset. |
| `icon192.png` | claude | Visual asset. |
| `icon256.png` | claude | Visual asset. |
| `icon512.png` | claude | Visual asset. |
| `icon64.png` | claude | Visual asset. |
| `index.html` | SHARED | UI shell + CSP/script ordering; lock before editing. |
| `manifest.json` | SHARED | PWA/release + visual metadata; lock before editing. |
| `modern-shell.js` | SHARED | Driver-facing structural navigation seam. Reuses canonical app renderers/state; lock before editing and run the full suite for behavior changes. |
| `schemas/` | claude | Data/contracts. |
| `scripts/` | claude | Release/certification tooling and deploy-asset inventory except exact temporary row above. |
| `service-worker.js` | SHARED | Offline shell/release-critical. Lock before editing; full suite required. |
| `styles.css` | gpt | Operator-directed 2026-09-14 presentation takeover for the approved reference UI redesign. It carries **no version string** by design — `tests/unit/cache-generation.spec.mjs` CG-11 asserts the absence. |
| `sw-bridge.js` | SHARED | Service-worker integration/release-critical. |
| `tests/` | claude | Playwright suite except exact temporary rows above. Assertions may not be weakened or quarantined to make a release green. |
| `vendor/` | claude | Bundled runtime dependencies/security provenance. |
| `wrangler.jsonc` | claude | Worker deployment/configuration. |

## Current lane intent

- `styles.css` remains GPT-owned for the approved redesign.
- `app.js` remains `SHARED` and requires the current covering lock plus a full suite.
- PR #210 zero-token onboarding is authoritative; the bounded repair may extend it but must not reinstate the superseded raw-token/admin-handler flow.
- The post-PR-210 full-repair exception is narrow and temporary: only the exact rows above are GPT-owned for this task.
- The rest of the `SHARED` set remains serialized because it is release-critical or protocol surface.
- Every other non-excepted path remains Claude-owned.

The CSS seam stays a real physical boundary and is worth keeping: presentation changes in `styles.css` do not need an `app.js` lock. It does **not** cover UI sections that still live inside `app.js` — those remain `SHARED` until an approved extraction creates more physical paths.

`/.agents/inbox/` remains the cross-session handoff channel.

## Enforcement

This map is enforced mechanically, not by recollection:

- `scripts/lane-guard.mjs` parses **this file** as the single source of truth. There is no second machine-readable ownership file to drift.
- `.githooks/pre-commit` rejects a staged change to a foreign lane, and a staged change to a `SHARED` path with no held lock covering that path. Enable per clone: `git config core.hooksPath .githooks` and `git config freightlogic.agent <claude|gpt>`.
- `.github/workflows/lanes.yml` re-checks path ownership and commit prefixes on every PR to `main`. The hook is fast feedback and is bypassable; CI is the boundary.
- A path with **no row in this table** fails closed. Adding a file means adding its row.
- A lock past `expected_release_utc` + 2h is reported as **stale**. It grants nothing and is never auto-stolen; reap it deliberately per `/AGENTS.md`.

## Cross-lane requests

If a task requires a foreign path, write a request under `/.agents/inbox/` on `agent-coordination`. Do not make an opportunistic cross-lane edit.
