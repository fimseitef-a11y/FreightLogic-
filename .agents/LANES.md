# FreightLogic Path Ownership

Ownership is physical-path based. Conceptual ownership does not authorize an edit outside the paths below. `SHARED` means serialized through the lock protocol in `/AGENTS.md`.

This map reflects the post-extraction v24.1 repository. The CSS presentation seam is now real; JavaScript UI/core code inside `app.js` remains serialized until a separately approved extraction creates additional physical paths.

**UI redesign takeover (2026-09-14, operator-directed).** The operator explicitly directed GPT to take over and handle the approved FreightLogic reference-image redesign. `styles.css` is therefore reassigned to `gpt` for the presentation implementation. All other non-`SHARED` paths remain `claude`; this is a targeted presentation takeover, not a blanket ownership transfer.

`SHARED` paths — `app.js`, `index.html`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js`, `manifest.json`, `.agents/`, `AGENTS.md`, `.gitignore`, `.assetsignore` — stay SHARED and still require a held lock, because that serialization protects against concurrent sessions, not just different agents. Commit-prefix discipline, the full-suite gate and release-marker discipline are unchanged. A path with no row still fails closed.

**OMEGA continuation closed (2026-09-15).** The bounded GPT task — app.js economics/math, market-classifier collision and release-generation discipline — **landed in `fb408a0` (PR #200)**, so its six exact-file exceptions are retired and their parent rows own those paths again. Deleted rather than flipped back: a redundant narrower row is just another thing to go stale. The task did not close physical iPhone A1–A10 or M6 raw-data certification, and nothing here does.

**Full-repair takeover (2026-09-15, operator-directed).** The operator explicitly directed GPT to fix every confirmed bug/error and reconcile the latest Grok/DeepSeek audit inputs without restarting or undoing verified work. This is a bounded repair/certification task, not a permanent lane transfer. The exact-file exceptions below authorize GPT to repair only the confirmed first-use cloud-admin race, trip identity/import data loss, payment-state UNKNOWN coercion, invented profit/hour speed, share-target filename hardening, legacy token cleanup gaps, and the release/test/docs files needed to prove and ship those fixes. DeepSeek's alleged 24.0.12/24.0.11 version mismatch was rejected by exact HEAD + post-deploy live parity and is not a repair target. These exceptions expire when the full-repair PR lands; parent ownership resumes immediately afterward. Physical iPhone A1–A10 and authentic M6 raw-data certification remain open evidence gates.

| Top-level path | Owner | Notes |
|---|---|---|
| `.github/workflows/full-repair-once.yml` | gpt | Temporary one-shot patch/test helper for this bounded repair; delete before merge. |
| `admin-driver-ui.js` | gpt | Temporary full-repair exception for first-use Manage Drivers event ownership and rotation parity. |
| `cloud-backup-worker.js` | gpt | Temporary full-repair exception for verified legacy plaintext-token cleanup gaps; bump Worker generation deliberately if source changes. |
| `tests/integration/full-repair-regressions.spec.mjs` | gpt | Regression coverage for field-observed/admin/import/payment/economics/share-target defects. |
| `tests/unit/worker-token-rotation.spec.mjs` | gpt | Temporary exception to strengthen legacy-token cleanup regression coverage. |
| `tests/run-all.mjs` | gpt | Temporary exception to register full-repair regression suite. |
| `scripts/verify-cloudflare-parity.mjs` | gpt | Temporary release-marker exception if the app generation advances. |
| `midwest-stack-config.json` | gpt | Temporary release-target marker exception only. |
| `midwest-stack-authority.js` | gpt | Temporary release-marker exception only. |
| `voice-load.js` | gpt | Temporary release-marker exception only. |
| `CLAUDE.md` | gpt | Temporary release/evidence documentation exception only. |
| `FIELD_TEST_CHECKLIST.md` | gpt | Temporary release/evidence documentation exception; A1–A10 remain open. |
| `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` | gpt | Temporary release/evidence documentation exception only. |
| `.assetsignore` | SHARED | Repository/deployment metadata; coordinate changes. |
| `.github/` | claude | Consolidated to the Claude completion lane on 2026-09-14; release/certification workflows except exact temporary row above. |
| `.githooks/` | claude | Lane-guard git hooks; enforcement tooling for this map. |
| `.gitignore` | SHARED | Repository-wide behavior. |
| `.agents/` | SHARED | Durable protocol on `main`; live state on `agent-coordination`. Do not edit another agent's live lock/inbox entry except per protocol. |
| `AGENTS.md` | SHARED | Coordination contract. |
| `AUDIT_REPORT.md` | claude | Core audit record; findings are recorded with their reproduction and their live production status. |
| `CLAUDE.md` | claude | Core architecture/operations context except exact temporary row above. |
| `FIELD_TEST_CHECKLIST.md` | claude | Physical-iPhone verification instrument maintained with release certification except exact temporary row above. |
| `README.txt` | claude | General/non-core documentation. |
| `RECON_24_0_2.md` | claude | Read-only core reconciliation/audit artifact; maintained with the Claude core/audit lane. |
| `_headers` | claude | CSP/security/deployment headers. |
| `admin-driver-ui.js` | claude | Admin UI except exact temporary row above. Auth/storage semantics here are core: the session-scoped admin token and `purgeLegacyTok()` are load-bearing and documented in CLAUDE.md. |
| `app.js` | SHARED | **Serialized until split. Any edit requires `lock/app-js` and full suite.** Decision/runtime/core behavior remains Claude-owned unless explicitly reassigned. |
| `cloud-backup-worker.js` | claude | Backup/API Worker source except exact temporary row above. Worker v17 is the pre-repair generation. |
| `dat-rateview.js` | claude | Freight-rate source client. Frozen/dormant and non-authoritative per the completion plan; may not influence canonical cargo-van pricing without operator re-authorization. |
| `docs/` | claude | Certification, backup/tax/authority contracts, completion plan and release documentation except exact temporary row above. |
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
| `midwest-stack-authority.js` | claude | Decision/bid advisory core and DZ gate integration except exact temporary marker row above. |
| `midwest-stack-config.json` | claude | Decision/bid configuration except exact temporary marker row above. |
| `modern-shell.js` | SHARED | Driver-facing structural navigation seam. Reuses canonical app renderers/state; lock before editing and run the full suite for behavior changes. |
| `schemas/` | claude | Data/contracts. |
| `scripts/` | claude | Release/certification tooling and the deploy-asset inventory except exact temporary row above. |
| `service-worker.js` | SHARED | Offline shell/release-critical. Lock before editing; full suite required. |
| `styles.css` | gpt | Operator-directed 2026-09-14 presentation takeover for the approved redesign. It carries **no version string** by design — `tests/unit/cache-generation.spec.mjs` CG-11 asserts the absence. |
| `sw-bridge.js` | SHARED | Service-worker integration/release-critical. |
| `tests/` | claude | Playwright suite except exact temporary rows above. Assertions may not be weakened or quarantined to make a release green. |
| `vendor/` | claude | Bundled runtime dependencies/security provenance. |
| `voice-load.js` | claude | Functional intake/parser behavior except exact temporary marker row above. |
| `wrangler.jsonc` | claude | Worker deployment/configuration. |

## Current lane intent

- `styles.css` remains GPT-owned for the approved redesign.
- `app.js` remains SHARED and needs `lock/app-js` plus the full suite for any edit.
- The full-repair exception is narrow and temporary: only the exact rows above are GPT-owned for this operator-directed repair.
- All non-excepted Claude paths remain Claude-owned.

The CSS seam stays a real physical boundary and is worth keeping: presentation changes in `styles.css` do not need an `app.js` lock. It does **not** cover UI sections that still live inside `app.js` — those remain SHARED until an approved extraction creates more physical paths.

`/.agents/inbox/` remains the cross-session handoff channel.

## Enforcement

This map is enforced mechanically, not by recollection:

- `scripts/lane-guard.mjs` parses **this file** as the single source of truth. There is no second machine-readable ownership file to drift.
- `.githooks/pre-commit` rejects a staged change to a foreign lane, and a staged change to a `SHARED` path with no held lock covering that path. Enable per clone: `git config core.hooksPath .githooks` and `git config freightlogic.agent <claude|gpt>`.
- `.github/workflows/lanes.yml` re-checks path ownership and commit prefixes on every PR to `main`. The hook is fast feedback and is bypassable; CI is the boundary.
- A path with no row in this table fails closed.
- A lock past `expected_release_utc` +2h is stale. It grants nothing and is never auto-stolen; reap deliberately per `/AGENTS.md`.

## Cross-lane requests

If a task requires a foreign path, write a request under `/.agents/inbox/` on `agent-coordination`. Do not make an opportunistic cross-lane edit.
