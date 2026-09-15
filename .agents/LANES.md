# FreightLogic Path Ownership

Ownership is physical-path based. Conceptual ownership does not authorize an edit outside the paths below. `SHARED` means serialized through the lock protocol in `/AGENTS.md`.

This map reflects the post-extraction v24.1 repository. The CSS presentation seam is now real; JavaScript UI/core code inside `app.js` remains serialized until a separately approved extraction creates additional physical paths.

**UI redesign takeover (2026-09-14, operator-directed).** The operator explicitly directed GPT to take over and handle the approved FreightLogic reference-image redesign. `styles.css` is therefore reassigned to `gpt` for the presentation implementation. All other non-`SHARED` paths remain `claude`; this is a targeted presentation takeover, not a blanket ownership transfer.

`SHARED` paths — `app.js`, `index.html`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js`, `manifest.json`, `.agents/`, `AGENTS.md`, `.gitignore`, `.assetsignore` — stay SHARED and still require a held lock, because that serialization protects against concurrent sessions, not just different agents. Commit-prefix discipline, the full-suite gate and release-marker discipline are unchanged. A path with no row still fails closed.

**OMEGA continuation closed (2026-09-15).** The bounded GPT task — app.js economics/math, market-classifier collision and release-generation discipline — **landed in `fb408a0` (PR #200)**. The task did not close physical iPhone A1–A11 or M6 raw-data certification, and nothing here does.

**Full-repair takeover resumed (2026-09-15, operator-directed).** The operator explicitly directed GPT to finish every remaining repo instruction now. This is the previously authorized bounded repair/certification task, resumed after the earlier GPT session hit its usage limit. It covers only the confirmed first-use cloud-admin race, trip identity/import data loss, payment-state UNKNOWN coercion, invented profit/hour speed, share-target filename hardening, verified legacy-token cleanup gaps, and the release/test/docs files required to prove and ship those fixes. The unsafe self-pushing `.github/workflows/full-repair-once.yml` mechanism is explicitly excluded: the repair must land through a normal reviewed PR. These exceptions expire when the reviewed full-repair PR lands. Physical iPhone A1–A11 and authentic M6 remain open evidence gates.

| Top-level path | Owner | Notes |
|---|---|---|
| `admin-driver-ui.js` | gpt | Temporary first-use Manage Drivers event-ownership/rotation parity exception. |
| `cloud-backup-worker.js` | gpt | Temporary verified legacy plaintext-token cleanup exception. |
| `tests/integration/full-repair-regressions.spec.mjs` | gpt | Temporary regression suite for this repair. |
| `tests/unit/worker-token-rotation.spec.mjs` | gpt | Temporary legacy-token cleanup regression exception. |
| `tests/unit/cache-generation.spec.mjs` | gpt | Temporary DB/app-generation invariant update for the schema migration. |
| `tests/run-all.mjs` | gpt | Temporary regression-registration exception. |
| `scripts/verify-cloudflare-parity.mjs` | gpt | Temporary app/Worker parity marker update. |
| `midwest-stack-config.json` | gpt | Temporary appTarget marker update only. |
| `midwest-stack-authority.js` | gpt | Temporary generation marker update only. |
| `voice-load.js` | gpt | Temporary generation marker update only. |
| `CLAUDE.md` | gpt | Temporary release/evidence documentation exception. |
| `FIELD_TEST_CHECKLIST.md` | gpt | Temporary release/evidence documentation exception; A1–A11 stay open. |
| `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` | gpt | Temporary parity-evidence documentation exception. |
| `.assetsignore` | SHARED | Repository/deployment metadata; coordinate changes. |
| `.github/` | claude | Consolidated to the Claude completion lane on 2026-09-14; release/certification workflows. |
| `.githooks/` | claude | Lane-guard git hooks; enforcement tooling for this map. |
| `.gitignore` | SHARED | Repository-wide behavior. |
| `.agents/` | SHARED | Durable protocol on `main`; live state on `agent-coordination`. Do not edit another agent's live lock/inbox entry except per protocol. |
| `AGENTS.md` | SHARED | Coordination contract. |
| `AUDIT_REPORT.md` | claude | Core audit record; findings are recorded with their reproduction and their live production status. |
| `CLAUDE.md` | claude | Core architecture/operations context except the exact temporary row above. |
| `FIELD_TEST_CHECKLIST.md` | claude | Physical-iPhone verification instrument except the exact temporary row above. |
| `README.txt` | claude | General/non-core documentation. |
| `RECON_24_0_2.md` | claude | Read-only core reconciliation/audit artifact; maintained with the Claude core/audit lane. |
| `_headers` | claude | CSP/security/deployment headers. |
| `admin-driver-ui.js` | claude | Admin UI except the exact temporary row above. Auth/storage semantics here are core. |
| `app.js` | SHARED | **Serialized until split. Any edit requires a covering lock and full suite.** |
| `cloud-backup-worker.js` | claude | Backup/API Worker source except the exact temporary row above. |
| `dat-rateview.js` | claude | Freight-rate source client. Frozen/dormant and non-authoritative per the completion plan. |
| `docs/` | claude | Certification, backup/tax/authority contracts, completion plan and release documentation except the exact temporary row above. |
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
| `midwest-stack-authority.js` | claude | Decision/bid advisory core and DZ gate integration except the exact temporary marker-only row above. |
| `midwest-stack-config.json` | claude | Decision/bid configuration except the exact temporary marker-only row above. |
| `modern-shell.js` | SHARED | Driver-facing structural navigation seam. Lock before editing. |
| `schemas/` | claude | Data/contracts. |
| `scripts/` | claude | Release/certification tooling and deploy-asset inventory except the exact temporary row above. |
| `service-worker.js` | SHARED | Offline shell/release-critical. Lock before editing; full suite required. |
| `styles.css` | gpt | Operator-directed presentation takeover for the approved redesign; carries no version string by design. |
| `sw-bridge.js` | SHARED | Service-worker integration/release-critical. |
| `tests/` | claude | Playwright suite except the exact temporary rows above. Assertions may not be weakened or quarantined to make a release green. |
| `vendor/` | claude | Bundled runtime dependencies/security provenance. |
| `voice-load.js` | claude | Functional intake/parser behavior except the exact temporary marker-only row above. |
| `wrangler.jsonc` | claude | Worker deployment/configuration. |

## Current lane intent

The targeted UI takeover and bounded full-repair exceptions are the only GPT application ownership:

- `styles.css` is GPT-owned for the approved redesign and can be changed without an `app.js` lock.
- `app.js` is `SHARED` and needs a current covering lock plus a full suite for any edit.
- The full-repair exception is narrow and temporary: only the exact rows above are GPT-owned for this operator-directed repair.
- The rest of the `SHARED` set remains serialized because it is release-critical or protocol surface.
- Every other non-excepted path remains Claude-owned.

`/.agents/inbox/` remains the cross-session handoff channel.

## Enforcement

This map is enforced mechanically, not by recollection:

- `scripts/lane-guard.mjs` parses **this file** as the single source of truth.
- `.githooks/pre-commit` rejects a staged foreign-lane edit and a staged `SHARED` edit with no held lock covering that path.
- `.github/workflows/lanes.yml` re-checks path ownership and commit prefixes on every PR to `main`.
- A path with **no row in this table** fails closed.
- A lock past `expected_release_utc` + 2h is stale. It grants nothing and is never auto-stolen; reap it deliberately per `/AGENTS.md`.

## Cross-lane requests

If a task requires a foreign path, use `/.agents/inbox/` on `agent-coordination`. Do not make an opportunistic cross-lane edit.
