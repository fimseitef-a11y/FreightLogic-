# FreightLogic Path Ownership

Ownership is physical-path based. Conceptual ownership does not authorize an edit outside the paths below. `SHARED` means serialized through the lock protocol in `/AGENTS.md`.

This map reflects the post-extraction v24.1 repository. The CSS presentation seam is now real; JavaScript UI/core code inside `app.js` remains serialized until a separately approved extraction creates additional physical paths.

**Single-lane consolidation (2026-09-14, operator-directed).** The operator directed the Claude lane to "take over everything and complete the app." The 2026-09-14 GPT completion takeover paragraph this replaces said it ends when Issue #119 closes **or when the takeover is explicitly ended**; this is that explicit end, and it ends the two-lane split with it rather than only the temporary rows. Every non-`SHARED` path below is now `claude`.

This is a change of *who may edit*, and nothing else. `SHARED` paths — `app.js`, `index.html`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js`, `manifest.json`, `.agents/`, `AGENTS.md`, `.gitignore`, `.assetsignore` — stay SHARED and still require a held lock, because that serialization protects against two *sessions*, not two agents. Commit-prefix discipline, the full-suite gate and release-marker discipline are unchanged. A path with no row still fails closed.

**Restoring the split** is a pure revert of this consolidation: set the rows back and reinstate the boundary paragraph. Nothing else in this file or in `scripts/lane-guard.mjs` encodes the two-agent assumption, and the guard reads this table rather than a generated copy, so the split can come back without touching code.

| Top-level path | Owner | Notes |
|---|---|---|
| `.assetsignore` | SHARED | Repository/deployment metadata; coordinate changes. |
| `.github/` | claude | Consolidated to the single lane on 2026-09-14; previously a temporary takeover row for release/certification workflows. |
| `.githooks/` | claude | Lane-guard git hooks; enforcement tooling for this map. |
| `.gitignore` | SHARED | Repository-wide behavior. |
| `.agents/` | SHARED | Durable protocol on `main`; live state on `agent-coordination`. Do not edit another agent's live lock/inbox entry except per protocol. |
| `AGENTS.md` | SHARED | Coordination contract. |
| `AUDIT_REPORT.md` | claude | Core audit record; findings are recorded with their reproduction and their live production status. |
| `CLAUDE.md` | claude | Core architecture/operations context. |
| `FIELD_TEST_CHECKLIST.md` | claude | Consolidated to the single lane on 2026-09-14; the physical-iPhone instrument, which is now maintained beside the certification record that cites it. |
| `README.txt` | claude | Consolidated to the single lane on 2026-09-14; general/non-core documentation. |
| `RECON_24_0_2.md` | claude | Read-only core reconciliation/audit artifact; maintained with the Claude core/audit lane. |
| `_headers` | claude | CSP/security/deployment headers. |
| `admin-driver-ui.js` | claude | Consolidated to the single lane on 2026-09-14; admin UI. Auth/storage semantics here are core: the session-scoped admin token and `purgeLegacyTok()` are load-bearing and documented in CLAUDE.md. |
| `app.js` | SHARED | **Serialized until split. Any edit requires `lock/app-js` and full suite.** Decision/runtime/core behavior remains Claude-owned unless explicitly reassigned. |
| `cloud-backup-worker.js` | claude | Consolidated to the single lane on 2026-09-14; backup/API Worker source. Worker v17 (monotonic backup/delta key clock) is the current generation. |
| `dat-rateview.js` | claude | Freight-rate source client. Frozen/dormant and non-authoritative per the completion plan; may not influence canonical cargo-van pricing without operator re-authorization. |
| `docs/` | claude | Consolidated to the single lane on 2026-09-14; the certification record, the backup/tax/authority contracts, and the completion plan all live here and are now maintained in the same lane as the code they describe. |
| `favicon16.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `favicon32.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `icon1024.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `icon120.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `icon128.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `icon152.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `icon167.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `icon180.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `icon192.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `icon256.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `icon512.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `icon64.png` | claude | Visual asset. Consolidated to the single lane on 2026-09-14. |
| `index.html` | SHARED | UI shell + CSP/script ordering; lock before editing. |
| `manifest.json` | SHARED | PWA/release + visual metadata; lock before editing. |
| `midwest-stack-authority.js` | claude | Decision/bid advisory core and DZ gate integration. |
| `midwest-stack-config.json` | claude | Decision/bid configuration. |
| `modern-shell.js` | SHARED | Driver-facing structural navigation seam. Reuses canonical app renderers/state; lock before editing and run the full suite for behavior changes. |
| `schemas/` | claude | Data/contracts. |
| `scripts/` | claude | Consolidated to the single lane on 2026-09-14; release/certification tooling and the deploy-asset inventory. |
| `service-worker.js` | SHARED | Offline shell/release-critical. Lock before editing; full suite required. |
| `styles.css` | claude | Consolidated to the single lane on 2026-09-14; the extracted presentation layer. It still carries **no version string** by design — `tests/unit/cache-generation.spec.mjs` CG-11 asserts the absence, so a reintroduced one fails on the next release. |
| `sw-bridge.js` | SHARED | Service-worker integration/release-critical. |
| `tests/` | claude | Consolidated to the single lane on 2026-09-14; the Playwright suite. Assertions may not be weakened or quarantined to make a release green — that rule survives the consolidation intact. |
| `vendor/` | claude | Bundled runtime dependencies/security provenance. |
| `voice-load.js` | claude | Functional intake/parser behavior. |
| `wrangler.jsonc` | claude | Worker deployment/configuration. |

## Current lane intent after the single-lane consolidation

One lane owns every non-`SHARED` path. The interesting question is therefore no longer *who* may edit a file but *what still serializes* — and the answer is unchanged:

- `app.js` is `SHARED` and needs `lock/app-js` plus a full suite for any edit. That has never been about two agents; it is a 1.1MB single-IIFE file where two concurrent editors lose work whoever they are.
- The rest of the `SHARED` set (`index.html`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js`, `manifest.json`, `.agents/`, `AGENTS.md`, `.gitignore`, `.assetsignore`) is release-critical or protocol surface, where a silent concurrent edit ships a broken generation.

The CSS seam stays a real physical boundary and is still worth keeping: presentation changes in `styles.css` do not need an `app.js` lock. It does **not** cover UI sections that still live inside `app.js` — those remain `SHARED` until an approved extraction creates more physical paths. That was true under two lanes and is true under one.

`/.agents/inbox/` remains the cross-session handoff channel. With a single lane it is no longer a lane boundary, but it is still where a request that another session must action belongs.

## Enforcement

This map is enforced mechanically, not by recollection:

- `scripts/lane-guard.mjs` parses **this file** as the single source of truth. There is no generated copy to drift from it.
- `.githooks/pre-commit` rejects a staged change to a foreign lane, and a staged change to a `SHARED` path with no held lock covering that path. Enable per clone: `git config core.hooksPath .githooks` and `git config freightlogic.agent <claude|gpt>`.
- `.github/workflows/lanes.yml` re-checks path ownership and commit prefixes on every PR to `main`. The hook is fast feedback and is bypassable; CI is the boundary.
- A path with **no row in this table** fails closed. Adding a file means adding its row.
- A lock past `expected_release_utc` + 2h is reported as **stale** and grants nothing — to its holder either. It is never auto-stolen; reap it deliberately per `/AGENTS.md`.

## Cross-lane requests

If a task requires a foreign path, write a request under `/.agents/inbox/` on `agent-coordination`. Do not make an opportunistic cross-lane edit.
