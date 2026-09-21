# FreightLogic Path Ownership

Ownership is physical-path based. Conceptual ownership does not authorize an edit outside the paths below. `SHARED` means serialized through the lock protocol in `/AGENTS.md`.

This map reflects the post-extraction v24.1 repository. The CSS presentation seam is now real; JavaScript UI/core code inside `app.js` remains serialized until a separately approved extraction creates additional physical paths.

**UI redesign takeover (2026-09-14, operator-directed).** The operator explicitly directed GPT to take over and handle the approved FreightLogic reference-image redesign. `styles.css` is therefore reassigned to `gpt` for the presentation implementation. All other non-`SHARED` paths remain `claude`; this is a targeted presentation takeover, not a blanket ownership transfer.

**Field certification runner exception (2026-09-17, operator-approved).** The operator approved a bounded physical-device certification companion so A1-A12 can be executed on the real iPhone with structured evidence instead of ad-hoc notes. The runner is isolated from `app.js` and the service worker: GPT owns only `field-certification.html`, `field-certification.js`, and `tests/integration/field-certification-runner.spec.mjs`. The one-time `tests/run-all.mjs` registration grant was consumed by PR #227 and is retired; `tests/run-all.mjs` again inherits the `tests/` Claude ownership so RH-01 cannot deadlock future Claude regressions. The runner may record device-observed evidence and auto-observable browser facts, but it may never auto-promote a hardware-only step to PASS without explicit observation. This exception does not transfer any other `tests/` path or runtime/core ownership.

`SHARED` paths — `app.js`, `index.html`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js`, `manifest.json`, `.agents/`, `AGENTS.md`, `.gitignore`, `.assetsignore` — stay SHARED and still require a held lock, because that serialization protects against concurrent sessions, not just different agents. Commit-prefix discipline, the full-suite gate and release-marker discipline are unchanged. A path with no row still fails closed.

**Admin Console Phase A lane exception (2026-09-18, operator-directed takeover).** Issue #231 already carries operator approval for a separate-origin Admin / Onboarding Console. While Claude's current UX/IA lock remains limited to `app.js` and `index.html`, GPT may own only the isolated `admin-console/` subtree plus the exact Admin Console regression file named below. This is an additive Phase A seam only: it does **not** transfer `cloud-backup-worker.js`, `app.js`, `index.html`, `service-worker.js`, `.github/`, or any other Claude/SHARED path. Worker CORS, deployment, live auth verification, and Phase C driver-surface removal remain under their existing ownership/lock rules. The console must preserve #231's zero-token, session-only-admin-credential, no-freight-data, no-service-worker contract and must not be exposed as a finished privileged surface before its distinct admin origin and live verification exist.

**Issue #252 live vision production-smoke exception — RETIRED 2026-09-21.** PR #286 merged the privacy-safe authenticated `POST /extract-image` smoke as `f1bb14b3` after red-first evidence (736/5, only LA-08..LA-12 red) and an exact-head **741/0** full-suite pass. The temporary three-path ownership grant is therefore retired: `.github/workflows/verify-authenticated-worker.yml`, `scripts/verify-live-authority.mjs`, and `tests/unit/live-authority-runner.spec.mjs` return to their normal Claude-owned parent lanes. No runtime/evaluator/Worker-source ownership transferred, and real iPhone A13 / real-screenshot quality evidence remains separate.

**v24.0.22 runtime integration takeover — RETIRED 2026-09-19.** The bounded GPT integration lane completed when clean successor PR #262 merged as `11cc8b78` after exact-head Lanes, CodeQL and full-suite success. The temporary ownership exceptions used only for that release are retired here: `CLAUDE.md`, `midwest-stack-config.json`, and `midwest-stack-authority.js` return to Claude; the temporary parity/test/run-all rows fall back to their Claude-owned parent lanes. `styles.css` remains GPT-owned under the separate UI-redesign directive, and the Admin Console plus field-certification exceptions are unaffected.

**v24.0.23 final PWA presentation integration takeover — RETIRED 2026-09-19.** The bounded operator-directed lane completed when PR #265 merged as `8e722522`, delivering the single presentation authority and governed v24.0.23 cache generation. The temporary marker exceptions are retired here: `CLAUDE.md`, `midwest-stack-config.json`, `midwest-stack-authority.js`, and `scripts/verify-cloudflare-parity.mjs` return to Claude ownership. Persistent GPT-owned seams remain `styles.css`, the isolated Admin Console subtree/regression, and the field-certification companion paths.

**Issue #268 accessibility completion exception — RETIRED 2026-09-19.** PR #275 merged the reviewed repair as `f75f9cc9`; exact-main Tests, CodeQL, post-deploy Live Parity, and Production Service Worker verification are green. The temporary test/run-all and release-marker exceptions are therefore retired. Physical iPhone A1-A13 remains a separate evidence gate under #226.

**v24.0.26 Issue #278 economics authority takeover — RETIRED 2026-09-20.** PR #281 merged the reviewed economics authority as `9e3be9e0` after exact-head Tests **736/0 across 72 specs**, Lanes, and CodeQL passed. Production Service Worker run `35543985994` observed cache `freightlogic-24.0.26`, all 22 runtime assets, five driver tabs, and no uncaught page errors; Live Parity run `35543985945` attempt 2 observed app/SW/manifest v24.0.26 with Worker v21 and passed. The bounded #278 ownership exceptions are therefore retired: `midwest-stack-config.json`, `midwest-stack-authority.js`, and `CLAUDE.md` return to Claude; the parity and test-specific exact rows fall back to their Claude-owned parent lanes. The economics regression remains in the suite; only temporary ownership is retired. Physical iPhone A1–A13 remains separate under #226.

**v24.0.25 PR #277 release-marker takeover — RETIRED 2026-09-20.** PR #277 merged as `436d6778` after exact-head Tests 722/0, Lanes, and CodeQL passed; production service-worker and live-parity gates subsequently observed v24.0.25. The temporary marker exceptions are retired here. `midwest-stack-config.json`, `midwest-stack-authority.js`, `CLAUDE.md`, and `scripts/verify-cloudflare-parity.mjs` return to their normal Claude/parent ownership. No economics, Worker, DB, or schema authority transferred.

**OMEGA continuation closed (2026-09-15).** The bounded GPT task — app.js economics/math, market-classifier collision and release-generation discipline — **landed in `fb408a0` (PR #200)**, so its six exact-file exceptions are retired and their parent rows own those paths again. Deleted rather than flipped back: a redundant narrower row is just another thing to go stale. The task did not close physical iPhone A1–A10 or M6 raw-data certification, and nothing here does.

**Post-PR-210 full-repair continuation — RETIRED 2026-09-16.** That paragraph granted GPT a bounded set of exact-file exceptions for the v24.0.14 / Worker v19 repair, and it set its own bound: *"These exact exceptions expire when the reviewed successor PR lands."* PR #211 landed as `ef2de47`, and production has served 24.0.14 / DB16 / Worker v19 since, observed by live all-asset parity run `35087770010`. The bound is met, so the exceptions are retired and their parent rows own those paths again — deleted rather than flipped back, because a redundant narrower row is just another thing to go stale, exactly as the OMEGA continuation was closed above. Six of them had no parent row (`cloud-backup-worker.js`, `midwest-stack-config.json`, `midwest-stack-authority.js`, `voice-load.js`, `CLAUDE.md`, `FIELD_TEST_CHECKLIST.md`) and keep a row naming `claude`, because a path with no row fails closed. PR #210 zero-token onboarding stays authoritative and the superseded raw-token/admin-handler flow must not be reinstated. Physical iPhone A1–A12 and authentic M6 remain open evidence gates.

This retirement was requested twice through `/.agents/inbox/` before it was taken — `claude-to-gpt-cert-chain-stale-2026-09-16.md` and `claude-to-gpt-suite-flakes-2026-09-16.md`, both naming retirement as the clean alternative — and it is reversible by restoring the rows. It does **not** touch the UI-redesign takeover: `styles.css` and the three redesign authority documents are a separate, still-current operator directive.

| Top-level path | Owner | Notes |
|---|---|---|
| `cloud-backup-worker.js` | claude | Worker source. The temporary v19 legacy plaintext-token cleanup exception is retired; preserve PR #210 zero-token onboarding. |
| `midwest-stack-config.json` | claude | Release/doctrine configuration; temporary #278 v24.0.26 ownership retired after PR #281 landed and was observed in production. |
| `midwest-stack-authority.js` | claude | Release/doctrine authority; temporary #278 v24.0.26 ownership retired after PR #281 landed and was observed in production. |
| `voice-load.js` | claude | Voice input module; carries a governed header version marker. |
| `CLAUDE.md` | claude | Core release/project record; temporary #278 v24.0.26 release-record authority is retired. |
| `FIELD_TEST_CHECKLIST.md` | claude | Physical-device certification gate. A1–A12 stay open; it defers to the current certification-state document for the candidate SHA. |
| `.claude/CLAUDE.md` | gpt | Concise Claude Code project instruction for the operator-approved UI redesign; points to the authoritative redesign brief and reference. |
| `UI_BRIEF_V24.5.md` | gpt | Operator-approved visual-redesign authority and pre-code gate contract; `v24.5` is a working label, not an automatic runtime version bump. |
| `FreightLogic_UI_Reference.html` | gpt | Repository-native structural/visual reconstruction of the operator-approved 10-screen mockup; reference only, never a production data source. |
| `admin-console/` | gpt | Issue #231 additive separate-origin Admin Console subtree only; no Worker, driver-app, or deployment authority. |
| `tests/integration/admin-console.spec.mjs` | gpt | Exact regression exception for the isolated #231 Admin Console contract only; no other `tests/` ownership transfer. |
| `field-certification.html` | gpt | Operator-approved same-origin physical-device certification companion; no app.js or decision-engine authority. |
| `field-certification.js` | gpt | Field-certification state/evidence capture. May auto-record browser-observable facts but may not infer hardware-only PASS. |
| `tests/integration/field-certification-runner.spec.mjs` | gpt | Exact regression exception for the field-certification companion only; no other tests/ ownership transfers. |
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
| `docs/` | claude | Certification, backup/tax/authority contracts, completion plan and release documentation. |
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
| `scripts/` | claude | Release/certification tooling and deploy-asset inventory. |
| `service-worker.js` | SHARED | Offline shell/release-critical. Lock before editing; full suite required. |
| `styles.css` | gpt | Operator-directed 2026-09-14 presentation takeover for the approved reference UI redesign. It carries **no version string** by design — `tests/unit/cache-generation.spec.mjs` CG-11 asserts the absence. |
| `sw-bridge.js` | SHARED | Service-worker integration/release-critical. |
| `tests/` | claude | Playwright suite. Assertions may not be weakened or quarantined to make a release green. |
| `vendor/` | claude | Bundled runtime dependencies/security provenance. |
| `wrangler.jsonc` | claude | Worker deployment/configuration. |

## Current lane intent

- `styles.css` remains GPT-owned for the approved redesign.
- The exact field-certification companion paths named above remain GPT-owned for the operator-approved bounded task. Its `tests/run-all.mjs` registration is already merged and that temporary whole-file exception is retired; `tests/run-all.mjs` inherits the Claude-owned `tests/` row again.
- `app.js` remains `SHARED` and requires the current covering lock plus a full suite.
- PR #210 zero-token onboarding is authoritative; nothing may reinstate the superseded raw-token/admin-handler flow.
- The post-PR-210 and v24.0.22 integration exceptions are retired. Persistent GPT-owned seams are `styles.css`, the three UI-redesign authority documents, the isolated `admin-console/` + its exact regression, and the exact field-certification companion paths.
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
- A lock past `expected_release_utc` + 2h is reported as **stale**. It grants nothing — including to its own holder — and it is never auto-stolen; reap it deliberately per `/AGENTS.md`.

## Cross-lane requests

If a task requires a foreign path, write a request under `/.agents/inbox/` on `agent-coordination`. Do not make an opportunistic cross-lane edit.
