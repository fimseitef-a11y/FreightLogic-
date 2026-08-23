# FreightLogic Path Ownership

Ownership is physical-path based. Conceptual ownership does not authorize an edit outside the paths below. `SHARED` means serialized through the lock protocol in `/AGENTS.md`.

This map reflects the post-extraction v24.1 repository. The CSS presentation seam is now real; JavaScript UI/core code inside `app.js` remains serialized until a separately approved extraction creates additional physical paths.

| Top-level path | Owner | Notes |
|---|---|---|
| `.assetsignore` | SHARED | Repository/deployment metadata; coordinate changes. |
| `.github/` | claude | CI/release/security workflows. |
| `.gitignore` | SHARED | Repository-wide behavior. |
| `.agents/` | SHARED | Durable protocol on `main`; live state on `agent-coordination`. Do not edit another agent's live lock/inbox entry except per protocol. |
| `AGENTS.md` | SHARED | Coordination contract. |
| `AUDIT_REPORT.md` | claude | Core audit record; GPT may request changes through inbox. |
| `CLAUDE.md` | claude | Core architecture/operations context. |
| `FIELD_TEST_CHECKLIST.md` | gpt | Non-core field-facing documentation; changes that alter test policy require Claude review. |
| `README.txt` | gpt | General/non-core documentation. |
| `_headers` | claude | CSP/security/deployment headers. |
| `admin-driver-ui.js` | gpt | Presentation/admin UI; if a change touches auth/storage semantics, hand off through inbox. |
| `app.js` | SHARED | **Serialized until split. Any edit requires `lock/app-js` and full suite.** Decision/runtime/core behavior remains Claude-owned unless explicitly reassigned. |
| `cloud-backup-worker.js` | claude | Worker/auth/storage/backup core. |
| `docs/` | gpt | General docs by default. Security/backup/tax/authority contract changes require Claude review; X-12 doc repair may be assigned to Claude because it is an audit finding. |
| `favicon16.png` | gpt | Visual asset. |
| `favicon32.png` | gpt | Visual asset. |
| `icon1024.png` | gpt | Visual asset. |
| `icon120.png` | gpt | Visual asset. |
| `icon128.png` | gpt | Visual asset. |
| `icon152.png` | gpt | Visual asset. |
| `icon167.png` | gpt | Visual asset. |
| `icon180.png` | gpt | Visual asset. |
| `icon192.png` | gpt | Visual asset. |
| `icon256.png` | gpt | Visual asset. |
| `icon512.png` | gpt | Visual asset. |
| `icon64.png` | gpt | Visual asset. |
| `index.html` | SHARED | UI shell + CSP/script ordering; lock before editing. |
| `manifest.json` | SHARED | PWA/release + visual metadata; lock before editing. |
| `midwest-stack-authority.js` | claude | Decision/bid advisory core and DZ gate integration. |
| `midwest-stack-config.json` | claude | Decision/bid configuration. |
| `schemas/` | claude | Data/contracts. |
| `scripts/` | claude | Verification/release/tooling scripts. |
| `service-worker.js` | SHARED | Offline shell/release-critical. Lock before editing; full suite required. |
| `styles.css` | gpt | Primary extracted presentation stylesheet. GPT may make presentation-only changes here without an `app.js` lock; behavior, data, decision, persistence, auth, or service-worker changes must stay in their owning/shared lanes. |
| `sw-bridge.js` | SHARED | Service-worker integration/release-critical. |
| `tests/` | claude | Test harness and assertions. GPT does not edit Claude-owned suites unless explicitly reassigned later. |
| `vendor/` | claude | Bundled runtime dependencies/security provenance. |
| `voice-load.js` | claude | Functional intake/parser behavior. |
| `wrangler.jsonc` | claude | Worker deployment/configuration. |

## Current lane intent after CSS extraction

Claude owns core implementation, audit remediation, security/storage/decision logic, `app.js` runtime behavior, and the test harness. GPT owns `styles.css`, bounded presentation assets, `admin-driver-ui.js` within its presentation-only boundary, and non-core documentation.

The CSS seam is the first safe independent application presentation lane. It does **not** authorize GPT to edit conceptual UI sections that still live inside `app.js`; those remain SHARED/serialized and core-owned unless a later approved extraction creates additional physical presentation paths.

## Cross-lane requests

If a task requires a foreign path, write a request under `/.agents/inbox/` on `agent-coordination`. Do not make an opportunistic cross-lane edit.
