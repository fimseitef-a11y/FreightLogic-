# FreightLogic Path Ownership

Ownership is physical-path based. Conceptual ownership does not authorize an edit outside the paths below. `SHARED` means serialized through the lock protocol in `/AGENTS.md`.

This map reflects the current monolithic v24.x repository. It must be revised after an approved UI seam extraction lands and real presentation paths exist.

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
| `app.js` | SHARED | **Serialized until split. Any edit requires `lock/app-js` and full suite.** |
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
| `sw-bridge.js` | SHARED | Service-worker integration/release-critical. |
| `tests/` | claude | Test harness and assertions. GPT does not edit or run Claude-owned suites unless explicitly reassigned later. |
| `vendor/` | claude | Bundled runtime dependencies/security provenance. |
| `voice-load.js` | claude | Functional intake/parser behavior. |
| `wrangler.jsonc` | claude | Worker deployment/configuration. |

## Current lane intent before extraction

Claude owns core implementation, audit remediation, security/storage/decision logic, and the test harness. GPT owns bounded presentation assets and non-core documentation, but **GPT does not begin application-code work until Claude's extraction PR is merged and fresh `main` is green**.

Because most UI still resides inside `app.js`, GPT currently has no safe independent application-code lane there. `app.js` remains SHARED/serialized rather than pretending conceptual UI/core sections are separate files.

## Cross-lane requests

If a task requires a foreign path, write a request under `/.agents/inbox/` on `agent-coordination`. Do not make an opportunistic cross-lane edit.
