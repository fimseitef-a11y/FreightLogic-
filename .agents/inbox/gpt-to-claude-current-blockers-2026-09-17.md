# GPT → Claude — current completion blockers / exact next actions (2026-09-17)

User explicitly said both agents are running and to proceed until everything is complete. This is a coordination handoff, not a request to restart completed audits.

## Exact current checkpoint

- `main`: `ab0b86945041c0dea0190559bb9956b5db10cbeb` (PR #236 merged).
- App/SW production: v24.0.17 / DB16, all 22 declared runtime assets green.
- Exact merged-main Tests run `35278341489`, job `105394228760`: **616 passed / 0 failed across 64 specs on first attempt**.
- Production SW gate `35278341549`: green.
- Live parity `35278341475`: app-side checks green including #228's 20-path withheld-file sweep; sole mismatch is backup/API Worker production **v19** while source requires **v20**.
- Closed and do not redo: #225, #228, #230, #232. PR #234 retired GPT's spent `tests/run-all.mjs` exception; that file again inherits Claude-owned `tests/`.

## P0 — Worker v20 production deploy / #221

Source repair is already merged. The remaining blocker is deployment/verification only.

The workflow `.github/workflows/deploy-backup-worker.yml` requires workflow_dispatch input exactly `DEPLOY PRODUCTION BACKUP WORKER`; default/CANCEL runs stop before deploy. ChatGPT's GitHub connector cannot dispatch custom workflow inputs, browser is logged out, and no Desktop Commander device is online. If your Claude Code environment has authenticated `gh`/GitHub/Cloudflare access, this is the highest-value next action:

1. dispatch the production backup Worker workflow with the required confirmation;
2. verify `/health` reports Worker v20;
3. dispatch/observe live parity and authenticated Worker verification on exact current head;
4. close #221 only if those live checks pass.

Do not expose or copy secrets into chat/Airtable/repo.

## P0 — #224 intermittent db===null

Do **not** clear #224 from green reruns. Current title now says root cause is still unproven.

Fresh GPT read-only source trace added in issue comment:
- `db` is initialized once and assigned only by `db = await initDB()`; no code resets it to null or closes the shared handle.
- explicit reload paths are: initDB open-error self-heal (before DB-backed readiness can succeed), Pro Hard Reset user action, and user-triggered SW Update reload; `sw-bridge.js` guards controllerchange reload behind `skipWaitingRequested` so first install cannot auto-reload.
- those paths do not explain the historical automatic post-readiness failures.

Keep lifecycle diagnostics armed. If a failure reproduces, use its document-id/navigation dump to identify the actual transition, then TDD the demonstrated mechanism. No retry/timeout/assertion weakening.

## P0/P1 — #231 Admin Console

Operator approval is settled. Exact source inventory is already in the issue comment; do not redesign the API:
- `GET /admin/users` (admin-auth; token-free list)
- `POST /admin/invites {name}` new invite
- `POST /admin/invites {userId}` re-invite preserving canonical user/backup identity
- `DELETE /admin/users/:id` revoke while preserving backup history
- do **not** use `POST /admin/users` or `/admin/users/:id/rotate` for human onboarding because those return permanent `flk_` bearer tokens.
- separate admin origin; session-only admin credential; exact-origin CORS; no service worker/offline admin credential cache; no freight-data access.
- delete/retire `admin-driver-ui.js` only after the separate console is live-verified, preserving any required one-time legacy credential cleanup.

Issue #231 still requires lane ownership for any new console paths plus TDD before implementation. Please take it in the Claude lane or explicitly grant an isolated GPT lane; do not create concurrent runtime writers.

## External/user-only gates after automatable work

- #222 GitHub main protection/rulesets/security settings require repository-admin UI/API not exposed to ChatGPT's connector.
- #226 real physical-iPhone A1–A12 plus private authentic M6 replay remain mandatory final-candidate evidence; runner is live, but do not certify while runtime generations mismatch.
- #204/#205 native iOS items require Apple/macOS/Xcode/entitlements where applicable; document true external blockers rather than silently omitting them.

Write durable state back to Airtable START HERE handoff layer when any of the above changes.
