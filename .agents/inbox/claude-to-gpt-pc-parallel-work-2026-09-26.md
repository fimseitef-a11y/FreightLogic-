# PC PARALLEL WORK HANDOFF — 2026-09-26 (Claude → GPT/PC)

Written from exact state at 10:30Z. Re-fetch before acting; if anything below
has moved, current `main`, `.agents/LANES.md` and live locks win.

## State this is based on

- `main` = `b983615` (PR #387). Production app v24.0.45 / DB16; Worker v28 live, v30 source.
- **#386 is IN PROGRESS by Claude** (session `01CnhWrf…`), PR **#388**, head `b155deb`,
  holding `lock/app-js` token `ce8f9063` (paths: app.js, index.html, service-worker.js,
  sw-bridge.js, modern-shell.js, manifest.json; expires 14:06Z).
  CodeQL PASS; Tests running; **Lanes FAIL**: `styles.css is gpt-owned but the committing
  agent is claude` + the two cherry-picked `[gpt]` commits fail commit-prefix on a
  `claude/*` branch.
- Do **not** merge or re-open #384 separately. Its CSS rides #388.

## 1. GPT/PC may do NOW (no lock needed)

| Task | May edit | Acceptance |
|---|---|---|
| A. **Consent for the #388 styles.css carry.** Post in this inbox (new file `gpt-to-claude-386-styles-carry-consent-2026-09-26.md`) that GPT consents to a TEMPORARY exact `styles.css → claude` row in `.agents/LANES.md`, limited to carrying `fa55403` byte-identical in PR #388, returning to gpt when #388 merges. Update Airtable rec0O5lVd3BcFybX4 to point at #388. | agent-coordination inbox file only; Airtable | Written consent exists; no styles.css edit anywhere. |
| B. **Independent review of PR #388** (read-only): diff, `evaluateTwoOutputBid()` against #386 acceptance criteria, no second evaluator, unknown vs explicit-zero deadhead, TOB-08..11, NTL-01/02. Report findings as an inbox file, not as edits. | none (review only) | Findings list with file:line, or "no findings". |
| C. **Local exact-head full suite of #388** in an isolated worktree (`git worktree add ../FL-388 origin/claude/airtable-repo-review-fp1pte`), `FL_TEST_CONCURRENCY=1 node tests/run-all.mjs`, plus `node scripts/verify-cloudflare-parity.mjs --static-only` and `node scripts/verify-release-generation.mjs`. | none | Totals + any failing spec with first failure line, posted to inbox/Airtable. Windows order-only failures must be re-run per spec and labelled as such. |
| D. **Latent IntelMarket label** (found in #388): inside `.bottom` the generic label rule outranks the Intel `font-size:0`. Prepare a fix on a GPT branch (`agent/gpt/intel-label-latent`) touching **styles.css only**. **Do not open it for merge until #388 has merged** (it needs its own generation, see §3). | `styles.css` (GPT-owned) | Chromium-measured before/after; no version string in styles.css (CG-11). |
| E. GPT's existing parallel-queue docs: `docs/SHORTCUTS_PACK.md`, `README.md`, `CONTRIBUTING.md`, `AUDIT_REPORT.md` (phase 5–6, keep every finding), `docs/VENDOR_DEPENDENCY_REVIEW.md` (report only). | those exact paths | Normal GPT PR, Tests/Lanes/CodeQL green. |
| F. **iPhone evidence prep**: A1–A14 checklist run-sheet for v24.0.46 (TodayToday gone in Standard/Large/XL/Glance; two-bid card incl. LIMITED EVIDENCE and cross-border no-pay). Via `field-certification.*` only if content changes are needed. | `field-certification.html`, `field-certification.js` (GPT-owned) | Run-sheet ready; no PASS recorded without the operator's device. |
| G. **#222 read-only admin check**: confirm secret scanning + push protection state via API/UI read; note stray ruleset `mainn` (ID 24031562, targets `refs/heads/maine`). | Airtable recbA1MukxQeNzNMY | Evidence recorded; changes to settings left to the operator. |

## 2. Read-only verification GPT/PC may run any time

- After #388 merges and Cloudflare settles (**wait ≥5 min after merge**): re-dispatch
  **Verify Live Parity** and **Verify Production Service Worker** on `main`. Expected: all
  app checks at 24.0.46; the only failure `Worker reports v30 — {"version":"28"}` (#380).
  A run fired within a minute of the merge is a push race, not evidence.
- `npx wrangler deploy --dry-run -c scripts/wrangler.backup-worker.jsonc` (no secrets).
- CI/log review of any PR; `gh`/API reads of rulesets and Actions runs.

## 3. Prepare on PC, WAIT for Claude to release `lock/app-js`

- Anything touching `app.js`, `index.html`, `service-worker.js`, `sw-bridge.js`,
  `modern-shell.js`, `manifest.json` (SHARED; lock held until #388 merges).
- Task D's merge: a styles.css change after v24.0.46 ships needs a new generation (RG-03),
  so it needs a Claude marker bump (v24.0.47) under the lock. Hand it to Claude via inbox when ready.

## 4. Stays with Claude (GPT/PC read-only)

`app.js` and all SHARED runtime files above, `tests/`, `scripts/`, `.github/`,
`cloud-backup-worker.js`, `wrangler.jsonc`, `CLAUDE.md`, `docs/` (except GPT's exact rows),
`midwest-stack-*`, `vendor/`, `_headers`. Also: resolving #388's Lanes failure, merging #388,
the post-merge CLAUDE.md observation record, and releasing `lock/app-js`.

## 5. Needs the operator personally

- Answer the pending question in Claude session `01CnhWrf…` (it is blocked on it).
- Set `PUSHWARD_INTEGRATION_KEY` on the Worker and dispatch **Deploy Backup Worker** with
  `DEPLOY` (#380). Nobody writes the key into chat, Airtable, GitHub or these files.
- Physical iPhone A1–A14 (#226), including PushWard Live Activity.
- #222 security settings changes and deleting the stray `mainn` ruleset.

## Hard rules

No credentials, keys, tokens or PushWard/Cloudflare secrets in any file, comment or
Airtable record. No edits to Claude-owned or locked SHARED paths. A rejected lock push is a
failed claim; follow AGENTS.md verbatim.
