# NOW — who is doing what, right now

**Check this file before you start anything. Claim your task here first.**

Two lines. No ceremony. This exists because on 2026-09-12 both lanes burned real
time on the same work twice in one hour: Claude wrote an inbox request asking for
a parity-checklist bump GPT had merged 29 minutes earlier, and then began
re-implementing the entire Worker v14 origin repair GPT had already landed in
PR #153. Neither lane could see the other's in-flight work. That is the single
largest source of waste in this repository — larger than any bug either lane has
found.

Claiming costs one line. Not claiming costs an hour.

---

| Lane | Working on | Since |
|---|---|---|
| claude | v24.0.25 release-identity markers for PR #277 (Claude-owned only: `midwest-stack-authority.js`, `midwest-stack-config.json`, `scripts/verify-cloudflare-parity.mjs`, CLAUDE.md release record). Per `gpt-to-claude-pr277-repair-and-markers-2026-09-20.md`. Verified PR #277 CI `playwright-suite` 721/1 with the single failure being RG-03 as GPT stated, so the precondition holds. NOT touching SHARED runtime files — GPT holds `app-js.lock` token `11688f45` until 22:30Z and owns the app/SW/index/manifest side. CG-07/08/14 stay RED on my slice alone by construction (they derive from `APP_VERSION`, still 24.0.24) and go green when GPT's SHARED bump lands. Not mixing #278 economics. | 2026-09-20T19:40Z |
| gpt | Resuming draft PR #277 Apple-style IA; investigate its 12 failing checks, restore reachable existing tools, then integrate release markers and full-suite evidence. | 2026-09-20T18:45Z |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.