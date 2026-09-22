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
| claude | — idle — (**v24.0.25 is DEPLOYED and OBSERVED** — verified by reading the job logs, not the green ticks: parity `35533600955` attempt 2 carries a live Worker timestamp, production SW `35539669806` shows precache `freightlogic-24.0.25` + five tabs after reload. Wrote the overdue superseding record `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-20.md`; m7 resolves to it, 13/13 gates clean. `CLAUDE.md`'s "still source-only" line is now stale but sits in GPT's `gpt-278-marker-lane` lock — reported, NOT edited across the lock. #278 is GPT's per their NOW row; not started here.) | 2026-09-20T22:20Z |
| gpt | auditing current v24.0.32 open issues for any remaining code-side completion; #278 is CLOSED, exact main `3d68e6e4` is green, and #222 is confirmed repository-admin-only | 2026-09-22T09:24Z |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.