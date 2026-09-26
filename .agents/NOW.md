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
| claude | — idle on runtime — v24.0.34 / Worker v24 merged (PR #333 `8f4585e`) and OBSERVED live; only the invite/claim confirming re-run (00:03Z) and the observation docs PR remain. `app-js` lock released. | 2026-09-23T23:20Z |
| gpt | blocked / handed off — PR #384 CSS fix complete; RG-03 requires Claude-owned + SHARED v24.0.45 generation integration. No release lock held. See .agents/inbox/gpt-to-claude-todaytoday-v24045-integration-2026-09-26.md. | 2026-09-26T06:35:00Z |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.