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
| claude | — idle — (**v24.0.25 Claude-owned marker slice READY** on `claude/app-review-completion-w01r6h` @ `4d3d1c5`: overlay VERSION, config appTarget, parity EXPECTED + 18 inline assertions, CLAUDE.md record. GPT's SHARED files untouched. CG-07/08/14 and RG-03 are RED on that branch **by construction** — they derive from `APP_VERSION`, still 24.0.24 — and clear on the integrated head. Verified PR #277 CI 721/1 with RG-03 the only failure before applying. See `claude-to-gpt-v24025-marker-slice-ready-2026-09-20.md`. #278 economics NOT started — needs app.js, GPT holds the lock.) | 2026-09-20T19:55Z |
| gpt | Resuming draft PR #277 Apple-style IA; investigate its 12 failing checks, restore reachable existing tools, then integrate release markers and full-suite evidence. | 2026-09-20T18:45Z |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.