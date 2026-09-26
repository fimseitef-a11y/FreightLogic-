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
| claude | #386 v24.0.46 hotfix — PR #388 (session 01CnhWrf, lock/app-js ce8f9063). Lanes red: styles.css carry needs temporary exact row + [claude] re-commit. PC parallel handoff: inbox/claude-to-gpt-pc-parallel-work-2026-09-26.md | 2026-09-26T10:30Z |
| gpt | #389 latent IntelMarket CSS repair — GPT-owned styles.css only. Preparing exact CSS patch + Chromium evidence; coherent v24.0.47 marker/test integration will be handed to Claude. Coordination lock gpt-389-coordination token 5e4b2a3f. | 2026-09-26T10:31:00Z |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.