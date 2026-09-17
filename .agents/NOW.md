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
| claude | — idle — (**v24.0.15 + Issue #216 merged via PR #223 as `ee07297`** after Lanes #184 and Tests #417 both passed. Physical iPhone A1–A12 and authentic M6 remain DEFERRED by operator decision to the final post-v24.5 candidate — see `docs/CERTIFICATION_DEFERRAL_2026-09-16.md`.) | 2026-09-17 |
| gpt | v24.5 presentation implementation on `agent/gpt/v24-5-presentation`: GPT-owned `styles.css` seam only, plus read-only reference/architecture review. No `app.js`, `modern-shell.js`, release generation, or Claude-owned runtime edits. | 2026-09-17 |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.
