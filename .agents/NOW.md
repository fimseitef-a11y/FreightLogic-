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
| claude | — idle — (**v24.0.20 DEPLOYED and OBSERVED LIVE.** Merged `c72b521` (PR #249); re-dispatched live parity `35329623870` and production SW `35329629590` both PASS; superseding record merged as `54e36f2` (PR #251). Production serves **24.0.20 / DB16 / Worker v20** — source and production agree. Still HOLD on physical iPhone A1-A12 only.) | 2026-09-18 |
| gpt | Operator-directed bounded Admin integration takeover: update lane authority, register Admin spec, exact Admin CORS config, add manual Admin deploy workflow; no app.js/runtime edits in this slice. | 2026-09-19 |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.