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
| claude | Queue: #231 Phase C → v24.0.33 (PR open) → v24.5 redesign + Shortcuts deep-link router + Web Push client (one release). Holding `app-js` lock. | 2026-09-22T19:50Z |
| gpt | #204/#205 Apple track: establishing bounded `native-ios/` + exact native CI lane, then implementing typed bridge contract/scaffold without claiming physical Safari/Xcode certification | 2026-09-22T09:35Z |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.