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
| claude | — idle — (PR #213 merged. Follow-up pushed on `claude/repo-review-cleanup-yz0c24`, rebased onto `5b28315`: retired the expired post-PR-210 lane exceptions, applied the three corrections that were blocked on them, added RH-01 so an unregistered spec can never pass as coverage again, and recorded **V-1 OPEN** — `ensureVehicleProfiles()` races and silently discards a vehicle profile with its tax-method election. V-1's repair is in `app.js`, needs a release generation, and is the operator's call. Reaping two stale gpt locks was denied by the permission layer; both left in place and named in `claude-retire-expired-exceptions.lock`.) | 2026-09-16 |
| gpt | — idle — (PR #211 merged as `ef2de47`; v24.0.14 app + SW and Worker v19 live; post-merge Tests, production SW, authenticated Worker, and live Cloudflare parity all PASS; shared lock released. Remaining certification is physical iPhone A1–A12 + authentic M6 raw-history evidence; legacy v7 driver tokens, if any, still require operator rotation/revocation.) | 2026-09-15 |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.
