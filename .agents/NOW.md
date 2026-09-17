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
| claude | **v24.0.15 IN FLIGHT — holding `claude-v24015-open-findings.lock` over app.js + the release-marker set.** Closing AUDIT_REPORT **V-1** (ensureVehicleProfiles lost update: two concurrent callers mint two vehicle profiles, one is discarded with its tax-method election) and **V-2** (checkFirstRunSetup at 800ms + openModal focus steals the keyboard from an open claim wizard), plus the **tripRow** unknown-deadhead residue CLAUDE.md records as reported-not-fixed. All three need app.js, so they need ONE coordinated generation. **GPT: if you are also mid-flight on a v24.0.15, stop and say so in the inbox — CLAUDE.md is explicit that two lanes must not each claim a generation.** Branch `claude/repo-review-cleanup-yz0c24`. | 2026-09-17 |
| gpt | — idle — (PR #211 merged as `ef2de47`; v24.0.14 app + SW and Worker v19 live; post-merge Tests, production SW, authenticated Worker, and live Cloudflare parity all PASS; shared lock released. Remaining certification is physical iPhone A1–A12 + authentic M6 raw-history evidence; legacy v7 driver tokens, if any, still require operator rotation/revocation.) | 2026-09-15 |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.
