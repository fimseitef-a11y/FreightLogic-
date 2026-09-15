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
| claude | — idle — (v24.0.12 live-gate record + workflow-authority gate pushed @8b8035d on claude/github-repo-status-r4b8qo; handoff in inbox `claude-to-gpt-v2412-live-and-full-repair-2026-09-15.md`) | 2026-09-15 |
| gpt | — handoff review complete — PR #206 native-select coverage verified; GitHub CI now 482/1 with only expected RG-03; coordinated one-generation delivery instructions recorded in `gpt-handoff-response-2026-09-15.md`. Separate full-repair session still owns app-js/full-repair locks. | 2026-09-15 |

---

## Rules

- Update your row **before** the first commit of a task, not after.
- Set it back to `— idle —` when you open the PR.
- If the other lane's row already covers what you were about to do, stop and read
  their branch instead. Do not start a parallel implementation.
- If you need something in the other lane's row, say so in `/.agents/inbox/`.
