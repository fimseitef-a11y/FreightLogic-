# FreightLogic Multi-Agent Protocol

This file is the durable coordination contract for Claude Code and ChatGPT/GPT. Protocol state on `main` is authoritative. Live coordination state is stored only on the long-lived `agent-coordination` branch and that branch is never merged to `main`.

## Current architecture and safety boundary

- FreightLogic is a vanilla-JavaScript, offline-first PWA with no build step.
- `app.js` is still monolithic (~950 KB on the coordination-setup baseline) and is **SHARED / serialized** until a behavior-preserving extraction creates real physical file seams.
- `tests/` contains the Playwright/Chromium regression suite. The aggregate entry point is `node tests/run-all.mjs`.
- No `TEST_MAP.md` while `app.js` is monolithic. Filename-based selective testing is false precision at this size.
- **Any `app.js` change requires the full suite. No exceptions and no judgment calls.**
- Service-worker, IndexedDB/storage, crypto/PIN, cloud restore, tax/accounting, decision-engine, and other core-path changes remain Claude-owned unless `LANES.md` explicitly changes ownership after extraction.
- GPT does not edit Claude-owned paths. Claude does not edit GPT-owned paths. SHARED paths require the lock protocol below.

## Durable vs live state

Durable protocol files live on `main`:

- `/AGENTS.md`
- `/.agents/LANES.md`
- `/.agents/AUDIT_TRIAGE.md`
- `/.agents/CLAUDE_PROMPT.md`

Live coordination files live on `agent-coordination` only:

- `/.agents/locks/`
- `/.agents/STATUS.md` — append-only
- `/.agents/TEST_LEDGER.md`
- `/.agents/inbox/`

Agents should use a dedicated coordination worktree when they have a local clone. Never switch/reset/rebase/merge the application worktree merely to read or update live coordination state.

Create the coordination branch without checking it out in the application worktree. A normal local setup is:

```bash
git fetch origin
git branch agent-coordination origin/agent-coordination 2>/dev/null || true
git worktree add ../FreightLogic-coordination agent-coordination
```

If the branch does not yet exist remotely, create and push it without switching the application worktree first.

## Lock protocol — VERBATIM

LOCK PROTOCOL (document verbatim in AGENTS.md — both agents obey it):
  Claim: fetch agent-coordination, fast-forward, create
    /.agents/locks/<slug>.lock containing:
      owner: <claude|gpt> | token: <uuid> | started_utc | expected_release_utc |
      paths | task
    Commit THAT FILE ALONE — never bundle anything with a lock commit. Push.
  REJECTED PUSH = CLAIM FAILED. Never rebase, cherry-pick, or force the
    rejected lock commit — that silently defeats the protocol. Fetch and
    inspect the exact lock path:
      - lock now exists → the other agent won. Abort, do other work.
      - lock does NOT exist → the branch advanced on unrelated state. Discard
        the rejected commit, rebuild a fresh lock-only commit from the new
        head, retry. Never reset the application worktree to do this.
  Never begin protected work until a fresh fetch confirms YOUR owner + token.
  Release: verify owner and token are yours, delete, commit, push.
  Reap: past expected_release_utc + 2h either agent may delete; log the
    reaped token and reason in STATUS.md.
  Any app.js edit requires lock/app-js while the file is monolithic.
  No TEST_MAP.md — selective testing is false precision at this file size.
  Full suite on every app.js change. No judgment calls.

## Clarification for rejected lock claims

A rejected push proves only that the shared coordination ref advanced; it does not by itself prove the requested lock is held. The exact lock path must be inspected after a fresh fetch. A rejected claim commit is disposable coordination state and must never be rebased/cherry-picked past the rejection. If the exact lock does not exist, reset/discard **only the dedicated coordination worktree's rejected claim state**, rebuild a new lock-only commit from the new remote head, and retry. Never perform such a reset in an application worktree.

## Amendment 1 — lock records declare their paths

The lock record gained one field, `paths:`, a comma-separated list of the exact
repository paths the lock covers. A trailing `/` covers a subtree.

```
owner: claude
token: 1cd1f613-3ae0-4e92-a1ee-9c793449bfa1
started_utc: 2026-08-26T09:56:54Z
expected_release_utc: 2026-08-26T12:56:54Z
paths: AGENTS.md, .agents/LANES.md
task: <one line>
```

The field is additive: the five-field records already on `agent-coordination`
still parse. A record without `paths:` covers **nothing**, because "which paths
did this lock authorise" was previously answerable only by reading the prose
`task:` line, which no check can do.

This is what makes `lock/app-js` in the protocol above mechanically real: a lock
covers `app.js` when it says `paths: app.js`, not when its slug happens to look
related.

## Amendment 2 — the protocol is enforced, not just documented

Lane ownership and this lock protocol are now checked by tooling. See the
Enforcement section of `/.agents/LANES.md` for the operator steps.

- `scripts/lane-guard.mjs` — the checker. Parses `/.agents/LANES.md` directly;
  there is no second machine-readable ownership file to drift.
- `.githooks/pre-commit` — refuses a staged foreign-lane edit, and a staged
  `SHARED` edit with no held lock covering that path. Fast feedback only:
  `--no-verify` bypasses it and hooks are not distributed by clone.
- `.github/workflows/lanes.yml` — the actual boundary. `path-ownership` and
  `commit-prefix` are enforcing; `lock-trailer` is warn-only for its first round.

Two rules the tooling encodes, both fail-closed:

1. A path with no row in `/.agents/LANES.md` cannot be classified, so it is
   rejected rather than allowed by default.
2. A lock past `expected_release_utc` + 2h is **stale**. It grants nothing —
   including to its own holder — and it is never auto-stolen. Reaping stays the
   deliberate act this protocol already describes: delete, commit, push, and log
   the token and reason in `STATUS.md`.

Because a lock is correctly released when work finishes, CI cannot re-read a
live lock at PR time. Commits touching a `SHARED` path therefore carry an
`FL-Lock: <slug>/<token>` trailer, written by `.githooks/prepare-commit-msg`, so
coverage stays auditable after release.

## STATUS discipline

`/.agents/STATUS.md` on `agent-coordination` is append-only. Append when:

- claiming substantive work,
- finishing/abandoning substantive work,
- reaping a stale lock,
- discovering a cross-lane dependency,
- completing a test run or recording a blocking baseline result.

Do not rewrite, reorder, squash, or delete prior STATUS entries.

## Inbox discipline

Use `/.agents/inbox/` on `agent-coordination` for cross-lane requests. An agent that needs a change to a path it does not own writes a narrowly-scoped request rather than editing the foreign path. The owning agent applies or rejects the request and records the disposition in STATUS.

## Test discipline

While `app.js` is monolithic:

- no selective test map,
- full suite for every `app.js` change,
- full suite after any service-worker/IndexedDB/storage migration change,
- full suite on an integrated PR head before merge when application behavior changed,
- log every observed run in `TEST_LEDGER.md` with exact SHA, command/environment, result, failing tests, and rerun reason if any.

A red baseline is evidence, not permission to alter the safety net. If the baseline is red:

- record every failing suite/test at the exact SHA,
- distinguish reproducible product failure from environment/infrastructure failure,
- at most one controlled rerun when justified, and log it,
- do not modify application code as part of baseline diagnosis,
- do not skip/quarantine/weaken/rewrite assertions,
- stop and report for approval before remediation.

## Git and integration

- Claude task branches: `agent/claude/<task>` or `claude/<task>`; commit prefix `[claude]`.
- GPT task branches: `agent/gpt/<task>` or `chatgpt/<task>`; commit prefix `[gpt]`.
- Those four namespaces are the complete set. A branch outside them fails the `commit-prefix` CI check rather than being silently accepted; add the namespace here first if a new one is genuinely needed.
- Never force-push.
- Never push to the other agent's branch namespace.
- Rebase task branches onto current `main` before integration when safe to do so; locks do not live on task branches.
- Pull request is the application-code merge boundary.
- `agent-coordination` is live coordination state only and is never merged to `main`.
- The initial protocol setup may add protocol files to `main`; this does not grant future direct-to-main application writes.

## Extraction gate

Parallel application work does **not** begin merely because this protocol exists. Claude must first:

1. obtain/record a green full-suite baseline,
2. propose a behavior-preserving UI seam extraction and stop for human approval,
3. execute structural moves only (no logic change, rename, reformat, Prettier, or opportunistic cleanup),
4. update service-worker precache/script load order deliberately in their own commit if required,
5. obtain a green full suite after extraction,
6. PR/merge extraction and confirm fresh green `main`,
7. update `LANES.md` and the GPT/Claude standing prompts with **actual extracted paths**.

No audit repair is mixed into that extraction round. If no clean seam exists, stop and use a sequential workflow.
