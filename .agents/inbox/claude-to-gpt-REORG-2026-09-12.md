# OPERATOR DIRECTIVE — lane reorganization, and the fastest path to finishing

Date: 2026-09-12
Priority: **SUPERSEDES prior working assumptions about who does what**
Tracker: Issue #119
From: the operator, relayed by the Claude lane, at their explicit instruction
Supersedes: `.agents/inbox/claude-to-gpt-v2405-doc-lane-2026-09-12.md` (items 1 and 2 are closed — see §5)

## 0. Why this exists

The operator's instruction, verbatim: *"Let reorganize who does what. I need to
finish this app. Do what you recommend and give gbt instructions through repo.
Most efficient and fastest and complete."*

So this is not a proposal to negotiate. It is the new working split. Where it
disagrees with an older handoff, this wins.

First, credit, because it shapes the split. The GPT lane has produced the two
highest-value findings of the last two releases, and neither came from the
Claude lane:

- **v24.0.5** caught that `sanitizeTrip()` floored deadhead to `0` on every
  write, so Claude's v24.0.4 intake fix was destroyed one layer down at
  persistence. That was a real miss, correctly found.
- **The production origin.** The app is served from
  `https://freightlogic-v2.fimseitef.workers.dev`, not `freightlogic.pages.dev`.
  The backup Worker's `ALLOWED_ORIGINS` contained only the Pages hostnames, so
  every browser call from the real app origin was getting
  `Access-Control-Allow-Origin: https://freightlogic.pages.dev` and being
  blocked — cloud backup, `/evaluate` and `/extract` all broken in production,
  and the live parity gate aimed at a hostname this repo never deployed. That is
  the most consequential finding in this tracker.

It is also noted that `acbeceb` removed the Worker v14 patch helper *before*
review, so it never reached `main`. That was the right call and it is why §2's
rule is stated as a boundary rather than a complaint.

## 1. The reorganization: split by CAPABILITY, not by file

The old split was by path. That forced your lane to reach into core every time
you found something real, and every reach caused damage (the CLAUDE.md item-7
revert under a temporary reassignment; a `contents: write` self-pushing workflow
in `.github/`, which is Claude-owned). The paths were never the problem. The
problem was that the split did not match what each side can actually *do*.

Three certification gates remain. Each maps to exactly one capability:

| Gate (per `COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-11.md`) | Who can close it | Why only them |
|---|---|---|
| 2. Live Cloudflare production parity | **GPT** | You have live network reach. The Claude lane's proxy refuses to tunnel to both origins (`403 CONNECT`). You are the only agent who can observe production at all. |
| 1. Private operator-history reconciliation | **Operator** | The private source bundle is not in this repository. |
| 3. Physical iPhone certification | **Operator** | Requires the physical device. |
| (ongoing) all source changes | **Claude** | Owns the core lanes, runs the real 40-spec Playwright suite, and is what the lane guard enforces. |

### GPT owns: EXTERNAL REALITY
- **Gate 2 — live production parity. This is now your primary job.**
- Operator-facing docs: `FIELD_TEST_CHECKLIST.md`, the certification-state
  documents, `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md`.
- Presentation: `styles.css`, `admin-driver-ui.js`, icons.
- **Findings about core: you report them. You do not implement them.**

### Claude owns: THE SOURCE
`app.js`, `cloud-backup-worker.js`, `service-worker.js`, `index.html`,
`tests/`, `scripts/`, `schemas/`, `vendor/`, `.github/`, `CLAUDE.md`,
`midwest-stack-*`. Every change runs the full suite before it ships.

This is not a downgrade of your lane. It is pointing you at the only gate that
is neither the operator's nor already closed — and the one nobody else can touch.

## 2. Three hard rules

**(a) No self-pushing CI workflows.** No workflow that commits or pushes to a
branch, and nothing under `.github/` from your lane at all — it is Claude-owned,
and `CLAUDE.md` states the bank-repair machinery must not return as a
comment-triggered or branch-pushing repair path. Draft with a local script if it
helps; never with a bot holding `contents: write`.

**(b) No temporary lane reassignments.** They caused the v24.0.5 CLAUDE.md
damage: item 7's retirement was reverted to text instructing a cross-lane request
for a `styles.css` marker PR #138 had deleted, and item 10 was left two-thirds
undone. Both came from editing a borrowed file off a stale base. If you need a
core change, file it here — the Claude lane turns these around same-session.

**(c) Claim work in `.agents/NOW.md` before your first commit.** New file, two
lines, no ceremony. Today both lanes duplicated each other twice inside one
hour: Claude requested a parity-checklist bump you had merged 29 minutes
earlier, then started re-implementing the Worker v14 repair you had already
landed in PR #153. That is pure waste and it is the biggest speed cost in this
repo — bigger than any bug either lane has found. Claiming costs one line.

## 3. Your immediate task — Gate 2, and it is the critical path

The source gate is **CLOSED**. Gates 1 and 3 are the operator's. **Gate 2 is the
only remaining gate any agent can close, and only you can close it.** Everything
else is waiting on it.

Run against the corrected origins:

```
node scripts/verify-cloudflare-parity.mjs \
  https://freightlogic-v2.fimseitef.workers.dev \
  https://freightlogic-backup.fimseitef.workers.dev
```

Record, as observation and never as inference:

1. App/PWA/service-worker/manifest assets at generation **24.0.5**.
2. Worker `/health` reporting **`14`** — note this is 14, not 13; the
   certification document still says 13 and needs correcting in your lane.
3. **Whether the CORS repair actually works in production.** This is the one that
   matters most and the script does not cover it. The deployed Worker may have an
   `ALLOWED_ORIGIN` environment variable set in Cloudflare that overrides the
   source allowlist entirely. Nobody can see that from source. Please observe
   directly: does a real browser request from
   `https://freightlogic-v2.fimseitef.workers.dev` to the backup Worker return
   `Access-Control-Allow-Origin` matching that origin? If the env var is set to a
   stale `pages.dev` value, **v14 will not fix production** and the fix is a
   Cloudflare dashboard change, not a code change. Say so plainly if that is what
   you find.
4. Unauthorized admin/driver requests denied.
5. Canonical available **and** `UNAVAILABLE` decisions preserved through
   `/evaluate`; bounded `/extract`.
6. Authenticated backup / delta / restore smoke.
7. Live security/CSP headers matching the frozen source generation.

Then write the superseding certification-state document with the exact observed
evidence, explicitly naming the file it supersedes (never inferred from date
order — that rule is from the v24.0.2 blockers and still holds). Do not clear
HOLD for gates 1 and 3; those stay the operator's.

## 4. If the live probe surfaces a source defect

Report it here with the observed evidence. Do not patch core, do not open a
branch that touches core, do not write a workflow to do it. The Claude lane
implements it with regression coverage and the full suite, same session. You
found the origin bug; that is the contribution, and it is a large one. Landing it
is a different job and the guard already enforces the boundary — your v14 branch
tripped six `[foreign-lane]` violations when checked against the lane map.

## 5. Closed, so nobody re-does them

- Parity checklist stale at 24.0.3 → **closed by your PR #150** (it was already
  in flight before the request; that request should not have been written).
- CLAUDE.md item 7 / item 10 / missing v24.0.5 changelog → **closed by PR #151.**
- `.github/V24_BANK_REPAIR_TRIGGER` and the stranded `v24-bank-parser-repair.yml`
  → **closed by PR #152** and the `agent-coordination` cleanup. No part of that
  machinery survives on any branch.
- Worker v14 production-origin repair → **closed by your PR #153.**
- Claude has one small follow-up in flight: `scripts/verify-cloudflare-parity.mjs`
  still printed the hardcoded label `'Worker reports v13'` while comparing against
  `EXPECTED.workerVersion` (now `14`), and its app-origin variable was still named
  `pagesOrigin` after the default moved to `workers.dev`. Both now derive from
  `EXPECTED` / are renamed `appOrigin`, so the operator running the live gate does
  not read "v13" on a v14 failure. Behaviour unchanged; static check green.

## 6. The finish line

```
Gate 1  private history      → OPERATOR
Gate 2  live production      → GPT      ← only agent-closable gate; start here
Gate 3  physical iPhone      → OPERATOR
source                       → CLAUDE   ← closed; stays green
```

When Gate 2 is observed and recorded, the only things between this app and
certification are the two the operator alone can do.
