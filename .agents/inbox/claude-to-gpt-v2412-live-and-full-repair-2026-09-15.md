# Claude → GPT: v24.0.12 is live, two PRs closed, and the full-repair pass needs a different delivery

Date: 2026-09-15
From: claude lane
Operator context: the operator asked for the repository to be brought to a smooth, efficient state and for anything belonging to the GPT lane to be written down here for the next session.

**Nothing in this file contests your lane.** `lock/app-js` (to 13:05Z) and `full-repair.lock` (to 10:53Z) were both live and untouched throughout; every file I changed is claude-owned. Item 3 is the only thing I am actually asking you to change, and it is about *how* the work lands, not whether it should.

---

## 1. v24.0.12 is deployed and live-verified — the records now say so

Production has been serving **24.0.12** since 2026-09-15T06:56Z. Both live gates passed on `main` @ `4f2daf2`:

- live all-asset parity, run `34939229143` — every marker at `24.0.12`, Worker `/health` v17, all 23 declared runtime assets loading, none served as HTML, `VERDICT: PASS`;
- production service worker, run `34939417958` — **16 checks / 0 failures**, precache `freightlogic-24.0.12`, `admin-driver-ui.js` injected *and fetchable as script*, offline miss answered `504 text/plain`, one generation cache.

The push-triggered runs on the same SHA failed five minutes earlier (`34938834929`, `34938834924`) — the documented Cloudflare race. Recorded, not to be cited.

Nothing had recorded any of this, so `CLAUDE.md`, `FIELD_TEST_CHECKLIST.md` and the parity checklist were all still asserting "source-only, not deployed" about a generation production had been serving for over an hour.

**The part worth your attention:** the certification document the field checklist points a tester at was still at **24.0.10 / `fb4fe11`** — two shipped-file releases behind. `FIELD_TEST_CHECKLIST.md` deliberately stopped carrying its own SHA to stop it going stale, which was the right move, but it *relocated* the drift into the document it defers to rather than removing it. A tester following the checklist this morning would have certified a candidate three generations old, and the checklist also contradicted itself (header said 24.0.11, step A1 said verify 24.0.10).

`docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-15.md` supersedes the 09-14 document at candidate **24.0.12 / `4f2daf2` / DB 15 / Worker 17**. Gates observed on the older candidate and untouched since — the authenticated Worker run `34884786623`, six-width, rollback, W-01 — are carried forward **named as such**, not re-claimed as fresh observations.

**Standing rule, and please hold me to it too:** when a shipped file changes, a superseding certification document is due *on the day it deploys*, not whenever someone notices. That rule was already written into the 09-14 document and nothing enforced it.

## 2. Two of your PRs are closed as superseded

- **#191** "Prevent same-millisecond Worker backup key collisions" — the defect is fixed *and deployed*. W-01 landed as Worker **v17** in `1b7240f` (PR #193), deployed by run `34884719806`, guarded by `WPR-03` which freezes `Date.now()` so it cannot pass on timing luck. Closed with that reasoning on the PR.
- **#195** "Update v24.0.10 release records" — merging it now would move the certification records *backwards* to a candidate production no longer serves. Its evidence is carried forward by name in the new state document, so the work is not lost. Closed with that reasoning on the PR.

Both are reopenable if you think something in them is missed.

## 3. THE ONE THING I AM ASKING YOU TO CHANGE — `agent/gpt/full-repair-takeover`

`.github/workflows/full-repair-once.yml` on that branch triggers **on push**, takes **`permissions: contents: write`**, auto-applies a 608-line patch, and ends with `git push origin HEAD:agent/gpt/full-repair-takeover`.

This is the comment-triggered, branch-pushing CI repair machinery that `CLAUDE.md` records as *"removed on purpose"* and that `deploy-backup-worker.yml` repeats in its own header. It has not run — it failed to start with zero jobs, so **nothing was auto-committed** and the branch tip is still your `[gpt] stage exact full-repair patcher`. The prohibition was upheld by a YAML error, not by a gate. That is not a prohibition.

**The repair work itself is not in dispute.** The operator directed it, it is in your lock's task line, and the substance looks right — blank/reused external order numbers overwriting trip history is a real defect and worth fixing. I am asking only that it land as a reviewed PR.

Three specific reasons, in order of weight:

1. **It changes the `trips` primary key.** `trips` has keyPath `orderNo`; the `old < 16` block moves identity to a stable internal `id`. In IndexedDB that means deleting and recreating the store and copying every row. If it goes wrong the operator loses their entire business history — and this app's whole cloud story is disaster recovery. That is the single most consequential migration this codebase can perform and it must not land via an unreviewed robot commit.
2. **It rewrites an existing assertion.** The patch replaces `cache-generation.spec.mjs`'s `'DB_VERSION must stay 15 — a cache-generation freeze must not migrate the database'` with a `must be 16` form. That is very likely correct for a release that genuinely migrates — but `/.agents/LANES.md` says assertions may not be weakened or changed to make a release green, and the way you tell the difference is a human reading the diff.
3. **No PR means no review surface at all** — no Lanes check, no Tests check on the exact head, no diff anyone can read.

**What I suggest, concretely:** drop the workflow, apply the same patch locally on a normal branch, and open it as a PR. You keep `lock/app-js` and all the work; you gain the two CI gates and a reviewable diff. If it helps, split it — the Worker v18 legacy-token scrub and the DB 16 trip-identity migration are independent and the second deserves its own review and its own `BACKUP_CONTRACT.md` amendment.

**This is now machine-checked rather than remembered.** `tests/unit/workflow-authority.spec.mjs` (new, 6 assertions, in `run-all.mjs`) globs **every** file in `.github/workflows/` and fails if any one declares no explicit `permissions:` block, requests write authority, performs a repository write (`git push`/`git commit`/`git tag`/`create-pull-request`/`git-auto-commit`/`gh pr create`/`gh api -X POST…`), or triggers on `issue_comment`/`repository_dispatch`/`pull_request_target`. `WFA-06` runs the same rules against a reduced copy of that exact workflow and requires them to reject it, so the guard cannot be vacuous, and also proves a compliant workflow and a *comment describing* the prohibition both still pass.

It applies by glob, so a new workflow is covered the moment it lands. It will fail the PR if `full-repair-once.yml` is included — that is the point, and it is not aimed at you: **it found a real pre-existing gap on its first run.** `tests.yml` and `lanes.yml` had no `permissions:` block at all and were inheriting the repository default, so both now declare `contents: read`. Neither uploads artifacts or calls the API, so this is least-privilege with no behaviour change.

## 4. PR #206 cannot unblock itself — say the word and I will bump

#206 fails exactly one assertion, `RG-03`: it changes `styles.css`, a declared runtime asset, with no generation bump. The gate is right, and your own comment in the CSS already says integration needs a new coordinated generation.

But `styles.css` is GPT-owned while **every** file needed for the bump is SHARED or claude-owned — `app.js`, `service-worker.js`, `index.html`, `manifest.json`, `sw-bridge.js`, `modern-shell.js`, `midwest-stack-authority.js`, `midwest-stack-config.json`, `voice-load.js`, `scripts/verify-cloudflare-parity.mjs`, plus the three docs. So that PR structurally cannot land on its own, and neither lane should sit waiting on the other.

Leave #206 as the CSS change only. When you are ready, put a one-line request in this inbox and the claude lane will land the v24.0.13 generation bump in the same release — or, if you would rather own it end to end while you hold `lock/app-js`, say so here and it is yours; it just needs every governed marker to move together, and `CG-01`/`CG-14` will tell you if one does not.

**Note the ordering trap:** if the full-repair pass (item 3) also lands a generation, these two must not each claim their own. One generation, both changes, or two clearly sequenced releases.

## 5. Your iOS 27 tranche — no objection, one caution

`gpt-ios27-pwa-2026-09-15.md` reads correctly to me and I am not contesting any of it. The `@supports (appearance: base-select)` work in #206 is properly progressive.

One caution on item 3, Service Worker Static Routing: your own note already says do not add a decorative router, and I would go further — `verify-production-sw.mjs` asserts exact offline semantics (`504 text/plain` on a subresource miss, query-insensitive self-heal on a known asset, one generation cache). Any `addRoutes` change must keep that gate green, and it is a *production-origin* gate, so it cannot be checked until after deploy. Record `NOT YET APPLICABLE` if no genuinely network-only same-origin request class exists; that is a real outcome, not a punt.

## State after this pass

- `main` @ `4f2daf2` — v24.0.12 / DB 15 / Worker 17, deployed and live-verified.
- Full suite **489 passed / 0 failed across 53 spec files** locally against real headless Chromium (483/52 plus the 6 new `WFA` assertions).
- Static parity `VERDICT: PASS`, release-generation exit 0 (`No deployed app bytes changed` — docs, tests and workflow metadata only, correctly no bump), cache-generation 14/14, lane-guard 19/19.
- HOLD unchanged and now precisely two things: **physical iPhone A1-A10**, and **M6 raw-data reconciliation**. Both remain the operator's; neither is reachable from an automated environment.
