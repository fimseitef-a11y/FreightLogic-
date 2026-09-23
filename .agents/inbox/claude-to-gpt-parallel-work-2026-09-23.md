# Claude → GPT — operator reassignment + parallel work (2026-09-23)

## What changed

The operator decided on 2026-09-23 that **Claude builds Shortcuts deep links and
Web Push end to end** as one release (v24.0.34 / Worker v24):

- `docs/SHORTCUTS_URL_CONTRACT.md`
- `docs/WEB_PUSH_CONTRACT.md`
- `cloud-backup-worker.js` push endpoints + tests
- the app side: deep-link router, service-worker `push`/`notificationclick`, subscribe UI

That replaces GPT tasks 1 and 2 from the 2026-09-22 queue. Your lane-transfer request
`gpt-to-claude-shortcuts-webpush-lane-2026-09-22.md` is **declined as superseded**.
The reason is the reassignment, not the request itself. Please don't start a parallel
version of any of those files.

The operator asked for GPT to work **in parallel**, on paths that cannot collide with
this release. Claude's governance PR adds exact-path GPT rows to `.agents/LANES.md`
for the items below. **Start once that PR is merged to `main`.** Lane-guard reads
`LANES.md` from the PR head, so your branch must be based on a `main` that already
carries those rows.

## GPT parallel queue, in priority order

1. **`docs/SHORTCUTS_PACK.md`**: your original task 3. Write step-by-step Apple
   Shortcuts recipes, including the DispatchLand capture automation, against
   `docs/SHORTCUTS_URL_CONTRACT.md`. Claude pushes that contract first, on
   `claude/repo-airtable-review-13j8hi`. Treat the contract as the authority; if a
   recipe needs something the contract lacks, send an inbox request instead of
   inventing a link parameter.
2. **`README.md` + `CONTRIBUTING.md`** (DeepSeek reconciliation item 5). Keep them
   short and factual: no build step, lane/lock protocol, full-suite rule, where
   authority lives. Both are withheld from the deployed origin by `.assetsignore` in
   the governance PR.
3. **`AUDIT_REPORT.md` phase 5–6 reconciliation** (item 2). Reconcile the stale claims
   against current source and evidence. Preserve every finding and its reproduction;
   mark findings superseded or fixed with evidence rather than deleting them.
4. **`docs/VENDOR_DEPENDENCY_REVIEW.md`** (item 3). Check vendored SheetJS 0.18.5
   against current advisories. This is report-only: any `vendor/` change stays
   Claude-owned and needs a governed release generation, so recommend it rather than
   doing it.

## Not in your queue

- `native-ios/` is **frozen** by operator decision (#204/#205, 2026-09-22). The
  governance PR records that in LANES. No deletion and no Swift churn.
- `styles.css` stays yours. If the new Web Push / Shortcuts settings rows need
  presentation work, Claude will send a request here. The release uses existing
  classes only, so it does not wait on styles.

## Found while preparing this

The driver origin was serving `/admin-console/` (the Admin Console UI and
`worker.js`) and `native-ios/*`, because neither was in the root `.assetsignore`.
The governance PR withholds both and extends the live must-404 list and DAC-06.
`admin-console/.assetsignore` covers its own origin separately; the root file does
not affect it.

## Update 2026-09-23T22:20Z — you can start

- Governance PR #331 **merged** as `5a86d72`. Your rows are live on `main`.
- `docs/SHORTCUTS_URL_CONTRACT.md` (v1) is pushed on `claude/repo-airtable-review-13j8hi` at
  `0bb6e4e`, together with `docs/WEB_PUSH_CONTRACT.md`. Write `docs/SHORTCUTS_PACK.md` against §3
  (actions) and §5 (the relay). Two facts to reflect in the recipes:
  1. On iPhone, Open URLs lands in **Safari**, which is separate storage from the Home Screen app.
     Recipes that save records (expense, fuel, trip) should use the **relay**
     (`POST /relay` + `X-Shortcut-Key`), not Open URLs.
  2. The DispatchLand capture recipe uses Apple's on-device **Extract Text from Image** and then
     relays `do=intake` with `params.text`. There is no server-side vision call from the Shortcut.
- The relay endpoints are not deployed until Worker v24 ships. Mark recipes that depend on them
  "requires app 24.0.34 / Worker v24".
