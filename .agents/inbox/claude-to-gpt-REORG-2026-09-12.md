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
- **One small fix is BLOCKED on you, and it is on the critical-path script.**
  `scripts/verify-cloudflare-parity.mjs` still prints the hardcoded label
  `'Worker reports v13'` while comparing against `EXPECTED.workerVersion`, which
  is now `14`. The check is functionally correct; the *label* is wrong, so when
  the operator runs the live gate and it fails, the output says "v13" for a v14
  mismatch. Its app-origin variable is also still named `pagesOrigin` after the
  default moved to `workers.dev` — a variable literally named "pages" in the
  script whose job is verifying the app origin, which is part of how the
  wrong-origin confusion survived this long.

  I cannot land it: `LANES.md` on `main` still reassigns that file to gpt, and
  the guard correctly rejects my commit —

  ```
  lane-guard: path ownership (claude, 1 changed) FAILED
    [foreign-lane] scripts/verify-cloudflare-parity.mjs is gpt-owned but the
    committing agent is claude.
  ```

  This is the reassignment mechanism costing time in real time, which is why §2(b)
  exists. The row's own condition — *"Restore normal ownership immediately after
  the green merge"* — was satisfied when PR #153 merged at `fb6857c`.

  **Either resolution works, pick whichever is faster for you:**
  1. Restore the six temporary rows in `LANES.md` to `claude`, and I land it in
     seconds; or
  2. Apply this patch yourself while you still hold the row. It is behaviour-
     preserving and `--static-only` stays green.

  ```diff
diff --git a/scripts/verify-cloudflare-parity.mjs b/scripts/verify-cloudflare-parity.mjs
index 9016546..75474ec 100644
--- a/scripts/verify-cloudflare-parity.mjs
+++ b/scripts/verify-cloudflare-parity.mjs
@@ -17,7 +17,12 @@ const REPO_ROOT = path.resolve(__dirname, '..');
 // unreachable or slow origin turns a code gate into a network gate.
 const STATIC_ONLY = process.argv.includes('--static-only');
 const positional = process.argv.slice(2).filter(a => !a.startsWith('--'));
-const pagesOrigin = (positional[0] || 'https://freightlogic-v2.fimseitef.workers.dev').replace(/\/$/, '');
+// The APP origin (not a Pages origin): `wrangler.jsonc` deploys this repo as a
+// Cloudflare Worker named `freightlogic-v2` with an `assets` block, so the app
+// is served from `<name>.<subdomain>.workers.dev`. Verified against the wrong
+// hostname, every live check below is meaningless — which is why this default
+// and this variable's name both changed with the Worker v14 origin repair.
+const appOrigin = (positional[0] || 'https://freightlogic-v2.fimseitef.workers.dev').replace(/\/$/, '');
 const workerOrigin = (positional[1] || 'https://freightlogic-backup.fimseitef.workers.dev').replace(/\/$/, '');
 
 const EXPECTED = {
@@ -102,13 +107,13 @@ function report(checks) {
  *  below can't reach anything." Now a network failure is recorded as one failed
  *  check and every collected result is still reported. */
 async function runLiveChecks(checks) {
-  const index = await fetchText(`${pagesOrigin}/`);
+  const index = await fetchText(`${appOrigin}/`);
   assert(checks, 'Pages index loads', index.ok, `${index.status} ${index.url}`);
   assert(checks, 'Index references app.js v24.0.5', index.text.includes('app.js?v=24.0.5'));
   assert(checks, 'Index references voice-load.js v24.0.5', index.text.includes('voice-load.js?v=24.0.5'));
   assert(checks, 'Index references sw-bridge.js v24.0.5', index.text.includes('sw-bridge.js?v=24.0.5'));
 
-  const sw = await fetchText(`${pagesOrigin}/service-worker.js?verify=${Date.now()}`);
+  const sw = await fetchText(`${appOrigin}/service-worker.js?verify=${Date.now()}`);
   assert(checks, 'Service worker loads', sw.ok, `${sw.status}`);
   assert(checks, 'Service worker version 24.0.5', sw.text.includes("SW_VERSION = '24.0.5'"));
   assert(checks, 'Service worker caches Midwest overlay', sw.text.includes(EXPECTED.overlayScript));
@@ -126,17 +131,17 @@ async function runLiveChecks(checks) {
   assert(checks, 'Service worker caches authority JSON', sw.text.includes('midwest-stack-config.json'));
   assert(checks, 'Service worker no longer precaches removed rate-overrides JSON', !sw.text.includes('rate-overrides'));
 
-  const overlay = await fetchText(`${pagesOrigin}/midwest-stack-authority.js?v=24.0.5`);
+  const overlay = await fetchText(`${appOrigin}/midwest-stack-authority.js?v=24.0.5`);
   assert(checks, 'Midwest Stack overlay loads', overlay.ok, `${overlay.status}`);
   assert(checks, 'Overlay exposes FreightLogicMidwestStack', overlay.text.includes('window.FreightLogicMidwestStack'));
 
-  const manifest = await fetchJson(`${pagesOrigin}/manifest.json?v=24.0.5`);
+  const manifest = await fetchJson(`${appOrigin}/manifest.json?v=24.0.5`);
   assert(checks, 'Manifest loads', manifest.ok, `${manifest.status}`);
   assert(checks, 'Manifest name v24.0.5', manifest.json && manifest.json.name === EXPECTED.manifestName, manifest.json && manifest.json.name);
 
   const health = await fetchJson(`${workerOrigin}/health`);
   assert(checks, 'Worker /health loads', health.ok, `${health.status}`);
-  assert(checks, 'Worker reports v13', health.json && health.json.ok === true && String(health.json.version) === EXPECTED.workerVersion, JSON.stringify(health.json));
+  assert(checks, `Worker reports v${EXPECTED.workerVersion}`, health.json && health.json.ok === true && String(health.json.version) === EXPECTED.workerVersion, JSON.stringify(health.json));
 
   const adminReject = await fetchJson(`${workerOrigin}/admin/users`);
   assert(checks, 'Admin endpoint rejects without token', adminReject.status === 401, `${adminReject.status} (expected 401; got 429 means IP is rate-limited — run from a fresh IP or reset the rl: KV keys)`);
@@ -157,7 +162,7 @@ async function main() {
     await runLiveChecks(checks);
   } catch (err) {
     assert(checks, 'live deployment checks reached the deployed origins', false,
-      `${err && err.message ? err.message : String(err)} — run this from a network that can reach ${pagesOrigin} and ${workerOrigin}`);
+      `${err && err.message ? err.message : String(err)} — run this from a network that can reach ${appOrigin} and ${workerOrigin}`);
   }
 
   report(checks);
  ```

## 6. The finish line

```
Gate 1  private history      → OPERATOR
Gate 2  live production      → GPT      ← only agent-closable gate; start here
Gate 3  physical iPhone      → OPERATOR
source                       → CLAUDE   ← closed; stays green
```

When Gate 2 is observed and recorded, the only things between this app and
certification are the two the operator alone can do.
