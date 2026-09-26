# GPT → Claude: Milestone 3 / PR #87 Reconciliation Risk Map

Date: 2026-08-26
Operator instruction: **Proceed**
Status: analysis only; **DO NOT START M3 UNTIL M1 + M2 ARE INTEGRATED GREEN**
Target later milestone: M3 — reconcile and land v24.1 Confidence + Evidence
Stale branch/PR: #87 (`claude/proceed-l4aacv`)

## Why this map exists

PR #87 contains useful v24.1 architecture, but it was authored before Gate 0 truth/provenance, before the M1 doctrine/UNKNOWN repair, before the M2 concurrency gate, and before the duplicate roadmap was retired. It must be treated as a source of patches to selectively reapply onto then-current main, **not** as a branch to blind merge.

The PR changes 18 paths, including `app.js`, `cloud-backup-worker.js`, `midwest-stack-authority.js`, service-worker/version surfaces, tests, and the now-retired `docs/V24_ROADMAP.md`.

## Hard reconciliation blockers

### 1. Never resurrect `docs/V24_ROADMAP.md`

PR #87 modifies `docs/V24_ROADMAP.md` and marks v24.1 "shipped." Gate 0 governance later retired that file. The only active roadmap is `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`.

**Disposition:** drop this file from the reconciled M3 change entirely. Do not restore it and do not copy its completion-status claims into the canonical roadmap until M3 actually passes its gate.

### 2. Rebase Midwest patch onto M1-fixed authority metadata/doctrine

PR #87's Midwest patch only bumps `v24.0.0 -> v24.1.0` and still labels the file `Midwest Stack v2 Authority Overlay`; it adds `getRateOverrideFreshness` export. M1 is specifically repairing stale generation wording, Cincinnati/Toledo Tier drift, DZ 0.90, UNKNOWN handling, and related authority parity.

**Disposition:** preserve/reapply only the useful freshness export against the M1-fixed file. Do not take the stale PR #87 file wholesale or reintroduce v2/Tier/DZ/finite() drift.

### 3. Strict UNKNOWN semantics must apply inside the evidence layer too

PR #87 correctly introduces `_evidenceNum()` because `Number(null)` and `Number('')` collapse to zero, but several downstream summaries still bypass that rule, e.g. patterns such as:

- `Number(lane.avgRPM || 0).toFixed(2)`;
- `Number(s.fuelPrice || 0).toFixed(2)`;
- `Number(s.opCPM).toFixed(2)` guarded only by positive checks;
- `Number(s.mpg || 0)`;
- count/age summaries using `|| 0` fallbacks.

These values are descriptive rather than canonical economics, but Gate 0/M1 prohibits invented numeric certainty in evidence just as strongly as in decisions.

**Disposition:** normalize material evidence fields once and render explicit UNKNOWN/no-data wording when absent. A missing observed value must never become a displayed `0`, `$0.00`, `0 MPG`, or precise zero-valued evidence statement.

### 4. Do not infer EIA provenance from price equality

PR #87 reconstructs `fuelPriceSource` by checking whether the stored driver fuel price is within 0.005 of the last EIA price:

```js
const _fuelFromEIA = Number(fuelPriceSetting) > 0 && _eiaLastPrice > 0
  && Math.abs(Number(fuelPriceSetting) - _eiaLastPrice) < 0.005;
```

That can mislabel a manually entered driver price as EIA merely because the numbers happen to match. Gate 0 provenance rules forbid deriving source identity from numeric coincidence.

**Disposition:** provenance must come from an explicit source marker captured at the time the price is set/applied, or remain UNKNOWN/driver-setting if exact origin cannot be proven. Do not infer source identity from value equality.

### 5. NWS/current-route evidence must be bound to an actual observation

PR #87 sets:

- `weatherChecked = navigator.onLine && (origin || dest)`; and
- `weatherAlertCount: 0`;
- then may use global NWS source health/lastSuccess to describe route weather.

Being online with a route is not proof that the current route was queried, and a prior successful NWS request may refer to another route/time. Hardcoding `0` can therefore become a false "0 active alerts" observation.

**Disposition:** only emit current-route NWS evidence when the exact route/request produced an observation tied to that decision. Otherwise use `NO_DATA` / `SOURCE_UNAVAILABLE` / UNKNOWN as appropriate. Source health alone is not a route observation.

### 6. Worker projection currently violates M1 UNKNOWN semantics

Current main `cloud-backup-worker.js` already contains projection fallbacks that can manufacture certainty:

- missing verdict -> `REJECT`;
- missing grade -> `F`;
- `Number(null)` True RPM -> `$0.00 / true mile`;
- null bid tier amount/RPM -> `$0 @ $0.00/mi`.

A separate M1 compatibility note was staged at `/.agents/inbox/gpt-to-claude-m1-worker-projection-integrity-2026-08-26.md`.

PR #87 builds directly on these helpers, so M3 must not preserve or reintroduce them if M1 fixes the Worker first.

### 7. Version/service-worker parity must be regenerated from then-current main

PR #87 hardcodes app/SW/cache/asset query versions to `24.1.0`, Worker `v13`, and its historical tested counts. Since M1 + M2 integrate first, M3 must reconcile version surfaces from the actual post-M2 base rather than copy the old branch wholesale.

Affected surfaces include at least `app.js`, `index.html`, `manifest.json`, `service-worker.js`, `sw-bridge.js`, `voice-load.js`, Worker health/version, parity docs/scripts, and any release cache tags.

**Disposition:** apply the final M3 release/version bump as one deliberate parity operation after logic reconciliation and tests. Do not trust PR #87's old 147/0 claims as certification of the rebased tree.

## Architecture worth preserving from PR #87

Subject to the blockers above, the following concepts remain aligned with the canonical roadmap:

- categorical `HIGH | MEDIUM | LOW` confidence only; no win probabilities;
- confidence is descriptive and cannot move verdict/grade/True RPM/bid floors;
- explicit distinction among `AVAILABLE`, `NO_DATA`, and `SOURCE_UNAVAILABLE`;
- source health + freshness + sample size + provenance as evidence metadata;
- immutable client-owned confidence projection into Worker `/evaluate`;
- Worker may explain/challenge evidence quality but cannot publish a competing confidence model;
- optional additive decision/bid-history confidence snapshot, provided storage/backup contracts remain compatible;
- `getRateOverrideFreshness` export from the Midwest adapter, re-applied to the M1-fixed file.

## Required M3 execution order after M1 + M2

1. Rebase/selectively port PR #87 logic onto then-current main.
2. Drop retired roadmap changes and stale completion claims.
3. Resolve all UNKNOWN/provenance/current-observation blockers above.
4. Preserve M1 doctrine/money parity and M2 concurrency behavior exactly.
5. Re-run/add v24.1 authority, evidence, UI, Worker-projection, missing-data, and provenance regressions.
6. Run the full suite on exact head.
7. Regenerate release/version/SW/manifest/Worker parity from that exact head.
8. Only then open/merge the reconciled M3 PR.

No provider adapter, vision runtime, lifecycle implementation, or later-mile intelligence work is authorized by this reconciliation map.
