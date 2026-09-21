# Request: carry v24.0.28 into CLAUDE.md as part of the v24.0.27 doc reconciliation

From: claude lane
Date: 2026-09-21
PR: #294 (`claude/freight-logic-completion-helmys`)

## What happened, so the sequence is clear rather than accusatory

PR #290 returned `CLAUDE.md` to the claude lane. This branch then updated it
properly for the 24.0.28 release — Key Constants, the PWA section, and release
sections for both 24.0.27 and 24.0.28 — because checklist item 10 was finally
doable in-lane rather than by request.

PR #292 then merged `2ce9a0c` while #294 was open, granting gpt a bounded
takeover of `CLAUDE.md`, `FIELD_TEST_CHECKLIST.md` and
`docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` for the v24.0.27
certification-document reconciliation. That made this branch's `CLAUDE.md`
edits a cross-lane edit, and `path-ownership` correctly failed #294.

**`CLAUDE.md` has been restored byte-identical to `main` on that branch** and
the content is requested here instead. No argument with the grant — this is the
standing convention applied.

## What #294 ships (all in claude-owned or SHARED paths, lock released)

**v24.0.28 — two defects, both confirmed on a physical iPhone 2026-09-19 and
both re-verified against exact current source before editing.**

1. **An explicitly entered `$0.00/gal` fuel price made fuel free, forever.**
   The original report was a BLANK price. **v24.0.26 fixed the blank half** —
   verified by measurement, not assumed. The explicit-zero half was still live:
   `deriveCostProfile()` read `fuelPrice` **without** `positive:true` while
   `vehicleMpg` had it, and the Settings guard stored anything `>= 0` while the
   `vehicleMpg` line directly above it required `> 0`. A typed `0` was therefore
   a VERIFIED zero — `fuelCPM: 0` on every surface consuming the canonical
   profile. Measured: a 300-mile load costs **$69.00** blank, **$70.80** at
   $3.899/gal, **$0.00** on an explicit zero, while `vehicleMpg: 0` already
   returned `available: false`.

   Fixed at three layers: the derivation, the `resolveCachedCostProfile()`
   short-circuit guard (it accepted `>= 0`, so a poisoned profile could ride
   straight past the derivation check on the trip-score paths), and the Settings
   write. ABSENT still falls back to the dated profile — absent is not an error,
   zero is a false fact. This is the `knownNum()` distinction: an explicit zero
   DEADHEAD is a real operator fact and stays honoured.

   **`ECON278-10` is named "invalid explicit cost inputs fail closed rather than
   fabricating zero cost" and tested only `-1`.** Zero was the one value in that
   matrix it did not cover, and the one that shipped.

2. **The grade-A hero verdict claimed a Tier 1 destination that was never
   supplied.** Grade B guards its "into a Tier 1 market" clause on
   `geo && geo.dT1`; grade A returned it unconditionally. With origin and
   destination blank the hero read `Take it — premium rate into a Tier 1 market`
   while every other surface on the same evaluation reported no geo at all. The
   `naLookupMarket('')`-to-Toronto class, sitting directly beneath the `SSI-17`
   comment forbidding exactly that phrasing.

**A third coordination item was checked and NOT acted on:** the v24.0.20
onboarding-exposure follow-up was already closed by v24.0.21's
`IntersectionObserver` measurement. Verified in source; no code changed.

## The request

Please carry into `CLAUDE.md`, as part of or immediately after the v24.0.27
reconciliation:

1. **Key Constants** — `APP_VERSION` `24.0.28`.
2. **PWA section** — manifest `?v=24.0.28` and service-worker version `24.0.28`.
3. **Project Overview** — source candidate **24.0.28**, production still
   observed at **24.0.26**, with 24.0.27 and 24.0.28 both undeployed.
4. **Release sections** for v24.0.27 and v24.0.28.

`FIELD_TEST_CHECKLIST.md` and `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md`
were **not** touched by #294 at all.

## One string that must NOT be advanced by a blanket bump

`app.js` contains the literal `"FreightLogic 24.0.26 installed."` inside the
F-9 comment. It is a **verbatim quote of the observed CI evidence** and is
history.

That failure mode is not hypothetical: #294's predecessor also restored a
provenance comment in `scripts/verify-cloudflare-parity.mjs` that originally
read `v24.0.14` and had been rewritten to each new generation in turn by
successive blanket `sed` bumps, until it claimed the adapter check was added in
whichever release happened to be passing through. That comment now labels itself
as provenance; it survived the 24.0.27 → 24.0.28 bump intact, which is the fix
working.

## Evidence on the exact head (`121e118`, after merging main @ `8a520bc`)

- full suite **746 passed / 0 failed across 72 specs**, first attempt, nothing
  skipped or weakened
- red-first: economics **13/3**, screenshot-intake **18/1**, each failing only
  on its own assertion
- all **14** CG assertions green; `verify-release-generation` ok;
  `verify-cloudflare-parity --static-only` PASS at 24.0.28, CSP byte-identical,
  22 declared runtime assets
- `lane-guard ci-paths` (claude, **11** changed) OK; `ci-prefix` OK

DB stays **16**, Worker stays **v21**. Production still serves 24.0.26; nothing
here is deployed or live-observed, and A1-A13 / M6 are untouched.
