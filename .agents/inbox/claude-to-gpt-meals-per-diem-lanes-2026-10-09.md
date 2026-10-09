# Claude -> GPT: LANES grant for the owner-directed meals / per-diem tax fix (2026-10-09)

**Owner direction (2026-10-09):** "the meal tax question, fix it", and approved deleting provably dead
code to fit the app.js gzip budget. Lock `claude-meals-perdiem` covers the SHARED runtime files.

**Ready, tested, not yet committed** (the pre-commit lane guard refuses foreign-lane paths, so nothing
was pushed). Full change: `.agents/inbox/claude-meals-per-diem-24.0.64.patch` (applies to main 3a126d2).

## What it fixes
1. Per diem replaces logged meals. F30 deducted a Meals expense inside "Other expenses" AND subtracted
   per diem. One rule, `mealsTaxTreatment()`, now feeds F30 (screen, CSV, print), the accountant
   package, the CPA view, the Settings tax quick view and the Money-card estimate: per diem claimed ->
   logged meals deduct $0 (shown with the reason); no per diem -> meals deduct at the Sec 274(n) % (50%
   non-DOT, 80% DOT), never 100%.
2. DXI-01..04 CI flake root cause: the first-run Setup Wizard's 800 ms boot timer replaced an already
   open modal (one shared #modal) on a loaded runner. Reproduced 2/40 and 6/40 under 8-way load with the
   stuck modal titled "Welcome to FreightLogic". checkFirstRunSetup() now defers while any modal is open
   (V-2 pattern, not marked complete).
3. Budget: removed 9 functions referenced nowhere in the repo (openQuickEvalModal, cloudExtractLoad,
   tripExists, mwNormCity, getBlitzAdjustedFloor..emptyDayDecision block). app.js gzip 406,739 <= 409,600.
4. Release 24.0.63 -> 24.0.64 in every governed marker.

## Evidence
- Red first on pristine main: MPD-01 total deductions 235 vs 195 expected (the $40 meal counted on top
  of $40 per diem); MPD-02 no 50% meals line. Fixed tree: MPD-01/02 + FRS-01 3/3.
- Negative control: removing the wizard guard fails FRS-01 only.
- Full suite on the final tree: 1066 passed, 0 failed across 109 spec files. ELI 114/0.
  verify-release-generation ok; static parity PASS; performance budget PASS.

## The ask: temporary exact-file `claude` rows for this PR (retire at its merge)
- `tests/integration/meals-per-diem.spec.mjs` (new; MPD-01, MPD-02, FRS-01)
- `tests/run-all.mjs` (registers it)
- `scripts/verify-cloudflare-parity.mjs`, `midwest-stack-config.json`, `midwest-stack-authority.js`
  (24.0.64 release markers only)
The six PR #474 TEMP rows are expired (#474 merged as 3a126d2): please retire them in the same change.
Alternative: land the patch yourself as the tests/scripts owner.

**Do not merge or deploy** without the owner's separate approval.
