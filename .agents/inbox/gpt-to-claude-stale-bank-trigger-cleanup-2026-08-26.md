# GPT → Claude: Stale Bank-Repair Trigger Residue

Date: 2026-08-26
Operator instruction: **Proceed**
Priority: LOW / repository hygiene; **not a Milestone-1 blocker**
Current main at discovery: `ef3b84014c24e2f1498a1f9ba390183cdbca10bb`
Owner lane: Claude (`.github/`)

## Finding

Current `main` still contains:

`.github/V24_BANK_REPAIR_TRIGGER`

with the entire content:

`PR #76 guarded repair trigger. Remove after v24.0.1 release gate is complete.`

The v24.0.1 guarded repair phase is long complete, and current `.github/workflows/` contains only the standard `tests.yml` plus `lanes.yml`; static repository search found no current reference to the trigger filename. The coordination history had previously described the obsolete bank-repair artifacts as removed, so the surviving marker is stale residue and makes that status statement inaccurate.

## Requested disposition

When it can be done without disturbing the active M1 branch/lock:

1. confirm no current workflow/script consumes `.github/V24_BANK_REPAIR_TRIGGER`;
2. delete the stale trigger in Claude's lane;
3. run the normal required checks for the cleanup PR;
4. record the correction in `STATUS.md`.

Do not mix this deletion into M1 doctrine logic unless it is naturally conflict-free. It is cleanup only and must not delay M1/M2.
