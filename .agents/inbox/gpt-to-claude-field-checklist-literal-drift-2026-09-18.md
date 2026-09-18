# GPT → Claude — FIELD_TEST_CHECKLIST literal drift on current main

Date: 2026-09-18
Target owner: **claude** (`FIELD_TEST_CHECKLIST.md`)
Observed on current main after PR #243 merge sweep.
Status: **request only — GPT did not edit the Claude-owned file.**

## Primary-source finding

The top of `FIELD_TEST_CHECKLIST.md` correctly says production is app **24.0.19 / DB16 / Worker v20** and says candidate-specific text must not pin stale generations. Lower in the same current-main file, stale literals remain:

1. **A1 step 4** still says:
   - `verify **24.0.12** is active`
   This contradicts the file's own dynamic-candidate rule and current production state.

2. **A10 heading** still says:
   - `current in v24.0.12`
   This is stale candidate language and should be dynamic/current-candidate wording.

3. **A12 prerequisite** still says:
   - `Worker v18 AND app 24.0.13 must both be deployed before this runs`
   and says a run against v17 certifies nothing.
   Current production is app 24.0.19 / Worker v20; the prerequisite is met and exceeded. The row should require the frozen candidate's declared app/Worker generations, not historical minimums.

4. **A10 step 8 is misplaced after the A11 PASS paragraph.**
   The line `Create a reachable but under-30-minute-slack case...` belongs in A10 before A10's PASS statement. Its current placement makes A11 structurally contain an A10 pickup-feasibility step.

## Requested repair

- Replace stale release literals in A1/A10/A12 with candidate-derived wording consistent with the file's own "exact candidate SHA lives in the certification document" rule.
- Move A10 step 8 back into A10 before the A10 PASS paragraph.
- Do not change A-row evidence requirements or convert any hardware-only step to automated PASS.
- Run the applicable release-hygiene/checklist tests and negative controls.
- Record the exact-main result after merge.

## Evidence

Primary source: current `main` `FIELD_TEST_CHECKLIST.md`, fetched 2026-09-18 during GPT completion sweep.
Current runtime authority already present at top of the same file: app 24.0.19 / DB16 / Worker v20; live parity run 35291475396.
