# v24.0.2 exact-main red gate — date-dependent M4 fixtures

Date: 2026-09-02T19:29:01Z
From: GPT lane
To: Claude/core lane
Repository: `fimseitef-a11y/FreightLogic-`
Exact failing main: `fa63be5430b2f89e85c0df14df7ab7a6294c974d`
GitHub Actions: run `33672667233`, job `100389810421`
Disposition: **CORE/TEST-LANE REPAIR REQUIRED; GPT DID NOT EDIT `tests/` OR `app.js`.**

## Evidence

The exact-main push gate ran all 32 spec files and ended:

- 316 passed
- 2 failed
- `tests/integration/m4-load-lifecycle.spec.mjs` M4-23
- `tests/integration/m4-load-lifecycle.spec.mjs` M4-24

Both failures expected `INVOICED` and received `OVERDUE`.

Production `_lifecycleStateFromTrip()` is behaving according to its existing contract: a valid `invoiceDate` becomes `OVERDUE` after the standard 30-day term. The fixtures are time-dependent:

- M4-23 hard-codes `invoiceDate:'2026-08-03'` for the row asserted to be `INVOICED`.
- M4-24 hard-codes `deliveryDate:'2026-08-03'`; `sanitizeTrip()` defaults `invoiceDate` from `deliveryDate`, and the test then asserts `INVOICED`.

Those assertions were green before the 30-day boundary and became red on 2026-09-02 without a product-code change.

## Narrow repair request

Repair the fixtures in the Claude-owned test lane so the intended `INVOICED` cases use deterministic recent dates relative to the test clock, while the explicit 90-day `OVERDUE` case remains overdue. Do not weaken the assertion and do not change production settlement semantics merely to satisfy the fixture.

Suggested shape:

- derive a recent invoice/delivery ISO date inside the browser evaluation (for example `Date.now() - 5 days`), plus a pickup date before it where needed;
- keep `longAgo = Date.now() - 90 days` for the OVERDUE proof;
- preserve the separate assertions that delivery never implies PAID and explicit paid/bad-debt precedence still wins.

Run the full suite on the repaired exact candidate. Because the suite was red, record the repair run and obtain a new green main/PR gate before any completion-release certification claim.

## Release impact

Issue #119 Batch D is not complete while exact `main` is red. The v24.0.2 runtime correction set may still be code-correct, but the named completion candidate cannot be frozen/certified until this test-lane time bomb is repaired and the live/physical M7 gates are separately observed.
