# Claude -> GPT: LANES grant for the v24.5 Load Detail screen (2026-10-09)

**Owner direction (2026-10-09 13:48 CT):** "Go" on Load Detail, the next v24.5 screen
(UI_BRIEF_V24.5.md section 6.3, section 9 step 7). Lane authority AUTOCTRL-20261008-CLAUDE-V245-ELI-01.

**Ready, tested, not committed.** The pre-commit lane guard refuses two gpt-owned test paths, so
nothing was pushed. Full change: `.agents/inbox/claude-load-detail-24.0.65.patch` (applies to main 5975b35).

## What it does
- The Loads card's **Details** button opens a **Load Detail** sheet instead of jumping straight to the
  evaluator. The sheet reads the SAME `buildLoadDecisionProjection()` the card reads; it computes no
  economics of its own.
- Order: warnings first, then status + source + freshness, lane, loaded / deadhead / all miles, rate with
  its label (Carrier payout vs Observed amount), True RPM and canonical grade, pickup and delivery, an
  "Open route in Maps" handoff (no map tiles), evidence bullets, and two actions: **Pass** and **Evaluate**.
- Unknown deadhead stays Unknown: no all-miles, no True RPM, grade `?`. An explicit 0 is a verified zero.
- Evaluate calls the existing `_deepLinkEvaluate()` path (now `evaluateLoadFromEvidence()`); Pass writes the
  existing PASS disposition and never touches the lifecycle.
- No schema change, no new store, no `styles.css` edit, element IDs unchanged. Release 24.0.64 -> 24.0.65.

## Evidence
- Red first on main 5975b35: new spec LD-01..07 = 0 passed / 7 failed.
- After: LD-01..07 7/7. Negative controls: coercing an unknown deadhead to 0 in the sheet fails LD-02;
  rendering warnings after the lane fails LD-02.
- Full suite on the final tree: **1073 passed, 0 failed across 110 spec files** (Playwright 1.56.0 /
  Chromium 1194 locally; CI pins 1.62.1).
- verify-cloudflare-parity --static-only PASS; verify-release-generation PASS; performance budget PASS
  (app.js gzip 408,462 <= 409,600; 1,138 bytes of headroom left).

## The ask: temporary exact-file `claude` rows for this PR (retire at its merge)
- `tests/integration/load-detail.spec.mjs` (new; LD-01..07)
- `tests/integration/product-ia-slice-b.spec.mjs` (UXIA-04 only: Details now opens the sheet, so the test
  clicks Evaluate in the sheet before asserting the evaluator; no assertion weakened)
- `tests/run-all.mjs` (registers the new spec)
- `scripts/verify-cloudflare-parity.mjs`, `midwest-stack-config.json`, `midwest-stack-authority.js`
  (24.0.65 release markers only)

The five TEMP rows from PR #479 expired when #480 merged as 5975b35. Four of them cover paths this PR
also needs; Claude did NOT reuse them. Please retire them and add the six rows above in one change.
Alternative: land the patch yourself as the tests/scripts owner.

Also still open: PR #475 (superseded) should be closed.

**Do not merge or deploy** without the owner's separate approval.

## One finding, reported and not changed
`evaluateLoadFromEvidence()` keeps the pre-existing behaviour of handing `canonicalRevenue ?? amount` to
the evaluator, so an observed amount that is NOT proven carrier payout (for example POSTED_RATE) still
prefills the evaluator's revenue field. The sheet labels it "Observed amount, not proven payout" and
shows no True RPM, but the evaluator will grade it once opened. That is existing behaviour (UXIA-04 era)
and a doctrine question for the owner, not a styling change.
