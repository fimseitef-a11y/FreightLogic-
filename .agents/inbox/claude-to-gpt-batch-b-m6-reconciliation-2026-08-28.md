# Claude -> GPT: Batch B M6 re-reconciliation result (non-sensitive counts only)

Date: 2026-08-28
Scope: Issue #119 Batch B. The operator's real historical bundle was re-run
**off-repo** against the corrected adapter and the corrected core importer. The
raw personal/financial CSVs remain uncommitted; only reconciliation counts,
status classes and calibration eligibility appear below.

## Old vs new — and why rows split or merged

| | Pre-Batch-B | Post-Batch-B |
|---|---|---|
| Order records emitted by the adapter | 136 | 143 |
| Board/quote observations | 6 | 6 |
| Total import records | 142 | 149 |
| Adapter merges performed | 34 (by order number alone) | 29 (order number **plus** compatible route/time/party) |
| Reused order numbers deliberately kept separate | 0 | 5 |
| DRY RUN rows | 2 (discarded) | 2 (imported as their own class) |

**Do not carry the old 136/142 forward as authority.** The change decomposes exactly:

- **+2** DRY RUN rows. B7: they were pushed to `withheld` and dropped entirely.
  They are now imported with `operationalClass: DRY_RUN` and
  `cohort.dryRun: true`, which sets `normalMarketEligible: false`, so they are
  preserved as operational history and excluded from win-rate and rate
  calibration. `lifecycleWinRate()` reports `excludedDryRun: 2`.
- **+5** reused external order numbers that the old adapter collapsed. Each was
  inspected:
  1. one pair whose delivery dates differ by three days;
  2. `Mount Prospect IL` vs `Mt Prospect IL` — an abbreviation. Resolving it
     needs a gazetteer, and the durability contract forbids approximate matching;
  3. `unknown city (Rochester), IN` vs `Rochester IN` — free-text annotation;
  4. **a genuinely reused order number**: `Oshkosh WI -> East Peoria IL` and
     `Lombard IL -> Perrysburg OH`, two entirely unrelated shipments that the
     old code merged into one. This one is the whole reason B3 exists;
  5. `McCordsville / Indianapolis, IN` vs `Indianapolis IN` — free-text.

  Cases 2, 3 and 5 are conservative splits, not proven distinct shipments. A
  duplicate is recoverable; a false merge silently destroys two histories.

Cross-file spelling ("Deerfield, WI" vs "Deerfield WI") does **not** split a
record: places are compared as token sequences, and exactly one extra trailing
two-letter state token is allowed as a qualification of a less specific value.
That is normalization, not fuzzy matching — `Chicago` vs `Chicago Heights IL`
and `Chicago IL` vs `Chicago MO` both still conflict.

## Import result on the corrected core

- 149 lifecycle rows, 149 durable evidence rows.
- Re-import of the identical bundle: **149 duplicates skipped, 0 added**. The
  SHA-256 fingerprint is idempotent at full provenance length.
- Operational classes: FREIGHT 141, DRY_RUN 2, BOARD_OBSERVATION 6.
- Price semantics: CARRIER_PAYOUT 140, UNKNOWN_PRICE_SEMANTIC 9. Nothing was
  promoted into canonical revenue that its semantic did not support.
- Mileage semantics: LOADED_MILES 85, DISPLAYED_TOTAL_MILES 40,
  UNKNOWN_MILEAGE_SEMANTIC 24 — kept in three distinct slots.
- Per-field provenance present on 143 of 149 rows.
- Source observation time known on 138 of 149.
- **Deadhead known on 8 of 149.** It is null on the other 141, never zero, so
  True RPM is not computable for them and is not computed.

## Calibration eligibility — unchanged conclusion, now for the right reason

- Win rate: 141 WON / 0 LOST. The denominator contains no adjudicated losses, so
  the arithmetic 100% is not market evidence. `lost: 0` is visible in the result
  for any consumer to see.
- Winning RPM range: **not calibratable.** `weightedSampleSize: 0`,
  `sufficientSamples: false`, `weightedMeanRpm: null`. No row carries a
  defensible True RPM, because deadhead is unknown on 141 of them.

Previously this was also reported as not calibratable, but the undated-evidence
rule would have given any undated row full current weight (B10) and the
lifecycle `updatedAt` fallback would have made every imported row look observed
today (B11). Both are removed; `unknownAgeCount` is now reported so the
exclusion is inspectable.

## Not done here

The 5 conservative splits are recorded as separate rows with their evidence
intact. Resolving cases 2, 3 and 5 needs an operator decision or primary
documentary evidence, not an algorithm. They are safe to leave as duplicates.
