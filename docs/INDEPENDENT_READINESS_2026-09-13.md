# Independent readiness work — 2026-09-13

Source baseline: `2834b34cd166717904180bb623793f1f84fbe51e` (app/PWA 24.0.7, DB 15, Worker source 15).
Status: **HOLD remains.** This is a bounded observation report, not final release certification.

## Presentation repair (PR #167)

- Tertiary labels now use opaque colors: dark `#9b9fa6`, light `#616771`.
- Contrast on the standard background/surface-0/1/2/3 palette is 6.03–7.63:1 dark and 4.68–5.70:1 light. These ratios are calculated from sRGB relative luminance; they are not an assertion that every inline runtime label is accessible.
- Theme control is 44×44 CSS px in both base and mobile rules; the preview browser measured 44×44 and successfully switched to light mode.
- Small amber navigation, grade, next-move, see-all, and goal labels use `--accent-text` while accent fills retain their color. Light warning text is `#806000` (4.81:1 or better on standard light surfaces).
- Existing global reduced-motion rules already reduce all animations/transitions, bound animation iterations, and disable smooth scrolling. No second blanket motion override was needed. Physical reduced-motion/progress-state verification remains with the post-structural pass.
- Preview light theme inspected in the cloud desktop browser; this is not physical-iPhone or six-width acceptance evidence. The cloud browser could not open the local preview. Local Chromium installation timed out; existing GitHub CI provides the regression gate.
- Initial CSS head `6fefec3`: CI run `34744500429`, **392 passed / 0 failed across 42 spec files**. The final PR head must pass its own checks before merge.

Claude's structural navigation/source work remains untouched. Final selectors, small-screen wrapping, keyboard/safe-area behavior, and PWA generation delivery must be reconciled after it lands. CSS-only changes do not by themselves prove that existing installed PWA caches refresh.

## Live deployment observation

The repository's existing `node scripts/verify-cloudflare-parity.mjs` ran against the production origins and returned **18 PASS / 1 FAIL**:

- app index, script references, service worker and manifest report 24.0.7;
- Worker health returns HTTP 200, **version 14**, observed at `2026-09-13T07:06:15.480Z`;
- unauthenticated admin request returns 401;
- the only failing assertion is expected Worker 15 versus live 14.

These are marker/content checks, not exact-byte certification. A separate byte/CORS probe using Python was refused with HTTP 403 (health response `error code: 1010`); it supplies no parity or CORS evidence. No auth tokens were available for evaluate/extract/backup/restore/rotation smokes. The existing backup deployment preflight passes. This session exposes no workflow-dispatch action or authenticated Cloudflare credential; no Worker deployment was attempted. The manual Deploy Backup Worker workflow remains the supported path.

## History recovery — previous source-missing status is partially resolved

The four attached source ZIPs contain application code/instructions, not the historical input CSVs. A wider private file search located the original `FREIGHTLOGIC_M6_HISTORICAL_IMPORT_BUNDLE_2026-08-27.zip`, including all five required inputs. Raw rows and candidate output remain outside the public repository.

| Input | Rows | Required columns |
| --- | ---: | --- |
| All_Trips_App_Import_v1.csv | 32 | PASS |
| text 2.csv | 58 | PASS |
| COMPLETE-UNIFIED-DATA.csv | 91 | PASS |
| RECOVERED_COMPLETED_ACCEPTED_LOADS_MAY_AUG_2026.csv | 26 | PASS |
| FREIGHT_INCREMENTAL_LEDGER_2026-08-21_TO_2026-08-26.csv | 9 | PASS |

`verify-history-bundle.mjs` exits 0: **216 rows, 5/5 files, 0 problems, 0 warnings**.

The unmodified `m6-import.mjs` adapter produced:

- 143 order candidates (including two excluded dry runs) plus six quote observations = **149 candidate records**;
- one partial row withheld separately; 37 non-trip rows skipped by the trip adapter;
- 29 reconciliation operations and five reused-ID separations;
- 139 orders with unknown deadhead, all withheld from True RPM; 77 source RPM values preserved separately;
- zero quote observations promoted to awards; zero missing-deadhead records marked True-RPM-defensible in the inspected output.

Two independent runs produced identical bytes for all three adapter files. This is deterministic adapter evidence, not a successful application database import/re-export or full conflict adjudication. The output is privately packaged as `FreightLogic_Recovered_History_2026-09-13.zip` for continuation.

**Remaining history gate:** isolated application import/re-export/idempotence and source-conflict review. The separate 125-row master described by the historical README remains unavailable; it must not be inferred from this bundle. Do not mark Gate C PASS or treat all 149 candidates as completed trips.

## Remaining completion dependencies

1. Claude structural UI pass and final exact generation/full-suite gate.
2. Worker 15 deployment (or the final source generation), current-origin CORS and authenticated smokes.
3. Exact production asset parity, including styles.css, after the final source lands.
4. Private history application round trip/reconciliation; independent 125-row master gap retained.
5. Physical iPhone acceptance on that final deployed generation.
