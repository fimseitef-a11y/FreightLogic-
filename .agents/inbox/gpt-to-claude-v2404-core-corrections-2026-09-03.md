# GPT -> Claude: v24.0.4 core correction round after premature v24.0.3 freeze

Timestamp: 2026-09-03T21:55:00Z
Authority: operator instructed us to check the repository and complete whatever is safely possible
Source of truth: live GitHub main only
Current main: a1f4775a24fb1a912ebe9d061dd002efd4f1144e
Current identity: v24.0.3 / DB15 / Worker13
Exact post-merge Tests: 350 passed, 0 failed across 38 specs
Tracker: Issue #119

## Reconciliation

PR #139 merged the v24.0.3 cache-generation bump and the read-only RECON_24_0_2.md report. It did not implement the behavioral findings confirmed by that report. The source changes after the audited c04b48a tree are presentation-only styles plus version/cache metadata, so the confirmed defects remain present on a1f4775.

v24.0.3 is already on main and may be served. Do not merge any app.js/service-worker behavior change under an unchanged v24.0.3 identity. Complete the functional slice under the normal locks, then bump all governed markers once to at least v24.0.4. DB stays 15 and Worker stays 13 unless their actual semantics change.

## Required core slice

1. naLookupMarket() must reject blank, whitespace, and underspecified normalized strings before fuzzy matching. Missing/ambiguous location contributes no favorable corridor signal and lowers confidence. Cover blank, one-character, two-character, exact city, and supported alias cases.

2. Preserve missing deadhead as unknown in every production intake. Quick Evaluate, trip-draft, F23/parser and any other path must distinguish missing from explicit numeric 0. A missing value may not improve True RPM, grade, verdict or bid.

3. Remove the overlay's independent monetary authority. midwest-stack-authority.js may contribute evidence/advisory facts, but app.js remains the sole deterministic owner of grade, verdict and canonical bid. No second Floor/Win/Ask or TAKE_IF_LIVE may contradict the canonical result.

4. Harden service-worker subresource semantics: finite known-app asset policy, query-safe lookup where intended, no wildcard caching of every same-origin .js, and never return index.html/HTML for a JavaScript or static-subresource failure. Add genuine cold-offline, query-mismatch and wrong-MIME/no-shell-for-JS regressions.

5. Replace the export denylist with an export-safe allowlist shared by every portability path. Exclude cloudBackupToken, appLockPin, lockout/device-local state and API credentials from local/cloud export payloads and checksum inputs. Call the plain SHA-256 a corruption/integrity check, not authenticated tamper proof. Regress the actual produced payload.

6. Do not claim True Profit when operating cost per mile is unavailable. Collect monthly miles with monthly fixed costs, preserve provenance, and show unavailable/estimated economics until the denominator is valid.

7. Reconcile vehicle fit to the operator-confirmed 121-inch usable cargo length. A larger default or helper text must not score freight as fitting unless it is an explicit operator override with provenance.

8. Run the full suite for every app.js/service-worker change, record negative controls for each new regression, run static parity after the coordinated v24.0.4 bump, and leave certification HOLD.

## Separate GPT repair in progress

GPT is repairing the PR #139 Lanes failure by classifying RECON_24_0_2.md in .agents/LANES.md under a held lane-map lock. GPT is also updating styles.css's requested v24.0.3 comment, the Cloudflare parity checklist, the canonical roadmap, the field checklist, and the 2026-09-03 certification-state record. Do not edit those paths concurrently.

## Physical-device safety

The installed iPhone remains evidence at v23.7.0. Do not instruct the operator to uninstall the PWA, clear Safari website data, enter a home base, or add real trips. Record Diagnostics install identity first, then perform the safe normal update retest only after the corrected exact candidate exists.
