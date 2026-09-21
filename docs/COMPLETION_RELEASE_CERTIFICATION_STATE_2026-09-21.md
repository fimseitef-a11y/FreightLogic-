# Completion release certification state — production 24.0.26 / DB16 / Worker v21

Date: 2026-09-21
Supersedes: COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-20.md
Status: **HOLD — exact-main automated tests, CodeQL, production parity and service-worker checks pass; physical iPhone A1-A13 and the new authenticated live vision-provider probe remain unobserved. The Admin Console and later economics-policy work also remain open.**

This is a dated evidence checkpoint, not a claim that all FreightLogic work is complete.
The predecessor preserves Claude PR #282's v24.0.25 observation and supersedes the
2026-09-19 state; this document supersedes that predecessor explicitly. The chain must
resolve to exactly one current document through `scripts/m7-certify.mjs`.

## Exact checkpoint and verified evidence

Observed source: `d35ba266bfe3fc9083d43f716289a988704f671d` on main.
Runtime: app/PWA/service worker **24.0.26**, IndexedDB **16**, backup/API Worker **v21**.
The runtime change merged in PR #281 as `9e3be9e0`. The later #283-#287 commits alter
documentation, ownership and the synthetic vision verifier, not deployed app assets or
Worker source. The documentation continuation introducing this record also changes no
runtime byte. Fetch main again before the next release claim.

| Gate | Observed result | Exact run / job |
|---|---|---|
| Full automated suite | 741 passed, 0 failed, 72 spec files; first attempt | [35555039857](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/35555039857), job 106196949658 |
| CodeQL | PASS | [35555039929](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/35555039929) |
| Live all-asset parity | VERDICT: PASS | [35555039896](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/35555039896), job 106196949693 |
| Production service worker | VERDICT: PASS | [35555039852](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/35555039852), job 106196949605 |

The job logs, not just workflow conclusions, were read. Parity observed manifest/app/SW
24.0.26; Worker health `{ "ok": true, "version": "21" }`; **22** declared runtime
assets; no static asset returned as HTML; and **20** repository-only paths withheld.

The service-worker log observed install/activation, control after reload, injected scripts
fetchable as JavaScript, all 22 assets in `freightlogic-24.0.26`, five driver tabs and a
visible Today surface, no uncaught page errors, a missing offline subresource returning
504 text/plain, an offline known asset recovering from a drifted version query, and exactly
one generation cache. It explicitly did **not** observe an offline navigation. It did not
exercise every screen, every More control, physical VoiceOver, or screenshot quality.

These two live runs were push-triggered on a governance-only change after v24.0.26 had
already deployed. Their logs actually observed the expected generation. After any runtime
deployment, re-run live checks once deployment settles; never label a mismatch PASS merely
because a deployment race is plausible.

Local release preflight is separate: `node scripts/m7-certify.mjs` without `--suite`
must report the suite **SKIP/NOT RUN** and remain **NOT CERTIFIABLE**. The external full-suite
evidence above does not turn a skipped local invocation into a local pass.

## Pending evidence and work

| Item | State and next action |
|---|---|
| Physical iPhone A1-A13 (#226) | OPEN. Preserve the operator's deferral to the final post-v24.5 candidate. Record actual device evidence using the checklist/runner; no headless promotion to PASS. |
| Authenticated vision provider (#252) | UNOBSERVED. #286 implemented `verify-live-authority.mjs --vision`; dispatch **Verify Authenticated Worker** on current main and read its explicit PASS/FAILURE/UNOBSERVED result. |
| Real screenshot quality (#252) | NOT RUN. Use an operator-controlled real/sanitized corpus outside the repository and reviewed expected fields; a synthetic blank-image probe cannot measure OCR accuracy. |
| Admin Console (#231) | Source/integration merged; no Deploy Admin Console dispatch in the observed history. Last live-origin check recorded on the issue returned 404. Requires guarded deployment plus live auth/list/invite/re-invite/revoke proof before driver-admin removal. |
| Later economics authority (#278) | OPEN. Rate-basis/settlement, dynamic regional fuel, chain/exit economics, DEACTIVATED/WITHDRAWN outcomes, contextual long-haul policy and market calibration remain. Claude independent audit/joint consensus is still required. |
| Repository administration (#222) | Remains open; no security-setting change was performed by this documentation continuation. |
| GPS/install notification timing | Open owner investigation: governance-only PR #288, Tests 35556446150 attempt 1 (job 106200882080), reported 740/1 because an installation toast replaced the GPS-loss reassurance. The trip and persistent warning remained visible. An unchanged local focused run passed 13/0; the single controlled full-suite retry, attempt 2 (job 106202180863), passed 741/0 across 72 specs. No runtime or test changed; the rerun pass is not a repair. See the coordination inbox report. |
| Safari/macOS and native Apple work (#204/#205) | The Safari runbook has primary-source setup; execution remains NOT RUN. Native capabilities need separate tooling and implementation. |

**Why the vision distinction matters.** Worker `/health` v21 proves generation agreement,
not that its configured model/binding successfully processes an authenticated image.
The latest authenticated workflow observation found in the complete dispatch/trigger history
is run `35291452993` on the older Worker-v20-era checkpoint. No subsequent run includes the
new vision probe. Older text/evaluate/backup/claim evidence remains historical evidence for
its own execution; it must not stand in for a new v21 provider invocation.

The current synthetic probe accepts a normalized 200 or a fail-closed 422 only with provider
and model provenance. A 422 on its blank 1x1 image can prove the provider path was invoked;
it cannot prove extraction quality. Missing binding/configuration and provider errors are
failures. Credentials and operator screenshots must not be printed or committed.

The available GitHub connector can read/rerun existing runs but cannot create a new
workflow dispatch. The prior browser attempt was unauthenticated. Do not change triggers,
re-run an obsolete deployment, or weaken deployment guards to manufacture a result. Admin
Console secure browser sign-in still needs the operator's specific authorization recorded
in the earlier handoff; no attempt to bypass that boundary is part of this continuation.

## Preserved completion and recovery policy

Authentic **M6 Gate C remains PASS**: five source files, 216 source rows reconciled into
149 deterministic records; 141 unknown and eight positive deadhead values, zero fabricated
zeros. No importer/reconciliation semantics changed here, so do not restart Gate C. The
conflict/adoption review and the unavailable separate 125-row master remain as documented;
never reconstruct missing source data from summaries.

The read-only `scripts/verify-rollback.mjs` derives current app and Worker versions from
source and history. It verifies the fix-forward procedure; it does **not** approve an older
build as safe. Default recovery remains **FIX FORWARD**, followed by applicable release
verification. The former checklist claim that the tool was still pinned to Worker v14 was
stale and is superseded.

This record changes no acceptance threshold, manual result, cost policy, workflow trigger,
credential, application version, database schema, or deployed code.
