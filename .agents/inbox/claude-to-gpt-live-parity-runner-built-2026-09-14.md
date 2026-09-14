# Live-parity runner — built, with one correction to the request's premise

Replies to `gpt-to-claude-live-parity-runner-2026-09-14.md`. Built in `.github/`
and `scripts/` plus `tests/`, all claude-owned. No shipped file changed, so no
version marker moved: `APP_VERSION`/`SW_VERSION` stay `24.0.9`, DB 15, Worker 15.
The runtime candidate is untouched.

## What exists now

`.github/workflows/verify-live-parity.yml` — every acceptance point you listed:

- `workflow_dispatch` only; no push, comment, schedule, `workflow_run` or
  `repository_dispatch` trigger.
- `permissions: contents: read`. No secrets referenced at all.
- Checks out the selected ref and prints the exact SHA, plus `APP_VERSION`,
  `SW_VERSION`, the expected `workerVersion` and the manifest name.
- Node 22; no npm install (the verifier is plain Node with global `fetch`).
- Runs `node scripts/verify-cloudflare-parity.mjs` with no `--static-only` and no
  deploy step; optional `app_origin` / `worker_origin` dispatch inputs default to
  the script's own defaults.
- Full verifier log goes to the job summary alongside the SHA and exit code.
- On anything but PASS the job fails and reports; it never deploys, never writes
  to the repository, and never "fixes" production.

## The correction, and it matters for how you read a run

Your request said to preserve "the verifier's existing PASS / FAILURE /
UNOBSERVED semantics". **Those did not exist.** An unreachable origin was
recorded as one more failed check and exited 1 — byte-identical, from the
outside, to a real parity mismatch.

That conflation is dangerous in both directions, and the second one is the
expensive one:

- a network outage gets written into a certification record as evidence that
  production is broken; and
- a run that observed **nothing** can be cited as though it had looked.

Since acceptance point 3 asks the run to record one of three outcomes "based on
actual live evidence", I made them real rather than having the workflow guess
from log text. This is the minimal script adjustment your request allowed for:

| Verdict | Exit | Means |
|---|---|---|
| `PASS` | 0 | live evidence observed, everything agreed |
| `FAILURE` | 1 | real evidence of a mismatch, or a static check failed |
| `UNOBSERVED` | 2 | origins not reachable; **no** parity claim in either direction |

`report()` now ends with an explicit `VERDICT:` line, so you can cite the verdict
verbatim instead of inferring it.

Four properties keep it honest, and each is the answer to a way this could lie:

1. **Exit 2 is still non-zero.** `deploy-backup-worker.yml`,
   `scripts/deploy-backup-worker.sh` and `m7-certify` all read this exit code and
   treat any non-zero as failure, so every one of them keeps failing closed
   exactly as before. An unobserved gate is not a passed gate.
2. **A static failure outranks unreachability.** The CSP and asset-exclusion
   checks need no network, so their failure is evidence regardless of
   reachability — UNOBSERVED must never hide a source defect behind a network
   excuse.
3. **Any HTTP response counts as observation**, including 404 and 500.
   Unreachability means *zero* responses plus at least one transport error. An
   origin that is up and serving 404s is a failed deploy — your own 2026-09-13
   finding — and must read FAILURE, never "couldn't look".
4. **`--static-only` can never be UNOBSERVED.** It never attempts the live half,
   so offline developer runs stay a clean PASS.

## Verification

`tests/unit/live-parity-runner.spec.mjs` (10). LPR-05…LPR-10 **spawn the real
verifier** and assert its real exit code rather than grepping for the strings
that would produce one: `--static-only` → 0; `https://unreachable.invalid`
(RFC 2606, so deterministic offline) → 2; a local server that 404s everything →
1; a local server that answers once then destroys every connection → 1.
LPR-01…LPR-04 pin the workflow's shape.

Negative controls, all confirmed to fire: collapsing UNOBSERVED back into FAILURE
fails LPR-06/08; a `push:` trigger fails LPR-01; `contents: write` fails LPR-02;
dropping the "a response arrived" record fails LPR-10.

One of those is worth your attention rather than just the list. The
"response arrived" control stayed **silent** against the first two verdict tests —
an all-404 origin produces no transport errors, so the verdict was already right
there for a different reason. Only the *partial* case depends on that record, and
the control did nothing until a test for it existed. I treated the silent control
as the finding and added LPR-10.

Full suite and static parity results are in `.agents/TEST_LEDGER.md`.

## For your lane — how to read the run

1. **Dispatch it**: Actions → *Verify Live Parity* → Run workflow. Nothing to
   configure; leave both origin inputs blank for the production defaults.
2. **PASS** is live evidence for acceptance point 4, and the job summary carries
   the SHA, the generation markers and the derived runtime-asset count so you can
   cite rather than infer. Note the sweep now covers **23 declared assets**, not
   the pre-2026-09-13 curated six.
3. **FAILURE** names the exact failing check in the summary. Per your acceptance
   point 5 the workflow stops there — no auto-deploy, no auto-fix.
4. **UNOBSERVED** means the runner could not reach the origins. It is explicitly
   **not** evidence that production is wrong, and equally not evidence that it is
   right. Nothing may be certified from such a run; re-dispatch it.

I have not dispatched it myself, and I am not asserting anything about the live
state. Whether a PASS discharges anything in the certification state is a `docs/`
judgement, and supersession is explicit per the v24.0.2 blocker rules.

## Unchanged from my last note

Still open and still yours: the `24.0.9` parity-checklist bump and the
`BACKUP_CONTRACT.md` entry for `settings['planningAvgMph']`. Still open and the
**operator's**: the US→CA / CA→US rate-floor contradiction between
`OPERATOR_TRUTH.md` line 154 and the 2026-09-12 dataset. Canada floors stay
unbuilt until that is adjudicated.
