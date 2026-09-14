# v24.0.9 "Can You Even Get There" — pickup feasibility, and a doctrine contradiction for the operator

Landed from the Claude lane under `lock/app-js` (paths `app.js`, `index.html`;
token `2189211a-cb06-4d29-8648-e7be0ac2d7ef`). `DB_VERSION` stays **15**, Worker
stays **v15**.

## What shipped

The highest-value item from the 2026-09-12 operator-data pass, which was
reported rather than built at the time. The evaluator had no notion of time: it
would grade, price and bid a load whose pickup had already closed, or that sat
further in deadhead than the remaining window allowed. The dataset's quote
1079840 — a 225-mile deadhead against a 19:00 cutoff — is the real instance.

`checkPickupFeasibility()` now runs immediately after the 7D dimensional gate
and before any economics, blocking with "CAN'T TAKE" rather than pricing freight
that cannot be served.

**The part that matters for your review: there is no default speed.** Converting
deadhead into drive time needs an operator fact, and `VAN_PROFILE_DEFAULT` is
the precedent for what happens when this repo guesses one — the brochure cargo
length was wrong by nine inches and every 122–130" load scored as fitting. A
guessed speed fails worse, because it would *reject* loads the driver could make
and the driver never learns what they turned down.

So `settings['planningAvgMph']` has no default and the gate is inert until the
operator sets it, the same shape as the EIA feed being inert without its key.
**This release therefore cannot change the verdict on any load scored the way
loads are scored today** — it only becomes able to block anything after the
operator supplies one number. An out-of-range figure disables the check rather
than clamping into range; substituting a bound would run the gate on a number
nobody chose.

Suite and static parity results are in `.agents/TEST_LEDGER.md`.

## Requests for your lane

1. **`docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` → `24.0.9`** (CLAUDE.md
   version-bump checklist item 13). DB 15 and Worker 15 are unchanged, so this
   is the app-version markers only. The frozen candidate your next parity run
   must target is now `24.0.9`.
2. **`docs/BACKUP_CONTRACT.md`** — Amendment 2 requires a new persisted field to
   be documented in the same change that adds it, and `docs/` is yours.
   `settings['planningAvgMph']` is a plain number or absent. It needs no new
   push/restore code: `cloudPushBackup()`'s settings dump and X-07's add-only
   settings merge both handle any settings key generically, and it is not
   credential-shaped so `isSettingExportSafe()` exports it normally. It was
   added to `ALLOWED_SETTINGS_KEYS` in the same commit that introduced it —
   third retrofit that list has needed, so worth a line.

## A contradiction I found and did NOT resolve — this one needs the operator

While checking whether the third reported-not-built item (Canada rate floors)
was buildable, I found the two sources disagree, and neither can set a
protective floor on its own:

| Source | US → CA | CA → US |
|---|---|---|
| `docs/OPERATOR_TRUTH.md` line 154, `BROKER_CONVERSATION_RELAY` 2026-06-26 | `$1.30–$1.40` | `$1.16–$1.20` |
| The 2026-09-12 operator dataset (not in the repo) | floor `1.69` | target `1.25–1.55` |

These are far apart — the US→CA figures differ by roughly `$0.30/mi`, and the
recorded one is explicitly labelled "broker-relayed observations, not guaranteed
market averages." Picking either would be inventing a protective floor, so I
built neither and I am not asserting which is right. `canadaEnabled`,
`cadUsdRate` and `borderAdminCost` all exist, so the wiring is ready the moment
there is an authoritative number.

Please put it to the operator as an `OPEN_QUESTIONS.md` item: which figures are
current, and is the 2026-09-12 dataset authoritative over the June broker relay?
A dated `OPERATOR_CORRECTION` row in `OPERATOR_TRUTH.md` would let this lane
implement it immediately.

## The other reported-not-built item, still correctly deferred

Trap-market additions (Lockport NY, Fremont CA, Boston outbound, Cheyenne, rural
AR/MS, interior New Mexico) still need real coordinates plus operator authority,
exactly as recorded on 2026-09-12. Adding a market is what the Gary, Indiana
episode was about — v24.0.4 found `'Gary'` resolving to Alberta, fixed the
matching rule to fail closed, and left the table gap for v24.0.5 to close with
real coordinates. Same discipline applies; not invented here.
