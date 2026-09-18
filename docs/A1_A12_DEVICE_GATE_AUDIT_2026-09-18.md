# A1–A12 device-gate audit — what needs your eyes, and what does not

Date: 2026-09-18
Scope: `FIELD_TEST_CHECKLIST.md` section A, against the companion at
`field-certification.html` / `field-certification.js`.
Purpose: make the physical-iPhone session **one sitting**, by removing everything
from it that does not require a human, a phone, or both.

This audit changes no gate's PASS criteria and promotes nothing. `.agents/LANES.md`
is explicit that the companion "may never auto-promote a hardware-only step to PASS
without explicit observation", and nothing here asks it to.

---

## 1. What the companion can and cannot see, structurally

This is the constraint everything below follows from, and it is easy to get wrong.

`field-certification.html` is a **separate page on the same origin** as the app. So:

| It CAN observe | It CANNOT observe |
|---|---|
| `manifest.json` → app generation | the app's rendered DOM — a different document |
| `app.js` source → `DB_VERSION`, any build SHA | what the evaluator **displayed** |
| service-worker registration, scope, script URL | whether a chart *looked* right |
| Cache Storage keys → which generation shells exist | safe-area insets, keyboard behaviour |
| Worker `/health` → Worker generation | anything in iOS Settings |
| `display-mode: standalone` → installed vs Safari | anything on a second device |
| **IndexedDB — the app's own stores, same origin** | whether the operator was actually there |
| `navigator.storage.persisted()` | |

The IndexedDB row is the one worth noticing: the companion can read what the app
**stored**, which is a real, checkable fact. It is not the same claim as what the app
**showed**, and several A-rows are explicitly about the latter. Where a row's PASS is
about rendering or about refusing to invent a number on screen, stored state is
corroborating evidence and nothing more.

Today the companion auto-records environment only (`observeEnvironment()`), and every
row still requires operator attestation. That is the correct default; the proposals in
§3 widen the *corroboration*, never the attestation.

---

## 2. Row-by-row classification

**EYES** = requires a human, a phone, or a second device.
**AUTO** = already auto-recorded by the companion today.
**AUTO-ABLE** = browser-observable and not hardware-only; proposed in §3, not built.

| Row | Est. | AUTO today | AUTO-ABLE (proposed) | Irreducibly EYES |
|---|---|---|---|---|
| **A1** install/update identity | 10 min | generation, SW script/scope, cache keys, DB schema, launch mode | post-reopen generation + single-generation cache assertion | install/update actions; no blank shell, reload loop or startup error; shell is Today/Loads/Evaluate/Trips/Money |
| **A2** UNKNOWN vs explicit zero | 10 min | — | stored trip's `emptyMiles` null vs 0 | **what the evaluator rendered** — no invented True RPM/grade/verdict/bid. This is the row; storage corroborates it |
| **A3** intake durability | 10 min | — | `normalizedEvidence` + `loadLifecycle` survive reload with provenance intact; non-carrier amount not promoted to canonical revenue | driving the shipped intake UI |
| **A4** offline round trip | 15 min | — | post-reconnect record counts (no duplication/loss) | **Airplane Mode**; offline launch of the installed app; navigating five surfaces offline |
| **A5** export/import + secrets | 15 min | — | **the whole secret-exclusion half** — parse the exported payload and assert no token/PIN/lockout material, UNKNOWN deadhead preserved, corrupted payload rejected | invoking share/export and the import path through the real UI |
| **A6** GPS background | 30 min | — | measured background minutes; `gpsLogs` continuity; degraded labelling present in stored state | **driving**, locking the phone 10+ min, judging "plausible or explicitly degraded" |
| **A7** permission loss mid-trip | 10 min | — | stored trip preserved; no precise mileage promoted | **revoking permission in iOS Settings**; visible degraded/paused state |
| **A8** stale-edit conflict | 10 min | — | post-save record revision — Tab 1's change survived | two real Safari tabs; observing the rejection/refresh |
| **A9** doctrine/geography/fit/profit | 20 min | — | — | six rendered outcomes in the evaluator. **All six are "what it showed"**; storage proves nothing here |
| **A10** pickup feasibility | 20 min | — | `planningAvgMph` present/absent/cleared | **CAN'T TAKE shown before economics**; eight rendered cases |
| **A11** iOS 27 regression | 25 min | browser/UA | `navigator.storage.persisted()` → **A11.5 outright**; computed `font-size` of every select → **A11.3's zoom precondition** | **A11.1 chart correctness, A11.2 icon rendering** — pixels, and the stated failure mode is "renders but reads wrong"; A11.4 scroll anchoring; A11.6 next-day reopen |
| **A12** zero-token onboarding | 40 min | both generations (prereq check) | Drivers list still shows **one** driver with backup count intact | two devices, iMessage **and** Mail, Add to Home Screen, the storage-partition answer, revoke |

**Total ≈ 3 h 35 m** of device time in one sitting.

### The honest conclusion

Automation cannot meaningfully shorten this. The time is dominated by physical waits
that no observer removes — driving for A6, ten minutes of a locked phone, a two-device
onboarding round trip in A12, and a next-day reopen in A11.6. What §3 removes is
**transcription and re-runs**, not minutes on the device.

Two rows are the exception and are worth building: **A11.5** (persisted storage) is a
single API call the companion can answer outright, and **A5's secret-exclusion half**
is a payload parse — the part most likely to be eyeballed wrongly by a tired human, and
the part with the worst consequence if it is.

---

## 3. Proposals for the companion — `gpt` lane

`field-certification.html` / `.js` are **gpt**-owned under `.agents/LANES.md`. These are
requests, not edits, and they are ordered by value.

1. **A11.5 — answer it, don't ask it.** `navigator.storage.persisted()` returns the
   grant. Record `true`/`false`/unavailable as an automated observation. This is the
   one row where the human is currently reading a Diagnostics line the companion could
   read itself, and for a bookkeeping app it is the difference between believing data
   is durable and knowing it.
2. **A5 — parse the exported payload.** Assert absent: `cloudBackupToken`, `appLockPin`,
   `cloudAdminTokenEnc`, lockout state; assert preserved: UNKNOWN deadhead as `null`.
   Record field **names** only, never values — same rule the M6 preflight follows.
3. **A1 — assert exactly one generation cache** and that it matches the manifest, from
   `caches.keys()`. The companion already lists them; this turns a list into a check.
   `freightlogic-share-v2` is **not** a generation — only version-shaped names count.
4. **A11.3 — measure the zoom precondition.** Fetch `styles.css` and `index.html` and
   report any control whose computed `font-size` is under 16px. The human still
   confirms the viewport did not zoom; this tells them where to look.
5. **A2 / A3 / A7 / A8 — read the stored record** after the operator's action and
   record it as corroboration, clearly labelled as storage state and not as the
   rendered outcome.

**Not proposed, deliberately:** anything that would let the companion mark a row PASS.
Every item above is an `automatedObservations` entry beside an attestation the operator
still makes.

---

## 4. Sequence — one sitting, no reinstalls

Ordering constraints that actually bind:

- **A1 first.** Every later row is performed against an installed app whose identity A1
  establishes. A partial run records rows against a generation A1 never certified.
- **A11.1 needs data before it can run at all.** The F31 chart is hidden below four
  weeks of data. Seed synthetic trips spanning 4+ weeks in Phase 1 or A11.1 cannot run.
- **A6 before A7.** A7 revokes location permission; doing it first breaks A6.
- **A5 late.** Import/restore mutates the data other rows rely on.
- **A12 last.** It installs, re-claims and revokes — it is the only row that
  deliberately disturbs install and account state.
- **A11.6 spans a night.** Start the run in the evening; it is the only step that
  cannot be collapsed into the sitting.

| Phase | Rows | Why grouped |
|---|---|---|
| **0. Pre-flight** (off-device, me) | — | Confirm generations, freeze the environment, seed 4+ weeks of synthetic data |
| **1. Identity** | A1 | Establishes the candidate; nothing else may precede it |
| **2. Evaluator, read-only** | A9, A10, A2 | Pure evaluator input/output, no state mutation, no mode changes — cheapest rows, done consecutively in one screen |
| **3. Data lifecycle** | A3, A8 | Intake + concurrency; both write records, neither changes device mode |
| **4. Offline** | A4 | One Airplane Mode toggle, in and out |
| **5. GPS** | A6 → A7 | One trip outdoors; the 10-minute lock is dead time by design; A7 immediately after, while permission state is the topic |
| **6. Rendering** | A11 (.1–.5) | Needs the seeded data from Phase 0; do after Money has real figures to compare the chart against |
| **7. Portability** | A5 | Mutates data — deliberately after everything that depends on it |
| **8. Onboarding** | A12 | Two devices, install, re-claim, revoke; disturbs account state, so last |
| **9. Next morning** | A11.6 | Reopen; confirm the cloud-backup paused banner and its one-tap Resume |

---

## 5. Stale prerequisites found while auditing — corrected

These were **not** cosmetic. A tester following the checklist as written would have
confirmed the wrong build, which is the exact failure this file records against itself
at 24.0.9, 24.0.11 and 24.0.12.

- **A1 step 4 said "verify 24.0.12 is active".** Production serves **24.0.19**.
- **A10's heading said "current in v24.0.12".**
- **A12's prerequisite said "Worker v18 AND app 24.0.13 must both be deployed".**
  That prerequisite is now **MET and exceeded** — Worker **v20** and app **24.0.19**
  are deployed and observed live (parity run `35291475396`, `VERDICT: PASS`; Worker
  deploy run `35291404482`). A12 was previously un-runnable on its own terms; it is
  now runnable.

Both generation references are corrected in `FIELD_TEST_CHECKLIST.md` to read from the
candidate rather than restating a number, so they cannot drift again the same way.

---

## 6. What this does not change

A1–A12 remain **deferred by the operator's 2026-09-16 decision** to the final
post-v24.5 candidate, and that rationale is untouched: five of the twelve rows (A1, A3,
A9, A10, A11) measure surfaces the v24.5 redesign rewrites, so evidence gathered now
expires when it merges. This audit prepares the session; it does not schedule it.
