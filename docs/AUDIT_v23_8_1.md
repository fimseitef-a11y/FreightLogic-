# FreightLogic v23.8.1 — Audit Report

Date: 2026-08-13
Scope: TASK 1–5 of the v23.8.1 consolidated work order, audited per TASK 6.

---

## 1. Syntax — `node --check` on all 7 JS files

| File | Result |
|---|---|
| app.js | ✅ pass |
| voice-load.js | ✅ pass |
| midwest-stack-authority.js | ✅ pass (untouched) |
| admin-driver-ui.js | ✅ pass (untouched) |
| service-worker.js | ✅ pass |
| sw-bridge.js | ✅ pass |
| cloud-backup-worker.js | ✅ pass |

`manifest.json` also validated with `JSON.parse()` — valid.

---

## 2. Version sweep

Final grep for `23\.[0-9]+\.[0-9]+` across `*.js/*.json/*.html/*.md`, every hit classified:

- **Current (23.8.1):** `app.js` (`APP_VERSION`, header banner), `voice-load.js`, `sw-bridge.js`, `service-worker.js` (`SW_VERSION`, `CACHE_NAME`, all `?v=` in `CORE` + `critical`), `manifest.json`, `index.html` (manifest link, script tags, design-system banner comment), `CLAUDE.md`.
- **Historical changelog line (leave):** `app.js:7` — the `v23.8.0:` bullet in the header changelog block, now one entry older.
- **Feature-origin comments (leave):** `app.js` F24–F31 section banners, `CLAUDE.md` F24–F32 subsection headers (e.g. `### F26 — First-Time Setup Wizard (v23.4.0)`).
- **Independently-versioned overlay (intentionally not bumped):** `midwest-stack-authority.js` — header comment and `const VERSION = '23.8.0'` stay as-is, same treatment as `cloud-backup-worker.js`'s own `version: '10'`. Its `?v=` **cache-busting query string** in `service-worker.js`'s `CORE`/`MIDWEST_STACK_TAG` *was* bumped to `?v=23.8.1` (verified precached under that URL — see §7) because that string is an app-shell cache-buster, not a claim about the overlay file's own content version.
- **Out of TASK 1/6 scope (left as historical, flagged here):** `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` still references `23.5.0`/`23.5.1` throughout. TASK 1 named only `RELEASE_NOTES_v23_5_1.md` and `FREIGHTLOGIC_SOURCE_AUTHORITY_v23_5_1.md` for the "current version is X" note; this checklist doc wasn't in scope and was left untouched. It reads as historical by its filename/date, so it doesn't contradict the CLAUDE.md source of truth, but a future pass should probably give it the same one-line note.

---

## 3. Escaping ratio — `innerHTML =` vs `escapeHtml(` in app.js

| | innerHTML assignments | escapeHtml( calls |
|---|---|---|
| Session start (`origin/main`, measured directly) | 272 | 291 |
| Now (this branch) | 278 | 300 |
| Δ | +6 | +9 |

The gap did not widen — `escapeHtml` calls grew faster than `innerHTML` assignments (+9 vs +6). All net-new `innerHTML` writes are in the F33 weather/hazard render helpers (`_renderConditionsHtml`) and the invite UI, and every interpolated value in them goes through `escapeHtml`.

Note: the work order's stated baseline was "273 vs 252". I measured `origin/main` directly at session start and got 272/291 — I'm reporting the number I actually measured rather than the quoted one, since I can't reconcile the discrepancy (possibly a different snapshot or counting method) and don't want to overstate confidence. Either way, the ratio improved, not regressed.

---

## 4. Offline test

Verified live in a headless browser (Playwright + Chromium, local static server), not just by inspection:

- Loaded the app fresh, went through normal boot.
- Set the browser context offline (`context.setOffline(true)`).
- Filled the Evaluator's origin/destination fields while offline — no thrown errors, `checkRouteConditions()` short-circuits on `!navigator.onLine` and the weather slot renders "Conditions not checked — offline" instead of silently showing nothing.
- Positioning brief, weather/hazard checks, and Settings all wrapped in try/catch with degrade-to-empty semantics; `checkStateDotHazards`, `checkRouteWeather`, and the state-DOT adapter all check `navigator.onLine` up front and return `[]`/silent on any failure — traced by code reading (see TASK 3 commit) since a live offline hazard-feed condition is hard to force from a script.
- No exceptions were thrown in any offline path exercised.

## 5. Invite flow test

Verified live end-to-end for the receiving side (the side testable without live worker credentials):

1. Opened `http://localhost:PORT/#token=flk_<fake-32-hex>` in a **fresh browser context** (no prior storage — stands in for "a clean browser profile").
2. Confirmed: the token was captured into `#cloudBackupToken`, the URL was stripped of the token (`location.href` no longer contains it), the toast copy is the new plain-language string, and — because the profile is empty — the **F26 Setup Wizard modal opened automatically** (via the existing `checkFirstRunSetup()` boot trigger), not the Insights screen.
3. Confirmed `localUserId` in IndexedDB (`usr_e5e14aee8c504578` in this run) and `trips` count `0` — a fresh, unrelated identity.
4. Re-tested the "returning user" branch (existing trip seeded, `f26SetupComplete` set) by code trace rather than a second live run — a raw second `indexedDB.open()` connection from the test harness raced with the app's own DB connection during a full page navigation and produced an inconclusive result; I judged forcing that test further wasn't worth the risk of a false read, given the branch is a straightforward `if (!state.isEmpty) location.hash = '#insights'`.

The outbound side (`POST /invite` actually succeeding against the live Cloudflare Worker) was **not** live-tested — this session has no real `cloudBackupToken` and no `ADMIN_TOKEN` to mint one, and the worker endpoint is a real deployed service I won't hit without a legitimate credential. Verified instead by code review against the existing `/admin/users` and driver-token-validation code paths it deliberately mirrors (`cloud-backup-worker.js:139–172` reused exactly, per the task's own instruction).

---

## 6. Isolation proof

**Claim: the owner's data is his, his friend's data is theirs, always.** Every code path that could theoretically move data between two users, and why each is closed:

1. **`localUserId` generation** (`ensureLocalUserId()`, `app.js:798`) runs unconditionally on every boot, before any URL/hash processing, and derives its value from `crypto`-random bytes generated on-device — it never reads from the invite token, the URL, or any network response. A friend's device always gets its own fresh ID. Verified live: fresh profile → `usr_e5e14aee8c504578`, 0 trips.
2. **The invite token** (`flk_...`) is a bearer credential for the **worker's** backup namespace only. It carries no reference to the inviter's `userId`, no embedded data, and is generated server-side by `crypto.randomUUID()` for a brand-new KV record (`cloud-backup-worker.js` `/invite` handler) — structurally identical to what `/admin/users` produces, with `invitedBy`/`invitedAt` recorded *only* for abuse tracing on the `user:*` record, never read by any data-access path.
3. **Server-side namespacing**: every backup/delta key is `user:{userId}:device:{deviceId}:...`, where `userId` comes from looking up the *presented* token's hash (`tokh:{hash}` → `{userId}`) — never from a client-supplied field. Two different tokens always resolve to two different `userId`s with disjoint key prefixes; there is no code path in the worker that reads one user's `userId` while authenticated as another.
4. **Client-side IndexedDB** (`FreightLogic_v18`) is entirely local to the browser/profile. A friend opening an invite link on their own device has their own separate IndexedDB from first boot — nothing in the deep-link handler (`cloudCheckSetupLink()`) touches IndexedDB except to read `localUserId`/trip count for routing (wizard vs. Insights), and it never writes trip/expense/fuel data.
5. **Encryption**: cloud backups are encrypted client-side with a passphrase that never leaves the device (`sessionStorage`, cleared on tab close) and is never sent to the worker — even if two users' encrypted blobs were somehow both visible to someone with `BACKUPS` KV access, the ciphertexts are independently keyed per user's own passphrase.
6. **The local invite log** (`friendInvites` setting) stores only what the inviter typed (name + optional contact) and a timestamp — never uploaded (confirmed by reading `inviteInitUI()`: the only network call is `cloudInviteFriend(name)`, which sends `{ name }` and nothing else).
7. **Admin endpoints** (`/admin/*`) remain gated by `ADMIN_TOKEN`, unrelated to any driver or invite token — no invite-flow code path can reach them.

No path found that could copy, merge, or expose one user's trips/expenses/backups to another. This is the most load-bearing claim in this report, and I want to be honest about its limits: it's a code-review-level proof (traced every read/write site touching `userId`, `localUserId`, and the KV key namespace), not a fuzzed or adversarially-tested one.

---

## 7. Service worker

Verified live (Playwright): on second navigation (after the SW has activated — the standard "first load doesn't get its own SW" browser behavior, not a bug), the SW:

- Registers and reaches `active: 'activated'`.
- Opens cache `freightlogic-23.8.1` (from `CACHE_NAME = freightlogic-${SW_VERSION}`) and precaches all 22 `CORE` entries, each with the bumped `?v=23.8.1` query string — confirmed `app.js?v=23.8.1`, `voice-load.js?v=23.8.1`, `admin-driver-ui.js?v=23.8.1`, `midwest-stack-authority.js?v=23.8.1`, `manifest.json?v=23.8.1`, `sw-bridge.js?v=23.8.1` all present.
- Script injection still works after the Settings restructure: on the SW-controlled reload, `admin-driver-ui.js?v=23.8.1` and `midwest-stack-authority.js?v=23.8.1` `<script>` tags were present in the served HTML, and `admin-driver-ui.js` ran successfully — its `init()` guard (`admin-driver-ui.js:131`, checks for `#adminPanel`/`#btnAdminToggle`/etc.) passed since those elements are still in the DOM (just hidden by default), and it relabeled the button to "👑 Manage Drivers" as designed.

---

## 8. Regression list — every file touched

| File | What changed | What could plausibly break |
|---|---|---|
| `app.js` | Version strings; escaped Schedule C print export; rewrote NWS weather layer into route-aware corridor sampling + new state-DOT hazard adapter + unified `checkRouteConditions`/staleness rendering; fixed the origin==destination duplicate-check bug; added invite UI + worker call; fixed `cloudCheckSetupLink()`'s dead `navigate('#insights')` call and its Home-fallback race; gated admin panel behind `#admin`; moved Storage & Recovery / Hard Reset into the Advanced disclosure; added "Set up" gate to Cloud Backup. | Weather/hazard rendering is new code on two hot render paths (positioning card, evaluator) — a bug there shows wrong/missing alerts, not a crash (everything is try/catch-wrapped). The `#admin` route special-cases `navigate()` — a typo there could strand users on a blank Insights render if `renderInsights()` throws (it's awaited, uncaught). The Cloud Backup "Set up" gate changes default visibility of existing fields — if a user relied on them always being visible, this is a UX change, not a functional loss (button reveals them). |
| `index.html` | Added Invite a Friend card; hid `#btnAdminToggle` by default; added `#cloudSetupPrompt`/"Set up" button; moved Storage & Recovery + Hard Reset markup into `#advSettingsBody`; reordered Money & AR / Tax Quick View / Export to Accountant above the Settings card within `#view-insights`. | All touched IDs verified unique and present post-edit. Reordering cards within the same `<section>` is low-risk (no cross-section ID or script dependency found), but this file is effectively unformatted/single-line per card — a future manual edit near these blocks should diff carefully. |
| `cloud-backup-worker.js` | New `POST /invite` endpoint (rate-limited 5/hr + 25 lifetime). | Purely additive — no existing route's logic was touched. Risk is scoped to the new endpoint: a bug there could over/under-rate-limit invites, or (if the driver-token check were ever weakened) let an unauthenticated caller mint users — the current code reuses the exact validated auth path, so this should be safe, but wasn't live-tested against the deployed worker. |
| `voice-load.js` | Version string only (line 1). | None expected. |
| `sw-bridge.js` | Version string only (line 1). | None expected. |
| `service-worker.js` | Version strings throughout (`SW_VERSION`, `CACHE_NAME` derives automatically, all `?v=` in `CORE`/`critical`). | None expected — verified live that install/activate/precache still succeed. |
| `manifest.json` | `name` field version string. | None expected. |
| `CLAUDE.md` | Version strings (Project Overview, Key Constants, PWA section). | Documentation only. |
| `docs/RELEASE_NOTES_v23_5_1.md`, `docs/FREIGHTLOGIC_SOURCE_AUTHORITY_v23_5_1.md` | TASK 1 added a one-line "current shipping version is 23.8.0" notice at the top of each; history below left untouched. | None — see note below. |

**Note on the two docs notes:** TASK 6's version-bump instructions listed specific files to move to 23.8.1 and did not include these two docs, so their notice text still says "23.8.0" rather than "23.8.1" — a one-word drift I deliberately didn't fix since it would've meant expanding TASK 6's scope beyond what was listed. The next release should either update these two notices or reword them to "see CLAUDE.md for the current version" so this drift can't recur.

`midwest-stack-authority.js` and `admin-driver-ui.js` — **not modified** at all (only `node --check`-verified). No regression surface introduced.

---

## 9. UI density observations (Phase Two input — no changes made)

Per the work order, these are observations only, for the upcoming visual-redesign round:

- The **Intelligence view** tile grid (`app.js:4817`-area, `index.html:1068`-area) is exactly what the work order already called out — a large flat grid of many equally-weighted tiles with no visual hierarchy between "check this daily" and "rarely used" actions.
- **Evaluator result card** (`_mwRenderDecision`, `app.js` ~6900+) stacks many inline-styled blocks (grade badge, bid range, lane intel, DAT market, weather/hazard slot, broker notes, AI result) in one long scroll with no section dividers beyond ad-hoc `border-top` rules — dense on a phone screen, especially once the F33 weather/hazard slot is showing multiple stale + fresh items.
- The **positioning card** (F24, `renderPositioningCard`) now has one more element (the "Check conditions now" button) competing for attention with the command badge, lane rows, and nearby-markets toggle — small, muted styling was chosen deliberately to minimize this, but it's still one more row.
- **Settings**, post-restructure, is meaningfully shorter at first paint (essential fields + compact Cloud Backup status + Invite card, Advanced collapsed) — this pass's main density win. The Advanced disclosure itself, once opened, is still a long uninterrupted scroll of five distinct sub-topics (Vehicle/Monthly/Financial/App/Integrations/Dead Zone/Storage/Danger Zone) separated only by thin `border-top` rules and small section-head labels — a candidate for its own sub-navigation or accordion-per-section in the redesign round.
- Every new element added in this pass reused existing classes (`card`, `btn`, `pill`, `row`, `muted`, `settings-section-head`) rather than introducing new inline style patterns, per the ground rules — no new visual language was added.

---

## 10. Pre-existing issue found during testing (not fixed — out of scope)

`voice-load.js:163` (`loadLatestDraft()`) throws `Cannot read properties of null (reading 'length')` on every boot in a fresh profile — reproduced live, and confirmed present byte-for-byte on `origin/main` before any of this work order's changes (`getDraftStore()` presumably returns `null` on a JSON-parse failure of empty/absent `sessionStorage`). Left untouched since it's unrelated to TASK 1–6 and outside the "minimal diffs" mandate; flagging for a future pass.

---

## Commits

1. `chore: reconcile version strings to 23.8.0`
2. `fix: apply escapeHtml consistently in Schedule C print export`
3. `feat: route-aware weather + state DOT hazard layer with staleness handling`
4. `feat: self-serve friend invites without admin token`
5. `refactor: restructure Settings into essential / advanced`
6. `chore: v23.8.1 — audit pass` (this commit)
