# FreightLogic Field Test Checklist

Device-only tests that can't be run from this environment (no real iOS Safari,
no week-long cold start, no real device backgrounding). Do these yourself, on
your actual phone, when convenient — each is designed to fit under 2 minutes,
so they're doable between loads or at a dock. You don't need to do them all in
one sitting; check them off as you go.

For each: **Steps**, then **Pass looks like** / **Fail looks like**.

---

## 1. iOS Safari 7-day eviction (⏱ 2 min to set up, then check back in a week)

Safari can silently delete IndexedDB data if the site goes unused for 7 days.
The app shows a warning banner about this (`showSafariWarning()`), but the
audit couldn't verify Safari actually evicts data on schedule, or that the
warning is enough to prevent real loss.

**Steps:**
1. On your iPhone, open FreightLogic in Safari (not "Add to Home Screen" yet).
2. Confirm the orange "Safari/iOS Data Warning" banner appears at the top.
   Log one trip so there's something to lose.
3. Tap **Add to Home Screen** from the Safari share sheet.
4. Don't open the app (from Safari *or* the home screen icon) for 8+ days.
5. On day 8+, open it from the home screen icon.

**Pass:** Your trip is still there.
**Fail:** The app opens to an empty state — your trip is gone. If this
happens, export a backup (Settings → Export & Backup) *immediately* after any
session going forward, and treat "Add to Home Screen" + weekly manual backups
as mandatory, not optional.

---

## 2. Week-long cold start (⏱ 1 min to check, after a week away)

**Steps:**
1. Note today's date and your current trip/expense count (Home screen).
2. Don't open the app for 7+ days (any browser/device — this is about app
   state survival, not the Safari-specific eviction above).
3. Open it again.

**Pass:** Same trip/expense count, no error toast, dashboard loads normally.
**Fail:** Error on startup ("App startup failed — try refreshing"), missing
data, or a stuck loading screen. Screenshot whatever you see and note the
exact device/browser/OS version.

---

## 3. Real device backgrounding during GPS trip tracking (⏱ 2 min)

**Steps:**
1. Start GPS trip tracking (Home → Start Trip).
2. Background the app (switch to another app, or lock your phone) for at
   least 10 minutes while actually driving or moving.
3. Return to FreightLogic.

**Pass:** Mileage looks right for the distance you actually covered; the trip
is still "tracking" (not silently stopped).
**Fail:** Mileage is 0 or way off, tracking silently stopped, or the app
shows an error when you return to it.

---

## 4. Storage full mid-save (⏱ 2 min)

Fill your device storage close to the limit (e.g. by taking a bunch of
photos, or checking iOS/Android Settings → Storage), then try to save a trip
with 2-3 receipt photos attached.

**Pass:** A clear "Storage full — export a backup and clear old data"
message. The trip you were entering is either fully saved or not saved at
all — never half-there (e.g. trip exists but missing the receipts, or a
corrupted amount).
**Fail:** Silent failure (tap Save, nothing happens, no message), or a
trip that saved with some fields blank/wrong that you didn't enter that way.

---

## 5. Airplane mode for a full driving day (⏱ 2 min to start, check at end of day)

**Steps:**
1. Enable Airplane Mode before your first load of the day.
2. Use the app normally all day — log the load, track GPS, log fuel, mark
   paid, whatever you'd normally do — entirely offline.
3. At day's end, disable Airplane Mode and open the app.

**Pass:** Nothing looks different. No sync errors, no "reconnecting" spinner
stuck, all your entries from the day are there and correct.
**Fail:** Any data entered while offline is missing, duplicated, or wrong
once you're back online; the app shows a persistent error banner that a
reconnect doesn't clear (reload the app once if so, then note whether that
fixed it).

---

## 6. GPS permission denied mid-trip (⏱ 2 min)

**Steps:**
1. Start GPS trip tracking.
2. Mid-trip, go to your phone's Settings and revoke location permission for
   the browser/app.
3. Return to FreightLogic and keep driving a bit, then stop tracking.

**Pass:** A clear message that location access was lost (not a silent wrong
number); the mileage shown is either reasonably accurate up to the point
permission was revoked, or clearly flagged as incomplete/estimated — not
presented as a confident, precise number that's actually garbage.
**Fail:** The trip shows a mileage number with no indication it's
unreliable — this is the one to watch closely, since a bad number here can
flow straight into your tax mileage deduction with no red flag.

---

## 7. Two tabs open at once, editing the same trip (⏱ 2 min)

This tests the fix for a real bug this audit found and fixed (F-6) — worth
confirming it behaves the way it's supposed to on your actual device/browser,
not just in the automated tests.

**Steps:**
1. Open FreightLogic in two browser tabs (or two windows) on the same
   device.
2. In Tab 1, open a trip for editing, change the pay amount, and save.
3. Without reloading Tab 2, in Tab 2 open the *same* trip for editing,
   change a different field (e.g. notes), and save.

**Pass:** Tab 2 shows a message like "This trip changed elsewhere — showing
the latest version" and reopens with Tab 1's pay change visible. You then
redo your notes edit and save again — no data silently lost.
**Fail:** Tab 2's save appears to succeed immediately with no warning, and
checking the trip afterward shows Tab 1's pay change is gone.

---

## 8. Clock skew / DST transition (⏱ 2 min, only doable on the actual transition dates)

**Steps:**
1. Around a DST transition (early November "fall back" or mid-March "spring
   forward" in the US), log a trip with a pickup time right around 1-3am
   local time on the transition day.
2. Check that the trip lands on the calendar date you actually meant, in
   Trips list, in Tax Season Export, and in the Money Dashboard's week
   bucket.

**Pass:** All three show the same, correct calendar date.
**Fail:** Any of them show the trip a day off, or the week/tax-year bucket
looks wrong for a date near a year boundary during a DST week.

---

## Reporting back

If any of these fail, the single most useful thing to send back is: which
numbered test, exact device + OS + browser version, and a screenshot if
there's anything on screen. For the ones involving data loss (1, 2, 4, 5),
also note whether you'd made a backup export recently — that's the
difference between "annoying" and "actually lost work."
