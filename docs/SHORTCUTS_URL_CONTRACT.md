# FreightLogic Shortcuts URL Contract — v1

**Status:** authoritative from app **v24.0.34** / Worker **v24**.
**Owner:** Claude lane. `docs/SHORTCUTS_PACK.md` (GPT lane) builds recipes on this contract. If a
recipe needs something this contract lacks, file a request under `/.agents/inbox/`; do not invent a
parameter in the pack.

**Why this exists.** On 2026-09-22 the operator froze the native iOS track: no paid Apple Developer
Program membership and no new Swift. Apple Shortcuts is the Siri replacement, and Web Push to the
installed Home Screen app is the notification layer (#204/#205). This document is the interface a
Shortcut is allowed to use.

---

## 1. The rules that never bend

1. **The app decides; links only fill in.** A link can open a surface, prefill fields, or run the
   canonical evaluator on the numbers it carries. It never computes a verdict, grade, True RPM or
   bid itself. The v24.0 authority rule applies unchanged.
2. **A link never saves anything on its own.** `trip`, `expense` and `fuel` open the existing
   form, filled in. The record is written only when the driver taps **Save**, the same as typing it.
   `evaluate` runs the evaluator, which scores and saves no trip.
3. **Fragment only.** Everything after `#` stays on the device; browsers never send it to a server.
   The query string (`?…`) is never read for actions, so a link cannot leak a load into an access
   log.
4. **No credentials in a link, ever.** If any parameter name looks like a credential (`token`, `key`,
   `pass`, `pin`, `secret`, `auth`, `bearer`, `session`, `cookie`), the **whole link is refused**.
   Credentials travel only as request headers to the Worker (see §5).
5. **UNKNOWN stays UNKNOWN.** A missing or blank number is unknown, not zero. For deadhead
   especially, `deadhead=0` is a verified zero (the driver is at the pickup), while an absent
   `deadhead` makes the evaluator ask for it. This is the v24.0.1 `knownNum()` rule.
6. **Out of range is dropped, not clamped.** A value outside its bounds is left blank, and the
   driver is told which field was dropped. Substituting the nearest bound would put a number in
   front of the driver that nobody chose.
7. **One shot.** After the app handles a link, it replaces the fragment with the destination
   route. Reloading, or reopening from history, does not replay the action.

---

## 2. Grammar

```
https://freightlogic-v2.fimseitef.workers.dev/#do=<action>&<name>=<value>&...
```

- Parsed with `URLSearchParams` on the fragment after `#`. Percent-encode every value (Shortcuts'
  **URL Encode** action does this).
- The whole fragment may be at most **8192** characters. Longer links are refused.
- An unrecognized `do` is refused: the driver lands on Today with a one-line explanation.
- Unknown parameter names are ignored, so a newer Shortcut still opens on an older app. The
  credential-shaped names in rule 4 are the exception: they refuse the whole link.
- Parameter names are case-sensitive and lower-case.

### Value types

| Type | Accepted | Bounds |
|---|---|---|
| `money` | decimal dollars, optional leading `$`, commas ignored (`1,250.50`) | `0 < x ≤ 100000` |
| `miles` | whole or decimal miles | `0 ≤ x ≤ 5000` |
| `deadhead` | whole or decimal miles; `0` is a verified zero | `0 ≤ x ≤ 3000` |
| `weight` | pounds | `0 < x ≤ 10000` |
| `inches` | inches | `0 < x ≤ 600` |
| `gallons` | gallons | `0 < x ≤ 500` |
| `date` | `YYYY-MM-DD` | a real calendar date |
| `datetime` | `YYYY-MM-DDTHH:MM` (device local time) | a real date and time |
| `place` | free text, e.g. `Chicago, IL` | trimmed, at most 80 characters |
| `text` | free text | trimmed, at most 120 characters unless stated |
| `lines` | multi-line text; line breaks are kept, other control characters removed | at most the stated length |

---

## 3. Actions (v1)

### `open` — go to a surface

| Parameter | Type | Notes |
|---|---|---|
| `to` | one of `today`, `loads`, `evaluate`, `trips`, `money`, `expenses`, `fuel`, `settings`, `intel`, `more` | required |

Example: `#do=open&to=money`

Plain route links such as `#trips` keep working as before. `open` exists so every Shortcut uses one
grammar.

### `evaluate` — score a load in the canonical evaluator

| Parameter | Type | Notes |
|---|---|---|
| `revenue` | money | line-haul pay |
| `loaded` | miles | loaded miles |
| `deadhead` | deadhead | absent means UNKNOWN; the evaluator asks for it |
| `origin` | place | |
| `dest` | place | |
| `broker` | text (60) | |
| `weight` | weight | van-fit gate |
| `length`, `width`, `height` | inches | van-fit gate |
| `pickup` | datetime | pickup cutoff for the reachability gate |

The link **replaces** the evaluator's load fields. Any field the link does not carry is cleared, so
a previous load's deadhead, dimensions or broker can never leak into this one. The driver's own
operating context (fatigue, day of week, weekly gross) is left alone. Nothing is saved as a trip.

Example:
`#do=evaluate&revenue=1450&loaded=612&deadhead=38&origin=Columbus%2C%20OH&dest=Atlanta%2C%20GA`

### `intake` — review pasted or OCR'd load text

| Parameter | Type | Notes |
|---|---|---|
| `text` | lines (**6000**) | a rate confirmation, board copy, or on-device OCR of a screenshot; line breaks are kept because the parser reads line by line |

Opens **Load Intake** with the text filled in and runs the same parse as tapping **Parse Load**.
The driver lands on the review draft; nothing is scored or saved until they tap. This is how a
DispatchLand screenshot becomes a scored load without a server-side vision call: a Shortcut runs
Apple's on-device **Extract Text from Image** and passes the text here.

### `trip` — start a new trip, prefilled

| Parameter | Type | Notes |
|---|---|---|
| `order` | text (40) | order number from the rate confirmation |
| `pay` | money | |
| `loaded` | miles | |
| `deadhead` | deadhead | absent means UNKNOWN |
| `pickup` | date | |
| `delivery` | date | |
| `customer` | text (60) | broker / shipper |
| `origin`, `dest` | place | |

Opens the **Add Trip** form in add mode with these values. The trip is saved only on **Save**. An
empty order number stays empty; no placeholder is ever invented.

### `expense` — add an expense, prefilled

| Parameter | Type | Notes |
|---|---|---|
| `amount` | money | |
| `category` | text (60) | e.g. `Tolls`, `Parking`, `Auto Insurance` |
| `date` | date | defaults to today |
| `note` | text (300) | |

### `fuel` — add a fuel stop, prefilled

| Parameter | Type | Notes |
|---|---|---|
| `gallons` | gallons | |
| `total` | money | total paid |
| `state` | text (2), a US state or Canadian province code | e.g. `OH` |
| `date` | date | defaults to today |
| `note` | text (300) | |

### Reserved: `relay`

`#do=relay&id=<relay id>` is produced by FreightLogic's own notifications (§5). Shortcuts must not
construct it; the app fetches the stored item and dispatches it through this same contract.

### Not in v1, on purpose

- **Mark paid**: choosing the right trip needs the driver's eyes. Use `#do=open&to=money`.
- **Start/stop GPS tracking**: location permission and the resume/discard choice are interactive by
  design (F-7). Use `#do=open&to=today`, where Start Trip is one tap.

Either can be added in a later version through an inbox request, once someone has a concrete
Shortcut that needs it.

---

## 4. iPhone: which app does the link open?

**Shortcuts' Open URLs opens Safari, not the Home Screen app.** On iOS, a Home Screen web app keeps
its own storage, separate from Safari's. The `webapp://` scheme that circulated during the iOS 26
betas is unreliable; later reports say it fails, so this contract does not depend on it.

So a direct link from a Shortcut lands in a Safari tab that **cannot see the installed app's
trips, settings or cost profile**. FreightLogic detects that case on iPhone and iPad (not running
standalone):

- `trip`, `expense`, `fuel`: before the form opens, a warning explains that a record saved in Safari
  will not appear in the Home Screen app. The driver chooses **Continue in Safari** or **Cancel**.
- `evaluate`, `intake`, `open`: run, with a one-line notice that the installed app's settings are
  not available in Safari, so the score uses defaults.

**The way to reach the installed app from a Shortcut is the relay (§5).** On Android and desktop,
where an installed PWA shares storage with the browser, direct links work as-is and no warning is
shown.

---

## 5. The relay: Shortcut → server → notification → installed app

The relay carries the same actions as §3, delivered as a push notification that opens the installed
app. It requires cloud backup to be set up (a driver account) and notifications to be turned on in
**Settings → Notifications & Shortcuts**.

### 5.1 The Shortcut key

In **Settings → Notifications & Shortcuts**, the driver taps **Create Shortcut key**. The app shows
`fls_` plus 48 hex characters **once**, with a Copy button, and the driver pastes it into their
Shortcut's Text action.

- The key can do exactly one thing: send a relay item to its own driver. It cannot read backups,
  trips or anything else. Its blast radius is spam notifications and prefilled forms that still need
  the driver's own tap to save.
- The Worker stores only its SHA-256 hash.
- Creating a new key revokes the previous one. **Revoke** removes it outright.

### 5.2 Sending

```
POST https://freightlogic-backup.fimseitef.workers.dev/relay
X-Shortcut-Key: fls_<48 hex>
Content-Type: application/json

{ "do": "expense", "params": { "amount": "45.10", "category": "Tolls" } }
```

- `do` and `params` follow §3 exactly: same actions, same names, same bounds. `relay` and `open`
  are not relay actions. The Worker validates the item before storing it, and the app validates it
  again before using it.
- Values may be strings or numbers. Unknown parameter names are dropped; credential-shaped names
  refuse the request (400).
- Response `200 { "ok": true, "id": "<relay id>", "pushed": <n> }`. `pushed` is the number of
  devices notified. `0` means no device has notifications on; the item still waits for the app.
- Errors: `401` missing or unknown key, `400` invalid action or parameters, `413` body over 16 KB,
  `429` rate limited (60 per hour per key).

### 5.3 Receiving

- The installed app's service worker shows a notification whose text is built **by the Worker from
  the validated parameters** (for example `Expense ready to save — $45.10 Tolls`). Shortcut-supplied
  text is never shown verbatim as a title.
- Tapping it opens the installed app at `#do=relay&id=<id>`. The app fetches the item with its own
  driver credential, dispatches it through §3, then deletes it from the relay.
- If the notification was missed, the app checks the relay each time it comes to the foreground and
  offers pending items on Today (**From Shortcuts**).
- Items expire after **72 hours** and at most **20** are kept per driver. They are plaintext at rest
  in the Worker's KV for that window, like any request the app already sends to `/extract` or
  `/evaluate`. Do not put anything in a relay item that should not sit on the server for three
  days.

---

## 6. Versioning

This is contract **v1**. New actions and parameters are additive, and unknown names are ignored by
older apps. Changing the meaning of an existing name requires `v2` and a new document.
