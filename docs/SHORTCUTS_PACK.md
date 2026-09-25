# FreightLogic Apple Shortcuts Pack

**Contract:** `docs/SHORTCUTS_URL_CONTRACT.md` v1, authoritative from app v24.0.34 / Worker v24.  
**Production app:** `https://freightlogic-v2.fimseitef.workers.dev/`

These recipes use only parameters defined by the URL contract. They do not compute FreightLogic grades, True RPM, bids, or save records automatically.

## Before building a Shortcut

For an installed iPhone Home Screen PWA, use the **relay** workflow for actions that need the app's own stored trips/settings. A direct **Open URLs** action opens Safari, whose storage is separate from the installed PWA.

In FreightLogic, open **Settings → Notifications & Shortcuts**, enable notifications, and create a Shortcut key. Keep that `fls_...` key in the Shortcut itself; never put it in a FreightLogic URL.

## Screenshot → FreightLogic on iPhone

### A. Free and instant — no connection required

1. Open the DispatchLand screenshot in **Photos**.
2. Tap **Live Text**, then **Copy All**.
3. Open the installed FreightLogic Home Screen app.
4. Go to **Evaluate → Scan Screenshot**.
5. Paste the copied text.
6. Tap **Parse Load**.
7. Review Pickup, Delivery, Loaded Miles, Empty Miles, rate and Load ID before evaluating or saving.

v24.0.39+ reads labelled lines such as `Pickup:`, `Delivery:`, `Loaded Miles:` and `Empty Miles:`. Missing values stay unknown; do not replace them with zero.

### B. Server read — Choose Screenshot

This path requires the installed app to be connected first.

1. In the Admin Console, create an invite. Use **Re-invite** for an existing driver so existing backups remain associated correctly.
2. Long-press the invite link and tap **Copy**.
3. In the installed FreightLogic app, go to **Settings → Cloud Backup → I have an invite link**.
4. Paste the invite link and connect.
5. Return to **Evaluate → Scan Screenshot → Choose Screenshot** and select the DispatchLand image.
6. Review every extracted field before evaluating or saving.

v24.0.40+ supports pasting the invite link into the connection flow. Never store an invite link in documentation or screenshots.

### C. Apple Shortcut — local text extraction

Create a Shortcut with:

1. **Select Photos** (or receive an image from the Share Sheet).
2. **Extract Text from Image**.
3. **Copy to Clipboard**.
4. Open the **FreightLogic Home Screen app**.
5. In FreightLogic, paste into **Evaluate → Scan Screenshot**, tap **Parse Load**, and review the result.

Do **not** use **Open URL** as the save path. It opens Safari, which has separate storage from the installed Home Screen PWA.

## 1. Evaluate a load from typed values

Use this when you already have the rate and mileage.

1. Ask for **Revenue**, **Loaded miles**, and **Deadhead miles**. Do not default a missing deadhead to zero.
2. Optionally ask for origin, destination, broker, weight, dimensions, and pickup time.
3. URL Encode every value.
4. Build:
   `https://freightlogic-v2.fimseitef.workers.dev/#do=evaluate&revenue=<revenue>&loaded=<loaded>&deadhead=<deadhead>&origin=<origin>&dest=<dest>`
5. Open the URL.

Omit a field that is genuinely unknown. Use `deadhead=0` only when zero is verified.

## 2. DispatchLand screenshot → Load Intake

This keeps screenshot OCR on the iPhone.

1. **Select Photos** or receive an image from the Share Sheet.
2. Run Apple's **Extract Text from Image**.
3. URL Encode the extracted text.
4. Build:
   `https://freightlogic-v2.fimseitef.workers.dev/#do=intake&text=<encoded OCR text>`
5. Open the URL.
6. Review the parsed draft in FreightLogic before evaluating or saving anything.

The contract caps intake text at 6,000 characters. Do not invent fields that OCR did not recover.

## 3. Prefill a trip

For a direct link, build:

`https://freightlogic-v2.fimseitef.workers.dev/#do=trip&order=<order>&pay=<pay>&loaded=<loaded>&deadhead=<deadhead>&pickup=<YYYY-MM-DD>&delivery=<YYYY-MM-DD>&customer=<customer>&origin=<origin>&dest=<dest>`

On iPhone, prefer the relay recipe below so the installed PWA receives the form. Saving still requires the driver's tap.

## 4. Add an expense by voice

1. Dictate or ask for the amount.
2. Choose/ask for category; optionally collect date and note.
3. Build a Dictionary:
   - `do`: `expense`
   - `params`: Dictionary containing `amount`, `category`, and any optional contract fields.
4. **Get Contents of URL**:
   - URL: `https://freightlogic-backup.fimseitef.workers.dev/relay`
   - Method: POST
   - Header `X-Shortcut-Key`: your `fls_...` key
   - Header `Content-Type`: `application/json`
   - Request Body: JSON using the Dictionary.
5. FreightLogic sends a notification to the installed app. Tap it, review the prefilled expense, then Save.

## 5. Add fuel

Use the same relay structure with `do=fuel`. Allowed parameters are `gallons`, `total`, two-letter state/province code, `date`, and `note`.

Example JSON shape:

`{ "do": "fuel", "params": { "gallons": "18.4", "total": "71.76", "state": "GA" } }`

## 6. Open a FreightLogic surface

For simple navigation, direct links may use:

`https://freightlogic-v2.fimseitef.workers.dev/#do=open&to=<surface>`

Contract surfaces: `today`, `loads`, `evaluate`, `trips`, `money`, `expenses`, `fuel`, `settings`, `intel`, `more`.


## 7. Batch DispatchLand intake — last 30 screenshots

Use this for daily capture. OCR stays on the iPhone and only text that looks like DispatchLand freight evidence is submitted.

1. Create a Shortcut key in FreightLogic Settings and keep it only in the Shortcut.
2. Create a Shortcut named **FreightLogic — Send DispatchLand Screenshots**.
3. Find Photos where Media Type is Screenshot; sort Date Taken newest first; limit 30.
4. Read a small last-sent timestamp file from the Shortcuts folder. If none exists, treat it as the first run; do not invent a timestamp.
5. Keep only screenshots newer than that timestamp. If none remain, show **Nothing new** and stop.
6. For each image, Extract Text from Image. Keep it only when text contains **Loaded mi**, **Empty mi**, or **Dispatchland**. Drop exact duplicate extracted text within this run.
7. Preserve the screenshot Date Taken as source identity. Unreadable values stay UNKNOWN. Displayed order miles are not automatically loaded miles; MM:SS badges are countdowns, not timestamps.
8. Submit accepted intake items through the existing authenticated relay in batches of 20 or fewer. With 30 qualifying screenshots, send 20 and then the remainder. Keep the Shortcut credential in its authentication header; never put it in the payload, screenshots, or documentation.
9. Advance the last-sent timestamp only after every batch receives a successful response. On any failure, leave the old timestamp untouched so a rerun can safely resend; FreightLogic evidence dedup handles cross-run duplicates.
10. Show **N loads sent**, then review the FreightLogic intake queue before evaluating or saving.

This workflow never deletes or alters Photos. Nonmatching screenshots stay on the phone and are not submitted.

### Back Tap

After the Shortcut works manually, go to iPhone **Settings → Accessibility → Touch → Back Tap → Double Tap** and select **FreightLogic — Send DispatchLand Screenshots**. Keep the manual Shortcut as a fallback.

### First-run check

Start with one or two known DispatchLand screenshots. Confirm that Load/Quote ID, origin, destination, loaded miles and empty miles remain distinct and missing values remain UNKNOWN. A board/auction screenshot is listing evidence only; it does not prove booked, picked up, completed, invoiced, or paid status.

### Batch troubleshooting

- **Nothing new:** no newer screenshots exist, or none matched the local DispatchLand text filter.
- **Text extraction stops on a large selection:** retry with a smaller recent set. Do not run the full historical photo library through the daily Shortcut.
- **Authentication error:** recreate/check the Shortcut credential in FreightLogic; never paste it into chat or documentation.
- **Request too large:** keep each batch at 20 or fewer and reduce unusually large OCR text.
- **Rate limited:** wait for the rate-limit window instead of looping retries.
- **Partial failure:** do not manually advance the timestamp. Rerun and let evidence dedup absorb already accepted items.
- **Personal screenshot concern:** filtering happens locally before submission, so nonmatching screenshots are not sent.
- **Duplicate/repost:** exact text duplicates within one run are dropped. Similar lanes with different IDs, prices, or times remain separate evidence.

### Historical backfill

Keep the one-time backfill separate. Use the approved Photos/Drive corpus workflow for older screenshots rather than processing months of images in one Shortcut run; large all-history runs can exceed iPhone Shortcut memory.

## Relay troubleshooting

- **401:** Shortcut key is missing, revoked, or incorrect.
- **400:** action/parameter failed contract validation.
- **413:** request body exceeds 16 KB.
- **429:** rate limited. The Worker enforces both **60 relay requests/hour per Shortcut key** and **120 relay requests/hour per IP address**.
- A successful **200** can include `"dropped": ["<parameter>", ...]`. Out-of-range values are **dropped, not clamped** (for example, `gallons` over 500 or `miles` over 5000). If `dropped` is non-empty, show those names to the driver instead of treating 200 as “every field arrived.”
- `pushed: 0`: the relay item was accepted, but no device is currently subscribed to notifications; FreightLogic can still offer the pending item when the app returns to the foreground.

Relay items expire after 72 hours and the Worker retains at most 20 per driver. Treat relay content accordingly.

## Safety rules

Never put passwords, PINs, cookies, bearer tokens, session values, or the Shortcut key into a deep-link parameter. Never turn blank/unknown freight values into zero. Review OCR and prefilled forms before acting. FreightLogic remains the authority for evaluation; Shortcuts only collect and transport inputs.
