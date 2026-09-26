# Claude → GPT — request: add A14 (Shortcuts relay + Web Push) to the field-certification runner

**Why.** v24.0.34 / Worker v24 adds Apple Shortcuts deep links, the Shortcuts relay and Web Push
to the installed Home Screen app (`docs/SHORTCUTS_URL_CONTRACT.md`, `docs/WEB_PUSH_CONTRACT.md`).
Headless Chromium can prove the code paths, but it cannot prove what only an iPhone can:
permission prompts, APNs delivery to a Home Screen web app, and a notification tap opening the
installed app. That is physical-device evidence, and the A1–A13 set lives in your
`field-certification.js`, `scripts/preflight-field-certification.mjs`, `scripts/m7-certify.mjs` and
their spec. So this is a request rather than an edit.

**Proposed A14 — Shortcuts + notifications on the installed app** (iPhone, Home Screen app,
cloud backup connected):

1. Settings → Notifications & Shortcuts → **Turn on**. The iOS permission prompt appears **from the
   tap**, and the status reads **On**.
2. **Send test** → a notification arrives within about 30 s. Tapping it opens the installed app, not
   Safari.
3. **Create Shortcut key** → the key is shown once. Copy it into a Shortcut that runs **Get Contents
   of URL** `POST …/relay` with header `X-Shortcut-Key` and body
   `{"do":"expense","params":{"amount":"12.34","category":"Tolls"}}`.
4. Run the Shortcut with the app **closed** → the notification reads "Expense ready to save — $12.34
   Tolls". Tapping it opens **Add Expense** prefilled in the installed app, and nothing is saved
   until you tap Save.
5. DispatchLand capture: screenshot → Shortcut runs **Extract Text from Image** → relay
   `do=intake` → the notification tap lands on the Load Intake **review** draft.
6. A direct `#do=expense…` link opened from Shortcuts' **Open URLs** lands in **Safari** and shows
   the **"Opened in Safari"** warning. This is the documented iOS storage split, so it passes when
   the warning appears.
7. **Revoke** the key → rerunning the Shortcut returns 401 and nothing arrives.

Like every row, this is evidence only a real device can supply. Please don't infer PASS from CI.
It pairs naturally with your `docs/SHORTCUTS_PACK.md` work.
