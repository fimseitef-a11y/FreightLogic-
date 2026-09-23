# FreightLogic Web Push Contract — v1

**Status:** authoritative from app **v24.0.34** / Worker **v24**.
**Owner:** Claude lane. Companion to `docs/SHORTCUTS_URL_CONTRACT.md`, whose relay (§5) is the main
thing push delivers today.

**Why.** On 2026-09-22 the operator froze native iOS (#204/#205). The chosen notification layer is
Web Push to the **installed Home Screen app**, which iOS has supported since 16.4. iOS still has
**no** Background Sync; push is not a way to run code in the background. A notification is
something the driver sees and taps, and nothing more.

---

## 1. What push is used for (v1)

| Event | Sender | Notification |
|---|---|---|
| A Shortcut sends a relay item | `POST /relay` | e.g. "Load text captured, tap to review"; opens `#do=relay&id=…` |
| The driver taps **Send test** in Settings | `POST /push/test` | "Notifications are working" |

Deliberately **not** in v1:

- **Server-scheduled reminders** (invoice follow-ups, maintenance due). The server cannot see the
  driver's data, because backups are encrypted on the device, so every reminder would have to be
  registered from the app. That is a v2 design with its own contract.
- **"Your backup looks stale" nudges.** The server cannot tell "no changes" from "sync paused", so
  such a nudge would mostly be noise. The in-app paused banner (v24.0.6) stays the authority.
- **Any evaluation in a notification.** The server never scores a load (the v24.0 authority rule).
  Notifications only invite the driver into the app, where the canonical evaluator runs.

---

## 2. Keys: VAPID

- The Worker signs every push with an ES256 **VAPID** key pair (RFC 8292).
- **Source of truth, in order:**
  1. Worker secrets `VAPID_PUBLIC_KEY` (base64url, 65-byte uncompressed P-256 point) and
     `VAPID_PRIVATE_JWK` (JSON JWK), if the operator sets them;
  2. otherwise a key pair the Worker generates once and stores in KV under `push:vapid`.
- The self-provisioned key lives next to the subscriptions it signs for, so storing it in KV grants
  nobody new anything: whoever can read that KV can already read the subscriptions. It exists so
  push works without an operator secret-setup step.
- `sub` claim: `VAPID_SUBJECT` if set, else `https://freightlogic-v2.fimseitef.workers.dev`.
- **Key changes self-heal.** The app records which public key it subscribed with. If
  `GET /push/key` returns a different key, the app unsubscribes and subscribes again on its next
  foreground.

## 3. Payload encryption

Every payload is encrypted with **`aes128gcm`** (RFC 8291 / RFC 8188): a fresh ephemeral P-256 key
and a 16-byte random salt per message, a single record, record size 4096, and the `0x02` padding
delimiter. The implementation is tested byte for byte against RFC 8291 Appendix A. The push service
(Apple, Google, Mozilla) sees only ciphertext.

Plaintext is small JSON, never more than 3 KB:

```json
{ "v": 1, "title": "FreightLogic", "body": "Expense ready to save — $45.10 Tolls",
  "url": "./#do=relay&id=rl_…", "tag": "relay-rl_…" }
```

The payload never carries relay parameters, load text or money beyond the one-line summary. The app
fetches the item itself with its driver credential.

## 4. Endpoints (Worker v24)

All JSON. "Driver auth" means the existing `X-Backup-Token` + `X-Device-Id` headers, the same gate
as `/backup`.

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /push/key` | none | `{ ok, publicKey }`: the VAPID public key (public by design) |
| `POST /push/subscribe` | driver | store `{ subscription: { endpoint, keys: { p256dh, auth } }, publicKey }` for this device |
| `DELETE /push/subscribe` | driver | remove this device's subscription (`{ endpoint }`) |
| `POST /push/test` | driver | send the test notification to this driver's devices; 10/hr |
| `GET /shortcut-key` | driver | `{ ok, exists, createdAt }`; never returns the key |
| `POST /shortcut-key` | driver | mint `fls_<48 hex>`, shown once; revokes any previous key; 10/hr |
| `DELETE /shortcut-key` | driver | revoke |
| `POST /relay` | `X-Shortcut-Key` | see the URL contract §5.2; 60/hr per key |
| `GET /relay` | driver | `{ ok, items: [{ id, do, params, createdAt }] }`, oldest first |
| `DELETE /relay/<id>` | driver | mark one item consumed |

`/push/key` and `/relay` sit **above** the driver-token gate, as `/claim` does, because neither
caller holds a driver token. `/relay` authenticates with the Shortcut key instead.

## 5. Subscription rules (server)

- **Endpoint allowlist.** The endpoint must be `https:` on a known push service host:
  `web.push.apple.com` (or any `*.push.apple.com`), `fcm.googleapis.com`,
  `updates.push.services.mozilla.com` (or any `*.push.services.mozilla.com`), or
  `*.notify.windows.com`. Anything else is refused (400). Otherwise the Worker could be steered into
  POSTing to an arbitrary URL (SSRF).
- `p256dh` must decode to a 65-byte uncompressed point that WebCrypto accepts as a P-256 key, and
  `auth` must decode to 16 bytes.
- Stored under `push:sub:<userId>:<sha256(endpoint) first 24 hex>`, with the device id and creation
  time. At most **5** per driver; the oldest is evicted.
- A push service answer of `404` or `410` deletes that subscription. Any other failure is counted
  and reported, and the subscription is kept.
- Every push carries `TTL: 86400` and `Urgency: normal` (`high` for relay items).

## 6. The app

- **Settings → Notifications & Shortcuts**: status (Off / On / Blocked / Not available here),
  **Turn on**, **Send test**, **Turn off**, plus the Shortcut key controls from the URL contract §5.1.
- Permission is requested **only from the Turn on tap**: iOS ignores a prompt that is not tied to
  a user gesture, and a prompt at boot trains people to deny it.
- On iPhone, push exists only in the installed Home Screen app. In a Safari tab the row says so and
  explains how to install, rather than showing a button that cannot work.
- Requires cloud backup (a driver token); without one the row explains that notifications ride on
  the same account.

## 7. The service worker

- `push`: parse the JSON; clamp title to 60 and body to 180 characters; accept `url` only if it
  resolves to the app's own origin **and** scope, else fall back to `./`; always call
  `showNotification` (iOS revokes permission from apps that receive silent pushes).
- `notificationclick`: close the notification. If an app window is open, focus it and post
  `{ type: 'FL_OPEN_URL', url }`; the app applies the fragment through the deep-link router.
  Otherwise open a window at `url`.
- Neither handler touches IndexedDB, credentials or the cache. The service worker stays a delivery
  layer.

## 8. Tests that pin this

- `tests/unit/worker-web-push.spec.mjs`: RFC 8291 Appendix A byte-for-byte; the VAPID JWT verifies
  with the published public key; endpoint allowlist; subscription validation; auth on every route;
  relay validation parity with the app's allowlist; 404/410 cleanup; rate limits.
- `tests/integration/shortcuts-deep-links.spec.mjs`: every action through the real router; no
  auto-save; UNKNOWN deadhead; out-of-range dropping; credential refusal; one-shot fragment; the
  iPhone Safari warning; relay dispatch.
- `tests/unit/sw-push.spec.mjs`: the service worker's `push` / `notificationclick` handlers,
  including same-origin URL enforcement.
