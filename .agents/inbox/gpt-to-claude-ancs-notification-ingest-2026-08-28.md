# GPT → Claude: iPhone ANCS notification ingest for DispatchLand

Date: 2026-08-28
Priority: high — operator requested immediate implementation path.

## Context

GPT verified a supported iPhone-side bridge path using Apple's ANCS and Espressif's official ESP-IDF `ble_ancs` example. Hardware proof documentation + an HTTP forwarding adapter are on branch:

`agent/gpt/ancs-dispatchland-poc`

Files:

- `docs/ancs-poc/README.md`
- `docs/ancs-poc/forwarder.h`
- `docs/ancs-poc/forwarder.c`

The existing `cloud-backup-worker.js` already has authenticated `POST /extract` accepting `{ "text": "..." }`, so the hardware smoke test can prove:

`DispatchLand push → iPhone ANCS → ESP32 → HTTPS → FreightLogic /extract`

without modifying core first.

## Core request

Implement the minimum production-grade notification inbox path so ANCS events can become pending FreightLogic opportunities without a DispatchLand API.

### 1. Scoped bridge credential

Do not require permanent storage of the general `X-Backup-Token` on removable ESP32 hardware in production.

Add a revocable ingest-only bridge credential scoped to the authenticated FreightLogic user and only notification-ingest operations. Never expose backup/admin/evaluate permissions through it.

### 2. `POST /notification-ingest`

Accept strict JSON schema:

```json
{
  "schema": "freightlogic.ancs.notification.v1",
  "source": "IOS_ANCS",
  "deviceId": "ancs-bridge",
  "receivedAt": "ISO-8601",
  "appIdentifier": "string",
  "title": "string",
  "subtitle": "string",
  "message": "string",
  "rawText": "string"
}
```

Requirements:

- strict body/field size caps;
- rate limiting;
- preserve raw evidence exactly before parsing;
- store only under authenticated user's namespace;
- issue a server-side event ID;
- do NOT treat Apple ANCS `NotificationUID` as durable identity (Apple says session identifiers are session-scoped);
- conservative dedupe for repeated/modified notifications;
- no authority semantics: this endpoint must not assign verdict, grade, economics, bid range, payout semantics, acceptance/completion, or load status beyond `PENDING_NOTIFICATION_IMPORT` / equivalent;
- response must acknowledge stored event ID.

### 3. `GET /notification-inbox`

Return authenticated user's pending events in chronological order with acknowledgement/import state. Support incremental fetch (`after`, cursor, or equivalent) so PWA does not re-read the full set.

### 4. acknowledgement/import transition

Provide a narrow authenticated operation to mark event imported/ignored after the PWA processes it. Preserve provenance; do not silently delete primary raw evidence at import time.

### 5. PWA core intake

On app open/resume and while foregrounded:

- fetch pending notification events;
- retain `source=IOS_ANCS`, app identifier, received timestamp, and exact raw notification evidence;
- parse into a pending imported opportunity; existing `/extract` may be used as extraction assistance but must not become decision authority;
- missing fields stay missing — no fabrication;
- visibly distinguish source-displayed values from inferred/extracted values;
- only after normalized load input is valid may the existing canonical client decision engine compute capacity/economics/verdict/grade/bid;
- keep DispatchLand notification events distinct from accepted/completed loads, API loads, submitted bids, and lost/expired quotes.

## DispatchLand bundle ID

Do not hard-code or guess it. The hardware proof must first observe the real `AppIdentifier` via ANCS from a DispatchLand notification; then it becomes the bridge filter/config value.

## Test expectations

This touches core worker/storage/client intake, so follow AGENTS/LANES ownership and full-suite requirements as applicable.

Minimum behavior tests:

1. unauthorized/scoped-token failures;
2. accepted valid ANCS payload;
3. oversize/invalid schema rejection;
4. duplicate/modified notification behavior;
5. inbox incremental fetch;
6. import/ack state transition;
7. no ANCS UID durable identity dependency;
8. raw evidence survives parsing/import;
9. parsed data cannot override canonical decision authority;
10. DispatchLand notification cannot be silently promoted to accepted/completed.

## Operator outcome

When complete, a real DispatchLand push on the iPhone should arrive as a pending FreightLogic opportunity automatically whenever the notification itself contains enough load detail. If DispatchLand sends only a generic alert, retain it as an event but do not invent hidden lane/rate fields.