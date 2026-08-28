# FreightLogic iPhone ANCS → DispatchLand Proof of Concept

Status: implementation-ready proof-of-concept specification, 2026-08-28.

## Goal

Capture notifications generated on the operator's iPhone by DispatchLand without requiring a DispatchLand API, then forward the raw notification evidence into FreightLogic for parsing and eventual opportunity creation.

This is an ingestion bridge only. It must never become a decision authority. `app.js` / the canonical FreightLogic decision engine remains the sole owner of verdict, grade, economics, and bid advice.

## Why this is technically viable now

Apple's Apple Notification Center Service (ANCS) lets an authorized Bluetooth Low Energy accessory observe notification lifecycle events and request notification attributes. Apple's published service UUID is `7905F431-B5CE-4E99-A40F-4B1E122D00D0`; the Notification Source, Control Point, and Data Source characteristics are documented by Apple.

Espressif ships an official ESP-IDF `ble_ancs` example for ESP32-family boards. The example advertises to iOS, pairs/bonds, discovers ANCS, subscribes to Notification Source/Data Source, and retrieves notification attributes such as app, title, and message.

Official sources:

- Apple ANCS specification: https://developer.apple.com/library/archive/documentation/CoreBluetooth/Reference/AppleNotificationCenterServiceSpecification/Specification/Specification.html
- Espressif ANCS example: https://github.com/espressif/esp-idf/tree/master/examples/bluetooth/bluedroid/ble/ble_ancs

## Existing FreightLogic server capability we can reuse

`cloud-backup-worker.js` already exposes authenticated `POST /extract` for AI field extraction from raw load text. It accepts:

```http
POST /extract
X-Backup-Token: <driver token>
X-Device-Id: ancs-bridge
Content-Type: application/json

{"text":"<raw load/notification text>"}
```

and returns normalized fields such as order number, customer, broker, origin, destination, pay, loaded miles, deadhead, pickup/delivery dates, weight, commodity, and notes.

For the first hardware smoke test, the ANCS bridge can POST to `/extract` and print the JSON response to serial. This proves the entire chain:

`DispatchLand push → iPhone ANCS → ESP32 → HTTPS → FreightLogic parser`.

It does **not** yet persist the notification as an opportunity in the iPhone PWA. That requires the core change described under "Core handoff" below.

## Hardware

Minimum:

- one ESP32-family development board supported by Espressif's ANCS example (classic ESP32, ESP32-C3, ESP32-S3, etc.)
- USB cable for power/programming
- a computer with ESP-IDF installed for the initial flash
- network path for HTTPS forwarding (iPhone Personal Hotspot, vehicle Wi-Fi, or another Wi-Fi network)

No Android phone is required.

## Phase A — prove iPhone notification capture first

1. Install current ESP-IDF.
2. Copy Espressif's official ANCS example:

```bash
cp -R "$IDF_PATH/examples/bluetooth/bluedroid/ble/ble_ancs" freightlogic-ancs
cd freightlogic-ancs
idf.py set-target esp32
idf.py build
idf.py -p <PORT> flash monitor
```

Use the actual board target (`esp32`, `esp32c3`, `esp32s3`, etc.).

3. Pair the accessory with the iPhone when iOS prompts for Bluetooth authorization and notification access.
4. Generate any test notification and confirm the accessory receives ANCS events.
5. Generate a DispatchLand notification.
6. Request and log these attributes:

- App Identifier
- Title
- Subtitle
- Message
- Date
- Positive/negative action labels only if useful for diagnostics

7. Record the **actual DispatchLand App Identifier / bundle ID** observed from ANCS. Do not guess it in code.

### Important ANCS rule

Apple states that notification identifiers and app identifiers exchanged in an ANCS session are valid within that session. FreightLogic must not use `NotificationUID` as a durable cross-session load identifier. The bridge may use the UID only while requesting attributes during the active BLE session.

## Phase B — filter DispatchLand and forward raw evidence

Once the real DispatchLand app identifier is observed, the bridge should ignore other apps and forward only DispatchLand notifications.

Canonical bridge payload:

```json
{
  "schema": "freightlogic.ancs.notification.v1",
  "source": "IOS_ANCS",
  "deviceId": "ancs-bridge",
  "receivedAt": "2026-08-28T05:15:00.000Z",
  "appIdentifier": "<observed DispatchLand bundle id>",
  "title": "<notification title>",
  "subtitle": "<notification subtitle>",
  "message": "<notification body>",
  "rawText": "<title>\n<subtitle>\n<message>"
}
```

Do not invent missing fields. Preserve the raw text exactly before parsing.

### Initial `/extract` smoke test

Until the dedicated inbox endpoint exists, send only this subset to the existing worker:

```json
{
  "text": "<title>\n<subtitle>\n<message>"
}
```

Headers:

```http
Content-Type: application/json
X-Backup-Token: <existing FreightLogic driver token>
X-Device-Id: ancs-bridge
```

For production, do **not** permanently embed the full backup token in removable hardware. The core implementation should mint a dedicated, revocable, ingest-only bridge credential.

## ESP32 forwarding adapter

`forwarder.c` in this directory is a small ESP-IDF adapter for the HTTP leg. It deliberately does not duplicate Espressif's ANCS implementation. Integrate it into the official `ble_ancs` example and call `fl_forward_notification(...)` after the example has assembled the App Identifier, title, subtitle, and message for an added/modified notification.

The adapter:

- filters by an observed DispatchLand app identifier supplied at build/config time;
- creates a raw text body without inventing missing data;
- sends HTTPS JSON to FreightLogic `/extract` for the smoke test;
- avoids logging the authorization token;
- leaves retry/persistent queueing for the production bridge.

## Core handoff required for automatic FreightLogic opportunities

The hardware proof can run against `/extract`, but true zero-touch intake needs a core-owned inbox contract.

Recommended minimal server/client change:

### `POST /notification-ingest`

Authenticated by a dedicated scoped bridge token, not the general backup token.

Input:

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

Server responsibilities:

- strict size limits and rate limiting;
- preserve raw evidence exactly;
- reject unknown schema/source;
- store only the user's own notification evidence;
- issue a server event ID independent of ANCS `NotificationUID`;
- dedupe conservatively without treating ANCS UID as durable identity;
- never assign rate semantics, verdict, grade, economics, or bid authority;
- expose pending events to the authenticated PWA.

### `GET /notification-inbox`

Return unseen/pending notification events for the authenticated user/device, chronological order, with acknowledgement state.

### PWA intake

On app open/resume and while foregrounded:

1. fetch pending notification events;
2. retain source=`IOS_ANCS` and the original raw evidence;
3. parse fields into a **pending imported opportunity**;
4. do not fabricate fields not present in the notification;
5. run canonical capacity/economics/decision logic only after a valid normalized opportunity exists;
6. visibly distinguish raw source fields from inferred/extracted fields;
7. preserve provenance so a DispatchLand notification cannot be confused with a completed/accepted load or an API load.

## DispatchLand-specific limitation

The bridge can only capture attributes iOS exposes for the notification. If DispatchLand sends only a generic message such as "You have just received a Quote", the bridge can record the event but cannot obtain hidden origin/destination/miles/weight from ANCS alone.

If DispatchLand includes lane/rate/weight/miles/details in the notification body, those can be forwarded automatically.

## Test matrix

1. Pair/reconnect after ESP32 reboot.
2. iPhone reboot and reconnect.
3. Non-DispatchLand notification is ignored after the bundle-ID filter is enabled.
4. DispatchLand notification produces exact title/subtitle/message in serial capture.
5. Long body fragmented across BLE MTU is reassembled correctly by the ANCS example.
6. HTTPS success to `/extract` returns structured fields.
7. Missing Wi-Fi does not block ANCS callback processing; forwarding failure is bounded and logged without secrets.
8. Duplicate notification modifications do not create uncontrolled duplicate opportunity records in the eventual inbox implementation.
9. No use of ANCS NotificationUID as a durable cross-session identifier.

## Definition of proof complete

The hardware proof is successful when a real DispatchLand notification arrives on the iPhone and the ESP32 serial log shows:

- the observed DispatchLand app identifier;
- exact notification title/body;
- an HTTP 200 from FreightLogic `/extract`;
- normalized extraction response corresponding only to information present in that notification.

At that point the only remaining engineering work for true zero-touch entry is the core notification inbox/persistence path.