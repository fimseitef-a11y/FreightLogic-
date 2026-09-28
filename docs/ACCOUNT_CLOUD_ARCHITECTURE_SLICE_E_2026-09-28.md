# FreightLogic Slice E — Account / Cloud Architecture and Migration Certification

**Status:** architecture contract only  
**Date:** 2026-09-28  
**Source baseline:** main `226b8cd5e802ebc69fcbcb5a8883ce2617c0a7fa`, FreightLogic v24.0.53 / IndexedDB v16 / Backup Worker v30  
**Validation base:** CI/test stabilization PR #428 merged to main as `9302e47b9dd5ac565cbd43bf9fc92d1fd74dac07`; it changes test/CI files only, so the runtime source baseline above is unchanged.  
**Issue:** #417 Slice E  
**Task:** AIAG-TASK-0028

## 1. Decision

FreightLogic remains **local-first and encrypted-backup-first** until a later, separately authorized implementation is certified against this contract.

Slice E does **not** authorize a migration, new account provider, paid service, credential change, database conversion, server-side plaintext, or cross-user data move. The purpose of this document is to make those future changes reviewable without weakening the working recovery path.

The target architecture separates four authorities that must never collapse into one:

1. **Local data authority** — IndexedDB remains the immediate source of truth for offline operation and unsynced edits.
2. **Identity/authentication authority** — proves which account/device may read or write encrypted cloud objects. Authentication is not decryption.
3. **Encryption authority** — the user/device-held secret needed to decrypt backup content. The server must not obtain it.
4. **Business/evidence authority** — existing FreightLogic reconciliation, lifecycle, UNKNOWN, provenance, economics, and audit contracts. Cloud transport must never reinterpret these values.

No future “account system” is allowed to turn a cloud login into access to plaintext freight history.

## 2. Current system truth that must be preserved

This section records implementation behavior from current primary repository evidence, not a desired future state.

### 2.1 Local-first storage

FreightLogic is an offline-first PWA. IndexedDB v16 is the durable working store. Local writes complete before cloud synchronization. A failed or delayed cloud push must never make a successful local mutation disappear or become “unsaved.”

The current backup contract covers persisted stores including trips, expenses, fuel, lane history, weekly reports, reload outcomes, bid history, documents, GPS logs, settings, receipts metadata, `loadLifecycle`, and `normalizedEvidence`. `receiptBlobs` and `auditLog` are intentionally outside cloud backup.

### 2.2 Current encrypted backup boundary

The client encrypts backup payloads with AES-256-GCM. The current key is derived locally from the operator passphrase using PBKDF2-SHA-256 at 600,000 iterations; decrypt retains legacy 100,000-iteration compatibility for older payloads.

The passphrase is held in `sessionStorage` and deliberately does not persist as an application setting. The Worker receives ciphertext, IV, salt and transport metadata, not the plaintext backup or passphrase.

This zero-knowledge property is a hard invariant for Slice E.

### 2.3 Current identity and device boundary

The client has a locally generated device identifier in `localStorage`. Driver API access uses a bearer credential; the Worker stores hashes rather than raw driver tokens.

The Worker has a canonical `user:<userId>` record. Invite/claim flow is designed to keep a stable `userId`; re-claim rotates the bearer credential instead of minting a new account, so recovery does not orphan backup history. A superseded token hash must not authenticate merely because a stale index key still exists.

Current behavior is effectively one canonical current driver-token hash per user. A future multi-device account design therefore cannot simply “add another token” without a versioned credential model and explicit backward compatibility.

### 2.4 Current portability trust boundary

Credentials are excluded from cloud backup and local export. At minimum this includes the driver bearer credential, encrypted admin token, app-lock PIN material and external API keys.

Inbound import is intentionally narrower than export. Endpoint authority and security settings that are safe to *describe* in an export are not automatically safe to *install* from an untrusted file.

Slice E must preserve the rule:

> **portable data never grants authentication, endpoint authority, admin authority, or decryption authority.**

### 2.5 Current restore semantics

Restore is reconciliation, not “remote wins.”

Protected `loadLifecycle` and `normalizedEvidence` records use stable internal identities and revision/timestamp-aware reconciliation. Settings are add-only on cloud merge where “newer” cannot be safely determined. Source references are unioned where appropriate. Unknown values remain unknown. External order numbers are linking signals, not unique internal identity.

The cloud delta path already distinguishes a confirmed retention gap from an unverifiable delta fetch/decrypt/parse path. Either must fail visibly rather than claim complete recovery.

## 3. Threat model

A future account/cloud implementation must assume all of the following can happen:

| Threat | Required behavior |
|---|---|
| Cloud storage/KV compromise | Attacker obtains ciphertext/metadata but not usable plaintext or decryption secret. |
| Bearer credential leak | Credential can be revoked/rotated without changing stable account identity or orphaning history. |
| Lost/stolen device | Device access can be revoked independently; another authorized device can keep the same account identity. |
| Malicious import/backup | Cannot install secrets, endpoint authority, admin authority, PIN state, or silently downgrade protected history. |
| Cross-user key collision/bug | A valid user credential must never fetch, enumerate, restore, or mutate another user's objects. |
| Stale device comes online | Older records cannot overwrite newer protected state merely because they sync later. |
| Two devices write concurrently | No silent loss; conflicts are deterministically reconciled or surfaced for operator resolution. |
| Clock skew | Ordering cannot depend solely on untrusted device wall-clock time. |
| Server rollback/stale snapshot | Client detects sequence/version regression or treats coverage as unverified. |
| Partial migration | Legacy restore remains usable; mixed generations fail closed rather than silently dropping fields. |
| Provider outage | Local work continues; pending sync is visible and durable. |
| Account auth provider compromise | Login alone still cannot decrypt historical freight data. |
| Observability/logging leak | Logs contain event class/status/correlation only; no secrets, raw freight rows, backup plaintext, passphrases, PINs, invite codes or full bearer tokens. |

## 4. Target logical model

This is a provider-neutral contract. Names below are conceptual and do not select a vendor or storage product.

### 4.1 Stable account identity

Introduce an immutable internal `accountId` that is independent of email, phone number, carrier name, device ID, login provider, display name and bearer credential.

For existing accounts, migration must map the current canonical `userId` to exactly one `accountId`. The mapping must be idempotent and auditable. Re-running migration must never create a second account for the same current user.

No merge of two existing user identities may occur automatically. Any future account merge is a separate high-risk operation requiring explicit operator review and a reversible pre-merge snapshot.

### 4.2 Device identity

Each installation receives a stable internal `deviceId` under an account. Devices are explicit records with at least:

- stable `deviceId`;
- account ownership;
- created/last-seen timestamps;
- credential generation / revocation state;
- client schema/app generation metadata;
- optional operator-facing nickname;
- no raw secret value.

A device identifier is not authentication by itself.

### 4.3 Credentials

Move from “one current token hash on the user record” to a versioned account → device-credential model only in a separately authorized implementation.

Properties:

- raw bearer credentials are returned only at issue/claim time;
- server stores only one-way credential verifiers;
- revoking one device does not rotate or invalidate unrelated devices unless the operator requests account-wide revocation;
- credential rotation preserves `accountId`, `deviceId`, and encrypted history;
- legacy single-token users remain valid during the compatibility window;
- downgrade from the new credential model to legacy single-token semantics is forbidden after cutover.

### 4.4 Encryption and key ownership

Identity authentication and backup decryption remain separate.

The preferred target is a two-layer key hierarchy:

- a random **Data Encryption Key (DEK)** encrypts backup/sync payloads with an authenticated cipher;
- a **Key Encryption Key (KEK)** derived locally from the operator's recovery/passphrase material wraps the DEK;
- the cloud may store the wrapped DEK and KDF parameters, but never the KEK, plaintext DEK, passphrase, recovery phrase or equivalent decrypting secret.

Why a hierarchy: changing the passphrase should be able to re-wrap a DEK without re-encrypting every historical object. This is an architectural target, not permission to replace the current PBKDF2/AES-GCM format.

Requirements for any future KDF/cipher change:

- version the envelope explicitly;
- retain current and legacy decrypt paths until migration certification proves old backups recover;
- authenticate all metadata that influences decryption or account/device binding;
- never silently fall back from a stronger envelope to plaintext or unauthenticated encryption.

### 4.5 Cloud object identity

Encrypted cloud records must be partitioned by immutable account identity and non-user-controlled object keys. A conceptual namespace is:

`account/<accountId>/device/<deviceId>/<objectType>/<serverSequence>`

The path is illustrative. The invariant is that authorization derives `accountId` from the authenticated credential; the caller never chooses another account namespace through a request parameter.

### 4.6 Sync envelopes

A future v2 sync envelope should carry non-secret reconciliation metadata outside ciphertext only when operationally necessary:

```
{
  envelopeVersion,
  accountIdBindingHash,
  deviceId,
  serverSequence,
  mutationId,
  payloadKind,
  createdAtServer,
  cipherSuite,
  kdfOrWrappedKeyVersion,
  ciphertext,
  iv,
  authenticatedMetadata
}
```

No origin/destination, rate, broker, notes, document contents, GPS coordinates or other freight facts belong in plaintext envelope metadata.

`mutationId` is globally unique and idempotent. `serverSequence` is monotonic within the account stream and is server-assigned so device clock skew cannot define sync order.

## 5. Reconciliation rules

The server is a blind encrypted transport/store, not the business merge authority.

Clients decrypt eligible envelopes and feed records through the existing canonical sanitizers/reconcilers. The first implementation must preserve these rules:

- stable internal record identity beats external order number;
- explicit tombstones are required for synchronized deletion; absence never means delete;
- revisioned protected records cannot be downgraded by stale replicas;
- scalar values and their provenance move together;
- UNKNOWN is not zero;
- lifecycle axes stay separate;
- exact replay is idempotent;
- ambiguous conflicts remain unresolved/surfaced rather than guessed;
- settings with no safe ordering remain conservative/additive unless a field receives an explicit versioned merge contract.

A future generalized change journal may be added only after tests prove parity with every existing store-specific rule. “Last write wins everywhere” is explicitly prohibited.

## 6. Local-first/offline behavior

Account/cloud adoption must not make the network part of the save path.

Required behavior:

1. local mutation commits first;
2. durable pending-sync intent is recorded locally;
3. UI may report pending/failed/paused sync but the local record remains usable;
4. reconnect uploads idempotently;
5. app remains fully usable offline for current offline-supported functions;
6. a cloud/auth outage does not block viewing or editing existing local freight data;
7. sign-out/revocation does not erase local data automatically;
8. destructive local wipe remains a separate explicit action with recovery warnings.

Installed-PWA storage partition behavior on iPhone remains a physical certification gate; architecture documents cannot declare Safari and Home Screen storage equivalent.

## 7. Migration plan

Every phase has a rollback point. No phase deletes legacy backup data.

### Phase E0 — design and test contracts

This document plus red-first contract tests/specs. No runtime behavior change.

**Exit:** architecture independently reviewed; threat model and certification matrix accepted.

### Phase E1 — versioned identity metadata, dark

Add account/device schema and adapters behind a disabled feature flag. Existing `userId`, token, backup and restore paths remain authoritative.

**Rollback:** disable flag; no user data conversion required.

### Phase E2 — shadow v2 encrypted envelopes

After every successful legacy backup, optionally create a v2 encrypted shadow using the same already-filtered data. Restore still reads legacy only.

Compare counts, protected checksums and semantic summaries after decrypt on the client/test harness. Never compare/log raw row content server-side.

**Rollback:** stop shadow writes; legacy backup remains complete.

### Phase E3 — dual-read certification

On synthetic/test identities, restore both legacy and v2 into isolated temporary databases and compare canonical exports after reconciliation.

For real operator data, any comparison tooling must operate locally and emit privacy-safe digests/counts only.

**Rollback:** keep v2 read disabled for normal users.

### Phase E4 — explicit opt-in v2 restore/sync

A bounded pilot may opt in only after legacy backup exists and passes recovery preflight. Keep legacy write/read available.

**Rollback:** return to legacy sync using the pre-cutover recovery point; do not translate v2-only state destructively.

### Phase E5 — v2 default, legacy safety window

Make v2 default only after defined observation period, physical iPhone gates, live synthetic cross-user tests, restore drills and zero unresolved data-loss/security findings.

Legacy restore remains read-only for the documented compatibility window.

### Phase E6 — legacy retirement

Requires a separate operator-approved retirement record proving:

- no unsupported legacy backup remains within required retention;
- documented export/recovery path exists;
- rollback/archive obligations are met;
- release notes identify the irreversible boundary.

No automatic retirement by date alone.

## 8. Rollback contract

Before any migration mutation:

- produce a verified legacy full backup;
- record app/DB/Worker generation and privacy-safe backup identifier;
- verify the backup is decryptable with operator-held material;
- never copy credentials into rollback artifacts.

A rollback is successful only when:

- the prior app can read its local schema or an explicitly supported downgrade snapshot;
- legacy cloud restore still reconstructs the certified state;
- protected lifecycle/evidence revisions do not regress;
- no v2 credential remains able to cross account boundaries;
- any v2-only pending mutations are either safely imported or explicitly reported as unresolved. They may not disappear silently.

## 9. Certification matrix

These are minimum gates for a future implementation. Each new behavioral assertion needs a meaningful negative control.

| Gate | Required evidence |
|---|---|
| E-01 Identity idempotency | Re-running legacy `userId` → `accountId` mapping creates no duplicate account. Negative: changed legacy identity does not alias. |
| E-02 Cross-user isolation | Authenticated synthetic account A cannot enumerate/read/write B objects. Negative must exercise guessed IDs and manipulated request fields. |
| E-03 Per-device revoke | Revoking device A does not revoke B; A immediately fails authenticated access. |
| E-04 Account-wide revoke | Explicit account revoke invalidates every device credential without exposing credential values. |
| E-05 Secret exclusion | Export, backup, sync, logs and certification artifacts contain no bearer/admin/PIN/passphrase/recovery secrets. Include key-shaped canaries. |
| E-06 Server-blind encryption | Stored v2 object is not parseable as freight plaintext; wrong recovery material fails authenticated decryption. |
| E-07 Legacy decrypt | Current 600k and supported legacy 100k payloads still restore during compatibility window. |
| E-08 KDF/envelope downgrade | Tampered version/cipher/KDF metadata fails closed; no plaintext/weak-mode fallback. |
| E-09 Offline local save | With network unavailable, supported writes persist locally and pending sync survives restart. |
| E-10 Idempotent replay | Same mutation/envelope replay produces no duplicate logical record. |
| E-11 Concurrent devices | Conflicting protected-record edits do not silently downgrade newer state; ambiguous cases surface. |
| E-12 UNKNOWN/provenance | Missing values remain UNKNOWN; provenance stays paired with its winning scalar. |
| E-13 Tombstones | Explicit delete syncs safely; absence from a remote snapshot never deletes local data. |
| E-14 Clock skew | Deliberately skewed device clocks do not reverse server stream order or protected revisions. |
| E-15 Partial retention/gap | Missing delta/object coverage is reported confirmed-gap or unverifiable, never “restore complete.” |
| E-16 Shadow parity | Legacy and v2 isolated restores produce equivalent canonical privacy-safe digests/counts. |
| E-17 Rollback drill | Pilot can return to certified legacy backup without data loss or credential leakage. |
| E-18 Physical iPhone | Relevant #226 rows, especially offline/relaunch and Safari↔Home-Screen partition behavior, are observed on the exact candidate. |
| E-19 Live Worker | Synthetic production account exercises create/rotate/revoke/backup/restore boundaries with cleanup and no raw user data. |
| E-20 Observability | Production logs demonstrate useful status without identities/secrets/raw freight payloads. |

Any cross-user isolation, encryption, rollback or restore-integrity failure is release-blocking.

## 10. Provider and deployment neutrality

This contract deliberately does not choose:

- an identity-as-a-service provider;
- SQL vs KV vs object storage for future data;
- a paid Apple capability;
- a new Cloudflare product;
- email/SMS delivery provider;
- passwordless/passkey vendor.

A provider evaluation may happen later, but it must be scored against this contract. A convenient SDK cannot weaken zero-knowledge encryption, offline operation, export/recovery rights, data retention controls or cross-user isolation.

## 11. Admin boundary

Admin capability remains separate from driver account use.

A future account system must not:

- place an admin credential in a driver backup;
- let a driver session obtain organization-wide user enumeration by default;
- expose raw freight data to an admin console merely because the admin can provision accounts;
- couple admin credential recovery to backup decryption;
- reuse an AI Agent/service credential as a driver/account credential.

Provisioning, revocation and audit metadata may be administrative. Freight payload access requires a separately justified data-access role and explicit design review.

## 12. AI Agent boundary

The private AI Agent integration is not the account database.

Agent RPC may receive only its minimized authorized envelope after driver authentication/privacy guards. It must not become a second user store, secret store, backup store or source of canonical freight history. Agent failure remains fail-closed and cannot block local-first operation.

## 13. Data retention and deletion

Future cloud account controls must distinguish:

- revoke access;
- remove one device;
- delete cloud backup copies;
- delete account metadata;
- wipe local device data;
- export/archive before deletion.

These are not synonyms. Destructive deletion must be explicit, previewed, audit-recorded without secrets, and where technically possible preceded by a verified recoverable export/backup. No implementation task may bundle account deletion into ordinary sign-out.

## 14. Required implementation work packages

After independent review, implementation should be split into separately mergeable tasks:

1. **E1 Identity/schema contracts** — types/adapters/tests only, disabled.
2. **E2 Device credential model** — server auth changes plus negative cross-user tests; no backup-format change.
3. **E3 Envelope/key hierarchy** — versioned client crypto and legacy compatibility tests; no default cutover.
4. **E4 Shadow sync** — v2 write path dark/shadow with privacy-safe parity evidence.
5. **E5 Dual-read restore** — isolated comparison/reconciliation, still not default.
6. **E6 Pilot/cutover tooling** — explicit opt-in, rollback automation, live synthetic certification.
7. **E7 Retirement** — only after a separate approval and compatibility-retention evidence.

Each package receives its own Task Control row, exact repository ownership/lock reconciliation, red-first tests, exact-head CI and Airtable checkpoint. No package inherits authorization from this architecture task.

## 15. Slice E architecture acceptance

AIAG-TASK-0028 is complete when:

- this architecture exists on a reviewable PR;
- it accurately reflects current primary backup/auth/restore behavior;
- it preserves local-first + zero-knowledge backup guarantees;
- it defines account/device/credential/key/reconciliation boundaries;
- it includes staged migration and rollback;
- it defines negative-control certification sufficient to detect cross-user, secret, integrity, offline and rollback defects;
- it makes clear that runtime migration requires new authorization.

It is **not** complete by deploying an account system, because deployment is outside this task's authority.

## 16. Primary repository references

- `docs/BACKUP_CONTRACT.md` — current portability, secret-exclusion, restore and protected-evidence contract.
- `cloud-backup-worker.js` — current user/token/invite/claim/revoke/backup namespace and private Agent ingress.
- `app.js` — client encryption, device ID, cloud push/pull, sync pending state, merge restore and claim/reconnect behavior.
- `docs/AUTHENTICATED_WORKER_CERT_DESIGN_2026-09-14.md` — synthetic production identity/testing boundary.
- `FIELD_TEST_CHECKLIST.md` / issue #226 — physical iPhone/offline/storage-partition evidence that headless CI cannot replace.
- Issue #417 — Slice E boundary and explicit requirement to preserve current local-first/encrypted recovery until migration is separately designed and certified.
