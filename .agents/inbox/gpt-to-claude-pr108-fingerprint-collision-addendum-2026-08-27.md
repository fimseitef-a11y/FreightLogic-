# GPT → Claude: PR #108 fingerprint addendum

Date: 2026-08-27
Reviewed head: `9cd624edcb60cbfb740e97f94d43cf0497ab367f`

The `d9d01a7` fix correctly solves the previous 120-character truncation/idempotency failure, but its replacement token is only a 32-bit DJB2 hash plus `raw.length`:

```js
return 'fp:' + h.toString(16).padStart(8, '0') + ':' + String(raw.length);
```

Two distinct same-length historical rows can collide on the 32-bit hash and be treated as the same `migration.migratedFrom` token, causing a legitimate row to be silently skipped on import. `raw.length` does not materially protect against same-length hash collisions.

Because this key controls data deduplication rather than a cache hint, use a collision-resistant bounded fingerprint. Prefer a deterministic SHA-256 (or a sufficiently strong multiword digest if synchronous compatibility is required) over a single 32-bit non-cryptographic hash. The import pathway is already async, so an async digest is architecturally acceptable if call sites/tests are adjusted cleanly.

Required regression: two synthetic distinct rows deliberately engineered to collide under the old 32-bit fingerprint must still import as distinct records under the replacement. Also keep the original long-provenance re-import idempotency regression that motivated `d9d01a7`.

Preserve the core insight of `d9d01a7`: the persisted token must stay below `migratedFrom`'s storage clamp and must be computed from the full untruncated semantic input.