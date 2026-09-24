#!/usr/bin/env node
// FreightLogic — delete dead legacy plaintext `token:` index keys (one-off, operator-approved).
//
// Worker v7 indexed every driver token as `token:<flk_…>`, so the KEY NAME is
// the plaintext credential. v14+ authenticates only through the account record,
// and `scripts/audit-legacy-tokens.mjs` proved on 2026-09-24 (run 35950761459)
// that the 3 remaining keys no longer authenticate. They are still old token
// bytes sitting in plaintext, so the operator approved deleting them.
//
// Safety rules, all enforced before any delete is sent:
//   - Every key is re-checked against the Worker's own rule (legacyIndexIsLive)
//     at run time. If ANY key is still live, nothing is deleted: a live
//     credential is retired by rotation, never by deleting its index entry.
//   - Only keys under the `token:` prefix are ever touched, one exact key at a
//     time. No prefix delete, no bulk endpoint.
//   - More than MAX_DELETE keys means the inventory is not what was audited,
//     so it refuses.
//   - Nothing prints a key name (the name IS the credential) or a value.
//
// Exit: 0 deleted (or nothing to delete), 1 refused, 2 KV unreachable.
// Env: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, FL_KV_NAMESPACE_ID,
//      FL_CONFIRM (must equal DELETE).

import { pathToFileURL } from 'node:url';
import { createKvReader, legacyIndexIsLive } from './audit-legacy-tokens.mjs';

export const LEGACY_PREFIX = 'token:';
export const MAX_DELETE = 10;

// Pure: decide what may be deleted. `entries` is [{ key, indexRec, userRec }].
export function planDeletion(entries) {
  const bad = entries.filter(e => typeof e.key !== 'string' || !e.key.startsWith(LEGACY_PREFIX));
  if (bad.length) return { ok: false, reason: 'a key outside the token: prefix was offered', toDelete: [] };
  const live = entries.filter(e => legacyIndexIsLive(e.key.slice(LEGACY_PREFIX.length), e.indexRec, e.userRec));
  if (live.length) return { ok: false, reason: `${live.length} entries still authenticate; rotate first`, toDelete: [] };
  if (entries.length > MAX_DELETE) return { ok: false, reason: `${entries.length} keys exceeds the ${MAX_DELETE} cap`, toDelete: [] };
  return { ok: true, reason: '', toDelete: entries.map(e => e.key) };
}

async function main() {
  const token = process.env.CLOUDFLARE_API_TOKEN;
  const account = process.env.CLOUDFLARE_ACCOUNT_ID;
  const ns = process.env.FL_KV_NAMESPACE_ID;
  if (process.env.FL_CONFIRM !== 'DELETE') {
    console.log('REFUSED — FL_CONFIRM is not DELETE. Nothing was deleted.');
    process.exit(1);
  }
  if (!token || !account || !ns) {
    console.log('UNOBSERVED — Cloudflare credential or namespace not supplied. Nothing was deleted.');
    process.exit(2);
  }
  const { api, headers, listKeys, getJson } = createKvReader({ token, account, ns });

  let entries;
  try {
    entries = [];
    for (const key of await listKeys(LEGACY_PREFIX)) {
      const indexRec = await getJson(key);
      const uid = indexRec && indexRec.userId;
      entries.push({ key, indexRec, userRec: uid ? await getJson('user:' + uid) : null });
    }
  } catch (e) {
    console.log(`UNOBSERVED — ${e.message}. Nothing was deleted.`);
    process.exit(2);
  }

  const plan = planDeletion(entries);
  console.log(`Legacy token: index keys found: ${entries.length}`);
  if (!plan.ok) {
    console.log(`REFUSED — ${plan.reason}. Nothing was deleted.`);
    process.exit(1);
  }
  let deleted = 0;
  for (const key of plan.toDelete) {
    const r = await fetch(`${api}/values/${encodeURIComponent(key)}`, { method: 'DELETE', headers });
    if (!r.ok) {
      console.log(`FAILED — delete returned HTTP ${r.status} after ${deleted} of ${plan.toDelete.length}.`);
      process.exit(1);
    }
    deleted++;
  }
  console.log(`Deleted ${deleted} dead legacy token: index entries.`);
  process.exit(0);
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) main();
