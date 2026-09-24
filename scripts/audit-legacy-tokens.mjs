#!/usr/bin/env node
// FreightLogic — legacy driver-token audit (read-only).
//
// Answers one question the 2026-09-23 direction left open: do any driver
// bearer tokens MINTED UNDER WORKER v7 still authenticate?
//
// Why it matters. v7 stored every driver token in KV in PLAINTEXT (P-01/P-02 in
// AUDIT_REPORT.md). v14 (deployed 2026-09-13T05:06:45Z) moved to hashed storage,
// but its cleanup is lazy: a v7 token is re-keyed only when it is next used, or
// retired only when it is rotated or re-claimed. A token that was merely
// migrated is still the same bytes that sat in plaintext, so it is still
// exposed-at-rest. The rule is "rotate only what is PROVEN still live" — this
// script is the proof, in either direction.
//
// Read-only. It lists and reads KV through the Cloudflare REST API and writes
// nothing. It NEVER prints a key name under `token:` (the key name IS the
// credential), never prints a record value, and never prints a token hash.
// It prints only counts and `userId`s, which are backup-key identifiers, not
// credentials, so the operator knows whom to rotate.
//
// Verdicts, the same three-outcome shape as the live-parity runner:
//   CLEAN       exit 0  no live credential minted before v14
//   FINDINGS    exit 1  at least one live pre-v14 credential; userIds printed
//   UNOBSERVED  exit 2  KV could not be read; NO claim in either direction
//
// Env: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, FL_KV_NAMESPACE_ID.

import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

// The moment v14 (hashed token storage) reached production. Every credential
// issued at or after this instant was issued by v14+ and never stored in
// plaintext. Recorded in CLAUDE.md's v24.0.6 section, run 34739479229.
export const V14_DEPLOYED_AT = '2026-09-13T05:06:45Z';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

// Classify one parsed `user:<id>` record. Pure, so it is unit-tested directly.
//   INACTIVE          revoked; authenticates nothing
//   LEGACY_PLAINTEXT  still carries a plaintext `token` — a v7 credential that
//                     has never even been used since v14
//   PRE_V14           issued before v14 and never rotated or re-claimed since
//   UNKNOWN_AGE       active, never rotated, no parseable createdAt — cannot be
//                     proven post-v14, so it is reported, never assumed clean
//   CURRENT           issued or re-issued by v14+
export function classifyUser(rec) {
  if (!rec || typeof rec !== 'object') return 'UNKNOWN_AGE';
  if (rec.active === false) return 'INACTIVE';
  if (typeof rec.token === 'string' && rec.token) return 'LEGACY_PLAINTEXT';
  const cutoff = Date.parse(V14_DEPLOYED_AT);
  const rotated = Date.parse(rec.rotatedAt || '');
  if (Number.isFinite(rotated) && rotated >= cutoff) return 'CURRENT';
  const created = Date.parse(rec.createdAt || '');
  if (!Number.isFinite(created)) return 'UNKNOWN_AGE';
  return created >= cutoff ? 'CURRENT' : 'PRE_V14';
}

// Would a legacy plaintext `token:<flk_…>` index entry still authenticate?
// Mirrors the Worker's rule: the USER record is the authority, so the entry is
// live only if that user is active and names this exact token's hash.
export function legacyIndexIsLive(tokenFromKey, indexRec, userRec) {
  if (!indexRec || !indexRec.userId || indexRec.active === false) return false;
  if (!userRec || userRec.active === false) return false;
  const canonical = userRec.tokenHash || (userRec.token ? sha256(userRec.token) : null);
  return !!canonical && canonical === sha256(tokenFromKey);
}

export function verdictFor(summary) {
  const live = summary.legacyPlaintext.length + summary.preV14.length
    + summary.unknownAge.length + summary.liveLegacyIndex;
  return live === 0 ? { verdict: 'CLEAN', code: 0 } : { verdict: 'FINDINGS', code: 1 };
}

// Read-only Cloudflare KV REST client, shared with the dead-residue cleanup so
// both scripts list and read keys the same way. It exposes no write method.
export function createKvReader({ token, account, ns }) {
  const api = `https://api.cloudflare.com/client/v4/accounts/${account}/storage/kv/namespaces/${ns}`;
  const headers = { Authorization: `Bearer ${token}` };
  async function listKeys(prefix) {
    const names = [];
    let cursor = '';
    do {
      const u = new URL(api + '/keys');
      u.searchParams.set('prefix', prefix);
      u.searchParams.set('limit', '1000');
      if (cursor) u.searchParams.set('cursor', cursor);
      const r = await fetch(u, { headers });
      if (!r.ok) throw new Error(`list ${prefix} → HTTP ${r.status}`);
      const body = await r.json();
      for (const k of body.result || []) names.push(k.name);
      cursor = body.result_info?.cursor || '';
    } while (cursor);
    return names;
  }
  async function getJson(key) {
    const r = await fetch(`${api}/values/${encodeURIComponent(key)}`, { headers });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`read → HTTP ${r.status}`);
    try { return JSON.parse(await r.text()); } catch { return undefined; }
  }
  return { api, headers, listKeys, getJson };
}

async function main() {
  const token = process.env.CLOUDFLARE_API_TOKEN;
  const account = process.env.CLOUDFLARE_ACCOUNT_ID;
  const ns = process.env.FL_KV_NAMESPACE_ID;
  if (!token || !account || !ns) {
    console.log('UNOBSERVED — Cloudflare credential or namespace not supplied. No claim is made.');
    console.log('VERDICT: UNOBSERVED');
    process.exit(2);
  }
  const { listKeys, getJson } = createKvReader({ token, account, ns });

  const summary = { users: 0, inactive: 0, current: 0, legacyPlaintext: [], preV14: [],
    unknownAge: [], legacyIndexKeys: 0, liveLegacyIndex: 0 };
  const userCache = new Map();
  try {
    for (const key of await listKeys('user:')) {
      // `user:<id>:device:…` backup keys share the prefix; only bare records count.
      if (key.split(':').length !== 2) continue;
      const rec = await getJson(key);
      const id = key.slice(5);
      userCache.set(id, rec);
      summary.users++;
      const c = classifyUser(rec);
      if (c === 'INACTIVE') summary.inactive++;
      else if (c === 'CURRENT') summary.current++;
      else if (c === 'LEGACY_PLAINTEXT') summary.legacyPlaintext.push(id);
      else if (c === 'PRE_V14') summary.preV14.push(id);
      else summary.unknownAge.push(id);
    }
    for (const key of await listKeys('token:')) {
      summary.legacyIndexKeys++;
      const indexRec = await getJson(key);
      const uid = indexRec && indexRec.userId;
      const userRec = uid ? (userCache.has(uid) ? userCache.get(uid) : await getJson('user:' + uid)) : null;
      if (legacyIndexIsLive(key.slice(6), indexRec, userRec)) summary.liveLegacyIndex++;
    }
  } catch (e) {
    console.log(`UNOBSERVED — ${e.message}. No claim is made.`);
    console.log('VERDICT: UNOBSERVED');
    process.exit(2);
  }

  const { verdict, code } = verdictFor(summary);
  console.log(`Driver accounts: ${summary.users} (inactive ${summary.inactive}, issued by v14+ ${summary.current})`);
  console.log(`Legacy plaintext token: index keys: ${summary.legacyIndexKeys} (still live: ${summary.liveLegacyIndex})`);
  const show = (label, ids) => console.log(`${label}: ${ids.length}${ids.length ? ' — ' + ids.join(', ') : ''}`);
  show('Active, plaintext v7 token still on the record', summary.legacyPlaintext);
  show(`Active, issued before v14 (${V14_DEPLOYED_AT}) and never rotated`, summary.preV14);
  show('Active, never rotated, issue time unknown', summary.unknownAge);
  if (code) console.log('Rotate each listed account in the Admin Console (Re-invite). Rotation is an operator action.');
  console.log(`VERDICT: ${verdict}`);
  process.exit(code);
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) main();
