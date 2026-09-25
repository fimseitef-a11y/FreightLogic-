// Worker v24 — Web Push + Shortcuts relay (docs/WEB_PUSH_CONTRACT.md,
// docs/SHORTCUTS_URL_CONTRACT.md §5).
//
// These drive the REAL exported fetch handler from cloud-backup-worker.js
// against an in-memory KV, with global fetch stubbed only at the push-service
// boundary. Nothing in the Worker is exported for testing: the encryption is
// verified from the outside, the way a browser would verify it.
//
// HOW THE CRYPTO IS PROVEN. The test carries its OWN RFC 8291 decryptor,
// written from the RFC's pseudocode with explicit HMAC steps (the Worker uses
// WebCrypto's HKDF), and WP-01 first proves that decryptor against the RFC's
// published Appendix A vector. Only then is it trusted to open what the
// Worker actually sends. A round-trip test in which the same code encrypts and
// decrypts would pass with both halves equally wrong.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const { test, run } = createSuite('unit/worker-web-push.spec.mjs');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ADMIN = 'test-admin-token-value';
const subtle = globalThis.crypto.subtle;

function makeKV(seed = {}) {
  const m = new Map(Object.entries(seed));
  const exp = new Map();
  const api = {
    _map: m,
    now: () => Date.now(),
    _live(k) {
      if (!m.has(k)) return false;
      const e = exp.get(k);
      if (e !== undefined && api.now() >= e) { m.delete(k); exp.delete(k); return false; }
      return true;
    },
    async get(k) { return api._live(k) ? m.get(k) : null; },
    async put(k, v, opts) {
      m.set(k, v);
      if (opts && opts.expirationTtl) exp.set(k, api.now() + opts.expirationTtl * 1000); else exp.delete(k);
    },
    async delete(k) { m.delete(k); exp.delete(k); },
    // The Worker must not depend on list() (1,000/day on the free tier). It is
    // counted so a test can prove the push/relay paths never call it.
    listCalls: 0,
    async list({ prefix = '' } = {}) {
      api.listCalls++;
      return { keys: [...m.keys()].filter(k => api._live(k) && k.startsWith(prefix)).map(name => ({ name })) };
    },
    dump() { return [...m.entries()].filter(([k]) => api._live(k)).map(([k, v]) => k + '=' + v).join('\n'); },
  };
  return api;
}

async function loadWorker() {
  const mod = await import(pathToFileURL(path.join(ROOT, 'cloud-backup-worker.js')).href);
  return mod.default;
}

const REQ = (url, opts = {}) => new Request('https://worker.test' + url, opts);

// ── base64url / bytes ─────────────────────────────────────────────────────────
const b64u = (bytes) => Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => new Uint8Array(Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
const utf8 = (s) => new TextEncoder().encode(s);
const cat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0); const o = new Uint8Array(n); let i = 0; for (const p of parts) { o.set(p, i); i += p.length; } return o; };

async function hmac(keyBytes, data) {
  const k = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}

/** RFC 8291 §3.4, receiver side, written from the pseudocode. */
async function rfc8291Decrypt(body, uaPrivJwk, uaPublic, authSecret) {
  const salt = body.slice(0, 16);
  const rs = new DataView(body.buffer, body.byteOffset + 16, 4).getUint32(0);
  const idlen = body[20];
  const keyid = body.slice(21, 21 + idlen);
  const ct = body.slice(21 + idlen);
  const asPub = await subtle.importKey('raw', keyid, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const uaPriv = await subtle.importKey('jwk', uaPrivJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const ecdh = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: asPub }, uaPriv, 256));
  const prkKey = await hmac(authSecret, ecdh);
  const keyInfo = cat(utf8('WebPush: info'), new Uint8Array([0]), uaPublic, keyid);
  const ikm = await hmac(prkKey, cat(keyInfo, new Uint8Array([1])));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, cat(utf8('Content-Encoding: aes128gcm'), new Uint8Array([0, 1])))).slice(0, 16);
  const nonce = (await hmac(prk, cat(utf8('Content-Encoding: nonce'), new Uint8Array([0, 1])))).slice(0, 12);
  const key = await subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']);
  const pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, ct));
  let end = pt.length - 1;
  while (end >= 0 && pt[end] === 0) end--;
  if (end < 0 || pt[end] !== 2) throw new Error('padding delimiter is not 0x02');
  return { plaintext: pt.slice(0, end), rs, keyid };
}

function jwkFromRaw(d, pub) {
  return { kty: 'EC', crv: 'P-256', d, x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)), ext: true };
}

/** A fresh user-agent subscription: what PushManager.subscribe() would hand the app. */
async function makeUA(endpoint = 'https://web.push.apple.com/QGZ7' + Math.random().toString(36).slice(2)) {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const jwk = await subtle.exportKey('jwk', kp.privateKey);
  const auth = globalThis.crypto.getRandomValues(new Uint8Array(16));
  return { endpoint, pub, jwk, auth, subscription: { endpoint, keys: { p256dh: b64u(pub), auth: b64u(auth) } } };
}

/** Capture push-service POSTs; answer with `status` (or a function of the URL). */
function stubPushService(status = 201) {
  const real = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    const body = init.body ? new Uint8Array(await new Response(init.body).arrayBuffer()) : new Uint8Array();
    const headers = new Headers(init.headers || {});
    calls.push({ url: u, headers, body });
    const s = typeof status === 'function' ? status(u) : status;
    return new Response(null, { status: s });
  };
  return { calls, restore() { globalThis.fetch = real; } };
}

async function seedDriver(worker, env, name = 'Push Driver', ip = '203.0.113.21') {
  const inv = await (await worker.fetch(REQ('/admin/invites', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Admin-Token': ADMIN },
    body: JSON.stringify({ name }),
  }), env)).json();
  const claimed = await (await worker.fetch(REQ('/claim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
    body: JSON.stringify({ code: inv.code }),
  }), env)).json();
  return { token: claimed.token, userId: claimed.userId };
}

const driverHdrs = (token, device = 'dev_push1') => ({ 'Content-Type': 'application/json', 'X-Backup-Token': token, 'X-Device-Id': device });

async function subscribe(worker, env, token, ua, device) {
  const key = await (await worker.fetch(REQ('/push/key'), env)).json();
  return worker.fetch(REQ('/push/subscribe', {
    method: 'POST', headers: driverHdrs(token, device),
    body: JSON.stringify({ subscription: ua.subscription, publicKey: key.publicKey }),
  }), env);
}

async function mintShortcutKey(worker, env, token) {
  const res = await worker.fetch(REQ('/shortcut-key', { method: 'POST', headers: driverHdrs(token) }), env);
  return { res, body: await res.json() };
}

const relayReq = (key, payload, extra = {}) => REQ('/relay', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.4', ...(key ? { 'X-Shortcut-Key': key } : {}), ...extra },
  body: typeof payload === 'string' ? payload : JSON.stringify(payload),
});

const newEnv = () => ({ BACKUPS: makeKV(), ADMIN_TOKEN: ADMIN });

// ── RFC 8291 Appendix A ──────────────────────────────────────────────────────
const RFC = {
  plaintext: 'When I grow up, I want to be a watermelon',
  auth: 'BTBZMqHH6r4Tts7J_aSIgg',
  uaPrivate: 'q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94',
  uaPublic: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
  asPublic: 'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
  body: 'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN',
};

test('[WP-01] the reference decryptor opens RFC 8291 Appendix A exactly', async () => {
  const uaPub = unb64u(RFC.uaPublic);
  const out = await rfc8291Decrypt(unb64u(RFC.body), jwkFromRaw(RFC.uaPrivate, uaPub), uaPub, unb64u(RFC.auth));
  eq(new TextDecoder().decode(out.plaintext), RFC.plaintext, 'decryptor does not reproduce the RFC plaintext');
  eq(out.rs, 4096, 'record size');
  eq(b64u(out.keyid), RFC.asPublic, 'keyid must be the application server public key');
});

test('[WP-02] GET /push/key is public, a real P-256 point, and stable once provisioned', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const r1 = await worker.fetch(REQ('/push/key'), env);
  eq(r1.status, 200, `expected 200, got ${r1.status}`);
  const k1 = (await r1.json()).publicKey;
  const raw = unb64u(k1);
  eq(raw.length, 65, 'uncompressed P-256 point is 65 bytes'); eq(raw[0], 4, 'uncompressed point starts 0x04');
  await subtle.importKey('raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const k2 = (await (await worker.fetch(REQ('/push/key'), env)).json()).publicKey;
  eq(k2, k1, 'the self-provisioned key must not change between calls');
  ok(env.BACKUPS.dump().includes('push:vapid='), 'self-provisioned key is persisted in KV');
});

test('[WP-03] operator VAPID secrets take precedence over the self-provisioned key', async () => {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pub = b64u(new Uint8Array(await subtle.exportKey('raw', kp.publicKey)));
  const env = { ...newEnv(), VAPID_PUBLIC_KEY: pub, VAPID_PRIVATE_JWK: JSON.stringify(await subtle.exportKey('jwk', kp.privateKey)) };
  const worker = await loadWorker();
  const k = (await (await worker.fetch(REQ('/push/key'), env)).json()).publicKey;
  eq(k, pub, 'configured VAPID_PUBLIC_KEY must be served');
  ok(!env.BACKUPS.dump().includes('push:vapid='), 'no key is generated when secrets are configured');
});

test('[WP-04] push subscription and test routes require a driver token', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const ua = await makeUA();
  for (const [method, p] of [['POST', '/push/subscribe'], ['DELETE', '/push/subscribe'], ['POST', '/push/test'],
    ['GET', '/shortcut-key'], ['POST', '/shortcut-key'], ['DELETE', '/shortcut-key'], ['GET', '/relay'], ['DELETE', '/relay/rl_abc123']]) {
    const res = await worker.fetch(REQ(p, { method, headers: { 'Content-Type': 'application/json' },
      body: method === 'GET' ? undefined : JSON.stringify({ subscription: ua.subscription }) }), env);
    ok(res.status === 401 || res.status === 403, `${method} ${p} without a token must be refused, got ${res.status}`);
  }
  ok(!env.BACKUPS.dump().includes('push:subs:'), 'nothing may be stored by an unauthenticated request');
});

test('[WP-05] subscribe refuses non-push-service endpoints and malformed keys (SSRF + curve checks)', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const { token } = await seedDriver(worker, env);
  const good = await makeUA();
  const bad = [
    ['http scheme', { ...good.subscription, endpoint: 'http://web.push.apple.com/x' }],
    ['arbitrary host', { ...good.subscription, endpoint: 'https://evil.example/collect' }],
    ['look-alike suffix', { ...good.subscription, endpoint: 'https://web.push.apple.com.evil.example/x' }],
    ['internal host', { ...good.subscription, endpoint: 'https://127.0.0.1/x' }],
    ['credentials in URL', { ...good.subscription, endpoint: 'https://user:pw@web.push.apple.com/x' }],
    ['short p256dh', { ...good.subscription, keys: { ...good.subscription.keys, p256dh: b64u(good.pub.slice(0, 33)) } }],
    ['off-curve p256dh', { ...good.subscription, keys: { ...good.subscription.keys, p256dh: b64u(cat(new Uint8Array([4]), new Uint8Array(64).fill(7))) } }],
    ['auth wrong length', { ...good.subscription, keys: { ...good.subscription.keys, auth: b64u(new Uint8Array(8)) } }],
  ];
  for (const [label, sub] of bad) {
    const res = await worker.fetch(REQ('/push/subscribe', { method: 'POST', headers: driverHdrs(token), body: JSON.stringify({ subscription: sub }) }), env);
    eq(res.status, 400, `${label} must be refused with 400, got ${res.status}`);
  }
  ok(!env.BACKUPS.dump().includes('push:subs:'), 'no refused subscription may be stored');
});

test('[WP-06] subscriptions are per driver, deduplicated by endpoint, capped at 5, and never listed', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const { token, userId } = await seedDriver(worker, env);
  const uas = [];
  for (let i = 0; i < 7; i++) {
    const ua = await makeUA(`https://web.push.apple.com/dev${i}`);
    uas.push(ua);
    env.BACKUPS.now = () => Date.now() + i * 1000;
    eq((await subscribe(worker, env, token, ua, 'dev_' + i)).status, 200, `subscribe ${i}`);
  }
  eq((await subscribe(worker, env, token, uas[6], 'dev_6')).status, 200, 're-subscribe');
  const stored = JSON.parse(await env.BACKUPS.get('push:subs:' + userId));
  eq(stored.length, 5, `expected the 5 newest subscriptions, got ${stored.length}`);
  const endpoints = stored.map(s => s.endpoint);
  ok(!endpoints.includes(uas[0].endpoint) && !endpoints.includes(uas[1].endpoint), 'the two oldest must be evicted');
  eq(new Set(endpoints).size, 5, 're-subscribing the same endpoint must not duplicate it');
  eq(env.BACKUPS.listCalls, 0, 'push routes must not call KV list() (free-tier budget)');
});

test('[WP-07] a test push is aes128gcm-encrypted to the subscription and VAPID-signed (RFC 8291/8292)', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const { token } = await seedDriver(worker, env);
  const ua = await makeUA('https://web.push.apple.com/QGZ-test-endpoint');
  await subscribe(worker, env, token, ua);
  const vapidPub = (await (await worker.fetch(REQ('/push/key'), env)).json()).publicKey;
  const svc = stubPushService(201);
  let res; try { res = await worker.fetch(REQ('/push/test', { method: 'POST', headers: driverHdrs(token) }), env); }
  finally { svc.restore(); }
  eq(res.status, 200, `expected 200, got ${res.status}`);
  const out = await res.json();
  eq(out.sent, 1, 'one device must be notified');
  eq(svc.calls.length, 1, 'exactly one push-service request');
  const call = svc.calls[0];
  eq(call.url, ua.endpoint, 'posted to the subscription endpoint');
  eq(call.headers.get('content-encoding'), 'aes128gcm', 'Content-Encoding');
  ok(Number(call.headers.get('ttl')) > 0, 'TTL header required');
  ok(['normal', 'high', 'low', 'very-low'].includes(call.headers.get('urgency')), 'Urgency header');

  const dec = await rfc8291Decrypt(call.body, ua.jwk, ua.pub, ua.auth);
  const payload = JSON.parse(new TextDecoder().decode(dec.plaintext));
  ok(typeof payload.title === 'string' && payload.title.length > 0, 'decrypted payload carries a title');
  ok(/working/i.test(payload.body), `test notification body, got ${JSON.stringify(payload.body)}`);
  ok(!/[\u0000-\u001f]/.test(payload.body), 'no control characters');
  ok(call.body.length <= 4096, 'push bodies must fit the 4096-octet push-service minimum');

  const m = /^vapid t=([^,\s]+),\s*k=([A-Za-z0-9_-]+)$/.exec(call.headers.get('authorization') || '');
  ok(m, `Authorization must be "vapid t=…, k=…", got ${call.headers.get('authorization')}`);
  eq(m[2], vapidPub, 'k must be the served VAPID public key');
  const [h, c, s] = m[1].split('.');
  const header = JSON.parse(Buffer.from(h, 'base64').toString());
  const claims = JSON.parse(Buffer.from(c, 'base64').toString());
  eq(header.alg, 'ES256', 'alg'); eq(claims.aud, 'https://web.push.apple.com', 'aud is the endpoint origin');
  const now = Math.floor(Date.now() / 1000);
  ok(claims.exp > now && claims.exp <= now + 24 * 3600, 'exp within 24h (RFC 8292)');
  ok(/^(mailto:|https:\/\/)/.test(claims.sub || ''), 'sub is a mailto: or https: contact');
  const verifyKey = await subtle.importKey('raw', unb64u(m[2]), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  ok(await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, verifyKey, unb64u(s), utf8(h + '.' + c)), 'ES256 signature must verify');
});

test('[WP-08] 404/410 from the push service deletes the subscription; other failures keep it', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const { token, userId } = await seedDriver(worker, env);
  const gone = await makeUA('https://web.push.apple.com/gone');
  const flaky = await makeUA('https://fcm.googleapis.com/fcm/send/flaky');
  await subscribe(worker, env, token, gone, 'dev_a');
  await subscribe(worker, env, token, flaky, 'dev_b');
  const svc = stubPushService(u => u.includes('/gone') ? 410 : 503);
  let out; try { out = await (await worker.fetch(REQ('/push/test', { method: 'POST', headers: driverHdrs(token) }), env)).json(); }
  finally { svc.restore(); }
  eq(out.removed, 1, 'the 410 subscription is removed'); eq(out.failed, 1, 'the 503 is counted as failed');
  const stored = JSON.parse(await env.BACKUPS.get('push:subs:' + userId));
  eq(stored.map(s => s.endpoint).join(','), flaky.endpoint, 'only the transiently failing subscription survives');
});

test('[WP-09] Shortcut keys: shown once, stored only as a hash, rotation and revoke both kill the old key', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const { token } = await seedDriver(worker, env);
  const first = await mintShortcutKey(worker, env, token);
  eq(first.res.status, 201, `mint → 201, got ${first.res.status}`);
  ok(/^fls_[a-f0-9]{48}$/.test(first.body.key), `key shape, got ${first.body.key}`);
  ok(!env.BACKUPS.dump().includes(first.body.key), 'the plaintext key must never be stored');
  const status = await (await worker.fetch(REQ('/shortcut-key', { headers: driverHdrs(token) }), env)).json();
  eq(status.exists, true, 'GET reports a key exists'); ok(!JSON.stringify(status).includes('fls_'), 'GET never returns the key');

  const okRelay = await worker.fetch(relayReq(first.body.key, { do: 'expense', params: { amount: '12.50' } }), env);
  eq(okRelay.status, 200, `first key works, got ${okRelay.status}`);

  const second = await mintShortcutKey(worker, env, token);
  ok(second.body.key && second.body.key !== first.body.key, 'rotation mints a different key');
  eq((await worker.fetch(relayReq(first.body.key, { do: 'expense', params: { amount: '1' } }), env)).status, 401, 'rotated-out key must be dead');
  eq((await worker.fetch(relayReq(second.body.key, { do: 'expense', params: { amount: '1' } }), env)).status, 200, 'new key works');

  eq((await worker.fetch(REQ('/shortcut-key', { method: 'DELETE', headers: driverHdrs(token) }), env)).status, 200, 'revoke');
  eq((await worker.fetch(relayReq(second.body.key, { do: 'expense', params: { amount: '1' } }), env)).status, 401, 'revoked key must be dead');
});

test('[WP-10] /relay validates the action against the URL contract before storing anything', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const { token, userId } = await seedDriver(worker, env);
  const { body: { key } } = await mintShortcutKey(worker, env, token);

  eq((await worker.fetch(relayReq(null, { do: 'expense', params: { amount: '5' } }), env)).status, 401, 'no key → 401');
  eq((await worker.fetch(relayReq('fls_' + 'a'.repeat(48), { do: 'expense', params: { amount: '5' } }), env)).status, 401, 'unknown key → 401');
  eq((await worker.fetch(relayReq(key, { do: 'delete-everything', params: {} }), env)).status, 400, 'unknown action → 400');
  eq((await worker.fetch(relayReq(key, { do: 'relay', params: { id: 'rl_x' } }), env)).status, 400, 'reserved relay action → 400');
  eq((await worker.fetch(relayReq(key, { do: 'expense', params: { amount: '5', token: 'flk_x' } }), env)).status, 400, 'credential-shaped param → 400');
  eq((await worker.fetch(relayReq(key, { do: 'intake', params: {} }), env)).status, 400, 'intake without text → 400');
  eq((await worker.fetch(relayReq(key, { do: 'intake', params: { text: 'x'.repeat(17000) } }), env)).status, 413, 'oversized body → 413');
  eq((await worker.fetch(relayReq(key, 'not json'), env)).status, 400, 'malformed JSON → 400');
  ok(!env.BACKUPS.dump().includes('relay:' + userId), 'nothing is stored for a refused relay');

  const res = await worker.fetch(relayReq(key, { do: 'evaluate', params: {
    revenue: '$1,450.00', loaded: 612, deadhead: '0', origin: '  Columbus, OH ', dest: 'Atlanta, GA',
    weight: '99999', surprise: 'ignored', pickup: '2026-13-40T99:00' } }), env);
  eq(res.status, 200, `valid evaluate → 200, got ${res.status}`);
  const out = await res.json();
  ok(/^rl_[0-9a-z]+$/.test(out.id), `relay id shape, got ${out.id}`);
  ok(Array.isArray(out.dropped) && out.dropped.includes('weight') && out.dropped.includes('pickup'), `out-of-range values are reported as dropped, got ${JSON.stringify(out.dropped)}`);
  const items = JSON.parse(await env.BACKUPS.get('relay:' + userId));
  const p = items[0].params;
  eq(p.revenue, 1450, 'money parsed from "$1,450.00"'); eq(p.loaded, 612, 'loaded');
  eq(p.deadhead, 0, 'an explicit deadhead of 0 is a verified zero and must survive');
  eq(p.origin, 'Columbus, OH', 'places are trimmed');
  ok(!('weight' in p) && !('pickup' in p) && !('surprise' in p), 'dropped and unknown params are not stored');

  const noDh = await (await worker.fetch(relayReq(key, { do: 'evaluate', params: { revenue: 900, loaded: 400 } }), env)).json();
  const again = JSON.parse(await env.BACKUPS.get('relay:' + userId)).find(i => i.id === noDh.id);
  ok(!('deadhead' in again.params), 'an absent deadhead stays absent (UNKNOWN), never 0');

  const multi = await (await worker.fetch(relayReq(key, { do: 'intake', params: { text: 'Pickup: Columbus, OH\r\nDeliver: Atlanta, GA\u0007\nRate: $1,450' } }), env)).json();
  const intake = JSON.parse(await env.BACKUPS.get('relay:' + userId)).find(i => i.id === multi.id);
  eq(intake.params.text, 'Pickup: Columbus, OH\nDeliver: Atlanta, GA\nRate: $1,450',
    'intake text keeps its line breaks (the parser reads line by line) and loses other control characters');
});

test('[WP-11] a relay notification carries a server-built summary and a relay link, never the parameters', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const { token } = await seedDriver(worker, env);
  const ua = await makeUA();
  await subscribe(worker, env, token, ua);
  const { body: { key } } = await mintShortcutKey(worker, env, token);
  const secretText = 'Broker ACME order 7781 pay 1450 Columbus OH to Atlanta GA';
  const svc = stubPushService(201);
  let out; try { out = await (await worker.fetch(relayReq(key, { do: 'intake', params: { text: secretText } }), env)).json(); }
  finally { svc.restore(); }
  eq(out.pushed, 1, 'one device notified');
  const payload = JSON.parse(new TextDecoder().decode((await rfc8291Decrypt(svc.calls[0].body, ua.jwk, ua.pub, ua.auth)).plaintext));
  eq(payload.url, './#do=relay&id=' + out.id, 'the notification opens the relay link');
  ok(!JSON.stringify(payload).includes('ACME') && !JSON.stringify(payload).includes('7781'), 'load text must not ride in the push payload');
  eq(svc.calls[0].headers.get('urgency'), 'high', 'relay pushes are high urgency');

  const ex = stubPushService(201);
  try { await worker.fetch(relayReq(key, { do: 'expense', params: { amount: '45.1', category: 'Tolls\u0007<b>' } }), env); }
  finally { ex.restore(); }
  const exp = JSON.parse(new TextDecoder().decode((await rfc8291Decrypt(ex.calls[0].body, ua.jwk, ua.pub, ua.auth)).plaintext));
  ok(exp.body.includes('$45.10'), `expense summary shows the amount, got ${exp.body}`);
  ok(!/[\u0000-\u001f]/.test(exp.body), 'control characters are stripped from the summary');
});

test('[WP-12] GET/DELETE /relay are per driver, oldest first, capped at 20, and expire after 72h', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const a = await seedDriver(worker, env, 'Driver A', '203.0.113.31');
  const b = await seedDriver(worker, env, 'Driver B', '203.0.113.32');
  const { body: { key } } = await mintShortcutKey(worker, env, a.token);
  const t0 = Date.now();
  const realNow = Date.now;
  try {
    for (let i = 0; i < 22; i++) {
      Date.now = () => t0 + i * 1000;
      eq((await worker.fetch(relayReq(key, { do: 'expense', params: { amount: String(i + 1) } }), env)).status, 200, `relay ${i}`);
    }
  } finally { Date.now = realNow; }
  const listA = await (await worker.fetch(REQ('/relay', { headers: driverHdrs(a.token) }), env)).json();
  eq(listA.items.length, 20, `cap 20, got ${listA.items.length}`);
  eq(listA.items[0].params.amount, 3, 'oldest-first after the two oldest were evicted');
  const listB = await (await worker.fetch(REQ('/relay', { headers: driverHdrs(b.token) }), env)).json();
  eq(listB.items.length, 0, "another driver must not see A's relay items");

  eq((await worker.fetch(REQ('/relay/' + listA.items[0].id, { method: 'DELETE', headers: driverHdrs(b.token) }), env)).status, 200, 'B deleting A\'s id is a no-op, not an error');
  eq((await (await worker.fetch(REQ('/relay', { headers: driverHdrs(a.token) }), env)).json()).items.length, 20, "B cannot delete A's item");
  eq((await worker.fetch(REQ('/relay/' + listA.items[0].id, { method: 'DELETE', headers: driverHdrs(a.token) }), env)).status, 200, 'A deletes its own');
  eq((await (await worker.fetch(REQ('/relay', { headers: driverHdrs(a.token) }), env)).json()).items.length, 19, 'consumed item is gone');
  eq((await worker.fetch(REQ('/relay/..%2Fuser', { method: 'DELETE', headers: driverHdrs(a.token) }), env)).status, 400, 'malformed relay id → 400');

  const later = Date.now;
  try {
    Date.now = () => t0 + 73 * 3600 * 1000;
    const expired = await (await worker.fetch(REQ('/relay', { headers: driverHdrs(a.token) }), env)).json();
    eq(expired.items.length, 0, 'items older than 72h are not served');
  } finally { Date.now = later; }
  eq(env.BACKUPS.listCalls, 0, 'relay routes must not call KV list()');
});

test('[WP-13] revoking the driver kills their Shortcut key', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const { token, userId } = await seedDriver(worker, env);
  const { body: { key } } = await mintShortcutKey(worker, env, token);
  eq((await worker.fetch(REQ('/admin/users/' + userId, { method: 'DELETE', headers: { 'X-Admin-Token': ADMIN } }), env)).status, 200, 'revoke driver');
  eq((await worker.fetch(relayReq(key, { do: 'expense', params: { amount: '5' } }), env)).status, 401, 'a revoked driver\'s key must not relay');
});

test('[WP-14] the Worker and the app enforce the SAME relay action contract', async () => {
  // Two transcriptions of one rule is how the X-07 restore gap and the
  // 2026-09-13 asset defect both happened. The contract block is byte-compared.
  const grab = (file) => {
    const src = readFileSync(path.join(ROOT, file), 'utf8');
    const m = /\/\/ @contract:relay-actions:begin\n([\s\S]*?)\/\/ @contract:relay-actions:end/.exec(src);
    ok(m, `${file} must carry the @contract:relay-actions block`);
    return m[1].replace(/\s+/g, ' ').trim();
  };
  const w = grab('cloud-backup-worker.js');
  const a = grab('app.js');
  eq(a, w, 'app.js and cloud-backup-worker.js disagree about the relay action contract');
  for (const action of ['evaluate', 'intake', 'trip', 'expense', 'fuel']) ok(w.includes(action + ':'), `contract names ${action}`);
});

// v27: re-running a Shortcut over screenshots already sent must not pile up
// duplicate relay items or notifications.
test('[WP-16] an exact repeat of a relay item is not stored or pushed again', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const a = await seedDriver(worker, env, 'Dup Driver', '203.0.113.41');
  const { body: { key } } = await mintShortcutKey(worker, env, a.token);
  const text = 'Load ID: 1214704\nPickup: Mobile, AL\nDelivery: Pascagoula, MS\nLoaded Miles: 380';
  const first = await (await worker.fetch(relayReq(key, { do: 'intake', params: { text } }), env)).json();
  eq(first.ok, true, 'first send accepted');
  ok(!first.duplicate, 'first send is not a duplicate');
  const again = await (await worker.fetch(relayReq(key, { do: 'intake', params: { text } }), env)).json();
  eq(again.ok, true, 'a repeat is not an error');
  eq(again.duplicate, true, 'a repeat says duplicate');
  eq(again.id, first.id, 'and names the first item');
  eq(again.pushed, 0, 'and sends no second notification');
  eq(again.waiting, true, 'the first item is still waiting');
  const list = await (await worker.fetch(REQ('/relay', { headers: driverHdrs(a.token) }), env)).json();
  eq(list.items.length, 1, `one stored item, got ${list.items.length}`);
  const other = await (await worker.fetch(relayReq(key, { do: 'intake', params: { text: text + '\nEmpty Miles: 44' } }), env)).json();
  ok(!other.duplicate && other.id !== first.id, 'a different screenshot is a new item');
  ok(!env.BACKUPS.dump().includes('Pascagoula') || JSON.parse(await env.BACKUPS.get('relayseen:' + a.userId)).every(e => !('params' in e)),
    'the repeat record holds a fingerprint, never the parameters');
  eq(env.BACKUPS.listCalls, 0, 'no KV list()');
});

test('[WP-17] a repeat is still skipped after the app consumed the first; after 14 days it is new', async () => {
  const env = newEnv(); const worker = await loadWorker();
  const a = await seedDriver(worker, env, 'Dup Driver 2', '203.0.113.42');
  const { body: { key } } = await mintShortcutKey(worker, env, a.token);
  const item = { do: 'expense', params: { amount: '42.10', category: 'Tolls' } };
  const first = await (await worker.fetch(relayReq(key, item), env)).json();
  eq((await worker.fetch(REQ('/relay/' + first.id, { method: 'DELETE', headers: driverHdrs(a.token) }), env)).status, 200, 'app consumes it');
  const again = await (await worker.fetch(relayReq(key, item), env)).json();
  eq(again.duplicate, true, 'still a duplicate after it was consumed');
  eq(again.waiting, false, 'and says it is no longer waiting');
  eq((await (await worker.fetch(REQ('/relay', { headers: driverHdrs(a.token) }), env)).json()).items.length, 0, 'nothing re-stored');
  const realNow = Date.now;
  try {
    Date.now = () => realNow() + 15 * 24 * 3600 * 1000;
    const later = await (await worker.fetch(relayReq(key, item), env)).json();
    ok(later.ok && !later.duplicate, 'after the 14-day window the same item is accepted again');
  } finally { Date.now = realNow; }
});

test('[WP-15] /health reports a Worker generation that carries Web Push (v24+)', async () => {
  // Pinned exactly at '24' until Worker v25; CG-09 already asserts header,
  // /health and the parity pin agree, so this only needs the Web Push floor.
  const env = newEnv(); const worker = await loadWorker();
  const body = await (await worker.fetch(REQ('/health'), env)).json();
  ok(Number(body.version) >= 24, `expected version >= 24, got ${body.version}`);
});

export async function runSpec() {
  return await run();
}
