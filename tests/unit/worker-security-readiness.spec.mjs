import { createSuite, ok, eq } from '../lib/harness.mjs';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const { test, run } = createSuite('unit/worker-security-readiness.spec.mjs');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ADMIN = 'test-admin-token-value';
const USER = 'u_12345678abcdef';
const TOKEN = 'flk_' + 'a'.repeat(32);

async function loadMod() {
  return await import(pathToFileURL(path.join(ROOT, 'cloud-backup-worker.js')).href + '?sec=' + Date.now());
}
async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function makeKV(seed = {}) {
  const m = new Map(Object.entries(seed));
  const api = {
    _map: m,
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
    async list({ prefix = '' } = {}) {
      return { keys: [...m.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })), list_complete: true };
    },
    keys() { return [...m.keys()]; },
    dump() { return [...m.entries()].map(([k,v]) => k + '=' + v).join('\n'); },
  };
  return api;
}
const req = (url, opts={}) => new Request('https://worker.test' + url, opts);

test('[SR-01] bounded reader rejects true bytes without trusting Content-Length', async () => {
  const { readBodyTextBounded } = await loadMod();
  const r = await readBodyTextBounded(new Request('https://x.test', {
    method:'POST', body:'x'.repeat(4097), headers:{'Content-Type':'text/plain'}
  }), 4096);
  eq(r.ok, false, 'oversized streamed body must fail');
  eq(r.status, 413, 'oversized streamed body must be 413');
});

test('[SR-02] bounded JSON reader accepts valid in-limit JSON', async () => {
  const { readJsonBounded } = await loadMod();
  const r = await readJsonBounded(new Request('https://x.test', {
    method:'POST', body:JSON.stringify({hello:'world'}), headers:{'Content-Type':'application/json'}
  }), 1024);
  eq(r.ok, true, 'small JSON must pass');
  eq(r.value.hello, 'world', 'JSON body must parse');
});

test('[SR-03] Durable Object counter allows exactly N requests under concurrency', async () => {
  const { RateLimitCounter } = await loadMod();
  const map = new Map();
  let tail = Promise.resolve();
  const storage = {
    transaction(fn) {
      const work = tail.then(() => fn({
        get: async k => map.get(k),
        put: async (k,v) => { map.set(k,v); },
      }));
      tail = work.then(()=>{}, ()=>{});
      return work;
    }
  };
  const obj = new RateLimitCounter({ storage }, {});
  const calls = await Promise.all(Array.from({length:20}, () => obj.fetch(new Request('https://rate.test/check', {
    method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({limit:7,windowMs:3600000})
  })).then(r=>r.json())));
  eq(calls.filter(x => !x.limited).length, 7, 'exactly seven requests must pass');
  eq(calls.filter(x => x.limited).length, 13, 'all requests after the limit must be denied');
});

test('[SR-04] legacy driver credential receives migration grace instead of instant lockout', async () => {
  const { enforceDriverCredentialLifetime } = await loadMod();
  const hash = await sha256Hex(TOKEN);
  const rec = { userId:USER, name:'Driver', tokenHash:hash, active:true, createdAt:'2026-01-01T00:00:00.000Z' };
  const kv = makeKV({ ['user:'+USER]:JSON.stringify(rec), ['tokh:'+hash]:JSON.stringify(rec) });
  const out = await enforceDriverCredentialLifetime({ BACKUPS:kv }, rec, hash, Date.parse('2026-09-29T00:00:00Z'));
  eq(out.ok, true, 'existing token must not be invalidated on v31 rollout');
  ok(out.user.credentialIssuedAt, 'migration must stamp credential issue time');
  ok(out.user.credentialExpiresAt, 'migration must stamp finite absolute expiry');
  ok(!Object.prototype.hasOwnProperty.call(out.user, 'token'), 'migration must not retain a legacy plaintext token field');
});

test('[SR-05] expired driver credential is denied and its presented token index is retired', async () => {
  const { enforceDriverCredentialLifetime } = await loadMod();
  const hash = await sha256Hex(TOKEN);
  const rec = {
    userId:USER, name:'Driver', tokenHash:hash, active:true,
    credentialIssuedAt:'2025-01-01T00:00:00.000Z',
    credentialLastSeenAt:'2026-01-01T00:00:00.000Z',
    credentialExpiresAt:'2026-01-02T00:00:00.000Z',
  };
  const kv = makeKV({ ['user:'+USER]:JSON.stringify(rec), ['tokh:'+hash]:JSON.stringify(rec) });
  const out = await enforceDriverCredentialLifetime({ BACKUPS:kv }, rec, hash, Date.parse('2026-09-29T00:00:00Z'));
  eq(out.ok, false, 'expired credential must fail');
  ok(!kv.keys().includes('tokh:'+hash), 'expired token index must be removed');
  ok(kv.keys().includes('user:'+USER), 'stable account identity must remain for re-invite');
});

test('[SR-06] admin credential lifetime is finite and an expired operator secret is refused', async () => {
  const mod = await loadMod();
  const worker = mod.default;
  const hash = await sha256Hex(ADMIN);
  const expired = { version:1, firstSeenAt:'2026-01-01T00:00:00Z', lastSeenAt:'2026-01-01T00:00:00Z', expiresAt:'2026-01-02T00:00:00Z' };
  const kv = makeKV({ ['admincred:'+hash]:JSON.stringify(expired) });
  const res = await worker.fetch(req('/admin/users', { headers:{'X-Admin-Token':ADMIN,'CF-Connecting-IP':'203.0.113.20'} }), { BACKUPS:kv, ADMIN_TOKEN:ADMIN });
  eq(res.status, 401, 'expired operator credential window must require ADMIN_TOKEN rotation');
});

test('[SR-07] permanent erase requires revoked state plus exact explicit confirmation', async () => {
  const worker = (await loadMod()).default;
  const hash = await sha256Hex(TOKEN);
  const active = { userId:USER, name:'Driver', tokenHash:hash, active:true, createdAt:'2026-01-01T00:00:00Z' };
  const kv = makeKV({ ['user:'+USER]:JSON.stringify(active), ['tokh:'+hash]:JSON.stringify(active) });
  const env = { BACKUPS:kv, ADMIN_TOKEN:ADMIN };
  const headers = {'X-Admin-Token':ADMIN,'CF-Connecting-IP':'203.0.113.21','Content-Type':'application/json'};
  let res = await worker.fetch(req('/admin/users/'+USER+'/erase', {method:'POST',headers,body:JSON.stringify({confirm:'ERASE',userId:USER})}), env);
  eq(res.status, 409, 'active account must be revoked before erasure');
  active.active=false; kv._map.set('user:'+USER, JSON.stringify(active));
  res = await worker.fetch(req('/admin/users/'+USER+'/erase', {method:'POST',headers,body:JSON.stringify({confirm:'NO',userId:USER})}), env);
  eq(res.status, 400, 'wrong confirmation must fail');
  ok(kv.keys().includes('user:'+USER), 'failed confirmation must not delete data');
});

test('[SR-08] permanent erase deletes one account fully without touching another account or global keys', async () => {
  const worker = (await loadMod()).default;
  const hash = await sha256Hex(TOKEN);
  const staleToken = 'flk_' + 'b'.repeat(32);
  const staleHash = await sha256Hex(staleToken);
  const rec = { userId:USER, name:'Private Name', tokenHash:hash, active:false, createdAt:'2026-01-01T00:00:00Z' };
  const other='u_fedcba9876543210';
  const kv = makeKV({
    ['user:'+USER]:JSON.stringify(rec),
    ['tokh:'+hash]:JSON.stringify(rec),
    ['tokh:'+staleHash]:JSON.stringify({...rec,tokenHash:staleHash}),
    ['user:'+USER+':device:d1:backup:one']:'ciphertext',
    ['user:'+USER+':device:d1:bptr']:JSON.stringify({keys:[],count:0}),
    ['push:subs:'+USER]:'[]',
    ['relay:'+USER]:'[]',
    ['relayseen:'+USER]:'[]',
    ['rem:'+USER]:'[]',
    ['rem:index']:JSON.stringify([USER,other]),
    ['sckuser:'+USER]:JSON.stringify({hash:'shortcutHash'}),
    ['sck:shortcutHash']:JSON.stringify({userId:USER}),
    ['inv:bound']:JSON.stringify({userId:USER}),
    ['rl:eval:'+USER+':123']:'5',
    ['user:'+other]:JSON.stringify({userId:other,name:'Other',active:true}),
    ['push:vapid']:'global-key',
    ['audit:admin:old']:'{"action":"old"}',
  });
  const headers={'X-Admin-Token':ADMIN,'CF-Connecting-IP':'203.0.113.22','Content-Type':'application/json'};
  const res=await worker.fetch(req('/admin/users/'+USER+'/erase',{method:'POST',headers,body:JSON.stringify({confirm:'ERASE',userId:USER})}),{BACKUPS:kv,ADMIN_TOKEN:ADMIN});
  eq(res.status,200,'confirmed revoked erase must succeed');
  const remaining=kv.keys();
  ok(!remaining.some(k => k === 'user:'+USER || k.startsWith('user:'+USER+':')), 'all user data must be gone');
  ok(!remaining.includes('tokh:'+hash) && !remaining.includes('tokh:'+staleHash), 'all bearer indexes naming account must be gone');
  ok(!remaining.includes('sck:shortcutHash') && !remaining.includes('sckuser:'+USER), 'shortcut credentials must be gone');
  ok(!remaining.includes('inv:bound'), 'bound invite must be gone');
  ok(remaining.includes('user:'+other), 'unrelated user must remain');
  ok(remaining.includes('push:vapid'), 'global VAPID key must remain');
  const remIndex=JSON.parse(await kv.get('rem:index'));
  ok(!remIndex.includes(USER) && remIndex.includes(other), 'reminder index must drop only erased user');
});

test('[SR-09] privileged audit records contain no raw identity, token, IP, or request body', async () => {
  const worker = (await loadMod()).default;
  const hash = await sha256Hex(TOKEN);
  const rec={userId:USER,name:'Secret Driver Name',tokenHash:hash,active:true,createdAt:'2026-01-01T00:00:00Z'};
  const kv=makeKV({['user:'+USER]:JSON.stringify(rec),['tokh:'+hash]:JSON.stringify(rec)});
  const ip='203.0.113.77';
  const revoke=await worker.fetch(req('/admin/users/'+USER,{method:'DELETE',headers:{'X-Admin-Token':ADMIN,'CF-Connecting-IP':ip}}),{BACKUPS:kv,ADMIN_TOKEN:ADMIN});
  eq(revoke.status,200,'revoke must succeed');
  const audit=await worker.fetch(req('/admin/audit?limit=20',{headers:{'X-Admin-Token':ADMIN,'CF-Connecting-IP':ip}}),{BACKUPS:kv,ADMIN_TOKEN:ADMIN});
  eq(audit.status,200,'operator may read sanitized admin audit');
  const text=await audit.text();
  ok(text.includes('user.revoke'),'audit must identify action class');
  ok(!text.includes(ADMIN),'admin token must not enter audit');
  ok(!text.includes(TOKEN),'driver token must not enter audit');
  ok(!text.includes(USER),'raw user id must not enter audit');
  ok(!text.includes('Secret Driver Name'),'driver name must not enter audit');
  ok(!text.includes(ip),'IP must not enter audit');
});

test('[SR-10] health exposes hardened-mode evidence and version 35', async () => {
  const worker=(await loadMod()).default;
  const soft=await (await worker.fetch(req('/health'),{BACKUPS:makeKV()})).json();
  eq(String(soft.version),'35','health generation must be v35');
  eq(soft.rateLimiter,'soft-kv','unit env without binding must identify fallback honestly');
  eq(soft.credentialPolicy,'finite-v1','finite credential policy must be advertised');
  const durable={ idFromName:n=>n, get:id=>({fetch:async()=>new Response('{"ok":true,"limited":false}',{status:200})}) };
  const hard=await (await worker.fetch(req('/health'),{BACKUPS:makeKV(),RATE_LIMITER:durable})).json();
  eq(hard.rateLimiter,'durable-object','bound production-like env must identify exact limiter');
});

test('[SR-11] production config and release gates require exact limiter + finite credential policy', async () => {
  const cfg=readFileSync(path.join(ROOT,'scripts/wrangler.backup-worker.jsonc'),'utf8');
  const deploy=readFileSync(path.join(ROOT,'.github/workflows/deploy-backup-worker.yml'),'utf8');
  const parity=readFileSync(path.join(ROOT,'scripts/verify-cloudflare-parity.mjs'),'utf8');
  ok(cfg.includes('"name": "RATE_LIMITER"') && cfg.includes('"class_name": "RateLimitCounter"'), 'production Worker config must bind RATE_LIMITER');
  ok(cfg.includes('"type": "durable-object"') && cfg.includes('"storage": "sqlite"'), 'rate limiter must be SQLite-backed Durable Object storage');
  ok(deploy.includes('"rateLimiter":"durable-object"'), 'deploy must refuse a soft-KV production limiter');
  ok(deploy.includes('"credentialPolicy":"finite-v1"'), 'deploy must prove finite credential policy is live');
  ok(parity.includes('workerVersion: "35"'), 'parity gate must expect Worker v35');
  ok(parity.includes("Worker uses exact Durable Object rate limiter"), 'parity gate must assert exact limiter mode');
});

test('[SR-12] permanent erasure fails closed if a KV namespace scan is truncated', async () => {
  const { eraseUserData } = await loadMod();
  let pages=0;
  const rec={userId:USER,name:'Driver',active:false};
  const kv={
    async get(k){ return k==='user:'+USER ? JSON.stringify(rec) : null; },
    async put(){},
    async delete(){},
    async list(){ pages++; return {keys:[],list_complete:false,cursor:'next-'+pages}; },
  };
  let threw=false;
  try { await eraseUserData({BACKUPS:kv}, USER); }
  catch (e) { threw=/pagination bound/i.test(String(e)); }
  ok(threw, 'erasure must not report success after an incomplete namespace enumeration');
  eq(pages, 100, 'the safety bound must be explicit and deterministic');
});

const USER_RATE_EXPECTED_MIN = 10;

test('[SR-13] exact limiter identities are pseudonymous and account erasure clears their state', async () => {
  const { eraseUserData } = await loadMod();
  const rec={userId:USER,name:'Driver',active:false,tokenHash:await sha256Hex(TOKEN)};
  const kv=makeKV({['user:'+USER]:JSON.stringify(rec)});
  const names=[]; let deleteCalls=0;
  const durable={
    idFromName(name){ names.push(name); return name; },
    get(){ return { fetch:async (_url,opts={})=>{
      if(opts.method==='DELETE'){ deleteCalls++; return new Response(null,{status:204}); }
      return new Response('{"ok":true,"limited":false}',{status:200});
    }}; },
  };
  const result=await eraseUserData({BACKUPS:kv,RATE_LIMITER:durable},USER);
  eq(result.found,true,'revoked account must be erased');
  ok(names.length>=USER_RATE_EXPECTED_MIN,'erasure must address all user-scoped limiter namespaces');
  ok(names.every(name=>/^v1:[a-f0-9]{64}$/.test(name)),'Durable Object names must be one-way pseudonyms');
  ok(names.every(name=>!name.includes(USER)),'raw userId must never appear in a Durable Object name');
  eq(deleteCalls,names.length,'every addressed exact limiter object must receive a delete');
});

test('[SR-14] permanent erasure refuses a corrupted reminder index before deleting the account', async () => {
  const { eraseUserData } = await loadMod();
  const rec={userId:USER,name:'Driver',active:false};
  const kv=makeKV({['user:'+USER]:JSON.stringify(rec),'rem:index':'{"broken":true}'});
  let threw=false;
  try { await eraseUserData({BACKUPS:kv},USER); }
  catch (e) { threw=/corrupted reminder index/i.test(String(e)); }
  ok(threw,'malformed reminder index must abort erasure');
  ok(kv.keys().includes('user:'+USER),'account must remain when erasure cannot prove reference cleanup');
});


test('[SR-15] bounded UTF-8 body enforcement preserves historical backup size metadata contract', async () => {
  const worker=(await loadMod()).default;
  const hash=await sha256Hex(TOKEN);
  const rec={
    userId:USER, name:'Driver', tokenHash:hash, active:true, backupCount:0,
    createdAt:new Date().toISOString(),
  };
  const kv=makeKV({
    ['user:'+USER]:JSON.stringify(rec),
    ['tokh:'+hash]:JSON.stringify(rec),
  });
  const payload='{"route":"MKE→CHI","note":"🚚 secure backup"}';
  ok(new TextEncoder().encode(payload).length > payload.length, 'fixture must distinguish UTF-8 bytes from JS string length');
  const res=await worker.fetch(req('/backup',{
    method:'POST',
    headers:{
      'X-Backup-Token':TOKEN,
      'X-Device-Id':'sec-size-contract',
      'Content-Type':'text/plain',
    },
    body:payload,
  }),{BACKUPS:kv});
  eq(res.status,200,'backup with multibyte content must be accepted');
  const body=await res.json();
  eq(body.size,payload.length,'response size must preserve historical JS string-length contract');
  const stored=await worker.fetch(req('/backup',{
    headers:{'X-Backup-Token':TOKEN,'X-Device-Id':'sec-size-contract'},
  }),{BACKUPS:kv});
  eq(await stored.text(),payload,'bounded reader must still store and restore the exact multibyte payload');
});

export async function runSpec(){ return run(); }
if (import.meta.url === `file://${process.argv[1]}`) {
  const r=await runSpec();
  process.exit(r.fail>0?1:0);
}
