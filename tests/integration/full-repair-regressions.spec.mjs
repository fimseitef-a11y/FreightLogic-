from pathlib import Path
import re

SELF = Path(__file__)

def read(p): return Path(p).read_text()
def write(p,s): Path(p).write_text(s)
def need(s, old, label):
    if old not in s: raise SystemExit(f'{label}: marker not found: {old[:100]!r}')

def replace_one(s, old, new, label):
    c=s.count(old)
    if c != 1: raise SystemExit(f'{label}: expected 1 occurrence, found {c}: {old[:100]!r}')
    return s.replace(old,new,1)

# ── app.js: release + DB16 + truthful data semantics ─────────────────────────
p='app.js'; s=read(p)
need(s, "const APP_VERSION = '24.0.12';", 'APP_VERSION')
s=s.replace('/** FreightLogic v24.0.12 USA ENGINE','/** FreightLogic v24.0.13 USA ENGINE',1)
marker=' *  v24.0.12 "Delivery Generation":'
note=(' *  v24.0.13 "First Real Use": field-observed repair generation. Trips move to an internal\n'
      ' *          stable-id store (DB 16) so blank/reused external order numbers cannot overwrite\n'
      ' *          history; payment UNKNOWN stays unknown; Profit/Hour uses only the operator-set\n'
      ' *          planning speed; first-use cloud admin has one event owner; share filenames are\n'
      ' *          header-safe. Cloud Worker v18 proactively scrubs legacy v7 plaintext-token\n'
      ' *          residue. Physical iPhone A1-A10 and authentic M6 remain certification gates.\n')
need(s,marker,'release header')
s=s.replace(marker,note+marker,1)
s=s.replace("const APP_VERSION = '24.0.12';","const APP_VERSION = '24.0.13';",1)
s=replace_one(s,'const DB_VERSION = 15;','const DB_VERSION = 16;','DB_VERSION')

s=replace_one(s,
  "notes:'', isPaid:false, paidDate:null, wouldRunAgain:null, needsReview:false, reviewReasons:[],",
  "notes:'', isPaid:false, paymentStatusKnown:true, paidDate:null, wouldRunAgain:null, needsReview:false, reviewReasons:[],",
  'newTripTemplate payment')
s=replace_one(s,
  '  t.isPaid = !!raw.isPaid;',
  "  const hasPaidFlag = Object.prototype.hasOwnProperty.call(raw || {}, 'isPaid') && typeof raw.isPaid === 'boolean';\n  t.isPaid = hasPaidFlag ? raw.isPaid : false;\n  t.paymentStatusKnown = typeof raw.paymentStatusKnown === 'boolean' ? raw.paymentStatusKnown : hasPaidFlag;",
  'sanitizeTrip payment')
s=replace_one(s,
  "  if (pay > 20000) reasons.push('Revenue exceeds sanity threshold');\n  return reasons;",
  "  if (pay > 20000) reasons.push('Revenue exceeds sanity threshold');\n  if (raw?.paymentStatusKnown === false) reasons.push('Payment status is unknown');\n  return reasons;",
  'review payment unknown')

old="      if (old < 15) { ensureStore(EVIDENCE_STORE, { keyPath:'evidenceId' }); }\n      ensureIndexes(EVIDENCE_STORE, ["
new="""      if (old < 15) { ensureStore(EVIDENCE_STORE, { keyPath:'evidenceId' }); }
      // v16: `orderNo` is external evidence, not identity. The legacy store keyed by
      // orderNo silently overwrote blank/reused numbers (observed 13 -> 12 on first import).
      // Preserve it for rollback, but migrate every surviving row to stable internal `id`.
      if (old < 16) {
        ensureStore('tripRecords', { keyPath:'id' });
        ensureIndexes('tripRecords', [
          ['pickupDate','pickupDate'], ['created','created'], ['customer','customer'],
          ['orderNo','orderNo',{ unique:false }]
        ]);
        if (d.objectStoreNames.contains('trips')) {
          const legacyTrips = e.target.transaction.objectStore('trips');
          const stableTrips = e.target.transaction.objectStore('tripRecords');
          const curReq = legacyTrips.openCursor();
          curReq.onsuccess = (ev) => {
            const cur = ev.target.result;
            if (!cur) return;
            const rec = Object.assign({}, cur.value || {});
            if (!rec.id) rec.id = crypto.randomUUID?.() || ('trip_' + Math.random().toString(36).slice(2) + Date.now().toString(36));
            // Pre-v16 rows cannot prove whether false was explicit or a sanitizer fallback.
            if (typeof rec.paymentStatusKnown !== 'boolean') rec.paymentStatusKnown = false;
            stableTrips.put(rec);
            cur.continue();
          };
        }
      }
      ensureIndexes('tripRecords', [
        ['pickupDate','pickupDate'], ['created','created'], ['customer','customer'],
        ['orderNo','orderNo',{ unique:false }]
      ]);
      ensureIndexes(EVIDENCE_STORE, ["""
s=replace_one(s,old,new,'DB16 migration')

old="""function tx(storeNames, mode='readonly'){
  const t = db.transaction(storeNames, mode);
  const stores = {};
  for (const n of (Array.isArray(storeNames)? storeNames:[storeNames])) stores[n] = t.objectStore(n);
  return { t, stores };
}"""
new="""function tx(storeNames, mode='readonly'){
  const logical = Array.isArray(storeNames) ? storeNames : [storeNames];
  const physicalFor = (n) => (n === 'trips' && db.objectStoreNames.contains('tripRecords')) ? 'tripRecords' : n;
  const physical = [...new Set(logical.map(physicalFor))];
  const t = db.transaction(physical, mode);
  const stores = {};
  for (const n of logical) stores[n] = t.objectStore(physicalFor(n));
  return { t, stores };
}"""
s=replace_one(s,old,new,'tx alias')
s=replace_one(s,
  "    for (const rec of records){ try{ stores[storeName].put(rec); }catch{} }",
  "    for (const rec of records){ try{ stores[storeName].put(storeName === 'trips' ? sanitizeTrip(rec) : rec); }catch{} }",
  'legacy migration put')

old="""async function tripExists(orderNo){
  const {stores} = tx('trips');
  return !!(await idbReq(stores.trips.get(orderNo)));
}"""
new="""function tripPaymentKnown(t){ return !!t && t.paymentStatusKnown === true && typeof t.isPaid === 'boolean'; }
function tripIsPaid(t){ return tripPaymentKnown(t) && t.isPaid === true; }
function tripIsUnpaid(t){ return tripPaymentKnown(t) && t.isPaid === false; }
async function findTripsByOrderNo(orderNo, limit=10){
  const key = normOrderNo(orderNo);
  if (!key) return [];
  const {stores} = tx('trips');
  if (!stores.trips.indexNames.contains('orderNo')) return [];
  return (await idbReq(stores.trips.index('orderNo').getAll(IDBKeyRange.only(key), limit))) || [];
}
async function tripExists(orderNo){ return (await findTripsByOrderNo(orderNo, 1)).length > 0; }"""
s=replace_one(s,old,new,'trip identity helpers')
s=replace_one(s,'stores.trips.get(t.orderNo)','stores.trips.get(t.id)','upsert stable id')

old="""async function deleteTrip(orderNo){
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['trips','receipts','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.trips.get(orderNo)); }catch(e){ console.warn(\"[FL]\", e); }
  stores.trips.delete(orderNo);
  try{ stores.receipts.delete(orderNo); }catch(e){ console.warn(\"[FL]\", e); }
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: orderNo, action:'DELETE_TRIP', beforeData: beforeData || null, afterData: null, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(true); txn.onerror = ()=> reject(txn.error); });
}"""
new="""async function deleteTrip(tripId){
  // Stable-id delete. External order numbers are not unique identities.
  const {t:txn, stores} = tx(['trips','receipts','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.trips.get(tripId)); }catch(e){ console.warn(\"[FL]\", e); }
  stores.trips.delete(tripId);
  try{ if (beforeData?.orderNo) stores.receipts.delete(beforeData.orderNo); }catch(e){ console.warn(\"[FL]\", e); }
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: tripId, action:'DELETE_TRIP', beforeData: beforeData || null, afterData: null, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(true); txn.onerror = ()=> reject(txn.error); });
}"""
s=replace_one(s,old,new,'delete stable id')
s=s.replace('deleteTrip(t.orderNo)','deleteTrip(t.id)').replace('deleteTrip(trip.orderNo)','deleteTrip(trip.id)')

old="""    if (mode==='add' && await tripExists(orderNo)){
      hint.textContent = 'Order # already exists. You can edit the existing trip instead.';
      const existingTrip = await idbReq(tx('trips').stores.trips.get(orderNo)).catch(()=>null);
      const openIt = confirm('Order # already exists. Open the existing trip instead of creating a duplicate?');
      if (openIt && existingTrip){ setTimeout(()=> openTripWizard(existingTrip), 0); closeModal(); }
      return false;
    }"""
new="""    if (mode==='add' && await tripExists(orderNo)){
      // External order numbers can be reused. Warn, but never merge identities from this field alone.
      hint.textContent = 'Order # already exists — allowed if this is a distinct load.';
    }"""
s=replace_one(s,old,new,'duplicate order blocker')
s=replace_one(s,'const inTrips = arr(parsed.trips);','const inTrips = arr(parsed.trips).map(x => sanitizeTrip(x));','restore sanitize trips')
s=replace_one(s,'ws.trips.get(incoming.orderNo)','ws.trips.get(incoming.id)','restore stable id')

paid_line="            isPaid: ['yes','true','paid','1'].includes(cellAt(row, 'Paid','IsPaid','Status').toLowerCase()),"
need(s,paid_line,'CSV paid')
s=s.replace(paid_line,paid_line+"\n            paymentStatusKnown: cellAt(row, 'Paid','IsPaid','Status').trim() !== '',",1)
s=replace_one(s,"t.isPaid?'Yes':'No', t.paidDate||''","tripPaymentKnown(t) ? (t.isPaid?'Yes':'No') : '', t.paidDate||''",'CSV paid export')

# Financial/AR uses only explicit unpaid.
s=s.replace('if (!cur.value.isPaid && !cur.value.needsReview)','if (tripIsUnpaid(cur.value) && !cur.value.needsReview)')
s=s.replace('if (!cur.value.isPaid) out.push(cur.value);','if (tripIsUnpaid(cur.value)) out.push(cur.value);')
s=s.replace('if (!t.isPaid) unpaid += pay;','if (tripIsUnpaid(t)) unpaid += pay;')
s=s.replace('if (!t.isPaid) rec.unpaid += pay;','if (tripIsUnpaid(t)) rec.unpaid += pay;')
s=s.replace('brokerTrips.filter(t => !t.isPaid)','brokerTrips.filter(t => tripIsUnpaid(t))')
s=s.replace('return !t.isPaid && refDate','return tripIsUnpaid(t) && refDate')
s=s.replace('if (!t.isPaid) unpaidCount++;','if (tripIsUnpaid(t)) unpaidCount++;')
old="""  for (const t of validTrips) {
    const pay = Number(t.pay || 0);
    totalEver += pay;
    if (!t.isPaid) { unpaidAmt += pay; unpaidCount++; } else { totalPaid += pay; }
  }"""
new="""  for (const t of validTrips) {
    if (!tripPaymentKnown(t)) continue;
    const pay = Number(t.pay || 0);
    totalEver += pay;
    if (tripIsUnpaid(t)) { unpaidAmt += pay; unpaidCount++; } else if (tripIsPaid(t)) { totalPaid += pay; }
  }"""
s=replace_one(s,old,new,'money payment totals')
s=s.replace("t.isPaid = !t.isPaid; t.paidDate = t.isPaid ? isoDate() : null;","t.isPaid = !t.isPaid; t.paymentStatusKnown = true; t.paidDate = t.isPaid ? isoDate() : null;")
s=s.replace("t.isPaid = true; t.paidDate = isoDate();","t.isPaid = true; t.paymentStatusKnown = true; t.paidDate = isoDate();")

# Profit/hour only when planning speed is explicit.
old="""  const estHours = totalMi > 0 ? Math.max(1, Math.round(totalMi / 50)) : 1;
  const profitPerHour = roundCents(trueProfit / estHours);"""
new="""  const avgMphK = knownNum(f.avgMph);
  const avgMph = (avgMphK !== null && avgMphK >= PICKUP_FEASIBILITY.MIN_MPH && avgMphK <= PICKUP_FEASIBILITY.MAX_MPH) ? avgMphK : null;
  const estHours = avgMph === null ? null : roundCents(totalMi / avgMph);
  const profitPerHour = estHours && estHours > 0 ? roundCents(trueProfit / estHours) : null;"""
s=replace_one(s,old,new,'profit/hour 50mph')
old="""  const vehicleMpg = knownNum(await getSetting('vehicleMpg', MW.mpg));
  const borderAdminCost"""
new="""  const vehicleMpg = knownNum(await getSetting('vehicleMpg', MW.mpg));
  const planningAvgMph = await getPlanningAvgMph();
  const borderAdminCost"""
s=replace_one(s,old,new,'planning mph setting')
old="""    revenue, effectiveRevenue, loadedMi, deadMi,
    mpg: vehicleMpg, fuelPrice, opCPM, borderAdminCost,
  });"""
new="""    revenue, effectiveRevenue, loadedMi, deadMi,
    mpg: vehicleMpg, fuelPrice, opCPM, borderAdminCost, avgMph: planningAvgMph,
  });"""
s=replace_one(s,old,new,'economics avgMph call')
s=replace_one(s,'$${profitPerHour.toFixed(0)}',"${profitPerHour === null ? '—' : ('$' + profitPerHour.toFixed(0))}",'profit/hour render')

# First-use admin race.
old="""  $('#btnAdminToggle')?.addEventListener('click', ()=>{ var p = $('#adminPanel'); if (!p) return; var s = p.style.display !== 'none'; p.style.display = s ? 'none' : ''; if (!s){ var saved = sessionStorage.getItem('fl_admin_tok'); if (saved){ var el = $('#adminToken'); if (el && !el.value) el.value = saved; } cloudAdminLoadUsers(); } });
  $('#btnAdminCreate')?.addEventListener('click', async ()=>{ haptic(20); await cloudAdminCreateUser(); });
  $('#btnAdminRefresh')?.addEventListener('click', async ()=>{ haptic(20); await cloudAdminLoadUsers(); });"""
new="""  // The service-worker-injected admin module clones these controls and owns their events.
  // Async boot used to bind a second handler afterward, so one tap opened and immediately
  // re-closed the panel on iPhone. Keep legacy bindings only when that module is absent.
  if (document.body?.dataset.flAdminUiReady !== '1') {
    $('#btnAdminToggle')?.addEventListener('click', ()=>{ var p = $('#adminPanel'); if (!p) return; var open = p.style.display === 'none'; p.style.display = open ? '' : 'none'; if (open){ var saved = sessionStorage.getItem('fl_admin_tok'); if (saved){ var el = $('#adminToken'); if (el && !el.value) el.value = saved; } cloudAdminLoadUsers(); } });
    $('#btnAdminCreate')?.addEventListener('click', async ()=>{ haptic(20); await cloudAdminCreateUser(); });
    $('#btnAdminRefresh')?.addEventListener('click', async ()=>{ haptic(20); await cloudAdminLoadUsers(); });
  }"""
s=replace_one(s,old,new,'admin duplicate handlers')
s=replace_one(s,'    sanitizeTrip, sanitizeExpense, sanitizeFuel,','    sanitizeTrip, sanitizeExpense, sanitizeFuel, tripPaymentKnown, tripIsPaid, tripIsUnpaid, findTripsByOrderNo,','test exports')
write(p,s)

# ── Service worker share-target hardening + v24.0.13 ─────────────────────────
p='service-worker.js'; s=read(p)
s=s.replace('/* FreightLogic v24.0.12','/* FreightLogic v24.0.13',1)
s=replace_one(s,"const SW_VERSION = '24.0.12';","const SW_VERSION = '24.0.13';",'SW_VERSION')
s=s.replace('?v=24.0.12','?v=24.0.13')
old="""            const contentType = ALLOWED_SHARE_TYPES.has(file.type) ? file.type : 'application/octet-stream';
            await shareCache.put(`/shared-file-${i}`, new Response(file, { headers: { 'Content-Type': contentType, 'X-Filename': file.name } }));"""
new="""            const contentType = ALLOWED_SHARE_TYPES.has(file.type) ? file.type : 'application/octet-stream';
            // Shared filenames are attacker-controlled input. Strip control bytes before headers.
            const safeFilename = String(file.name || `shared-file-${i}`)
              .replace(/[\\u0000-\\u001F\\u007F]/g, '_').slice(0, 180) || `shared-file-${i}`;
            await shareCache.put(`/shared-file-${i}`, new Response(file, { headers: { 'Content-Type': contentType, 'X-Filename': safeFilename } }));"""
s=replace_one(s,old,new,'share target filename')
write(p,s)

# ── Admin module parity and self-setup ───────────────────────────────────────
p='admin-driver-ui.js'; s=read(p)
old="""      return`<div class=\"admin-user\" data-u=\"${X(v.userId||'')}\"><div class=\"au-name\">${X(s.n)} ${badge}</div><div class=\"au-meta\">${X((v.createdAt||'').slice(0,10))}</div>${v.active?'<div class=\"btn-row\" style=\"margin-top:8px\"><button class=\"btn sm danger\" data-revoke=\"1\">Remove Access</button></div>':''}</div>`;"""
new="""      return`<div class=\"admin-user\" data-u=\"${X(v.userId||'')}\" data-name=\"${X(s.n)}\"><div class=\"au-name\">${X(s.n)} ${badge}</div><div class=\"au-meta\">${Number(v.backupCount||0)} backup(s) · ${X((v.createdAt||'').slice(0,10))}</div>${v.active?'<div class=\"btn-row\" style=\"margin-top:8px\"><button class=\"btn sm\" data-rotate=\"1\">🔑 Rotate Token</button><button class=\"btn sm danger\" data-revoke=\"1\">Remove Access</button></div>':''}</div>`;"""
s=replace_one(s,old,new,'admin row parity')
needle="""    box.querySelectorAll('[data-revoke=\"1\"]').forEach(btn=>btn.onclick=async()=>{"""
insert="""    box.querySelectorAll('[data-rotate=\"1\"]').forEach(btn=>btn.onclick=async()=>{
      let row=btn.closest('[data-u]'),id=row?.getAttribute('data-u'),name=row?.getAttribute('data-name')||'Driver';if(!id)return;
      if(!confirm(`Rotate ${name}'s token? The old token will stop working.`))return;
      btn.disabled=true;
      try{let d=await Q('/admin/users/'+encodeURIComponent(id)+'/rotate',{method:'POST',headers:G()});shareInvite(name,d.token);T('Token rotated');H();loadUsers()}
      catch(e){btn.disabled=false;T(e.message||'Rotate failed',1)}
    });
    box.querySelectorAll('[data-revoke=\"1\"]').forEach(btn=>btn.onclick=async()=>{"""
s=replace_one(s,needle,insert,'admin rotate binding')
old="""        <div class=\"muted\" style=\"font-size:12px;margin-bottom:10px\">Setup link sent — they open it, pick a passphrase, and they're in. No token typing needed.</div>
        <button class=\"btn sm\" id=\"btnShareInvite\" style=\"width:100%;font-size:13px\">📤 Resend to ${X(s.n)}</button>"""
new="""        <div class=\"muted\" style=\"font-size:12px;margin-bottom:10px\">Driver token created. Use it on this device or share a one-tap setup link.</div>
        <div class=\"btn-row\"><button class=\"btn sm primary\" id=\"btnUseHere\" style=\"flex:1;font-size:13px\">Use on this device</button><button class=\"btn sm\" id=\"btnShareInvite\" style=\"flex:1;font-size:13px\">📤 Share</button></div>"""
s=replace_one(s,old,new,'admin create result')
old="""      let shareBtn=$('btnShareInvite');
      if(shareBtn)shareBtn.onclick=()=>{shareInvite(s.n,d.token);H()};
    }
    $('adminDriverName').value='';
    // Auto-share immediately — no extra tap needed.
    shareInvite(s.n,d.token);"""
new="""      let useBtn=$('btnUseHere');
      if(useBtn)useBtn.onclick=()=>{let target=$('cloudBackupToken');if(target){target.value=d.token;target.dispatchEvent(new Event('input',{bubbles:true}));target.focus();target.scrollIntoView({behavior:'smooth',block:'center'})}T('Driver token filled — choose your encryption passphrase');H()};
      let shareBtn=$('btnShareInvite');
      if(shareBtn)shareBtn.onclick=()=>{shareInvite(s.n,d.token);H()};
    }
    $('adminDriverName').value='';"""
s=replace_one(s,old,new,'admin use-here')
write(p,s)

# ── Worker v18: proactive legacy plaintext cleanup ───────────────────────────
p='cloud-backup-worker.js'; s=read(p)
s=s.replace('// FreightLogic Cloud Backup Worker v17','// FreightLogic Cloud Backup Worker v18',1)
hdr='// v17: backup/delta keys are minted from a MONOTONIC clock.'
need(s,hdr,'worker v17 header')
s=s.replace(hdr,"// v18: legacy v7 plaintext-token cleanup is proactive, not only rotation-time.\n// Admin listing scrubs every legacy user record it encounters; lazy driver migration rewrites\n// the matching user record; revoke removes any plaintext field before persisting. No new token\n// is ever stored raw.\n"+hdr,1)
old="""                const u = JSON.parse(val);
                // Never expose driver tokens in the admin listing
                users.push({ userId: u.userId, name: u.name, createdAt: u.createdAt, active: u.active, backupCount: u.backupCount || 0 });"""
new="""                let u = JSON.parse(val);
                // Bounded proactive v7 sweep: scrub plaintext from every user record listed.
                if (u.token && u.userId) {
                  const legacyPlaintext = u.token;
                  const cleanHash = u.tokenHash || await hashToken(legacyPlaintext);
                  const clean = Object.assign({}, u, { tokenHash: cleanHash });
                  delete clean.token;
                  const cleanupOps = [env.BACKUPS.put('user:' + u.userId, JSON.stringify(clean)), env.BACKUPS.delete('token:' + legacyPlaintext)];
                  if (clean.active) cleanupOps.push(env.BACKUPS.put('tokh:' + cleanHash, JSON.stringify(clean)));
                  await Promise.all(cleanupOps);
                  u = clean;
                }
                // Never expose driver tokens in the admin listing
                users.push({ userId: u.userId, name: u.name, createdAt: u.createdAt, active: u.active, backupCount: u.backupCount || 0 });"""
s=replace_one(s,old,new,'worker admin sweep')
old="""            await Promise.all([
              env.BACKUPS.put('tokh:' + driverTokenHash, JSON.stringify(migRec)),
              env.BACKUPS.delete('token:' + driverToken),
            ]);
            tokenRaw = JSON.stringify(migRec);"""
new="""            const migOps = [
              env.BACKUPS.put('tokh:' + driverTokenHash, JSON.stringify(migRec)),
              env.BACKUPS.delete('token:' + driverToken),
            ];
            if (migRec.userId) migOps.push(env.BACKUPS.put('user:' + migRec.userId, JSON.stringify(migRec)));
            await Promise.all(migOps);
            tokenRaw = JSON.stringify(migRec);"""
s=replace_one(s,old,new,'worker lazy migration')
old="""          parsed.active = false;
          // Deactivate user record and revoke token in parallel
          const ops = [env.BACKUPS.put('user:' + delId, JSON.stringify(parsed))];
          if (parsed.tokenHash) ops.push(env.BACKUPS.delete('tokh:' + parsed.tokenHash));
          // Legacy plaintext key cleanup
          if (parsed.token) ops.push(env.BACKUPS.delete('token:' + parsed.token));"""
new="""          parsed.active = false;
          const legacyPlaintext = parsed.token;
          delete parsed.token;
          // Deactivate user record and revoke token in parallel. Never write raw token back.
          const ops = [env.BACKUPS.put('user:' + delId, JSON.stringify(parsed))];
          if (parsed.tokenHash) ops.push(env.BACKUPS.delete('tokh:' + parsed.tokenHash));
          if (legacyPlaintext) ops.push(env.BACKUPS.delete('token:' + legacyPlaintext));"""
s=replace_one(s,old,new,'worker revoke scrub')
s=replace_one(s,"version: '17'","version: '18'",'worker health version')
write(p,s)

# ── Release markers ──────────────────────────────────────────────────────────
for p in ['sw-bridge.js','modern-shell.js','voice-load.js','midwest-stack-authority.js']:
    write(p,read(p).replace('24.0.12','24.0.13'))
write('index.html',read('index.html').replace('?v=24.0.12','?v=24.0.13'))
write('manifest.json',read('manifest.json').replace('FreightLogic v24.0.12','FreightLogic v24.0.13'))
write('midwest-stack-config.json',read('midwest-stack-config.json').replace('FreightLogic v24.0.12','FreightLogic v24.0.13'))
s=read('scripts/verify-cloudflare-parity.mjs').replace('24.0.12','24.0.13').replace('workerVersion: "17"','workerVersion: "18"')
write('scripts/verify-cloudflare-parity.mjs',s)

p='tests/unit/cache-generation.spec.mjs'; s=read(p)
old="eq(dbm[1], '15', 'DB_VERSION must stay 15 — a cache-generation freeze must not migrate the database');"
new="eq(dbm[1], '16', 'DB_VERSION must be 16 — v24.0.13 migrates trips from external order-number identity to stable internal ids');"
s=replace_one(s,old,new,'cache DB invariant'); write(p,s)

# ── Worker cleanup regressions ───────────────────────────────────────────────
p='tests/unit/worker-token-rotation.spec.mjs'; s=read(p)
anchor='\nexport async function runSpec() { return run(); }\n'
need(s,anchor,'worker test export')
tests=r'''

test('[WTR-09] lazy legacy authentication rewrites the user record without plaintext', async () => {
  const worker = await loadWorker();
  const token = 'flk_' + 'abcd1234'.repeat(4), userId = 'u_3f2a1b4c-5d6';
  const rec = { userId, name:'Legacy Lazy', token, createdAt:'2026-03-13T00:00:00.000Z', active:true };
  const kv = makeKV({ ['user:'+userId]:JSON.stringify(rec), ['token:'+token]:JSON.stringify(rec) });
  const env = { BACKUPS:kv, ADMIN_TOKEN:ADMIN };
  const res = await worker.fetch(new Request('https://worker.test/backup', { method:'GET', headers:{'X-Backup-Token':token,'X-Device-Id':'devA'} }), env);
  eq(res.status, 404, 'valid migrated token reaches backup lookup');
  eq(await kv.get('token:'+token), null, 'plaintext key deleted');
  const clean = JSON.parse(await kv.get('user:'+userId));
  eq(clean.token, undefined, 'user record plaintext field deleted'); ok(clean.tokenHash, 'user record gains tokenHash');
});

test('[WTR-10] admin listing proactively sweeps dormant v7 plaintext residue', async () => {
  const worker = await loadWorker();
  const token = 'flk_' + '1234abcd'.repeat(4), userId = 'u_4f3e2d1c-6b7';
  const rec = { userId, name:'Dormant Legacy', token, createdAt:'2026-03-13T00:00:00.000Z', active:true };
  const kv = makeKV({ ['user:'+userId]:JSON.stringify(rec), ['token:'+token]:JSON.stringify(rec) });
  const env = { BACKUPS:kv, ADMIN_TOKEN:ADMIN };
  const res = await worker.fetch(adminReq('/admin/users','GET'), env); eq(res.status,200,'admin listing succeeds');
  eq(await kv.get('token:'+token), null, 'dormant plaintext key deleted');
  const clean=JSON.parse(await kv.get('user:'+userId)); eq(clean.token,undefined,'user record scrubbed'); ok(clean.tokenHash,'hash retained');
});

test('[WTR-11] revoking a legacy account never writes its plaintext token back', async () => {
  const worker = await loadWorker();
  const token = 'flk_' + 'aabbccdd'.repeat(4), userId = 'u_5e4d3c2b-7a8';
  const rec = { userId, name:'Legacy Revoke', token, createdAt:'2026-03-13T00:00:00.000Z', active:true };
  const kv = makeKV({ ['user:'+userId]:JSON.stringify(rec), ['token:'+token]:JSON.stringify(rec) });
  const env = { BACKUPS:kv, ADMIN_TOKEN:ADMIN };
  const res=await worker.fetch(adminReq('/admin/users/'+userId,'DELETE'),env); eq(res.status,200,'legacy revoke succeeds');
  eq(await kv.get('token:'+token),null,'plaintext key deleted');
  const clean=JSON.parse(await kv.get('user:'+userId)); eq(clean.token,undefined,'revoked record scrubbed'); eq(clean.active,false,'still revoked');
});
'''
s=s.replace(anchor,tests+anchor,1); write(p,s)

# ── Convert this patcher into the permanent browser regression spec ─────────
reg=r'''import { createSuite, ok, eq, startServer, newPage } from '../lib/harness.mjs';
const { test, run } = createSuite('integration/full-repair-regressions.spec.mjs');
let page;
async function boot(){
  if(page) return page;
  const base=await startServer(); page=await newPage({testsEnabled:true});
  await page.goto(base+'/#home'); await page.waitForFunction(()=>!!window.__FL_TESTS); return page;
}

test('[FR-01] Profit/Hour is UNKNOWN without operator planning speed and real with it', async()=>{
  const p=await boot(); const r=await p.evaluate(()=>{const f=window.__FL_TESTS.deriveUnifiedEconomics; const b={revenue:1000,effectiveRevenue:1000,loadedMi:500,deadMi:0,mpg:20,fuelPrice:4,opCPM:.2,borderAdminCost:0}; return [f(b),f({...b,avgMph:50})]});
  eq(r[0].available,true); eq(r[0].estHours,null); eq(r[0].profitPerHour,null); eq(r[1].estHours,10); ok(Number.isFinite(r[1].profitPerHour),'explicit speed produces profit/hour');
});

test('[FR-02] payment absence stays UNKNOWN while explicit false/true stay authoritative', async()=>{
  const p=await boot(); const r=await p.evaluate(()=>{const T=window.__FL_TESTS; const u=T.sanitizeTrip({id:'u1',orderNo:'A',pay:100,loadedMiles:10,emptyMiles:0}); const n=T.sanitizeTrip({id:'u2',orderNo:'B',pay:100,loadedMiles:10,emptyMiles:0,isPaid:false}); const y=T.sanitizeTrip({id:'u3',orderNo:'C',pay:100,loadedMiles:10,emptyMiles:0,isPaid:true}); return {u,n,y,uu:T.tripIsUnpaid(u),nu:T.tripIsUnpaid(n),yp:T.tripIsPaid(y)}});
  eq(r.u.paymentStatusKnown,false); eq(r.uu,false); eq(r.n.paymentStatusKnown,true); eq(r.nu,true); eq(r.y.paymentStatusKnown,true); eq(r.yp,true);
});

test('[FR-03] DB16 tripRecords uses stable id and permits two blank order numbers', async()=>{
  const p=await boot(); const r=await p.evaluate(async()=>{const db=await new Promise((res,rej)=>{const q=indexedDB.open('FreightLogic_v18');q.onsuccess=()=>res(q.result);q.onerror=()=>rej(q.error)}); const tx=db.transaction('tripRecords','readwrite'), st=tx.objectStore('tripRecords'); const kp=st.keyPath, unique=st.index('orderNo').unique; st.put({id:'fr-b1',orderNo:'',created:1,pickupDate:'2026-01-01',customer:'A'}); st.put({id:'fr-b2',orderNo:'',created:2,pickupDate:'2026-01-02',customer:'B'}); await new Promise((res,rej)=>{tx.oncomplete=res;tx.onerror=()=>rej(tx.error)}); const rt=db.transaction('tripRecords').objectStore('tripRecords'); const all=await new Promise((res,rej)=>{const q=rt.index('orderNo').getAll(IDBKeyRange.only(''));q.onsuccess=()=>res(q.result);q.onerror=()=>rej(q.error)}); db.close(); return {kp,unique,count:all.filter(x=>x.id.startsWith('fr-b')).length}}); eq(r.kp,'id'); eq(r.unique,false); eq(r.count,2);
});

test('[FR-04] admin module leaves Manage Drivers open after one tap', async()=>{
  const p=await boot(); await p.addScriptTag({url:'/admin-driver-ui.js?v=24.0.13'}); await p.waitForFunction(()=>document.body.dataset.flAdminUiReady==='1'); const r=await p.evaluate(()=>{const b=document.getElementById('btnAdminToggle'), panel=document.getElementById('adminPanel'); panel.style.display='none'; b.click(); return {display:panel.style.display,ready:document.body.dataset.flAdminUiReady}}); eq(r.ready,'1'); ok(r.display!=='none','one tap leaves admin panel open');
});

test('[FR-05] service worker sanitizes shared filenames before X-Filename', async()=>{
  const txt=await (await fetch('/service-worker.js')).text(); ok(txt.includes('safeFilename'),'safe filename exists'); ok(txt.includes("replace(/[\\u0000-\\u001F\\u007F]/g, '_')"),'control bytes stripped'); ok(!txt.includes("'X-Filename': file.name"),'raw filename not used');
});

export async function runSpec(){ return run(); }
'''
SELF.write_text(reg)

# Register the new regression suite.
p='tests/run-all.mjs'; s=read(p)
imp="import { runSpec as fullRepairRegressions } from './integration/full-repair-regressions.spec.mjs';\n"
if imp not in s:
    s=s.replace("import { runSpec as releaseGenerationDiscipline } from './unit/release-generation-discipline.spec.mjs';\n", "import { runSpec as releaseGenerationDiscipline } from './unit/release-generation-discipline.spec.mjs';\n"+imp,1)
if '  fullRepairRegressions,' not in s:
    s=s.replace('const specs = [\n','const specs = [\n  fullRepairRegressions,\n',1)
write(p,s)

# Current marker docs only; historical release paragraphs remain untouched when differently phrased.
for p in ['CLAUDE.md','FIELD_TEST_CHECKLIST.md','docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md']:
    if Path(p).exists():
        x=read(p).replace('FreightLogic v24.0.12','FreightLogic v24.0.13').replace('candidate v24.0.12','candidate v24.0.13').replace('Candidate: v24.0.12','Candidate: v24.0.13')
        write(p,x)

assert "const APP_VERSION = '24.0.13';" in read('app.js')
assert 'const DB_VERSION = 16;' in read('app.js')
assert "const SW_VERSION = '24.0.13';" in read('service-worker.js')
assert 'Worker v18' in read('cloud-backup-worker.js')
print('Full-repair patch applied; regression spec materialized.')
