import { createSuite, ok, eq, startServer, newPage, stopServer } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/full-repair-regressions.spec.mjs');
let page;
async function boot(){
  if (page) return page;
  const base = await startServer();
  page = await newPage({ testsEnabled:true });
  await page.goto(base + '/#home');
  await page.waitForFunction(() => !!window.__FL_TESTS);
  return page;
}

test('[FR-01] Profit/Hour is UNKNOWN without operator planning speed and real with it', async () => {
  const p=await boot();
  const r=await p.evaluate(() => {
    const f=window.__FL_TESTS.deriveUnifiedEconomics;
    const base={revenue:1000,effectiveRevenue:1000,loadedMi:500,deadMi:0,mpg:20,fuelPrice:4,opCPM:0.2,borderAdminCost:0};
    return [f(base),f({...base,avgMph:50})];
  });
  eq(r[0].available,true); eq(r[0].estHours,null); eq(r[0].profitPerHour,null);
  eq(r[1].estHours,10); ok(Number.isFinite(r[1].profitPerHour),'explicit speed produces profit/hour');
});

test('[FR-02] payment absence stays UNKNOWN while explicit false/true stay authoritative', async () => {
  const p=await boot();
  const r=await p.evaluate(() => {
    const T=window.__FL_TESTS;
    const u=T.sanitizeTrip({id:'u1',orderNo:'A',pay:100,loadedMiles:10,emptyMiles:0});
    const n=T.sanitizeTrip({id:'u2',orderNo:'B',pay:100,loadedMiles:10,emptyMiles:0,isPaid:false});
    const y=T.sanitizeTrip({id:'u3',orderNo:'C',pay:100,loadedMiles:10,emptyMiles:0,isPaid:true});
    return {u,n,y,uu:T.tripIsUnpaid(u),nu:T.tripIsUnpaid(n),yp:T.tripIsPaid(y)};
  });
  eq(r.u.paymentStatusKnown,false); eq(r.uu,false);
  eq(r.n.paymentStatusKnown,true); eq(r.nu,true);
  eq(r.y.paymentStatusKnown,true); eq(r.yp,true);
});

test('[FR-03] DB16 tripRecords uses stable id and permits two blank/reused order numbers', async () => {
  const p=await boot();
  const r=await p.evaluate(async () => {
    const db=await new Promise((resolve,reject)=>{const q=indexedDB.open('FreightLogic_v18');q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error)});
    const store=db.transaction('tripRecords','readwrite').objectStore('tripRecords');
    const kp=store.keyPath, unique=store.index('orderNo').unique;
    store.put({id:'fr-blank-1',orderNo:'',created:1,pickupDate:'2026-01-01',customer:'A'});
    store.put({id:'fr-blank-2',orderNo:'',created:2,pickupDate:'2026-01-02',customer:'B'});
    await new Promise((resolve,reject)=>{store.transaction.oncomplete=resolve;store.transaction.onerror=()=>reject(store.transaction.error)});
    const tx=db.transaction('tripRecords','readonly'), s=tx.objectStore('tripRecords');
    const all=await new Promise((resolve,reject)=>{const q=s.index('orderNo').getAll(IDBKeyRange.only(''));q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error)});
    db.close(); return {kp,unique,count:all.filter(x=>x.id.startsWith('fr-blank-')).length};
  });
  eq(r.kp,'id'); eq(r.unique,false); eq(r.count,2);
});

test('[FR-04] controlled-PWA admin module owns Manage Drivers without double-toggle race', async () => {
  const p=await boot();
  await p.addScriptTag({url:'/admin-driver-ui.js?v=24.0.13'});
  await p.waitForFunction(() => document.body.dataset.flAdminUiReady === '1');
  const r=await p.evaluate(() => {
    const b=document.getElementById('btnAdminToggle'),panel=document.getElementById('adminPanel');
    panel.style.display='none'; b.click();
    return {display:panel.style.display, ready:document.body.dataset.flAdminUiReady};
  });
  eq(r.ready,'1'); ok(r.display !== 'none','one tap leaves admin panel open');
});

test('[FR-05] service worker sanitizes attacker-controlled shared filenames before X-Filename', async () => {
  const txt=await (await fetch('/service-worker.js')).text();
  ok(txt.includes('safeFilename'),'safe filename variable exists');
  ok(txt.includes("replace(/[\\u0000-\\u001F\\u007F]/g, '_')"),'control bytes are stripped');
  ok(!txt.includes("'X-Filename': file.name"),'raw file.name is never written to header');
});

export async function runSpec(){ const r=await run(); try{await page?.close()}catch{}; return r; }
