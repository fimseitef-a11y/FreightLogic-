#!/usr/bin/env node
// FreightLogic M6 — one-time historical import adapter for the operator's
// 2026-08-27 bundle. Reconciles the bundle's overlapping CSV snapshots into the
// normalized historical-record shape that importHistoricalOpportunities()
// (app.js, merged in v24.2) consumes, honoring every hard rule in the bundle's
// M6_IMPORT_README.md and the reconciliation rules in the master handoff.
//
// This is a file-specific ADAPTER, not doctrine. It computes no True RPM, sets
// no pricing, and never invents a missing fact. Run:
//   node scripts/m6-import.mjs <bundle-dir> [out-dir]
// Emits records-for-import.json, withheld.json, and import-report.md.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';

const BUNDLE = process.argv[2];
const OUT = process.argv[3] || BUNDLE;
if (!BUNDLE || !existsSync(BUNDLE)) { console.error('usage: node scripts/m6-import.mjs <bundle-dir> [out-dir]'); process.exit(2); }

/* ---- robust CSV (quoted fields, embedded commas/newlines) ---- */
function parseCSV(text){
  const rows=[]; let i=0, field='', row=[], q=false;
  const pushF=()=>{row.push(field);field='';}; const pushR=()=>{rows.push(row);row=[];};
  while(i<text.length){const c=text[i];
    if(q){ if(c==='"'){ if(text[i+1]==='"'){field+='"';i+=2;continue;} q=false;i++;continue;} field+=c;i++;continue;}
    if(c==='"'){q=true;i++;continue;}
    if(c===','){pushF();i++;continue;}
    if(c==='\r'){i++;continue;}
    if(c==='\n'){pushF();pushR();i++;continue;}
    field+=c;i++;
  }
  if(field.length||row.length){pushF();pushR();}
  return rows.filter(r=>r.some(x=>x!==''));
}
function readRows(file){
  const rows = parseCSV(readFileSync(path.join(BUNDLE,file),'utf8'));
  const hdr = rows[0].map(h=>h.trim());
  return rows.slice(1).map(r => { const o={}; hdr.forEach((h,i)=>o[h]=(r[i]??'').trim()); return o; });
}
// A value is UNKNOWN unless it parses finite. Never coerce blank -> 0.
const num = v => { if(v===undefined||v===null||String(v).trim()==='') return null; const n=Number(v); return Number.isFinite(n)?n:null; };
const str = v => (v===undefined||v===null) ? '' : String(v).trim();
const iso = v => { const s=str(v); return /^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0,10) : null; };
const city = (c,s) => [str(c),str(s)].filter(Boolean).join(', ');
const tsOf = d => { const t=Date.parse(str(d)); return Number.isFinite(t)?t:null; };

/* ---- reconciled completed-ORDER ledger, keyed by order number ---- */
const orders = new Map(); // orderNo -> record
const report = { files:{}, statuses:{}, missingDeadhead:0, withheldFromTrueRpm:0, sourceRpmPreserved:0, reconciled:0, withheld:{ dry_run:0, live_quote:0, partial:0, chat_captured:0 } };

// Merge a candidate into the ledger with source precedence (higher first-seen wins
// for a field; we only FILL nulls, never overwrite a stronger value).
function upsertOrder(orderNo, cand, sourceName){
  const key = orderNo.toUpperCase();
  const cur = orders.get(key);
  if (!cur){ orders.set(key, { ...cand, _sources:[sourceName] }); return; }
  for (const k of Object.keys(cand)){
    if (k.startsWith('_')) continue;
    const v = cand[k];
    const empty = cur[k]===null || cur[k]===undefined || cur[k]==='';
    if (empty && !(v===null||v===undefined||v==='')) cur[k]=v;
  }
  // A stronger operator-confirmed status is preserved; never downgrade.
  cur._sources.push(sourceName);
  report.reconciled++;
}

/* ---- 1. All_Trips_App_Import_v1.csv (32 completed, operator import file) ---- */
{
  const rows = readRows('All_Trips_App_Import_v1.csv'); report.files['All_Trips_App_Import_v1.csv']={read:rows.length,accepted:0};
  for (const r of rows){
    const orderNo = str(r.Order_Number); if(!orderNo) continue;
    // Miles here is a SOURCE total, NOT verified deadhead-inclusive -> displayed
    // total, loaded/deadhead UNKNOWN, True RPM not computable.
    upsertOrder(orderNo, {
      kind:'ORDER', stableId:orderNo, orderNo,
      broker: str(r.Company),
      origin: city(r.Pickup_City,r.Pickup_State), destination: city(r.Delivery_City,r.Delivery_State),
      pickupAt: iso(r.Pickup_Date), deliveryAt: iso(r.Delivery_Date),
      amount: num(r.Gross_Pay), priceSemantic:'CARRIER_PAYOUT',
      loadedMi: null, deadMi: null, mileageSemantic:'DISPLAYED_TOTAL_MILES',
      displayedTotalMi: num(r.Miles), sourceDisplayedRpm: null,
      opportunity:'WON', execution: iso(r.Delivery_Date)?'DELIVERED':'NOT_STARTED', settlement:'NOT_INVOICED',
      deadZoneExit:false, operatorConfirmed:true, awarded:true,
      sourceName:'All_Trips_App_Import_v1.csv', sourceTimestamp: tsOf(r.Pickup_Date), rawEvidenceRef:`alltrips:${orderNo}`,
    }, 'All_Trips');
    report.files['All_Trips_App_Import_v1.csv'].accepted++;
  }
}

/* ---- 2. text 2.csv (58 completed orders, sparse) ---- */
{
  const rows = readRows('text 2.csv'); report.files['text 2.csv']={read:rows.length,accepted:0};
  for (const r of rows){
    const orderNo = str(r.Order_Number); if(!orderNo) continue;
    upsertOrder(orderNo, {
      kind:'ORDER', stableId:orderNo, orderNo,
      broker: str(r.Carrier),
      origin: str(r.Pickup_City), destination: str(r.Delivery_City),
      pickupAt: null, deliveryAt: iso(r.Completed_Date),
      amount: num(r.Gross_Pay), priceSemantic:'CARRIER_PAYOUT',
      loadedMi:null, deadMi:null, mileageSemantic: num(r.Total_Miles)!==null?'DISPLAYED_TOTAL_MILES':'UNKNOWN_MILEAGE_SEMANTIC',
      displayedTotalMi: num(r.Total_Miles), sourceDisplayedRpm: num(r.RPM),
      opportunity:'WON', execution: iso(r.Completed_Date)?'DELIVERED':'NOT_STARTED', settlement:'NOT_INVOICED',
      deadZoneExit:false, operatorConfirmed:true, awarded:true,
      sourceName:'text 2.csv', sourceTimestamp: tsOf(r.Completed_Date), rawEvidenceRef:`text2:${orderNo}`,
    }, 'text2');
    report.files['text 2.csv'].accepted++;
  }
}

/* ---- 3. COMPLETE-UNIFIED-DATA.csv — Trip rows ONLY (Empty Miles=0 is UNKNOWN) ---- */
{
  const rows = readRows('COMPLETE-UNIFIED-DATA.csv'); report.files['COMPLETE-UNIFIED-DATA.csv']={read:rows.length,accepted:0,skippedNonTrip:0};
  for (const r of rows){
    if (str(r.Type).toLowerCase()!=='trip'){ report.files['COMPLETE-UNIFIED-DATA.csv'].skippedNonTrip++; continue; }
    const orderNo = str(r['Order #']); if(!orderNo) continue;
    const loaded = num(r['Loaded Miles']);
    // Empty Miles == 0 is NOT trustworthy proof of zero deadhead -> UNKNOWN.
    upsertOrder(orderNo, {
      kind:'ORDER', stableId:orderNo, orderNo,
      broker: str(r.Broker)==='Unknown Broker'?'':str(r.Broker),
      origin: str(r.Origin), destination: str(r.Destination),
      pickupAt: iso(r['Pickup Date']), deliveryAt: iso(r['Delivery Date']),
      amount: num(r.Revenue), priceSemantic:'CARRIER_PAYOUT',
      loadedMi: loaded, deadMi: null, mileageSemantic: loaded!==null?'LOADED_MILES':'UNKNOWN_MILEAGE_SEMANTIC',
      displayedTotalMi: null, sourceDisplayedRpm: null,
      opportunity:'WON', execution: iso(r['Delivery Date'])?'DELIVERED':'NOT_STARTED', settlement:'NOT_INVOICED',
      deadZoneExit:false, operatorConfirmed:true, awarded:true,
      sourceName:'COMPLETE-UNIFIED-DATA.csv', sourceTimestamp: tsOf(r['Pickup Date']), rawEvidenceRef:`unified:${orderNo}`,
    }, 'unified');
    report.files['COMPLETE-UNIFIED-DATA.csv'].accepted++;
  }
}

/* ---- 4. RECOVERED (26) — CLAUDE-SECONDARY; status-driven; dry_run withheld ---- */
const withheld = [];
{
  const rows = readRows('RECOVERED_COMPLETED_ACCEPTED_LOADS_MAY_AUG_2026.csv'); report.files['RECOVERED']={read:rows.length,accepted:0,withheld:0};
  for (const r of rows){
    const status = str(r.status).toLowerCase();
    const orderNo = str(r.id);
    const loaded = num(r.loaded_miles), dead = num(r.deadhead_miles);
    const base = {
      broker:'', origin: str(r.origin), destination: str(r.destination),
      pickupAt: iso(r.date), deliveryAt: null,
      amount: num(r.final_rate), priceSemantic: num(r.final_rate)!==null?'CARRIER_PAYOUT':'UNKNOWN_PRICE_SEMANTIC',
      loadedMi: loaded, deadMi: dead, mileageSemantic: loaded!==null?'LOADED_MILES':'UNKNOWN_MILEAGE_SEMANTIC',
      displayedTotalMi: num(r.displayed_or_total_miles),
      // captured_rpm is a SOURCE-displayed RPM, never relabeled True RPM.
      sourceDisplayedRpm: num(r.captured_rpm),
      deadZoneExit:false, operatorConfirmed:false, // secondary per master handoff
      sourceName:'RECOVERED_COMPLETED_ACCEPTED_LOADS_MAY_AUG_2026.csv',
      sourceTimestamp: tsOf(r.date), rawEvidenceRef:`recovered:${orderNo||str(r.origin)+'-'+str(r.destination)+'-'+str(r.date)}`,
    };
    report.statuses[status]=(report.statuses[status]||0)+1;
    if (status==='dry_run'){ withheld.push({ reason:'dry_run (kept separate from normal freight economics)', status, ...base }); report.withheld.dry_run++; report.files['RECOVERED'].withheld++; continue; }
    const opp = (status==='completed'||status==='awarded'||status==='in_progress')?'WON':'SEEN';
    const exe = status==='completed'?'DELIVERED': status==='in_progress'?'EN_ROUTE_PICKUP':'NOT_STARTED';
    upsertOrder(orderNo || base.rawEvidenceRef, {
      kind:'ORDER', stableId: orderNo || base.rawEvidenceRef, orderNo: orderNo,
      opportunity:opp, execution:exe, settlement:'NOT_INVOICED', awarded:true, ...base,
    }, 'RECOVERED');
    report.files['RECOVERED'].accepted++;
  }
}

/* ---- 5. INCREMENTAL (9) — mixed; live_quote/partial NOT completed ---- */
const observations = [];
{
  const rows = readRows('FREIGHT_INCREMENTAL_LEDGER_2026-08-21_TO_2026-08-26.csv'); report.files['INCREMENTAL']={read:rows.length,accepted:0,observations:0,withheld:0};
  for (const r of rows){
    const status = str(r.status).toLowerCase();
    const orderNo = str(r.id);
    const loaded = num(r.loaded_miles), dead = num(r.empty_miles);
    const base = {
      broker:'', origin: str(r.origin), destination: str(r.destination),
      pickupAt: iso(r.date), deliveryAt: null,
      amount: num(r.final_rate) ?? num(r.submitted_bid) ?? num(r.target_rate),
      priceSemantic: num(r.final_rate)!==null?'CARRIER_PAYOUT': num(r.submitted_bid)!==null?'OPERATOR_BID':'UNKNOWN_PRICE_SEMANTIC',
      loadedMi: loaded, deadMi: dead, mileageSemantic: loaded!==null?'LOADED_MILES':'UNKNOWN_MILEAGE_SEMANTIC',
      displayedTotalMi: num(r.displayed_or_total_miles), sourceDisplayedRpm: num(r.displayed_rpm),
      deadZoneExit:false, operatorConfirmed:true, // operator-confirmed recent ledger
      sourceName:'FREIGHT_INCREMENTAL_LEDGER_2026-08-21_TO_2026-08-26.csv',
      sourceTimestamp: tsOf(r.date), rawEvidenceRef:`incr:${orderNo||''}:${str(r.origin)}-${str(r.destination)}-${str(r.date)}`,
    };
    report.statuses[status]=(report.statuses[status]||0)+1;
    if (status==='partial'){ withheld.push({ reason:'partial (not a completed trip)', status, ...base }); report.withheld.partial++; report.files['INCREMENTAL'].withheld++; continue; }
    if (status==='live_quote'){ observations.push({ kind:'QUOTE_OBSERVATION', opportunity:'SEEN', ...base }); report.withheld.live_quote++; report.files['INCREMENTAL'].observations++; continue; }
    if (status==='chat_captured'){ observations.push({ kind:'QUOTE_OBSERVATION', opportunity:'SEEN', ...base }); report.withheld.chat_captured++; report.files['INCREMENTAL'].observations++; continue; }
    // awarded / in_progress -> ORDER
    const opp='WON'; const exe = status==='in_progress'?'EN_ROUTE_PICKUP':'NOT_STARTED';
    upsertOrder(orderNo || base.rawEvidenceRef, { kind:'ORDER', stableId: orderNo||base.rawEvidenceRef, orderNo, opportunity:opp, execution:exe, settlement:'NOT_INVOICED', awarded:true, ...base }, 'INCREMENTAL');
    report.files['INCREMENTAL'].accepted++;
  }
}

/* ---- assemble + True-RPM defensibility check ---- */
const orderRecords = [...orders.values()];
for (const rec of orderRecords){
  const loadedKnown = rec.loadedMi!==null && rec.loadedMi!==undefined;
  const deadKnown = rec.deadMi!==null && rec.deadMi!==undefined;
  rec.trueRpmDefensible = loadedKnown && deadKnown; // both required
  if (!deadKnown) report.missingDeadhead++;
  if (!rec.trueRpmDefensible) report.withheldFromTrueRpm++;
  if (rec.sourceDisplayedRpm!==null && rec.sourceDisplayedRpm!==undefined) report.sourceRpmPreserved++;
  delete rec._sources;
}
const importRecords = [...orderRecords, ...observations];

report.totals = {
  reconciledOrderRecords: orderRecords.length,
  quoteObservations: observations.length,
  withheldRows: withheld.length,
  importRecords: importRecords.length,
};

writeFileSync(path.join(OUT,'records-for-import.json'), JSON.stringify(importRecords,null,2));
writeFileSync(path.join(OUT,'withheld.json'), JSON.stringify(withheld,null,2));
writeFileSync(path.join(OUT,'import-report.json'), JSON.stringify(report,null,2));
console.log(JSON.stringify(report,null,2));
