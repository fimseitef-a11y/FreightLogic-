#!/usr/bin/env node
// FreightLogic M6 — one-time historical import adapter for the operator's
// 2026-08-27 bundle. Reconciles the bundle's overlapping CSV snapshots into the
// normalized historical-record shape that importHistoricalOpportunities()
// (app.js, merged in v24.2) consumes, honoring every hard rule in the bundle's
// M6_IMPORT_README.md and the reconciliation rules in the master handoff.
//
// This is a file-specific ADAPTER, not doctrine. It computes no True RPM, sets
// no pricing, and never invents a missing fact.
//
// Issue #119 Batch B corrections (source audit:
// .agents/inbox/gpt-to-claude-batch-b-source-audit-2026-08-28.md):
//   B3  rows are no longer pre-collapsed by external order number alone;
//   B4  merging is authority-aware, so a later operator correction supersedes
//       an already-populated lower-authority value;
//   B5  per-field provenance survives the merge instead of being deleted;
//   B6  a source column named `Carrier` stays a carrier label;
//   B7  DRY RUN is imported as its own excluded operational class, not dropped;
//   B8  an unrecognized status never manufactures an award;
//   B9  full source timestamps keep their clock precision.
// Run:
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
// B9: preserve whatever precision the SOURCE actually carried. Slicing a full
// timestamp down to a date was a convenience that destroyed the clock evidence
// reused-ID disambiguation and evidence chronology depend on. A genuinely
// date-only source value stays date-only; nothing is widened either.
const iso = v => {
  const s = str(v);
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  if (/^\d{4}-\d{2}-\d{2}[T ]/.test(s) && Number.isFinite(Date.parse(s))) return s.replace(' ', 'T');
  return null;
};
const city = (c,s) => [str(c),str(s)].filter(Boolean).join(', ');
const tsOf = d => { const t=Date.parse(str(d)); return Number.isFinite(t)?t:null; };

/* ---- reconciled completed-ORDER ledger ---- */
const orders = new Map();
const report = { files:{}, statuses:{}, missingDeadhead:0, withheldFromTrueRpm:0, sourceRpmPreserved:0, reconciled:0, reusedIdKeptSeparate:0, withheld:{ live_quote:0, partial:0, chat_captured:0 }, dryRuns:0, unknownStatus:0 };

// B4: docs/EVIDENCE_PROVENANCE.md's precedence order, as data. Index IS the
// rank — lower outranks higher. The previous rule was "first source wins, later
// sources may only fill blanks", under which an explicit operator correction
// could never replace an already-populated AI-recovered guess.
const AUTHORITY_ORDER = [
  'OPERATOR_CORRECTION','PRIMARY_DOCUMENT','OPERATOR_CONFIRMED_HISTORY',
  'CANONICAL_DOCTRINE','VERIFIED_EXTERNAL_DOC','DERIVED_MATH','AI_SECONDARY',
];
const rank = a => { const i = AUTHORITY_ORDER.indexOf(a); return i < 0 ? AUTHORITY_ORDER.length : i; };
const present = v => v !== null && v !== undefined && v !== '';

// Material facts get field-level provenance. Everything else is structural.
const MATERIAL_FIELDS = [
  'broker','carrierLabel','origin','destination','pickupAt','deliveryAt',
  'amount','priceSemantic','loadedMi','deadMi','displayedTotalMi',
  'mileageSemantic','sourceDisplayedRpm','opportunity','execution','settlement',
];

// B3: identity is NOT the external order number. Two shipments genuinely reuse
// one order number across providers and across months, and collapsing on it
// destroys both.
//
// The order number is treated as what it is — a CANDIDATE signal. Rows sharing
// one are only merged when their supplied route/time facts are compatible;
// otherwise they stay separate and the app's conservative linker decides later
// with the full evidence in front of it.
//
// Compatibility mirrors the app's doctrine exactly. A missing fact is unknown
// and never conflicts. A LESS SPECIFIC value is not a contradiction either —
// these files spell the same city three ways ("Chicago" in one, "Chicago, IL"
// in another), and treating that as a conflict would split one shipment into
// three, which is just the opposite error. The comma boundary keeps that from
// becoming approximate matching: "Chicago" vs "Chicago Heights, IL" still
// conflicts, and so does "Chicago, IL" vs "Chicago, MO".
// Identical to the app's `_placeConflict` doctrine: compare TOKEN SEQUENCES, so
// "Deerfield, WI" and "Deerfield WI" are the same place (these files genuinely
// spell it both ways), and allow exactly one extra trailing two-letter state
// token as a qualification of a less specific value.
const placeTokens = v => String(v ?? '').toUpperCase().replace(/[.,]/g, ' ').trim().split(/\s+/).filter(Boolean);
function placeConflict(a, b){
  const x = placeTokens(a), y = placeTokens(b);
  if (!x.length || !y.length) return false;
  if (x.join(' ') === y.join(' ')) return false;
  const [shortSeq, longSeq] = x.length <= y.length ? [x, y] : [y, x];
  if (longSeq.length === shortSeq.length + 1
      && /^[A-Z]{2}$/.test(longSeq[longSeq.length - 1])
      && longSeq.slice(0, shortSeq.length).join(' ') === shortSeq.join(' ')) return false;
  return true;
}
function timeConflict(a, b){
  if (!a || !b) return false;
  const sa = String(a), sb = String(b);
  const dateOnly = v => /^\d{4}-\d{2}-\d{2}$/.test(v);
  if (dateOnly(sa) || dateOnly(sb)) return sa.slice(0,10) !== sb.slice(0,10);
  const ta = Date.parse(sa), tb = Date.parse(sb);
  if (!Number.isFinite(ta) || !Number.isFinite(tb)) return sa !== sb;
  return ta !== tb;
}
function partyConflict(a, b){
  const x = String(a ?? '').trim().toLowerCase(), y = String(b ?? '').trim().toLowerCase();
  if (!x || !y) return false;
  return x !== y;
}
function compatible(a, b){
  return !placeConflict(a.origin, b.origin)
      && !placeConflict(a.destination, b.destination)
      && !timeConflict(a.pickupAt, b.pickupAt)
      && !timeConflict(a.deliveryAt, b.deliveryAt)
      && !partyConflict(a.broker, b.broker);
}

function seedProvenance(cand, sourceName, authority){
  const fp = {};
  for (const f of MATERIAL_FIELDS){
    if (present(cand[f])) fp[f] = { sourceName, authority, rawEvidenceRef: cand.rawEvidenceRef || '' };
  }
  return fp;
}

function candidateKey(cand){
  return String(cand.orderNo ?? '').trim().toUpperCase();
}

function upsertOrder(_orderNoIgnored, cand, sourceName, authority){
  const candidates = candidateKey(cand);
  // No order number at all: nothing to reconcile against, so it is its own row.
  const bucket = candidates ? (orders.get(candidates) || []) : [];
  if (!candidates){
    orders.set('anon:' + orders.size, [{ ...cand, _sources:[sourceName], _fieldProvenance: seedProvenance(cand, sourceName, authority) }]);
    return;
  }
  const cur = bucket.find(existing => compatible(existing, cand));
  const auth = AUTHORITY_ORDER.includes(authority) ? authority : 'AI_SECONDARY';
  if (!cur){
    const rec = { ...cand, _sources: [sourceName], _fieldProvenance: seedProvenance(cand, sourceName, auth) };
    bucket.push(rec);
    orders.set(candidates, bucket);
    if (bucket.length > 1) report.reusedIdKeptSeparate++;
    return;
  }
  for (const k of Object.keys(cand)){
    if (k.startsWith('_')) continue;
    const v = cand[k];
    if (!present(v)) continue;
    if (!MATERIAL_FIELDS.includes(k)){
      if (!present(cur[k])) cur[k] = v;
      continue;
    }
    const held = cur._fieldProvenance[k];
    // B4: a higher-authority source supersedes an already-populated value; a
    // lower-authority one never does. An empty slot is filled by anything.
    if (!present(cur[k]) || !held || rank(auth) < rank(held.authority)){
      cur[k] = v;
      // B5: provenance follows the VALUE. A merged row must never keep one
      // row-level source label while carrying material facts from another file.
      cur._fieldProvenance[k] = { sourceName, authority: auth, rawEvidenceRef: cand.rawEvidenceRef || '' };
    }
  }
  if (!cur._sources.includes(sourceName)) cur._sources.push(sourceName);
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
      // B2: no `stableId` from an external order number. That value was trusted
      // ahead of broker/route compatibility by the core key builder, which
      // laundered a reused provider ID into internal identity.
      kind:'ORDER', orderNo,
      broker: str(r.Company),
      origin: city(r.Pickup_City,r.Pickup_State), destination: city(r.Delivery_City,r.Delivery_State),
      pickupAt: iso(r.Pickup_Date), deliveryAt: iso(r.Delivery_Date),
      amount: num(r.Gross_Pay), priceSemantic:'CARRIER_PAYOUT',
      loadedMi: null, deadMi: null, mileageSemantic:'DISPLAYED_TOTAL_MILES',
      displayedTotalMi: num(r.Miles), sourceDisplayedRpm: null,
      opportunity:'WON', execution: iso(r.Delivery_Date)?'DELIVERED':'NOT_STARTED', settlement:'NOT_INVOICED',
      deadZoneExit:false, operatorConfirmed:true, awarded:true,
      sourceName:'All_Trips_App_Import_v1.csv', sourceTimestamp: tsOf(r.Pickup_Date), rawEvidenceRef:`alltrips:${orderNo}`,
    }, 'All_Trips_App_Import_v1.csv', 'OPERATOR_CONFIRMED_HISTORY');
    report.files['All_Trips_App_Import_v1.csv'].accepted++;
  }
}

/* ---- 2. text 2.csv (58 completed orders, sparse) ---- */
{
  const rows = readRows('text 2.csv'); report.files['text 2.csv']={read:rows.length,accepted:0};
  for (const r of rows){
    const orderNo = str(r.Order_Number); if(!orderNo) continue;
    upsertOrder(orderNo, {
      kind:'ORDER', orderNo,
      // B6: this column is named `Carrier`. Nothing in the bundle documents it
      // as the broker, so it is preserved under its actual source semantic and
      // canonical `broker` is left UNKNOWN rather than guessed.
      broker: '', carrierLabel: str(r.Carrier),
      origin: str(r.Pickup_City), destination: str(r.Delivery_City),
      pickupAt: null, deliveryAt: iso(r.Completed_Date),
      amount: num(r.Gross_Pay), priceSemantic:'CARRIER_PAYOUT',
      loadedMi:null, deadMi:null, mileageSemantic: num(r.Total_Miles)!==null?'DISPLAYED_TOTAL_MILES':'UNKNOWN_MILEAGE_SEMANTIC',
      displayedTotalMi: num(r.Total_Miles), sourceDisplayedRpm: num(r.RPM),
      opportunity:'WON', execution: iso(r.Completed_Date)?'DELIVERED':'NOT_STARTED', settlement:'NOT_INVOICED',
      deadZoneExit:false, operatorConfirmed:true, awarded:true,
      sourceName:'text 2.csv', sourceTimestamp: tsOf(r.Completed_Date), rawEvidenceRef:`text2:${orderNo}`,
    }, 'text 2.csv', 'OPERATOR_CONFIRMED_HISTORY');
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
      kind:'ORDER', orderNo,
      broker: str(r.Broker)==='Unknown Broker'?'':str(r.Broker),
      origin: str(r.Origin), destination: str(r.Destination),
      pickupAt: iso(r['Pickup Date']), deliveryAt: iso(r['Delivery Date']),
      amount: num(r.Revenue), priceSemantic:'CARRIER_PAYOUT',
      loadedMi: loaded, deadMi: null, mileageSemantic: loaded!==null?'LOADED_MILES':'UNKNOWN_MILEAGE_SEMANTIC',
      displayedTotalMi: null, sourceDisplayedRpm: null,
      opportunity:'WON', execution: iso(r['Delivery Date'])?'DELIVERED':'NOT_STARTED', settlement:'NOT_INVOICED',
      deadZoneExit:false, operatorConfirmed:true, awarded:true,
      sourceName:'COMPLETE-UNIFIED-DATA.csv', sourceTimestamp: tsOf(r['Pickup Date']), rawEvidenceRef:`unified:${orderNo}`,
    }, 'COMPLETE-UNIFIED-DATA.csv', 'OPERATOR_CONFIRMED_HISTORY');
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

    // B7: a DRY RUN is real operational history. Withholding it entirely lost
    // the record; importing it as ordinary freight would corrupt economics.
    // It is imported under its own operational class, which the lifecycle
    // cohort excludes from normal-market calibration.
    if (status==='dry_run'){
      upsertOrder(orderNo || base.rawEvidenceRef, {
        kind:'ORDER', orderNo, operationalClass:'DRY_RUN', statusRaw: status,
        opportunity:'SEEN', execution:'NOT_STARTED', settlement:'NOT_INVOICED',
        awarded:false, dryRun:true, ...base,
      }, 'RECOVERED_COMPLETED_ACCEPTED_LOADS_MAY_AUG_2026.csv', 'AI_SECONDARY');
      report.dryRuns++; report.files['RECOVERED'].accepted++;
      continue;
    }

    // B8: only a RECOGNIZED status may claim an award. An unrecognized status
    // previously still carried `awarded:true` alongside `opportunity:'SEEN'` —
    // a record simultaneously claiming it was and was not won.
    const RECOGNIZED = { completed:'WON', awarded:'WON', in_progress:'WON', lost:'LOST', expired:'EXPIRED', cancelled:'CANCELLED' };
    const recognized = Object.prototype.hasOwnProperty.call(RECOGNIZED, status);
    if (!recognized) report.unknownStatus++;
    const opp = recognized ? RECOGNIZED[status] : 'SEEN';
    const exe = status==='completed'?'DELIVERED': status==='in_progress'?'EN_ROUTE_PICKUP':'NOT_STARTED';
    upsertOrder(orderNo || base.rawEvidenceRef, {
      kind:'ORDER', orderNo, statusRaw: status,
      opportunity:opp, execution:exe, settlement:'NOT_INVOICED',
      // Tri-state: an unrecognized status establishes nothing about award, so
      // it stays null rather than becoming a false `true` or a false `false`.
      awarded: recognized ? (opp === 'WON') : null,
      ...base,
    }, 'RECOVERED_COMPLETED_ACCEPTED_LOADS_MAY_AUG_2026.csv', 'AI_SECONDARY');
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
    if (status==='live_quote'){ observations.push({ kind:'QUOTE_OBSERVATION', opportunity:'SEEN', awarded:false, statusRaw:status, ...base }); report.withheld.live_quote++; report.files['INCREMENTAL'].observations++; continue; }
    if (status==='chat_captured'){ observations.push({ kind:'QUOTE_OBSERVATION', opportunity:'SEEN', awarded:null, statusRaw:status, ...base }); report.withheld.chat_captured++; report.files['INCREMENTAL'].observations++; continue; }
    // B8: same rule here — only a recognized status establishes an award.
    const RECOGNIZED_INC = { awarded:'WON', in_progress:'WON', completed:'WON', lost:'LOST', expired:'EXPIRED', cancelled:'CANCELLED' };
    const recognizedInc = Object.prototype.hasOwnProperty.call(RECOGNIZED_INC, status);
    if (!recognizedInc) report.unknownStatus++;
    const opp = recognizedInc ? RECOGNIZED_INC[status] : 'SEEN';
    const exe = status==='in_progress'?'EN_ROUTE_PICKUP': status==='completed'?'DELIVERED':'NOT_STARTED';
    upsertOrder(orderNo || base.rawEvidenceRef, {
      kind:'ORDER', orderNo, statusRaw: status,
      opportunity:opp, execution:exe, settlement:'NOT_INVOICED',
      awarded: recognizedInc ? (opp === 'WON') : null, ...base,
    }, 'FREIGHT_INCREMENTAL_LEDGER_2026-08-21_TO_2026-08-26.csv', 'OPERATOR_CONFIRMED_HISTORY');
    report.files['INCREMENTAL'].accepted++;
  }
}

/* ---- assemble + True-RPM defensibility check ---- */
const orderRecords = [...orders.values()].flat();
for (const rec of orderRecords){
  const loadedKnown = rec.loadedMi!==null && rec.loadedMi!==undefined;
  const deadKnown = rec.deadMi!==null && rec.deadMi!==undefined;
  rec.trueRpmDefensible = loadedKnown && deadKnown; // both required
  if (!deadKnown) report.missingDeadhead++;
  if (!rec.trueRpmDefensible) report.withheldFromTrueRpm++;
  if (rec.sourceDisplayedRpm!==null && rec.sourceDisplayedRpm!==undefined) report.sourceRpmPreserved++;
  // B5: field-level provenance is carried into the import record instead of
  // being deleted. A row whose amount came from one file and whose mileage came
  // from another must not present a single source label as if it owned both.
  rec.fieldProvenance = rec._fieldProvenance;
  rec.contributingSources = rec._sources;
  delete rec._sources;
  delete rec._fieldProvenance;
}
const importRecords = [...orderRecords, ...observations];

report.totals = {
  reconciledOrderRecords: orderRecords.length,
  quoteObservations: observations.length,
  dryRunRecords: report.dryRuns,
  unknownStatusRows: report.unknownStatus,
  withheldRows: withheld.length,
  importRecords: importRecords.length,
  multiSourceRecords: orderRecords.filter(r => (r.contributingSources || []).length > 1).length,
  reusedIdKeptSeparate: report.reusedIdKeptSeparate,
};

writeFileSync(path.join(OUT,'records-for-import.json'), JSON.stringify(importRecords,null,2));
writeFileSync(path.join(OUT,'withheld.json'), JSON.stringify(withheld,null,2));
writeFileSync(path.join(OUT,'import-report.json'), JSON.stringify(report,null,2));
console.log(JSON.stringify(report,null,2));
