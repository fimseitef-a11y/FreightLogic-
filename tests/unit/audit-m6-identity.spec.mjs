import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('unit/audit-m6-identity.spec.mjs');
const script = fileURLToPath(new URL('../../scripts/m6-import.mjs', import.meta.url));
const source = readFileSync(script,'utf8');
const start = source.indexOf('// A value is UNKNOWN');
const end = source.indexOf('/* ---- 1.');
if(start<0 || end<start) throw new Error('Production M6 reconciliation boundaries missing');
function reconcile(rows){
  return new Function('rows',source.slice(start,end)+'\nfor (const r of rows) upsertOrder(r.orderNo,r,r.sourceName||"synthetic.csv",r.authority||"OPERATOR_CONFIRMED_HISTORY"); reconcileOrders(); return {records:[...orders.values()].flat(),report,iso};')(rows);
}
const first = {orderNo:'REUSED',broker:'Broker A',origin:'Chicago, IL',destination:'Toledo, OH',pickupAt:'2026-08-01',amount:500,sourceName:'a.csv'};
const second = {...first,destination:'Miami, FL',amount:600,sourceName:'b.csv'};
const sparse = {orderNo:'REUSED',amount:900,sourceName:'sparse.csv',authority:'OPERATOR_CORRECTION'};

test('[M6-AUDIT-01] ambiguous reused-ID evidence cannot overwrite either known load',()=>{
  const r=reconcile([first,second,sparse]);
  eq(r.records.length,3);
  eq(r.records.find(x=>x.destination==='Toledo, OH').amount,500);
  eq(r.records.find(x=>x.destination==='Miami, FL').amount,600);
  const unresolved=r.records.find(x=>x.identityResolution==='AMBIGUOUS');
  ok(unresolved && unresolved.amount===900 && unresolved.needsReview);
  eq(unresolved.identityCandidateCount,2);
});
test('[M6-AUDIT-02] sparse evidence arriving first produces the same unresolved result',()=>{
  const shape=r=>r.records.map(x=>[x.destination||'',x.amount,x.identityResolution||'']).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  eq(JSON.stringify(shape(reconcile([sparse,second,first]))),JSON.stringify(shape(reconcile([first,second,sparse]))));
});
test('[M6-AUDIT-03] provider conflicts remain separate on identical route/time/order',()=>{
  const r=reconcile([first,{...first,broker:'Broker B',amount:650,sourceName:'provider-b.csv'}]);
  eq(r.records.length,2);
  eq(r.records.find(x=>x.broker==='Broker A').amount,500);
  eq(r.records.find(x=>x.broker==='Broker B').amount,650);
});
test('[M6-AUDIT-04] uniquely supported stronger correction replaces value and provenance',()=>{
  const r=reconcile([first,{...first,amount:700,sourceName:'operator-correction.csv',authority:'OPERATOR_CORRECTION'}]);
  eq(r.records.length,1);
  eq(r.records[0].amount,700);
  eq(r.records[0]._fieldProvenance.amount.sourceName,'operator-correction.csv');
});
test('[M6-AUDIT-05] unsupported sparse identity remains unresolved even with one candidate',()=>{
  const r=reconcile([first,sparse]);
  eq(r.records.length,2);
  eq(r.records.find(x=>x.identityResolution==='INSUFFICIENT_IDENTITY').amount,900);
  eq(r.records.find(x=>x.destination).amount,500);
});
test('[M6-AUDIT-06] impossible calendar dates are rejected without losing real precision',()=>{
  const {iso}=reconcile([]);
  eq(iso('2026-02-30'),null);
  eq(iso('2026-02-30T10:00:00Z'),null);
  eq(iso('2028-02-29'),'2028-02-29');
  eq(iso('2026-08-01T14:03:25-04:00'),'2026-08-01T14:03:25-04:00');
});

function csv(rows){
  return rows.map(row=>row.map(v=>'"'+String(v??'').replaceAll('"','""')+'"').join(',')).join('\n')+'\n';
}
function runBundle(trips, sparseRows=[]){
  const dir=mkdtempSync(path.join(tmpdir(),'fl-m6-audit-'));
  try{
    const files={
      'All_Trips_App_Import_v1.csv':[['Order_Number','Company','Pickup_City','Pickup_State','Delivery_City','Delivery_State','Pickup_Date','Delivery_Date','Gross_Pay','Miles'],...trips],
      'text 2.csv':[['Order_Number','Carrier','Pickup_City','Delivery_City','Completed_Date','Gross_Pay','Total_Miles','RPM'],...sparseRows],
      'COMPLETE-UNIFIED-DATA.csv':[['Type','Order #','Broker','Origin','Destination','Pickup Date','Delivery Date','Revenue','Loaded Miles']],
      'RECOVERED_COMPLETED_ACCEPTED_LOADS_MAY_AUG_2026.csv':[['id','status']],
      'FREIGHT_INCREMENTAL_LEDGER_2026-08-21_TO_2026-08-26.csv':[['id','status']]
    };
    for(const [name,rows] of Object.entries(files)) writeFileSync(path.join(dir,name),csv(rows));
    execFileSync(process.execPath,[script,dir],{encoding:'utf8',timeout:15000});
    return {records:JSON.parse(readFileSync(path.join(dir,'records-for-import.json'),'utf8')),withheld:JSON.parse(readFileSync(path.join(dir,'withheld.json'),'utf8')),report:JSON.parse(readFileSync(path.join(dir,'import-report.json'),'utf8'))};
  } finally {rmSync(dir,{recursive:true,force:true});}
}
test('[M6-AUDIT-07] full CLI retains ambiguous evidence in explicit withheld output',()=>{
  const r=runBundle([
    ['REUSED','Broker A','Chicago','IL','Toledo','OH','2026-08-01','2026-08-02','500','100'],
    ['REUSED','Broker A','Chicago','IL','Miami','FL','2026-08-01','2026-08-02','600','200']
  ],[['REUSED','','','','','900','','']]);
  eq(r.records.length,2);
  eq(r.withheld.length,1);
  eq(r.withheld[0].amount,900);
  eq(r.withheld[0].identityResolution,'AMBIGUOUS');
  eq(r.report.totals.ambiguousIdentity,1);
  ok(r.withheld[0].reason.includes('operator reconciliation'));
});
test('[M6-AUDIT-08] full CLI keeps unknown amount/mileage nullable and observed zero distinct',()=>{
  const r=runBundle([
    ['UNKNOWN','Broker A','Chicago','IL','Toledo','OH','2026-08-01','2026-08-02','',''],
    ['ZERO','Broker A','Chicago','IL','Erie','PA','2026-08-01','2026-08-02','0','100']
  ]);
  const unknown=r.records.find(x=>x.orderNo==='UNKNOWN'),zero=r.records.find(x=>x.orderNo==='ZERO');
  eq(unknown.amount,null);eq(unknown.deadMi,null);eq(unknown.loadedMi,null);
  eq(unknown.trueRpmDefensible,false);
  eq(zero.amount,0);eq(zero.deadMi,null);eq(zero.trueRpmDefensible,false);
});
test('[M6-AUDIT-09] same route and order without shared event time cannot establish identity',()=>{
  const r=reconcile([first,{...first,pickupAt:null,amount:900,sourceName:'undated.csv'}]);
  eq(r.records.length,2);
  eq(r.records.find(x=>x.pickupAt).amount,500);
  eq(r.records.find(x=>x.identityResolution==='INSUFFICIENT_IDENTITY').amount,900);
});
test('[M6-AUDIT-10] missing provider cannot merge across a known provider boundary',()=>{
  const r=reconcile([first,{...first,broker:null,amount:900,sourceName:'unknown-provider.csv'}]);
  eq(r.records.length,2);
  eq(r.records.find(x=>x.broker).amount,500);
  eq(r.records.find(x=>x.identityResolution==='INSUFFICIENT_IDENTITY').amount,900);
});
export const runSpec=run;
