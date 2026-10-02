import { readFileSync } from 'node:fs';
import { createSuite, ok, eq } from '../lib/harness.mjs';
const {test,run}=createSuite('unit/audit-storage-recovery.spec.mjs');
const source=readFileSync(new URL('../../app.js',import.meta.url),'utf8');
const start=source.indexOf('async function initDB(){'),end=source.indexOf('// ── Legacy DB migration:',start);
if(start<0 || end<start) throw new Error('Production initDB boundary missing');
const create=new Function('indexedDB','DB_NAME','DB_VERSION','toast',source.slice(start,end)+'\nreturn initDB;');
for(const name of ['VersionError','QuotaExceededError','UnknownError']){
  test('[DB-AUDIT] '+name+' preserves storage and reports the original error',async()=>{
    const error=Object.assign(new Error(name),{name}),req={error};
    let deletes=0;
    const idb={open(){Promise.resolve().then(()=>req.onerror());return req;},deleteDatabase(){deletes++;}};
    let rejected;
    try{await create(idb,'FreightLogic_v18',16,()=>{})();}catch(e){rejected=e;}
    eq(rejected,error);eq(deletes,0,'An open failure must not delete data');
  });
}
test('[DB-AUDIT] successful connection closes on version change and announces reload',async()=>{
  let closes=0;const messages=[],connection={close(){closes++;}},req={result:connection};
  const idb={open(){Promise.resolve().then(()=>req.onsuccess());return req;}};
  const result=await create(idb,'FreightLogic_v18',16,(...args)=>messages.push(args))();
  eq(result,connection);ok(typeof connection.onversionchange==='function');
  connection.onversionchange();eq(closes,1);ok(messages[0][0].includes('Reload'));eq(messages[0][1],true);
});
export const runSpec=run;
