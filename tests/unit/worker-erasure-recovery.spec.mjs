// Erasure scope and interrupted child deletion use the real admin handler.
import { createSuite, ok, eq } from '../lib/harness.mjs';
import worker from '../../cloud-backup-worker.js';
const { test, run } = createSuite('unit/worker-erasure-recovery.spec.mjs');
const ADMIN='test-erasure-admin-token',TARGET='u_12345678',RELATED='u_1234567890abcdef',ACCOUNT='user:'+TARGET;
function makeKV(seed={}) {
  const map=new Map(Object.entries(seed)),deleted=[],failures=new Map();
  return {
    _map:map,deleted,failures,
    async get(key){return map.get(key)??null;},
    async put(key,value){map.set(key,value);},
    async delete(key){
      if((failures.get(key)||0)>0){failures.set(key,failures.get(key)-1);throw new Error('Injected deletion failure');}
      deleted.push(key);map.delete(key);
    },
    async list({prefix='',cursor}={}){
      const keys=[...map.keys()].filter(key=>key.startsWith(prefix)).sort(),offset=Number(cursor||0),next=offset+20;
      return {keys:keys.slice(offset,next).map(name=>({name})),list_complete:next>=keys.length,cursor:next<keys.length?String(next):''};
    }
  };
}
function seed(extra={}) {
  return {
    [ACCOUNT]:JSON.stringify({userId:TARGET,name:'Revoked test driver',tokenHash:'target-token-hash',active:false}),
    ['tokh:target-token-hash']:JSON.stringify({userId:TARGET,active:false}),
    ...extra
  };
}
async function erase(kv,confirm='ERASE') {
  return worker.fetch(new Request('https://worker.test/admin/users/'+TARGET+'/erase',{
    method:'POST',headers:{'X-Admin-Token':ADMIN,'Content-Type':'application/json','CF-Connecting-IP':'203.0.113.81'},
    body:JSON.stringify({userId:TARGET,confirm})
  }),{BACKUPS:kv,ADMIN_TOKEN:ADMIN});
}
test('[ER-01] erasure does not select a longer supported legacy account ID',async()=>{
  const related={
    ['user:'+RELATED]:JSON.stringify({userId:RELATED,active:true}),
    ['user:'+RELATED+':device:d:backup:one']:'related-encrypted-backup',
    ['user:'+RELATED+':device:d:dptr']:'{"keys":[],"count":0}',
    ['sck:related-shortcut']:JSON.stringify({userId:RELATED}),
    ['push:vapid']:'global-public-key-metadata'
  };
  const kv=makeKV(seed({['user:'+TARGET+':device:d:backup:one']:'target-backup',...related}));
  eq((await erase(kv)).status,200,'target erasure succeeds');
  eq(await kv.get(ACCOUNT),null,'target account deleted');
  eq(await kv.get('user:'+TARGET+':device:d:backup:one'),null,'target child deleted');
  for(const [key,value]of Object.entries(related))eq(await kv.get(key),value,'unrelated exact value preserved: '+key);
  eq(kv.deleted.at(-1),ACCOUNT,'canonical account deleted last');
});
test('[ER-02] failed second child batch preserves identity and retry removes orphan Shortcut alias',async()=>{
  const extra={};
  for(let i=0;i<55;i++)extra['user:'+TARGET+':device:d:backup:'+String(i).padStart(3,'0')]='ciphertext-'+i;
  extra['sckuser:'+TARGET]='{"hash":"target-shortcut"}';
  extra['sck:target-shortcut']=JSON.stringify({userId:TARGET});
  extra['sck:stale-shortcut']=JSON.stringify({userId:TARGET});
  extra['rem:index']=JSON.stringify([TARGET,RELATED]);
  const kv=makeKV(seed(extra)),original=await kv.get(ACCOUNT);
  kv.failures.set('sck:target-shortcut',1);
  eq((await erase(kv)).status,500,'failure visible, never success');
  eq(await kv.get(ACCOUNT),original,'revoked identity survives partial failure');
  ok(kv.deleted.length>=50,'fault after a completed first batch');
  ok(!kv.deleted.includes(ACCOUNT),'account not deleted in failed operation');
  eq(await kv.get('sckuser:'+TARGET),null,'shortcut metadata already deleted');
  ok(await kv.get('sck:target-shortcut'),'failed alias still exists for retry');
  eq((await erase(kv)).status,200,'real authenticated route resumes');
  eq(await kv.get(ACCOUNT),null,'identity removed after recovery');
  eq(await kv.get('sck:target-shortcut'),null,'alias recovered without metadata');
  eq(await kv.get('sck:stale-shortcut'),null,'exact-owner stale aliases removed');
  ok(![...kv._map.keys()].some(key=>key.startsWith('user:'+TARGET+':')),'no target child remains');
  eq(kv.deleted.at(-1),ACCOUNT,'canonical identity deleted last after retry');
  eq(await kv.get('rem:index'),JSON.stringify([RELATED]),'other reminder entry preserved');
});
test('[ER-03] failed final account deletion resumes after children are gone',async()=>{
  const child='user:'+TARGET+':device:d:backup:one',kv=makeKV(seed({[child]:'ciphertext'}));kv.failures.set(ACCOUNT,1);
  eq((await erase(kv)).status,500,'final deletion failure visible');
  eq(await kv.get(child),null,'child deletion completed');
  ok(await kv.get(ACCOUNT),'identity remains for retry');
  eq((await erase(kv)).status,200,'retry succeeds');eq(await kv.get(ACCOUNT),null,'identity erased');
});
test('[ER-04] revoke and confirmation gates prevent destructive deletion',async()=>{
  const kv=makeKV(seed());eq((await erase(kv,'NO')).status,400);eq(kv.deleted.length,0);
  const active=JSON.parse(await kv.get(ACCOUNT));active.active=true;await kv.put(ACCOUNT,JSON.stringify(active));
  eq((await erase(kv)).status,409,'active driver rejected');eq(kv.deleted.length,0);
});
export const runSpec=run;
if(import.meta.url==='file://'+process.argv[1]){
  const result=await runSpec();process.exit(result.fail>0?1:0);
}
