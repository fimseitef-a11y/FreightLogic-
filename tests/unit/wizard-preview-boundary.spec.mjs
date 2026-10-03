import {readFileSync} from 'node:fs';
import {createSuite,ok,eq} from '../lib/harness.mjs';
const {test,run}=createSuite('unit/wizard-preview-boundary.spec.mjs');
const appSource=readFileSync(new URL('../../app.js',import.meta.url),'utf8');
const start=appSource.indexOf('  async function updateLiveScore(){'),end=appSource.indexOf('  function debounceLiveScore(){',start);
if(start<0||end<start)throw new Error('Production wizard preview boundary missing');
const knownStart=appSource.indexOf('function knownNum('),knownEnd=appSource.indexOf('function tripHasKnownDeadhead(',knownStart);
if(knownStart<0||knownEnd<knownStart)throw new Error('Production numeric parser boundary missing');
const create=new Function('$','body','liveScoreEl','trip','mode','normOrderNo','_getTripsAndExps','renderLiveScore',appSource.slice(knownStart,knownEnd)+appSource.slice(start,end)+'return updateLiveScore;');
function fixture({pay='600',loaded='100',empty='',history=async()=>({trips:[],exps:[]})}={}){
  const fields={f_pay:{value:pay},f_loaded:{value:loaded},f_empty:{value:empty},f_customer:{value:'Test'},f_orderNo:{value:'preview'}};
  const view={textContent:'',innerHTML:''},rendered=[];
  const update=create(selector=>fields[selector.slice(1)],{},view,{},'new',x=>x,history,(_container,trip)=>rendered.push(trip));
  return {fields,view,rendered,update};
}
test('[FIN-AUDIT-PREVIEW-01] blank required inputs never enter scoring as zero',async()=>{
  for(const overrides of [{empty:''},{empty:' '},{pay:''},{loaded:''}]){
    const f=fixture(overrides);await f.update();eq(f.rendered.length,0);ok(f.view.textContent.includes('must be known'));
  }
});
test('[FIN-AUDIT-PREVIEW-02] actual zero remains an explicit input',async()=>{
  const f=fixture({pay:'0',empty:'0'});await f.update();eq(f.rendered.length,1);
  eq(f.rendered[0].pay,0);eq(f.rendered[0].emptyMiles,0);eq(f.rendered[0].loadedMiles,100);
});
test('[FIN-AUDIT-PREVIEW-03] clearing deadhead during the history await cannot restore a stale precise preview',async()=>{
  let release;const history=new Promise(resolve=>{release=resolve;});
  const f=fixture({empty:'20',history:()=>history}),pending=f.update();
  f.fields.f_empty.value='';release({trips:[],exps:[]});await pending;
  eq(f.rendered.length,0);ok(f.view.textContent.includes('must be known'));
});
export const runSpec=run;
