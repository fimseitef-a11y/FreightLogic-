import { readFileSync,readdirSync } from 'node:fs';
import { createSuite,ok,eq } from '../lib/harness.mjs';
import { assetsIgnoreMatcher } from '../../scripts/lib/deploy-assets.mjs';
import { runSpec as workerErasureRecovery } from './worker-erasure-recovery.spec.mjs';
import { runSpec as wizardPreviewBoundary } from './wizard-preview-boundary.spec.mjs';
import { runSpec as wizardUnknownEconomics } from '../integration/wizard-unknown-economics.spec.mjs';
const {test,run}=createSuite('unit/audit-ci-integrity.spec.mjs');
const read=p=>readFileSync(new URL('../../'+p,import.meta.url),'utf8');
const wf=n=>read('.github/workflows/'+n+'.yml');
test('[CI-AUDIT-01] ELI, Agent and native checks cover main PR/push without path omissions',()=>{
 for(const name of ['eli-runtime','ai-agent-cutover','native-ios']){
   const source=wf(name),triggers=source.slice(source.indexOf('\non:'),source.indexOf('\npermissions:'));
   ok(/pull_request:/.test(triggers),name+' PR coverage');
   ok(/push:/.test(triggers),name+' push coverage');
   ok(!/\n\s+paths:/.test(triggers),name+' upstream contract paths cannot bypass checks');
 }
});
test('[CI-AUDIT-02] both API deployment paths serialize the same resource',()=>{
 const group=s=>s.match(/\n\s+group:\s*(\S+)/)?.[1];
 const agent=wf('ai-agent-cutover'),backup=wf('deploy-backup-worker');
 const job=name=>agent.split('\n  '+name+':\n')[1]?.split(/\n  [a-z][a-z-]*:\n/)[0]||'';
 for(const name of ['dark-cutover','activate-canary']){
   const block=job(name);ok(block,name+' exists');
   eq(group(block),group(backup),name+' serializes the API deployment resource');
   ok(/cancel-in-progress:\s*false/.test(block),name+' cannot cancel a live deployment');
 }
 ok(/cancel-in-progress:\s*false/.test(backup));
 ok(!job('contract').includes('group: '+group(backup)),'contract checks cannot hold production approval lock');
});
test('[CI-AUDIT-03] privileged backup/admin deployment requires main and an environment',()=>{
 for(const name of ['deploy-backup-worker','deploy-admin-console']){
   const source=wf(name);
   ok(source.includes("github.ref != 'refs/heads/main'"));
   ok(/\n\s+environment:\s*production-/.test(source));
   ok(source.includes("github.event.inputs.confirm != 'DEPLOY'"));
 }
});
test('[CI-AUDIT-04] every ELI subtree file is withheld by the actual asset matcher',()=>{
 const match=assetsIgnoreMatcher(),root=new URL('../../eli-runtime/',import.meta.url);
 let files=0;
 function visit(url,relative){
   for(const item of readdirSync(url,{withFileTypes:true})){
     const p=relative+item.name;
     if(item.isDirectory()) visit(new URL(item.name+'/',url),p+'/');
     else {files++;ok(match(p).excluded,p+' must be repository-only');}
   }
 }
 visit(root,'eli-runtime/');ok(files>10);
});
test('[CI-AUDIT-05] public-withholding probes refer to existing private source paths',()=>{
 const source=read('scripts/verify-cloudflare-parity.mjs');
 ok(source.includes("'schemas/broker-memory-schema.json'"));
 ok(!source.includes("'schemas/broker-memory.schema.json'"));
 ok(source.includes("'eli-runtime/worker.mjs'"));
 ok(source.includes("'agent-runtime/worker.mjs'"));
});
test('[CI-AUDIT-06] manifest shortcuts use implemented entry actions',()=>{
 const shortcuts=JSON.parse(read('manifest.json')).shortcuts;
 eq(shortcuts[0].url,'./#do=trip');eq(shortcuts[1].url,'./#omega');
});

function mergeResults(results){
 return results.reduce((total,result)=>({
   pass:total.pass+(result?.pass||0),
   fail:total.fail+(result?.fail||0),
   skip:total.skip+(result?.skip||0),
 }),{pass:0,fail:0,skip:0});
}

// The aggregate runner enumerates specs explicitly. Keep the resumed audit
// regressions mechanically attached to an already-registered audit entry so a
// missing registration cannot produce a false-green PR.
export async function runSpec(){
 return mergeResults([
   await run(),
   await workerErasureRecovery(),
   await wizardPreviewBoundary(),
   await wizardUnknownEconomics(),
 ]);
}
