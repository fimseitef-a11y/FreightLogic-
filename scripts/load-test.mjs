#!/usr/bin/env node
// Bounded HTTP load harness. Production is refused unless an operator explicitly
// passes --allow-production; CI never does so. Intended for staging/local use.
const args=process.argv.slice(2);
const origin=(args.find(a=>a.startsWith('--origin='))||'--origin=http://127.0.0.1:4173').slice(9).replace(/\/$/,'');
const pathArg=(args.find(a=>a.startsWith('--path='))||'--path=/').slice(7);
const concurrency=Math.max(1,Math.min(200,Number((args.find(a=>a.startsWith('--concurrency='))||'--concurrency=20').split('=')[1])));
const total=Math.max(concurrency,Math.min(20000,Number((args.find(a=>a.startsWith('--requests='))||'--requests=500').split('=')[1])));
const allowProduction=args.includes('--allow-production');
const host=new URL(origin).hostname;
const productionHosts=new Set(['freightlogic-v2.fimseitef.workers.dev','freightlogic-backup.fimseitef.workers.dev','freightlogic-admin-console.fimseitef.workers.dev']);
if(productionHosts.has(host)&&!allowProduction){
  console.error('REFUSED: bounded load tests must run against local/staging, not FreightLogic production.');
  process.exit(2);
}
const times=[];let errors=0,next=0;const started=performance.now();
async function worker(){
  for(;;){
    const n=next++; if(n>=total)return;
    const t=performance.now();
    try{
      const r=await fetch(origin+pathArg,{redirect:'manual',signal:AbortSignal.timeout(10000)});
      await r.arrayBuffer().catch(()=>{});
      if(!r.ok)errors++;
    }catch{errors++;}
    times.push(performance.now()-t);
  }
}
await Promise.all(Array.from({length:concurrency},worker));
times.sort((a,b)=>a-b);
const pct=p=>times[Math.min(times.length-1,Math.floor((times.length-1)*p))]||0;
const seconds=(performance.now()-started)/1000;
const out={origin,path:pathArg,requests:total,concurrency,seconds:Number(seconds.toFixed(3)),rps:Number((total/seconds).toFixed(2)),errors,errorRate:Number((errors/total).toFixed(4)),p50Ms:Number(pct(.50).toFixed(1)),p95Ms:Number(pct(.95).toFixed(1)),p99Ms:Number(pct(.99).toFixed(1))};
console.log(JSON.stringify(out,null,2));
if(errors/total>0.01)process.exit(1);
