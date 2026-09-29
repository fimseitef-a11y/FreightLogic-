#!/usr/bin/env node
import http from 'node:http';
import { performance } from 'node:perf_hooks';

const args=Object.fromEntries(process.argv.slice(2).map(x=>{
  const i=x.indexOf('=');
  return i<0?[x.replace(/^--/,'') ,true]:[x.slice(2,i),x.slice(i+1)];
}));
const PROD='https://freightlogic-backup.fimseitef.workers.dev';
const requests=Math.max(1,Math.min(5000,Number(args.requests||500)));
const concurrency=Math.max(1,Math.min(100,Number(args.concurrency||25)));
const timeoutMs=Math.max(1000,Math.min(30000,Number(args.timeout||10000)));
const maxErrorRate=Number(args.maxErrorRate||0.01);
const maxP95=Number(args.maxP95||750);

let localServer=null;
let target=String(args.target||'');
if(args.selfTest){
  localServer=http.createServer((req,res)=>{
    if(req.url==='/health'){res.writeHead(200,{'Content-Type':'application/json'});res.end('{"ok":true}');return;}
    res.writeHead(404);res.end();
  });
  await new Promise(r=>localServer.listen(0,'127.0.0.1',r));
  target=`http://127.0.0.1:${localServer.address().port}/health`;
}
if(!target){
  console.error('Usage: node scripts/load-test-worker.mjs --target=https://staging.example/health [--requests=5000 --concurrency=50]');
  console.error('For CI harness validation use --selfTest.');
  process.exit(2);
}
if(target.startsWith(PROD) && process.env.ALLOW_PRODUCTION_LOAD_TEST!=='I_UNDERSTAND'){
  console.error('REFUSED: production load testing is disabled by default. Use a staging/local target.');
  process.exit(3);
}

const latencies=[];
let errors=0, cursor=0;
const started=performance.now();
async function one(){
  const t0=performance.now();
  try{
    const res=await fetch(target,{cache:'no-store',signal:AbortSignal.timeout(timeoutMs)});
    await res.arrayBuffer();
    if(!res.ok) errors++;
  }catch{errors++;}
  latencies.push(performance.now()-t0);
}
await Promise.all(Array.from({length:Math.min(concurrency,requests)},async()=>{
  for(;;){
    const n=cursor++;
    if(n>=requests) return;
    await one();
  }
}));
const elapsed=(performance.now()-started)/1000;
latencies.sort((a,b)=>a-b);
const pct=p=>latencies[Math.min(latencies.length-1,Math.floor((latencies.length-1)*p))]||0;
const result={
  target: target.startsWith(PROD)?PROD:'non-production',
  requests,concurrency,elapsedSeconds:Number(elapsed.toFixed(3)),
  rps:Number((requests/elapsed).toFixed(1)),
  errors,errorRate:Number((errors/requests).toFixed(4)),
  p50Ms:Number(pct(.50).toFixed(1)),p95Ms:Number(pct(.95).toFixed(1)),p99Ms:Number(pct(.99).toFixed(1)),
};
console.log(JSON.stringify(result,null,2));
if(localServer) await new Promise(r=>localServer.close(r));
if(result.errorRate>maxErrorRate || result.p95Ms>maxP95){
  console.error(`FAIL: errorRate<=${maxErrorRate} and p95<=${maxP95}ms required.`);
  process.exit(1);
}
console.log('PASS: bounded load-test thresholds met.');
