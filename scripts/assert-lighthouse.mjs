#!/usr/bin/env node
import { readFileSync } from 'node:fs';

const files=process.argv.slice(2);
if(!files.length){console.error('Usage: node scripts/assert-lighthouse.mjs <report...>');process.exit(2);}
const reports=files.map(f=>JSON.parse(readFileSync(f,'utf8')));
const median=values=>{const a=values.filter(Number.isFinite).sort((x,y)=>x-y);return a.length?a[Math.floor(a.length/2)]:NaN;};
const metric=id=>median(reports.map(r=>Number(r.audits?.[id]?.numericValue)));
const score=median(reports.map(r=>Number(r.categories?.performance?.score)));
const values={
  score,
  lcp:metric('largest-contentful-paint'),
  cls:metric('cumulative-layout-shift'),
  tbt:metric('total-blocking-time'),
  fcp:metric('first-contentful-paint'),
  speedIndex:metric('speed-index'),
};
console.log('Lighthouse median:',JSON.stringify(values,null,2));
const limits={
  scoreMin:Number(process.env.FL_LH_SCORE_MIN||0.75),
  lcpMax:Number(process.env.FL_LH_LCP_MAX||2500),
  clsMax:Number(process.env.FL_LH_CLS_MAX||0.10),
  tbtMax:Number(process.env.FL_LH_TBT_MAX||300),
};
const failures=[];
if(!(values.score>=limits.scoreMin))failures.push(`performance score ${values.score} < ${limits.scoreMin}`);
if(!(values.lcp<=limits.lcpMax))failures.push(`LCP ${values.lcp}ms > ${limits.lcpMax}ms`);
if(!(values.cls<=limits.clsMax))failures.push(`CLS ${values.cls} > ${limits.clsMax}`);
if(!(values.tbt<=limits.tbtMax))failures.push(`TBT ${values.tbt}ms > ${limits.tbtMax}ms`);
if(failures.length){for(const f of failures)console.error('FAIL:',f);process.exit(1);}
console.log('PASS: Lighthouse median stays inside performance regression gates.');
console.log('NOTE: INP is a field metric; this lab gate uses TBT as the interaction-responsiveness proxy and does not invent an INP value.');
