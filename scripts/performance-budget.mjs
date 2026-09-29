#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { gzipSync, brotliCompressSync, constants } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const targetJs=Number(process.env.FL_JS_GZIP_TARGET || 200*1024);
const maxJs=Number(process.env.FL_JS_GZIP_MAX || 400*1024);
const files=['app.js','styles.css','index.html'];

const rows=files.map(rel=>{
  const p=path.join(root,rel);
  const raw=readFileSync(p);
  const gzip=gzipSync(raw,{level:9}).length;
  const br=brotliCompressSync(raw,{params:{[constants.BROTLI_PARAM_QUALITY]:11}}).length;
  return {file:rel,raw:raw.length,gzip,brotli:br};
});

console.log('FreightLogic static performance budget');
for(const r of rows){
  console.log(`${r.file.padEnd(14)} raw=${r.raw} gzip=${r.gzip} brotli=${r.brotli}`);
}
const js=rows.find(r=>r.file==='app.js');
console.log(`JS gzip enterprise target <= ${targetJs} bytes; regression ceiling <= ${maxJs} bytes.`);
if(js.gzip>targetJs){
  console.warn(`TARGET GAP: app.js gzip is ${js.gzip-targetJs} bytes above the enterprise route target.`);
}
if(js.gzip>maxJs){
  console.error(`FAIL: app.js gzip ${js.gzip} exceeds regression ceiling ${maxJs}.`);
  process.exit(1);
}
if(process.argv.includes('--enforce-target') && js.gzip>targetJs) process.exit(2);
console.log('PASS: compressed JS stays within the current regression ceiling.');
