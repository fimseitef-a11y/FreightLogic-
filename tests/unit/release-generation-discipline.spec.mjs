import {createSuite,eq,ok} from '../lib/harness.mjs';
import {generationVerdict,verifyGeneration} from '../../scripts/verify-release-generation.mjs';
const {test,run}=createSuite('unit/release-generation-discipline.spec.mjs');
test('[RG-01] changed runtime with reused generation fails even if all markers agree',()=>{
  eq(generationVerdict('24.0.10','24.0.10',['app.js']).ok,false,'reused generation rejected');
  eq(generationVerdict('24.0.10','24.0.10',['styles.css']).ok,false,'CSS also requires delivery generation');
});
test('[RG-02] forward generation passes; backwards and malformed versions fail',()=>{
  eq(generationVerdict('24.0.10','24.0.11',['app.js']).ok,true,'forward patch');
  eq(generationVerdict('24.0.10','24.0.9',['app.js']).ok,false,'numeric downgrade');
  eq(generationVerdict('24.0.10',null,[]).ok,false,'missing marker');
  eq(generationVerdict('24.0.10','24.0.10',[]).ok,true,'documentation-only commit');
});
test('[RG-03] exact checkout respects runtime release generation against its base',()=>{
  const r=verifyGeneration();ok(r.ok,JSON.stringify(r));
});
export const runSpec=run;
if(process.argv[1]?.endsWith('release-generation-discipline.spec.mjs')){const r=await run();process.exit(r.fail?1:0);}
