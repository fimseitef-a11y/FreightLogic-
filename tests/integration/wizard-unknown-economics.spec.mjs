import { launchApp, createSuite, skipFirstRunWizard, eq, ok } from '../lib/harness.mjs';
const {test,run}=createSuite('integration/wizard-unknown-economics.spec.mjs');
let app;
test('[FIN-AUDIT-WIZARD] unknown mileage does not become zero in the live preview',async()=>{
  const profile=await app.page.evaluate(async()=>{
    const api=window.__FL_TESTS;
    if(!api||typeof api.openTripWizard!=='function'||typeof api.setSetting!=='function'||typeof api.resolveCanonicalCostProfile!=='function'||!Number.isInteger(api.COST_MODEL_VERSION))throw new Error('Production economics/wizard APIs missing');
    for(const [key,value]of [['costModelVersion',api.COST_MODEL_VERSION],['vehicleMpg',20],['fuelPrice',4],['nonFuelVariableCpm',0.10],['fixedCostPerMile',0.05]])await api.setSetting(key,value);
    const resolved=await api.resolveCanonicalCostProfile();
    if(resolved.available!==true)throw new Error('Explicit fixture cost profile unavailable');
    await api.openTripWizard({_evalPrefill:true,orderNo:'UNKNOWN-DH-REGRESSION',pay:600,loadedMiles:100,emptyMiles:null});
    return resolved;
  });
  eq(profile.available,true);eq(profile.fuelSource,'USER');eq(profile.mpgSource,'USER');
  await app.page.locator('#f_pay').fill('600');
  await app.page.locator('#f_loaded').fill('100');
  await app.page.locator('#f_empty').fill('');
  const unknown=async()=>app.page.waitForFunction(()=>document.querySelector('#liveScore')?.textContent.includes('deadhead must be known'));
  await unknown();
  ok(!(await app.page.locator('#liveScore').innerText()).includes('True RPM'),'unknown deadhead hides precise RPM');
  eq(await app.page.evaluate(()=>window.__FL_TESTS.computeLoadScore({pay:600,loadedMiles:100,emptyMiles:null},[],[]).available),false);
  await app.page.locator('#f_empty').fill('0');
  await app.page.waitForFunction(()=>document.querySelector('#liveScore')?.textContent.includes('True RPM'));
  const zero=await app.page.evaluate(()=>window.__FL_TESTS.computeLoadScore({pay:600,loadedMiles:100,emptyMiles:0},[],[]));
  ok(zero.available!==false,'known cost prerequisites permit actual-zero branch: '+JSON.stringify(zero));eq(zero.rpm,6,'actual-zero deadhead produces canonical RPM6');
  ok((await app.page.locator('#liveScore').innerText()).includes('$6'),'actual-zero live preview renders RPM6');
  await app.page.locator('#f_empty').fill('20');
  await app.page.waitForFunction(()=>{const text=document.querySelector('#liveScore')?.textContent||'';return text.includes('True RPM')&&text.includes('$5');});
  eq(await app.page.evaluate(()=>window.__FL_TESTS.computeLoadScore({pay:600,loadedMiles:100,emptyMiles:20},[],[]).rpm),5);
  await app.page.locator('#f_empty').fill('');
  await unknown();ok(!(await app.page.locator('#liveScore').innerText()).includes('True RPM'),'clearing removes previous score');
  await app.page.locator('#f_empty').fill('0');
  await app.page.locator('#f_loaded').fill('');
  await unknown();ok(!(await app.page.locator('#liveScore').innerText()).includes('True RPM'),'blank loaded miles remain unknown');
  await app.page.locator('#f_loaded').fill('100');
  await app.page.waitForFunction(()=>document.querySelector('#liveScore')?.textContent.includes('True RPM'));
  await app.page.locator('#f_pay').fill('');await unknown();
  ok(!(await app.page.locator('#liveScore').innerText()).includes('True RPM'),'blank pay removes precise economics');
  await app.page.locator('#f_pay').fill('0');
  await app.page.waitForFunction(()=>document.querySelector('#liveScore')?.textContent==='');
});

test('[FIN-AUDIT-SCORE-01] unknown pay never becomes a scored factual zero',async()=>{
  const rows=await app.page.evaluate(()=>{
    const api=window.__FL_TESTS,profile=api.deriveCostProfile({costModelVersion:api.COST_MODEL_VERSION,vehicleMpg:20,fuelPrice:4,nonFuelVariableCpm:0.10,fixedCostPerMile:0.05});
    if(!profile.available)throw new Error('Cost fixture unavailable');
    return [undefined,null,'',' ',false,true,NaN,Infinity,{},'junk'].map((pay,index)=>({index,score:api.computeLoadScore({pay,loadedMiles:100,emptyMiles:0},[],[],profile)}));
  });
  for(const {index,score}of rows){eq(score.available,false,'unknown pay '+index);eq(score.verdict,'UNAVAILABLE');eq(score.rpm,null);eq(score.counterOffer,null);eq(score.fuelCost,null);}
});
test('[FIN-AUDIT-SCORE-02] actual zero and known amounts retain distinct economics; invalid bounds fail visibly',async()=>{
  const result=await app.page.evaluate(()=>{
    const api=window.__FL_TESTS,profile=api.deriveCostProfile({costModelVersion:api.COST_MODEL_VERSION,vehicleMpg:20,fuelPrice:4,nonFuelVariableCpm:0.10,fixedCostPerMile:0.05});
    if(!profile.available)throw new Error('Cost fixture unavailable');
    const score=trip=>api.computeLoadScore(trip,[],[],profile);
    return {
      zero:score({pay:0,loadedMiles:100,emptyMiles:0}),zeroString:score({pay:'0',loadedMiles:100,emptyMiles:'0'}),
      known:score({pay:600,loadedMiles:100,emptyMiles:0}),
      maximum:score({pay:600000,loadedMiles:300000,emptyMiles:0}),
      invalid:[score({pay:600,loadedMiles:300001,emptyMiles:0}),score({pay:600,loadedMiles:100,emptyMiles:null}),score({pay:600,loadedMiles:100,emptyMiles:-1}),score({pay:-1,loadedMiles:100,emptyMiles:0}),score({pay:'-1',loadedMiles:100,emptyMiles:0})]
    };
  });
  for(const score of [result.zero,result.zeroString]){ok(score.available!==false,'explicit zero amount remains available: '+JSON.stringify(score));eq(score.rpm,0);eq(score.trueProfit,-35);}
  eq(result.known.rpm,6);eq(result.known.trueProfit,565);ok(result.maximum.available!==false);eq(result.maximum.rpm,2);
  for(const score of result.invalid){eq(score.available,false);eq(score.rpm,null);}
});

export async function runSpec(){
  app=await launchApp();await skipFirstRunWizard(app.page);
  try{return await run();}finally{await app.close();}
}
if(import.meta.url==='file://'+process.argv[1]){
  const {stopServer}=await import('../lib/harness.mjs');const result=await runSpec();await stopServer();process.exit(result.fail?1:0);
}
