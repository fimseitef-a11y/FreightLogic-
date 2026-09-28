// Issue #417 Slice D — vehicle identity/provenance contracts.
import { readFileSync } from 'node:fs';
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/product-ia-slice-d.spec.mjs');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function boot(){
  const app=await launchApp();
  await skipFirstRunWizard(app.page);
  await app.page.waitForFunction(() => !!window.__FL_TESTS, null, {timeout:10000});
  await sleep(400);
  return app;
}

test('[UXIA-11] two-step first run captures explicit carrier and Year Make Model Trim identity', async () => {
  // This contract is specifically the real first-run path. Do not suppress the
  // app's queued 800ms first-run check and then manually open a second wizard:
  // the queued check can re-render the modal while Playwright is filling step 2.
  const app=await launchApp();
  try{
    await app.page.waitForSelector('#wz_home');
    ok(await app.page.locator('#wz_home').count()===1,'step 1 remains Home');
    await app.page.fill('#wz_home','Milwaukee, WI');
    await app.page.click('#wzNext');
    await app.page.waitForSelector('#wz_carrier');
    for(const id of ['wz_carrier','wz_vyear','wz_vmake','wz_vmodel','wz_vtrim']){
      ok(await app.page.locator('#'+id).count()===1,id+' must exist on the single vehicle step');
    }
    await app.page.fill('#wz_carrier','Example Carrier');
    await app.page.fill('#wz_vyear','2016');
    await app.page.fill('#wz_vmake','Ford');
    await app.page.fill('#wz_vmodel','Transit T250');
    await app.page.fill('#wz_vtrim','148 Low Roof');
    await app.page.fill('#wz_payload','3000');
    await app.page.click('#wzNext');
    await sleep(500);
    const vals=await app.page.evaluate(async () => {
      const T=window.__FL_TESTS;
      return {
        done:await T.getSetting('f26SetupComplete',false),
        carrier:await T.getSetting('carrierName',''),
        year:await T.getSetting('vehicleYear',''),
        make:await T.getSetting('vehicleMake',''),
        model:await T.getSetting('vehicleModel',''),
        trim:await T.getSetting('vehicleTrim',''),
        identityProvenance:await T.getSetting('vehicleIdentityProvenance',null),
        limitProvenance:await T.getSetting('vanProfileProvenance',null),
        profile:await T.getVanProfile(),
      };
    });
    ok(vals.done,'setup must complete after exactly Home + Vehicle');
    eq(vals.carrier,'Example Carrier','carrier identity must persist');
    eq(vals.year,'2016','year must persist');
    eq(vals.make,'Ford','make must persist separately');
    eq(vals.model,'Transit T250','model must persist separately');
    eq(vals.trim,'148 Low Roof','trim must persist separately');
    eq(vals.identityProvenance?.source,'OPERATOR_ENTRY','identity provenance must record operator entry');
    eq(vals.limitProvenance?.fields?.payloadLbs?.source,'USER_OPERATING_LIMIT','onboarding payload must be a user operating limit');
    eq(vals.profile.payloadLbs,3000,'onboarding payload must feed the existing fit profile');
  } finally { await app.close(); }
});

test('[UXIA-11] standard-spec provider abstraction fails closed to UNKNOWN without an authorized provider', async () => {
  const app=await boot();
  try{
    const spec=await app.page.evaluate(() => window.__FL_TESTS.lookupStandardVehicleSpec({
      year:'2016',make:'Ford',model:'Transit T250',trim:'148 Low Roof'
    }));
    eq(spec.available,false,'no authorized provider means no standard spec');
    eq(spec.status,'UNKNOWN','unavailable spec must remain UNKNOWN');
    eq(spec.limits,null,'UNKNOWN spec must not fabricate zero/default limits');
    ok(/verified provider/i.test(spec.reason||''),'reason should make the authority boundary visible');
  } finally { await app.close(); }
});

test('[UXIA-11] standard spec cannot replace user limits without explicit confirmation', async () => {
  const app=await boot();
  try{
    const result=await app.page.evaluate(() => {
      const T=window.__FL_TESTS;
      const user={cargoLengthIn:121,cargoWidthIn:65,wheelWellWidthIn:54.8,cargoHeightIn:56,doorWidthIn:60,doorHeightIn:52,payloadLbs:3000};
      const spec={available:true,status:'AVAILABLE',providerId:'fixture-provider',specId:'fixture-2016-transit',
        limits:{cargoLengthIn:126,cargoWidthIn:70,wheelWellWidthIn:54.8,cargoHeightIn:72,doorWidthIn:61,doorHeightIn:70,payloadLbs:3598}};
      return {
        denied:T.planStandardSpecReplacement(user,spec,{confirmed:false}),
        confirmed:T.planStandardSpecReplacement(user,spec,{confirmed:true}),
      };
    });
    eq(result.denied.applied,false,'unconfirmed replacement must not apply');
    eq(result.denied.requiresConfirmation,true,'differences require explicit confirmation');
    eq(result.denied.profile.cargoLengthIn,121,'unconfirmed plan must preserve user limits');
    ok(result.denied.materialDivergence,'materially different published values must be identified');
    eq(result.confirmed.applied,true,'confirmed replacement may apply');
    eq(result.confirmed.profile.cargoLengthIn,126,'confirmed plan may use the standard spec value');
    eq(result.confirmed.provenance.source,'STANDARD_SPEC_CONFIRMED','confirmed replacement must persist source provenance');
    eq(result.confirmed.provenance.standardSpec.providerId,'fixture-provider','provider identity must travel with provenance');
  } finally { await app.close(); }
});

test('[UXIA-11] Settings renders STANDARD SPEC separately from USER OPERATING LIMIT and persists operator edits', async () => {
  const app=await boot();
  try{
    await app.page.evaluate(() => { location.hash='#insights'; });
    await sleep(500);
    await app.page.click('#advSettingsToggle');
    await app.page.waitForSelector('#vehicleIdentityCard');
    const labels=await app.page.evaluate(() => ({
      identity:document.getElementById('vehicleIdentityCard')?.innerText||'',
      standard:document.getElementById('standardVehicleSpecCard')?.innerText||'',
      limits:document.getElementById('userOperatingLimitsCard')?.innerText||'',
    }));
    ok(/Carrier/i.test(labels.identity) && /Year/i.test(labels.identity) && /Model/i.test(labels.identity),'identity card must expose explicit identity fields');
    ok(/STANDARD SPEC/i.test(labels.standard),'standard spec must be distinctly labelled');
    ok(/USER OPERATING LIMIT/i.test(labels.limits),'operator limit must be distinctly labelled');

    await app.page.fill('#carrierName','Settings Carrier');
    await app.page.fill('#vehicleYear','2020');
    await app.page.fill('#vehicleMake','Mercedes-Benz');
    await app.page.fill('#vehicleModel','Sprinter 2500');
    await app.page.fill('#vehicleTrim','144 High Roof');
    await app.page.fill('#vanCargoLengthIn','122');
    await app.page.fill('#vanPayloadLbs','2800');
    await app.page.click('#btnSaveSettings');
    await sleep(450);
    const saved=await app.page.evaluate(async () => {
      const T=window.__FL_TESTS;
      return {
        carrier:await T.getSetting('carrierName',''),
        model:await T.getSetting('vehicleModel',''),
        identity:await T.getSetting('vehicleIdentityProvenance',null),
        limits:await T.getSetting('vanProfileProvenance',null),
        profile:await T.getVanProfile(),
      };
    });
    eq(saved.carrier,'Settings Carrier','Settings carrier must persist');
    eq(saved.model,'Sprinter 2500','Settings model must persist');
    eq(saved.identity?.source,'OPERATOR_ENTRY','Settings identity edits must record operator provenance');
    eq(saved.limits?.source,'USER_OPERATING_LIMIT','saving limits must label them user operating limits');
    eq(saved.profile.cargoLengthIn,122,'fit evaluator profile must continue to read the saved operator limit');
    eq(saved.profile.payloadLbs,2800,'payload fit limit must remain operator-controlled');
  } finally { await app.close(); }
});

test('[UXIA-13] vehicle identity and provenance keys are portable but no credential authority is added', async () => {
  const app=await boot();
  try{
    const keys=['carrierName','vehicleYear','vehicleMake','vehicleModel','vehicleTrim','vehicleIdentityProvenance','vanProfileProvenance'];
    const exported=await app.page.evaluate(keys => {
      const T=window.__FL_TESTS;
      return T.exportSafeSettings(keys.map((key,i)=>({key,value:'v'+i}))).map(x=>x.key);
    },keys);
    for(const key of keys) ok(exported.includes(key),key+' must remain backup/export eligible');
    const source=readFileSync(new URL('../../app.js',import.meta.url),'utf8');
    for(const key of keys) ok(source.includes("'"+key+"'"),key+' must be present in the recognized import allow-list');
    ok(!source.includes('vehicleSpecApiKey'),'Slice D must not introduce external provider credentials');
  } finally { await app.close(); }
});

export async function runSpec(){ return run(); }
if(import.meta.url===`file://${process.argv[1]}`){
  const r=await runSpec();
  process.exit(r.fail>0?1:0);
}
