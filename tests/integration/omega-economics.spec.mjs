// Paused OMEGA continuation: drive actual app math, IndexedDB, KPI DOM and exports.
import { launchApp, createSuite, eq, ok, skipFirstRunWizard } from '../lib/harness.mjs';
const {test,run} = createSuite('integration/omega-economics.spec.mjs');
let app;
const econ = (overrides={}) => app.page.evaluate(o => window.__FL_TESTS.deriveUnifiedEconomics({revenue:140,effectiveRevenue:140,loadedMi:100,deadMi:0,mpg:20,fuelPrice:4,opCPM:0.4,borderAdminCost:0,...o}), overrides);
async function seed(rows){
  await app.page.evaluate(async rows => {
    const T=window.__FL_TESTS, db=await T.initDB();
    const storeName=db.objectStoreNames.contains('tripRecords')?'tripRecords':'trips';
    const tx=db.transaction(storeName,'readwrite'), store=tx.objectStore(storeName);
    store.clear();
    for(const [i,r] of rows.entries()) store.put({...T.sanitizeTrip({id:`omega-${i}`,orderNo:`OMEGA-${i}`,pickupDate:T.isoDate(),deliveryDate:T.isoDate(),pay:600,loadedMiles:100,emptyMiles:0}),...r,needsReview:false});
    await new Promise((resolve,reject)=>{tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);});
    db.close(); T.invalidateKPICache();
  },rows);
}
test('[OI-01] economics never rounds a just-below-floor RPM into the next grade',async()=>{
  for(const [floor,belowGrade,atGrade] of [[1.25,'F','E'],[1.4,'E','D'],[1.5,'D','C'],[1.6,'C','B'],[1.75,'B','A']]){
    const pay= floor*100-0.01, below=await econ({revenue:pay,effectiveRevenue:pay});
    ok(below.trueRPM<floor,`raw ${pay}/100 must remain below ${floor}`);
    const grades=await app.page.evaluate(({rpm,floor})=>[window.__FL_TESTS.deriveUnifiedGrade(rpm).raw.grade,window.__FL_TESTS.deriveUnifiedGrade(floor).raw.grade],{rpm:below.trueRPM,floor});
    eq(grades[0],belowGrade,'below boundary');eq(grades[1],atGrade,'exact boundary');
  }
});
test('[OI-02] negative, nonfinite and nonnumeric mileage cannot become zero or explosive RPM',async()=>{
  for(const key of ['loadedMi','deadMi']) for(const value of [-1,-100,Infinity,NaN,null,'',true,[],300001]){
    const e=await econ({[key]:value});eq(e.available,false,`${key}=${String(value)}`);eq(e.trueRPM,null,'no fabricated RPM');
  }
  eq((await econ({loadedMi:0})).available,false,'no loaded-mile denominator');
  eq((await econ({deadMi:0})).available,true,'explicit zero deadhead remains valid');
});
test('[OI-03] absent or invalid MPG and fuel price cannot produce profitable zero-fuel economics',async()=>{
  for(const value of [undefined,null,'',0,-1,Infinity,'bad']){
    const e=await econ({mpg:value});eq(e.available,false,'invalid mpg');eq(e.fuel,null,'fuel unknown');eq(e.trueProfit,null,'profit unknown');
  }
  for(const value of [undefined,null,'',-1,Infinity]) eq((await econ({fuelPrice:value})).available,false,'invalid price');
  eq((await econ({fuelPrice:0})).fuel,0,'explicit zero price is distinguishable from absence');
});
test('[OI-04] unknown trip mileage suppresses score and counteroffer; explicit zero scores normally',async()=>{
  const r=await app.page.evaluate(()=>{
    const T=window.__FL_TESTS,base={pay:600,loadedMiles:100};
    return [null,'',undefined,-2,0].map(emptyMiles=>T.computeLoadScore({...base,emptyMiles},[],[]));
  });
  for(const x of r.slice(0,4)){eq(x.verdict,'UNAVAILABLE','unknown score');eq(x.marginScore,null,'not zero score');eq(x.counterOffer,null,'no counteroffer');}
  eq(r[4].rpm,6,'known-zero score');
});
test('[OI-05] quick and full KPI paths retain gross but label incomplete whole-week RPM unknown',async()=>{
  await seed([{emptyMiles:0},{emptyMiles:null,pay:900}]);
  for(const fn of ['computeQuickKPIs','computeKPIs']){
    const r=await app.page.evaluate(async fn=>{await window.__FL_TESTS[fn]();return ['wkGross','wkAll','wkRpm','wkDeadhead'].map(id=>document.getElementById(id).textContent);},fn);
    ok(r[0].includes('1,500'),'gross includes both known payments');
    eq(r[1],'Unknown','all miles');eq(r[2],'Unknown','RPM');eq(r[3],'Unknown','deadhead percent');
  }
});
test('[OI-06] CSV retains raw unknown deadhead and leaves derived all miles/RPM blank',async()=>{
  await seed([{emptyMiles:null},{emptyMiles:0}]);
  const pending=app.page.waitForEvent('download');await app.page.evaluate(()=>window.__FL_TESTS.exportTripsCSV());
  const download=await pending, stream=await download.createReadStream();let text='';for await(const chunk of stream) text+=chunk.toString();
  const rows=await app.page.evaluate(text=>window.__FL_TESTS.parseCSVLines(text.replace(/^\uFEFF/,'').split(/\r?\n/)),text);
  const header=rows[0]||[], col=name=>header.indexOf(name);
  ok(col('EmptyMiles')>=0,'EmptyMiles header');ok(col('AllMiles')>=0,'AllMiles header');ok(col('RPM')>=0,'RPM header');
  eq(rows[1][col('EmptyMiles')],'','raw unknown empty');eq(rows[1][col('AllMiles')],'','derived all blank');eq(rows[1][col('RPM')],'','derived RPM blank');
  eq(rows[2][col('EmptyMiles')],'0','explicit zero');eq(rows[2][col('AllMiles')],'100','known total');eq(rows[2][col('RPM')],'6.00','known RPM');
});
test('[OI-07] persisted weekly P&L and share text do not turn unknown mileage/fuel into zero',async()=>{
  await seed([{emptyMiles:null}]);
  const r=await app.page.evaluate(async()=>{const T=window.__FL_TESTS;const report=await T.generateWeeklyPnL(T.getWeekId());return {report,text:T.formatWeeklyReportText(report)};});
  eq(r.report.grossRev,600,'gross retained');eq(r.report.avgRPM,null,'unknown RPM');eq(r.report.totalDeadMi,null,'unknown deadhead');eq(r.report.fuelEstimate,null,'unknown fuel');
  ok(r.text.includes('Avg RPM:          Unknown'),'share RPM unknown');ok(r.text.includes('Fuel Estimate:    Unknown'),'share fuel unknown');
});
test('[OI-08] weekly key maps back to the same Monday across year and DST boundaries',async()=>{
  for(const date of ['2026-01-05','2026-03-09','2026-09-14','2026-12-28','2027-01-04']){
    const result=await app.page.evaluate(async date=>{const T=window.__FL_TESTS;return T.generateWeeklyPnL(T.getWeekId(date+'T12:00:00'));},date);
    eq(result.weekStart,date,`week ${date}`);
  }
});
test('[OI-09] weekly image reaches a real download without the wkTripsArr initialization crash',async()=>{
  await seed([{emptyMiles:null}]);
  const pending=app.page.waitForEvent('download',{timeout:10000});await app.page.evaluate(()=>window.__FL_TESTS.generateWeeklyReport());
  const file=await pending;ok(file.suggestedFilename().endsWith('.png'),'weekly PNG generated');
});
test('[OI-10] authoritative density rejects city-name collisions and preserves actual anchors',async()=>{
  const r=await app.page.evaluate(()=>{
    const T=window.__FL_TESTS;
    return ['Calgary, AB','Daytona Beach, FL','North Chicago, IL','Gary, IN','Dayton, OH','St. Louis, MO','Cleveland, TN','Columbus, GA'].map(city=>({city,geo:T.mwGeoCheck('Chicago, IL',city)}));
  });
  for(const i of [0,1,2,6,7]) eq(r[i].geo.intoDensity,false,`${r[i].city} cannot borrow another city's density`);
  for(const i of [3,4,5]) eq(r[i].geo.intoDensity,true,`${r[i].city} anchor retained`);
});
test('[OI-11] place normalization preserves known identities and distinguishes collision pairs',async()=>{
  const r=await app.page.evaluate(()=>{const T=window.__FL_TESTS;return ['Dayton','Edmonton','Gary','Calgary'].map(x=>T.naLookupMarket(x)?.city);});
  eq(r[0],'dayton','Dayton');eq(r[1],'edmonton','Edmonton');eq(r[2],'gary','Gary');eq(r[3],'calgary','Calgary');
  // THE LOOKUP HALF ABOVE CANNOT FAIL ON THE DEFECT IT GUARDS, which is why the
  // normalizer half below exists. Verified by negative control: reverting BOTH
  // separator fixes in usaNormCity/caNormCity leaves this whole spec at 13/0.
  // Every name in a market table still resolves under the OLD rule — 'Dayton'
  // via usaNormCity (no US state is spelled 'on'), 'Edmonton' because the fuzzy
  // pass accepts key.startsWith(norm) so 'edmonton'.startsWith('edmont') still
  // matches. Only a name that is in NO table can show the letters being eaten,
  // and a lookup-based assertion can never reach one.
  const names=['Dayton','Boston','Edmonton','Gary','Calgary','Tacoma'];
  const norm=await app.page.evaluate(n=>{const T=window.__FL_TESTS;return n.map(x=>[T.usaNormCity(x),T.caNormCity(x)]);},names);
  for(const [i,name] of names.entries()){
    eq(norm[i][0],name.toLowerCase(),`usaNormCity keeps ${name} intact`);
    eq(norm[i][1],name.toLowerCase(),`caNormCity keeps ${name} intact`);
  }
  // Under the old rule caNormCity('Boston')->'bost', ('Dayton')->'dayt' and
  // usaNormCity('Tacoma')->'taco'. Boston and Tacoma are in no market table, so
  // they are the cases that actually fail when the rule regresses.
  // And the rule was NARROWED, not disabled: a genuinely separator-qualified
  // state or province is still stripped, by comma and by space alike.
  const q=await app.page.evaluate(()=>{const T=window.__FL_TESTS;
    return [T.usaNormCity('Dayton, OH'),T.usaNormCity('Dayton OH'),T.caNormCity('Toronto, ON'),T.caNormCity('Toronto ON')];});
  eq(q[0],'dayton','comma-qualified state stripped');eq(q[1],'dayton','space-qualified state stripped');
  eq(q[2],'toronto','comma-qualified province stripped');eq(q[3],'toronto','space-qualified province stripped');
});
test('[OI-13] missing setting fallbacks are caller-local while persisted zero remains authoritative',async()=>{
  const r=await app.page.evaluate(async()=>{const T=window.__FL_TESTS;const first=await T.getSetting('omegaFallbackProbe',0);const second=await T.getSetting('omegaFallbackProbe',17.5);await T.setSetting('omegaFallbackProbe',0);const persisted=await T.getSetting('omegaFallbackProbe',17.5);return [first,second,persisted];});
  eq(r[0],0,'first caller fallback');eq(r[1],17.5,'later caller fallback not poisoned');eq(r[2],0,'persisted explicit zero authoritative');
});
test('[OI-12] actual evaluator rejects negative deadhead before rendering a grade',async()=>{
  await app.page.evaluate(()=>{location.hash='#omega';});
  await app.page.waitForSelector('#evalAdvToggle');
  if (!(await app.page.isVisible('#mwOrigin'))) await app.page.click('#evalAdvToggle');
  await app.page.waitForSelector('#mwDeadMi');
  await app.page.fill('#mwOrigin','Chicago, IL');await app.page.fill('#mwDest','Detroit, MI');
  await app.page.fill('#mwLoadedMi','100');await app.page.fill('#mwRevenue','500');await app.page.fill('#mwDeadMi','-90');
  await app.page.evaluate(()=>window.__FL_TESTS.mwEvaluateLoad());
  const text=await app.page.locator('#mwEvalOutput').textContent();ok(text.includes('Enter deadhead miles'),'negative mileage rejected');
});
test('[OI-14] Home reading an unset MPG first cannot blank the evaluator\'s grade',async()=>{
  // The END-TO-END shape of the fallback-cache defect, and the reason it cost 22
  // assertions across six specs rather than one. OI-13 covers the seam in
  // isolation; this covers the actual production sequence, which is what broke:
  // Home renders before the evaluator and reads getSetting('vehicleMpg', 0), so
  // an operator who had never entered an MPG had a 0 nobody supplied standing in
  // canonical economics — which correctly refuses mpg<=0 — and an ordinary,
  // complete, perfectly gradeable load rendered no grade at all.
  await app.page.evaluate(async()=>{
    const db=await window.__FL_TESTS.initDB();
    const tx=db.transaction('settings','readwrite');
    tx.objectStore('settings').delete('vehicleMpg');
    await new Promise((res,rej)=>{tx.oncomplete=res;tx.onerror=()=>rej(tx.error);});
    db.close();
  });
  await app.page.reload({waitUntil:'load'});                         // empties SETTINGS_CACHE
  await app.page.waitForFunction(()=>!!window.__FL_TESTS);
  await app.page.evaluate(()=>window.__FL_TESTS.computeQuickKPIs());  // Home reads MPG first
  await app.page.evaluate(()=>{location.hash='#omega';});
  await app.page.waitForSelector('#evalAdvToggle');
  if (!(await app.page.isVisible('#mwOrigin'))) await app.page.click('#evalAdvToggle');
  await app.page.waitForSelector('#mwDeadMi');
  await app.page.fill('#mwOrigin','Chicago, IL');await app.page.fill('#mwDest','Detroit, MI');
  await app.page.fill('#mwLoadedMi','280');await app.page.fill('#mwRevenue','560');await app.page.fill('#mwDeadMi','0');
  await app.page.evaluate(()=>window.__FL_TESTS.mwEvaluateLoad());
  const state=await app.page.evaluate(()=>{const out=document.querySelector('#mwEvalOutput');
    return {text:out?.textContent||'',grade:out?.querySelector('.fl-eval-grade')?.textContent||null};});
  ok(!state.text.includes('Economics unavailable'),`a complete load must still grade when MPG was never set; got: ${state.text.slice(0,160)}`);
  ok(state.grade && state.grade!=='✕',`expected a real letter grade, got: ${JSON.stringify(state.grade)}`);
});
test('[OI-15] the rendered trip row never shows a loaded-only rate as True RPM',async()=>{
  // The fourth and last site of the v24.0.11 unknown-deadhead sweep, and the one
  // still rendering the coercion AS FACT. exportTripsCSV (OI-06), computeLoadScore
  // (OI-04) and renderLiveScore were closed then; tripRow() still computed
  // Number(t.loadedMiles||0)+Number(t.emptyMiles||0) and printed the result as a
  // $/mi figure with a letter-grade chip beside it — on the Home recent-trips list
  // and the Trips page, which are the two surfaces a driver actually looks at.
  // CLAUDE.md recorded it as reported-not-fixed and asked for exactly this test.
  //
  // Driven through the REAL renderer rather than a helper, because what was wrong
  // was what the driver SAW. tripRow() is not on __FL_TESTS, so this renders both
  // modes and reads the DOM.
  await seed([{orderNo:'OMEGA-UNK',emptyMiles:null},{orderNo:'OMEGA-ZERO',emptyMiles:0}]);
  const rows = await app.page.evaluate(async () => {
    const T = window.__FL_TESTS;
    const all = await T.dumpStore('trips');
    const pick = o => all.find(t => t.orderNo === o);
    const read = (node) => ({
      grade: node.querySelector('.fl-grade-chip')?.textContent?.trim() || '',
      text: node.textContent || '',
    });
    // Both modes: compact is Home, full is the Trips page.
    const out = {};
    for (const [key, orderNo] of [['unknown','OMEGA-UNK'],['zero','OMEGA-ZERO']]){
      const t = pick(orderNo);
      out[key] = { compact: read(T.tripRow(t,{compact:true})), full: read(T.tripRow(t)) };
    }
    return out;
  });

  // UNKNOWN deadhead: no rate, no grade. `$6.00/mi` is what it used to print —
  // the loaded-only rate, indistinguishable from a real one.
  for (const mode of ['compact','full']){
    ok(!/\$\d+\.\d\d\s*\/\s*mi/.test(rows.unknown[mode].text),
      `${mode}: an unstated deadhead must not render a $/mi rate, got: ${rows.unknown[mode].text.slice(0,140)}`);
    ok(['—','?',''].includes(rows.unknown[mode].grade),
      `${mode}: an unstated deadhead must not earn a letter grade, got "${rows.unknown[mode].grade}"`);
  }

  // EXPLICIT ZERO is a verified fact and must still grade normally — the control
  // that keeps the fix from being "hide everything".
  ok(/\$6\.00/.test(rows.zero.full.text),
    `an explicit zero deadhead must still show its real $6.00/mi, got: ${rows.zero.full.text.slice(0,140)}`);
  ok(/^[A-F]$/.test(rows.zero.compact.grade),
    `an explicit zero deadhead must still earn a real letter grade, got "${rows.zero.compact.grade}"`);
});

export async function runSpec(){app=await launchApp();await skipFirstRunWizard(app.page);await app.page.reload({waitUntil:'load'});await app.page.waitForFunction(()=>!!window.__FL_TESTS);try{return await run();}finally{await app.close();}}
if(process.argv[1]?.endsWith('omega-economics.spec.mjs')){const r=await runSpec();process.exit(r.fail?1:0);}
