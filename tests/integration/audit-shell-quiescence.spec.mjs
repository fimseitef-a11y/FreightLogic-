// Real Chromium DOM mutation delivery against the shipped adapter.
// This is not physical-device performance or accessibility certification.
import {readFileSync} from 'node:fs';
import {launchBlank,createSuite,ok,eq} from '../lib/harness.mjs';
const SOURCE=readFileSync(new URL('../../modern-shell.js',import.meta.url),'utf8');
const {test,run}=createSuite('integration/audit-shell-quiescence.spec.mjs');
const FIXTURE='<!doctype html><html lang="en"><head><meta charset="utf-8"></head><body>'
  +'<header id="mainHeader"><div class="brand"><div class="title"><strong>FreightLogic</strong></div></div><div class="hdr-row"><div class="row"></div></div></header>'
  +'<main class="app"><section class="view" id="view-home"><div id="homeKPICard">Daily money</div><div id="homePositioningCard" style="display:none">Market evidence</div><div id="homePositionBanner">Position</div><div id="homeTripTrackCard">Tracking</div><div id="homeMoneyCard">Money</div><div id="homeMaintenanceAlert">Maintenance</div><div id="homeFuelNudge">Fuel</div><div id="homeWeeklyReport">Weekly report</div><div id="homeRecentTripsCard">Recent trips</div></section></main>'
  +'<div class="bottom"><nav class="nav"><a href="#home" data-nav="home">Today</a><a href="#loads" data-nav="loads">Loads</a><a href="#omega" data-nav="omega">Evaluate</a><a href="#trips" data-nav="trips">Trips</a><a href="#money" data-nav="money">Money</a></nav></div></body></html>';
async function mount(){
  const app=await launchBlank(),errors=[];app.page.on('pageerror',error=>errors.push(error.message));
  try{
    await app.page.setContent(FIXTURE,{waitUntil:'load'});
    await app.page.addScriptTag({content:SOURCE});
    await app.page.waitForFunction(()=>!!window.FreightLogicModernShell,null,{timeout:10000});
    return {...app,errors};
  }catch(error){await app.close();throw error;}
}
async function frames(page,action='none'){
  return page.evaluate(async action=>{
    const counts=[];let count=0;
    const observer=new MutationObserver(records=>{count+=records.length;});
    observer.observe(document.body,{childList:true,subtree:true,attributes:true,attributeFilter:['id','class','style','hidden','aria-label','aria-hidden','aria-expanded']});
    try{
      if(action==='show')document.getElementById('homePositioningCard').style.display='block';
      else if(action==='hide')document.getElementById('homePositioningCard').style.display='none';
      else if(action==='repeat')for(let i=0;i<10;i++)window.FreightLogicModernShell.installTodayCommandCenter();
      else if(action==='navigate')window.FreightLogicModernShell.navigate('trips');
      for(let i=0;i<24;i++){await new Promise(resolve=>requestAnimationFrame(resolve));counts.push(count);count=0;}
      return counts;
    }finally{observer.disconnect();}
  },action);
}
function settled(counts,message){eq(counts.slice(-8).reduce((sum,n)=>sum+n,0),0,message+': '+JSON.stringify(counts));}
test('[ASQ-01] initial adapter reaches DOM quiescence',async()=>{
  const app=await mount();try{
    settled(await frames(app.page),'unchanged writes must stop');eq(app.errors.length,0,JSON.stringify(app.errors));
    ok(await app.page.evaluate(()=>document.getElementById('view-home').classList.contains('today-command-v2')));
  }finally{await app.close();}
});
test('[ASQ-02] external visibility and disclosure synchronize then settle',async()=>{
  const app=await mount();try{
    await frames(app.page);settled(await frames(app.page,'show'),'show must settle');
    eq(await app.page.evaluate(()=>document.getElementById('homePositioningDisclosure').hidden),false);
    await app.page.click('#homePositioningDisclosure');settled(await frames(app.page),'expansion must settle');
    const state=await app.page.evaluate(()=>{
      const p=document.getElementById('homePositioningCard'),b=document.getElementById('homePositioningDisclosure');
      return {expanded:b.getAttribute('aria-expanded'),hidden:p.getAttribute('aria-hidden'),visible:getComputedStyle(p).display!=='none',classExpanded:p.classList.contains('today-position-expanded')};
    });
    eq(state.expanded,'true');eq(state.hidden,'false');eq(state.visible,true);eq(state.classExpanded,true);
    settled(await frames(app.page,'hide'),'hide must settle');
    eq(await app.page.evaluate(()=>{const b=document.getElementById('homePositioningDisclosure');return b.hidden&&b.getAttribute('aria-expanded')==='false';}),true);
    eq(app.errors.length,0,JSON.stringify(app.errors));
  }finally{await app.close();}
});
test('[ASQ-03] repeated synchronization is idempotent and navigation works',async()=>{
  const app=await mount();try{
    await frames(app.page);const repeated=await frames(app.page,'repeat');eq(repeated.reduce((sum,n)=>sum+n,0),0,'ten unchanged synchronizations perform no observed DOM writes');
    settled(await frames(app.page,'navigate'),'navigation must settle');
    const state=await app.page.evaluate(()=>({hash:location.hash,active:document.querySelector('.bottom .nav a[data-nav="trips"]').classList.contains('active'),label:document.querySelector('.bottom .nav a[data-nav="trips"]').getAttribute('aria-label')}));
    eq(state.hash,'#trips');eq(state.active,true);eq(state.label,'Trips');eq(app.errors.length,0,JSON.stringify(app.errors));
  }finally{await app.close();}
});
export const runSpec=run;
