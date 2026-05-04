(function(){'use strict';
window._flAdminUiJs=true;
const API='https://freightlogic-backup.fimseitef.workers.dev';
const $=id=>document.getElementById(id);
const T=(m,e)=>{try{window.toast?window.toast(m,!!e):console[e?'warn':'log'](m)}catch(_){console[e?'warn':'log'](m)}};
const H=()=>{try{window.haptic&&window.haptic(10)}catch(_){}};
const X=s=>String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

const LOC_KEY='fl_admin_tok';
function saveTok(v){try{if(v)localStorage.setItem(LOC_KEY,v);else localStorage.removeItem(LOC_KEY)}catch(_){}}
function loadTok(){try{return localStorage.getItem(LOC_KEY)||''}catch(_){return''}}
function getTok(){return(($('adminToken')||{}).value||'').trim()||loadTok()}
const G=()=>({'Content-Type':'application/json','X-Admin-Token':getTok()});
const Q=async(u,o)=>{let r=await fetch(API+u,o||{}),j=await r.json().catch(()=>null);if(!r.ok||!j||j.ok===false)throw Error(j&&j.error||`HTTP ${r.status}`);return j};
const R=id=>{let e=$(id);if(!e)return null;let n=e.cloneNode(true);e.parentNode.replaceChild(n,e);return n};

function initials(name){
  return String(name||'?').trim().split(/\s+/).slice(0,2).map(w=>w[0]||'').join('').toUpperCase()||'?';
}
function buildInviteLink(token){
  try{return window.location.origin+window.location.pathname+'?token='+encodeURIComponent(token)}
  catch(_){return API+'?token='+encodeURIComponent(token)}
}
function shareInvite(name,token){
  let link=buildInviteLink(token);
  let text='Hi '+name+'! Here\'s your FreightLogic setup link:\n\n'+link+'\n\nOpen it, pick a passphrase (8+ chars), tap Connect — done!';
  if(navigator.share){navigator.share({text}).catch(()=>copyLink(link))}else copyLink(link);
}
function copyLink(text){
  navigator.clipboard.writeText(text).then(()=>T('Link copied')).catch(()=>{
    let ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;opacity:0';
    document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);T('Link copied');
  });
}

function renderTokenState(){
  let saved=loadTok();
  let wrap=$('adminTokenWrap'),bar=$('adminConnectedBar'),inp=$('adminToken');
  if(!wrap||!bar||!inp)return;
  if(saved){wrap.style.display='none';bar.style.display='flex';}
  else{wrap.style.display='';bar.style.display='none';}
}

async function loadUsers(){
  let box=$('adminUserList'),tok=getTok();
  if(!box)return;
  if(!tok){
    box.innerHTML='<div style="color:var(--text-tertiary);font-size:12px;text-align:center;padding:12px 0">Enter your admin token above.</div>';
    return;
  }
  box.innerHTML='<div style="color:var(--text-tertiary);font-size:12px;padding:8px 0">Loading…</div>';
  try{
    let d=await Q('/admin/users',{method:'GET',headers:G()}),u=Array.isArray(d.users)?d.users.slice():[];
    u.sort((a,b)=>String(b.createdAt||'').localeCompare(String(a.createdAt||'')));
    let active=u.filter(v=>v.active).length;
    let hdr='<div style="font-size:11px;font-weight:700;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:.5px;padding-bottom:8px;border-bottom:1px solid var(--border-subtle);margin-bottom:6px">'
      +(u.length?u.length+' driver'+(u.length!==1?'s':'')+(active<u.length?' · '+active+' active':''):'No drivers yet')+'</div>';
    if(!u.length){box.innerHTML=hdr+'<div style="color:var(--text-tertiary);font-size:13px;text-align:center;padding:14px 0">Add the first driver above ↑</div>';return;}
    let rows=u.map(v=>{
      let ini=initials(v.name),isActive=v.active,backups=v.backupCount||0,joined=(v.createdAt||'').slice(0,10);
      return'<div class="au-row" data-u="'+X(v.userId||'')+'" style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border-subtle)">'
        +'<div style="width:40px;height:40px;border-radius:50%;background:var(--surface-2);border:1.5px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:800;color:'+(isActive?'var(--accent-text)':'var(--text-tertiary)')+';flex-shrink:0">'+X(ini)+'</div>'
        +'<div style="flex:1;min-width:0">'
          +'<div style="font-size:14px;font-weight:700;display:flex;align-items:center;gap:6px;flex-wrap:wrap">'+X(v.name)
            +'<span style="font-size:10px;font-weight:700;padding:2px 7px;border-radius:20px;background:'+(isActive?'rgba(52,211,153,.15)':'var(--surface-2)')+';color:'+(isActive?'var(--good)':'var(--text-tertiary)')+'">'+( isActive?'Active':'Revoked')+'</span>'
          +'</div>'
          +'<div style="font-size:11px;color:var(--text-tertiary);margin-top:2px">'+backups+' backup'+(backups!==1?'s':'')+' · joined '+X(joined)+'</div>'
        +'</div>'
        +(isActive?'<button type="button" class="btn sm danger au-revoke" style="font-size:11px;padding:6px 10px;flex-shrink:0">Revoke</button>':'')
      +'</div>';
    }).join('');
    box.innerHTML=hdr+rows;
    box.querySelectorAll('.au-revoke').forEach(btn=>btn.onclick=async()=>{
      let id=btn.closest('[data-u]')?.getAttribute('data-u');if(!id)return;
      if(!confirm('Revoke this driver\'s access?\nThey won\'t be able to back up or restore.'))return;
      btn.disabled=true;btn.textContent='…';
      try{await Q('/admin/users/'+encodeURIComponent(id),{method:'DELETE',headers:G()});T('Access revoked');H();loadUsers();}
      catch(e){btn.disabled=false;btn.textContent='Revoke';T(e.message||'Failed',1);}
    });
  }catch(e){box.innerHTML='<div style="color:var(--bad);font-size:12px;padding:8px 0">'+X(e.message||'Could not load drivers')+'</div>';}
}

async function createUser(){
  let nameEl=$('adminDriverName'),name=(nameEl?.value||'').trim();
  if(!name){T('Enter a driver name',1);nameEl?.focus();return;}
  let tok=getTok();if(!tok){T('Enter admin token first',1);return;}
  let btn=$('btnAdminCreate');if(btn){btn.disabled=true;btn.textContent='Adding…';}
  let res=$('adminCreateResult');
  if(res){res.style.display='';res.innerHTML='<div style="color:var(--text-tertiary);font-size:12px;padding:6px 0">Creating account…</div>';}
  try{
    let d=await Q('/admin/users',{method:'POST',headers:G(),body:JSON.stringify({name})}),dName=d.name||name;
    let link=buildInviteLink(d.token);
    if(res){
      res.innerHTML=
        '<div style="border:1.5px solid var(--good-border);border-radius:12px;padding:14px 14px 12px;background:var(--surface-0);margin-top:4px">'
          +'<div style="font-size:14px;font-weight:800;color:var(--good);margin-bottom:6px">✓ '+X(dName)+' added</div>'
          +'<div style="font-size:12px;color:var(--text-secondary);line-height:1.55;margin-bottom:10px">Send them this link — they open it, pick a passphrase, tap Connect. No token typing needed.</div>'
          +'<div style="background:var(--surface-2);border-radius:8px;padding:8px 10px;font-size:11px;word-break:break-all;color:var(--text-tertiary);margin-bottom:10px;border:1px solid var(--border-subtle);line-height:1.5">'+X(link)+'</div>'
          +'<div style="display:flex;gap:8px">'
            +'<button type="button" class="btn primary" id="btnShareNew" style="flex:2;font-weight:700;font-size:14px">📤 Send to '+X(dName)+'</button>'
            +'<button type="button" class="btn" id="btnCopyNew" style="flex:1">Copy</button>'
          +'</div>'
        +'</div>';
      let sb=$('btnShareNew'),cb=$('btnCopyNew');
      if(sb)sb.onclick=()=>{shareInvite(dName,d.token);H();};
      if(cb)cb.onclick=()=>{copyLink(link);H();};
    }
    if(nameEl)nameEl.value='';
    T(dName+' added');H();loadUsers();
    setTimeout(()=>nameEl?.focus(),80);
  }catch(e){
    if(res)res.innerHTML='<div style="color:var(--bad);font-size:12px;padding:4px 0">'+X(e.message||'Create failed')+'</div>';
    T(e.message||'Create failed',1);
  }finally{
    if(btn){btn.disabled=false;btn.textContent='Add Driver';}
  }
}

function injectAdminTokenUI(){
  let inp=$('adminToken');if(!inp||$('adminConnectedBar'))return;
  let wrap=inp.closest('.pass-wrap')||inp.parentNode;
  wrap.id='adminTokenWrap';
  wrap.insertAdjacentHTML('afterend',
    '<div id="adminConnectedBar" style="display:none;align-items:center;gap:8px;font-size:13px;color:var(--good);margin-top:6px;margin-bottom:8px;padding:8px 12px;background:rgba(52,211,153,.08);border-radius:10px;border:1px solid var(--good-border)">'
    +'<span style="font-size:16px">🔐</span><span style="flex:1;font-weight:600">Admin connected</span>'
    +'<a href="#" id="adminChangeTok" style="font-size:12px;color:var(--text-tertiary);text-decoration:none">Change</a></div>'
  );
  let changeLink=$('adminChangeTok');
  if(changeLink)changeLink.onclick=e=>{
    e.preventDefault();saveTok('');let el=$('adminToken');if(el)el.value='';
    renderTokenState();setTimeout(()=>$('adminToken')?.focus(),50);
  };
  if(!inp.dataset.flAdminBound){
    inp.dataset.flAdminBound='1';
    inp.addEventListener('blur',()=>{let v=(inp.value||'').trim();if(v){saveTok(v);renderTokenState();loadUsers();}});
    inp.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();let v=(inp.value||'').trim();if(v){saveTok(v);renderTokenState();loadUsers();setTimeout(()=>$('adminDriverName')?.focus(),80);}}});
  }
}

function init(){
  if(document.body&&document.body.dataset.flAdminUiReady==='1')return;
  if(!$('adminPanel')||!$('btnAdminToggle')||!$('btnAdminCreate')||!$('btnAdminRefresh')||!$('adminDriverName'))return;

  // Style the create button as a primary action
  let cb=$('btnAdminCreate');
  if(cb){cb.className='btn primary';cb.style.cssText='width:100%;margin-top:8px;font-size:15px;font-weight:700;padding:14px';cb.textContent='Add Driver';}

  // Better placeholder
  let nameEl=$('adminDriverName');if(nameEl&&!nameEl.placeholder)nameEl.placeholder='Driver name (e.g. Marcus)';

  injectAdminTokenUI();
  renderTokenState();

  let p=$('adminPanel');
  let t=R('btnAdminToggle')||$('btnAdminToggle');
  let c=R('btnAdminCreate')||$('btnAdminCreate');
  let r=R('btnAdminRefresh')||$('btnAdminRefresh');

  t.textContent='👥 Manage Drivers';
  t.onclick=()=>{
    let open=p.style.display!=='none';
    p.style.display=open?'none':'';
    if(!open){renderTokenState();loadUsers();setTimeout(()=>{if(loadTok())$('adminDriverName')?.focus();else $('adminToken')?.focus();},80);}
  };
  c.onclick=createUser;
  r.onclick=()=>{H();loadUsers();};

  if(nameEl&&!nameEl.dataset.flEnterBound){
    nameEl.dataset.flEnterBound='1';
    nameEl.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();createUser();}});
  }

  document.body.dataset.flAdminUiReady='1';
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
let _n=0,_i=setInterval(()=>{if(document.body?.dataset.flAdminUiReady==='1')return clearInterval(_i);init();if(++_n>=30)clearInterval(_i);},1000);
})();
