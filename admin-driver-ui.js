(function(){'use strict';
const API='https://freightlogic-backup.fimseitef.workers.dev',$=id=>document.getElementById(id);
const T=(m,e)=>{try{window.toast?window.toast(m,!!e):console[e?'warn':'log'](m)}catch(_){console[e?'warn':'log'](m)}};
const H=()=>{try{window.haptic&&window.haptic(10)}catch(_){}};
const X=s=>String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const S=s=>{let p=String(s||'Driver').split(' | ');return{n:(p[0]||'Driver').trim()||'Driver'}};

// Admin token stored in localStorage — entered once, remembered on this device forever.
const LOC_KEY='fl_admin_tok';
function saveTok(v){try{if(v)localStorage.setItem(LOC_KEY,v);else localStorage.removeItem(LOC_KEY)}catch(_){}}
function loadTok(){try{return localStorage.getItem(LOC_KEY)||''}catch(_){return''}}
function getTok(){return(($('adminToken')||{}).value||'').trim()||loadTok()}
const G=()=>({'Content-Type':'application/json','X-Admin-Token':getTok()});
const Q=async(u,o)=>{let r=await fetch(API+u,o||{}),j=await r.json().catch(()=>null);if(!r.ok||!j||j.ok===false)throw Error(j&&j.error||`HTTP ${r.status}`);return j};
const R=id=>{let e=$(id);if(!e)return null;let n=e.cloneNode(true);e.parentNode.replaceChild(n,e);return n};

// Build the invite link for a driver — token is embedded in the URL, never shown raw.
function buildInviteLink(token){
  try{return window.location.origin+window.location.pathname+'?token='+encodeURIComponent(token)}
  catch(_){return API+'?token='+encodeURIComponent(token)}
}

// Share the invite or fall back to clipboard copy.
function shareInvite(name, token){
  let link=buildInviteLink(token);
  let text=`Hi ${name}! Here's your FreightLogic setup link:\n\n${link}\n\nOpen it, pick a passphrase (8+ chars), tap Connect — done!`;
  if(navigator.share){navigator.share({text}).catch(()=>copyFallback(link))}
  else copyFallback(link);
}
function copyFallback(text){
  navigator.clipboard.writeText(text).then(()=>T('Invite link copied')).catch(()=>{
    let ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;opacity:0';
    document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);
    T('Invite link copied');
  });
}

// Show/hide the token input depending on whether a token is already saved.
function renderTokenState(){
  let saved=loadTok();
  let wrap=$('adminTokenWrap'),bar=$('adminConnectedBar'),inp=$('adminToken');
  if(!wrap||!bar||!inp)return;
  if(saved){
    wrap.style.display='none';
    bar.style.display='';
  } else {
    wrap.style.display='';
    bar.style.display='none';
  }
}

async function loadUsers(){
  let box=$('adminUserList'),tok=getTok();
  if(!box)return;
  if(!tok){box.innerHTML='<div class="muted" style="font-size:12px">Enter your admin token above.</div>';return}
  box.innerHTML='<div class="muted" style="font-size:12px">Loading drivers…</div>';
  try{
    let d=await Q('/admin/users',{method:'GET',headers:G()}),u=Array.isArray(d.users)?d.users.slice():[];
    u.sort((a,b)=>String(b.createdAt||'').localeCompare(String(a.createdAt||'')));
    if(!u.length){box.innerHTML='<div class="muted" style="font-size:12px">No drivers yet — add the first one above.</div>';return}
    box.innerHTML=u.map(v=>{
      let s=S(v.name),badge=v.active?'<span class="au-badge active">Active</span>':'<span class="au-badge revoked">Revoked</span>';
      return`<div class="admin-user" data-u="${X(v.userId||'')}"><div class="au-name">${X(s.n)} ${badge}</div><div class="au-meta">${X((v.createdAt||'').slice(0,10))}</div>${v.active?'<div class="btn-row" style="margin-top:8px"><button class="btn sm danger" data-revoke="1">Remove Access</button></div>':''}</div>`;
    }).join('');
    box.querySelectorAll('[data-revoke="1"]').forEach(btn=>btn.onclick=async()=>{
      let id=btn.closest('[data-u]')?.getAttribute('data-u');if(!id)return;
      if(!confirm('Remove this driver\'s access?'))return;
      btn.disabled=true;
      try{await Q('/admin/users/'+encodeURIComponent(id),{method:'DELETE',headers:G()});T('Driver removed');H();loadUsers()}
      catch(e){btn.disabled=false;T(e.message||'Failed',1)}
    });
  }catch(e){box.innerHTML=`<div class="muted" style="font-size:12px;color:var(--bad)">${X(e.message||'Could not load drivers')}</div>`}
}

async function createUser(){
  let name=(($('adminDriverName')||{}).value||'').trim();
  if(!name){T('Enter a driver name',1);$('adminDriverName')?.focus();return}
  let tok=getTok();if(!tok){T('Connect as admin first',1);return}
  let btn=$('btnAdminCreate');if(btn)btn.disabled=true;
  let res=$('adminCreateResult');
  if(res){res.style.display='';res.innerHTML='<div class="muted" style="font-size:12px">Creating…</div>'}
  try{
    let d=await Q('/admin/users',{method:'POST',headers:G(),body:JSON.stringify({name})}),s=S(d.name);
    if(res){
      res.innerHTML=`<div class="admin-result-box" style="background:var(--surface-0);border:1px solid var(--good-border);border-radius:var(--r-sm);padding:12px">
        <div style="font-weight:800;color:var(--good);margin-bottom:8px">✓ ${X(s.n)} added</div>
        <div class="muted" style="font-size:12px;margin-bottom:10px">Send them the setup link — they open it, pick a passphrase, and they're in. No token typing needed.</div>
        <button class="btn primary" id="btnShareInvite" style="width:100%;font-size:14px">📤 Send to ${X(s.n)}</button>
      </div>`;
      let shareBtn=$('btnShareInvite');
      if(shareBtn)shareBtn.onclick=()=>{shareInvite(s.n,d.token);H()};
    }
    $('adminDriverName').value='';
    T(s.n+' created');H();loadUsers();
    let nameEl=$('adminDriverName');if(nameEl)setTimeout(()=>nameEl.focus(),60);
  }catch(e){
    if(res)res.innerHTML=`<div class="muted" style="font-size:12px;color:var(--bad)">${X(e.message||'Create failed')}</div>`;
    T(e.message||'Create failed',1);
  }finally{if(btn)btn.disabled=false}
}

function injectAdminTokenUI(){
  // Inject the "Connected" bar and "change" link next to the token input if not already present.
  let inp=$('adminToken');if(!inp||$('adminConnectedBar'))return;
  let wrap=inp.closest('.pass-wrap')||inp.parentNode;
  wrap.id='adminTokenWrap';
  wrap.insertAdjacentHTML('afterend',
    '<div id="adminConnectedBar" style="display:none;font-size:13px;color:var(--good);margin-top:4px;margin-bottom:6px">'+
    '🔐 Admin connected &nbsp;·&nbsp; <a href="#" id="adminChangeTok" style="font-size:12px;color:var(--text-tertiary)">change</a></div>'
  );
  let changeLink=$('adminChangeTok');
  if(changeLink)changeLink.onclick=e=>{
    e.preventDefault();
    saveTok('');
    let el=$('adminToken');if(el)el.value='';
    renderTokenState();
    setTimeout(()=>$('adminToken')?.focus(),50);
  };
  // Save token on blur.
  if(!inp.dataset.flAdminBound){
    inp.dataset.flAdminBound='1';
    inp.addEventListener('blur',()=>{let v=(inp.value||'').trim();if(v){saveTok(v);renderTokenState();loadUsers()}});
    inp.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();let v=(inp.value||'').trim();if(v){saveTok(v);renderTokenState();loadUsers();$('adminDriverName')?.focus()}}});
  }
}

function init(){
  if(document.body&&document.body.dataset.flAdminUiReady==='1')return;
  if(!$('adminPanel')||!$('btnAdminToggle')||!$('btnAdminCreate')||!$('btnAdminRefresh')||!$('adminDriverName'))return;

  // Update the Create button label.
  let cb=$('btnAdminCreate');if(cb)cb.textContent='➕ Add Driver';

  injectAdminTokenUI();
  renderTokenState();

  let p=$('adminPanel');
  let t=R('btnAdminToggle')||$('btnAdminToggle');
  let c=R('btnAdminCreate')||$('btnAdminCreate');
  let r=R('btnAdminRefresh')||$('btnAdminRefresh');

  t.textContent='👑 Manage Drivers';
  t.onclick=()=>{
    let open=p.style.display!=='none';
    p.style.display=open?'none':'';
    if(!open){
      renderTokenState();
      loadUsers();
      // Focus name field if already connected, otherwise focus token field.
      setTimeout(()=>{
        if(loadTok())$('adminDriverName')?.focus();
        else $('adminToken')?.focus();
      },80);
    }
  };
  c.onclick=createUser;
  r.onclick=loadUsers;

  // Enter on name field triggers create.
  let nameEl=$('adminDriverName');
  if(nameEl&&!nameEl.dataset.flEnterBound){
    nameEl.dataset.flEnterBound='1';
    nameEl.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();createUser()}});
  }

  document.body.dataset.flAdminUiReady='1';
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
let _n=0,_i=setInterval(()=>{if(document.body?.dataset.flAdminUiReady==='1')return clearInterval(_i);init();if(++_n>=30)clearInterval(_i)},1000);
})();
