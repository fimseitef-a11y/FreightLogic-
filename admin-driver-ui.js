(function(){'use strict';
const API='https://freightlogic-backup.fimseitef.workers.dev',$=id=>document.getElementById(id);
const T=(m,e)=>{try{window.toast?window.toast(m,!!e):console[e?'warn':'log'](m)}catch(_){console[e?'warn':'log'](m)}};
const H=()=>{try{window.haptic&&window.haptic(10)}catch(_){}};
const X=s=>String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const P=s=>{s=String(s||'').trim();let d=s.replace(/\D+/g,'');if(d.length===10)return`(${d.slice(0,3)}) ${d.slice(3,6)}-${d.slice(6)}`;if(d.length===11&&d[0]==='1')return`+1 ${d.slice(1,4)}-${d.slice(4,7)}-${d.slice(7)}`;return s.slice(0,24)};
const S=s=>{let p=String(s||'Driver').split(' | ');return{n:(p[0]||'Driver').trim()||'Driver',p:p.slice(1).join(' | ').trim()}};

// Persist admin token in sessionStorage so it's remembered for the full session.
const SESS_KEY='fl_admin_token';
function saveAdminToken(val){try{if(val)sessionStorage.setItem(SESS_KEY,val);else sessionStorage.removeItem(SESS_KEY)}catch(_){}}
function getSavedToken(){try{return sessionStorage.getItem(SESS_KEY)||''}catch(_){return''}}
function restoreAdminToken(){let el=$('adminToken');if(el&&!el.value){let v=getSavedToken();if(v)el.value=v}}
function getToken(){let el=$('adminToken');return(el?el.value:'').trim()||getSavedToken()}

const G=()=>({'Content-Type':'application/json','X-Admin-Token':getToken()});
const Q=async(u,o)=>{let r=await fetch(API+u,o||{}),j=await r.json().catch(()=>null);if(!r.ok||!j||j.ok===false)throw Error(j&&j.error||`Request failed (${r.status})`);return j};
const R=id=>{let e=$(id);if(!e)return null;let n=e.cloneNode(true);e.parentNode.replaceChild(n,e);return n};

function ensurePhone(){if($('adminDriverPhone')||!$('adminDriverName'))return;$('adminDriverName').insertAdjacentHTML('afterend','<label for="adminDriverPhone">Driver phone</label><input id="adminDriverPhone" type="tel" placeholder="e.g., (414) 555-1212" autocomplete="tel" inputmode="tel">')}

// Copy text to clipboard with visual feedback on the button.
function copyToClipboard(text, btn){
  navigator.clipboard.writeText(text).then(()=>{
    let orig=btn.textContent;btn.textContent='Copied!';btn.disabled=true;
    setTimeout(()=>{btn.textContent=orig;btn.disabled=false},1500);
  }).catch(()=>{
    // Fallback for older browsers / non-HTTPS.
    let ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.opacity='0';
    document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);
    let orig=btn.textContent;btn.textContent='Copied!';btn.disabled=true;
    setTimeout(()=>{btn.textContent=orig;btn.disabled=false},1500);
  });
}

function showToken(d){
  let b=$('adminCreateResult');if(!b)return;
  b.style.display='';
  b.innerHTML=`<div class="admin-result-box">
    <div style="font-weight:800;font-size:14px;margin-bottom:6px">✅ Driver created</div>
    <div><b>Name:</b> ${X(d.n)}</div>
    ${d.p?`<div><b>Phone:</b> ${X(d.p)}</div>`:''}
    <div style="margin-top:6px"><b>Backup token — give this to the driver:</b></div>
    <div class="ar-token" id="adminResultToken">${X(d.t)}</div>
    <div class="btn-row" style="margin-top:8px;gap:8px">
      <button class="btn sm" id="btnCopyToken" style="flex:1">📋 Copy Token</button>
      <button class="btn sm" id="btnCopyMsg" style="flex:1">📨 Copy Invite</button>
    </div>
  </div>`;
  let tok=d.t;
  let copyBtn=$('btnCopyToken'),msgBtn=$('btnCopyMsg');
  if(copyBtn)copyBtn.onclick=()=>copyToClipboard(tok,copyBtn);
  if(msgBtn){
    let msg=`Hi ${d.n}! Here's your FreightLogic backup token:\n\n${tok}\n\nPaste it in Settings → Cloud Backup → Your Token, then set a passphrase to activate.`;
    msgBtn.onclick=()=>copyToClipboard(msg,msgBtn);
  }
  // Auto-focus name field for next add.
  let nameEl=$('adminDriverName');if(nameEl)setTimeout(()=>nameEl.focus(),50);
}

async function loadUsers(){
  restoreAdminToken();
  let box=$('adminUserList'),tok=getToken();
  if(!box)return;
  if(!tok){box.innerHTML='<div class="muted" style="font-size:12px">Enter your admin token to load drivers.</div>';return}
  box.innerHTML='<div class="muted" style="font-size:12px">Loading drivers…</div>';
  try{
    let d=await Q('/admin/users',{method:'GET',headers:G()}),u=Array.isArray(d.users)?d.users.slice():[];
    u.sort((a,b)=>String(b.createdAt||'').localeCompare(String(a.createdAt||'')));
    if(!u.length){box.innerHTML='<div class="muted" style="font-size:12px">No drivers created yet.</div>';return}
    box.innerHTML=u.map(v=>{
      let s=S(v.name),badge=v.active?'<span class="au-badge active">Active</span>':'<span class="au-badge revoked">Revoked</span>';
      return`<div class="admin-user" data-u="${X(v.userId||'')}"><div class="au-name">${X(s.n)} ${badge}</div><div class="au-meta">${s.p?`${X(s.p)} • `:''}${X(v.createdAt||'')}</div>${v.active?'<div class="btn-row" style="margin-top:8px"><button class="btn sm danger" data-revoke="1">Revoke Token</button></div>':''}</div>`;
    }).join('');
    box.querySelectorAll('[data-revoke="1"]').forEach(btn=>btn.onclick=async()=>{
      let id=(btn.closest('[data-u]')||{}).getAttribute&&btn.closest('[data-u]').getAttribute('data-u');
      if(!id)return;btn.disabled=true;
      try{await Q('/admin/users/'+encodeURIComponent(id),{method:'DELETE',headers:G()});T('Driver token revoked');H();loadUsers()}
      catch(e){btn.disabled=false;T(e.message||'Revoke failed',1)}
    });
  }catch(e){box.innerHTML=`<div class="muted" style="font-size:12px;color:var(--bad)">${X(e.message||'Could not load drivers')}</div>`}
}

async function createUser(){
  let name=(($('adminDriverName')||{}).value||'').trim()||'Driver',phone=P((($('adminDriverPhone')||{}).value||'')),btn=$('btnAdminCreate');
  let tok=getToken();if(!tok)return T('Enter the admin token first',1);
  saveAdminToken(tok);
  // Also write back to the field in case it was restored from sessionStorage only.
  let el=$('adminToken');if(el&&!el.value)el.value=tok;
  btn&&(btn.disabled=true);
  try{
    let stored=phone?`${name.slice(0,50)} | ${phone}`:name.slice(0,50),
        r=await Q('/admin/users',{method:'POST',headers:G(),body:JSON.stringify({name:stored})}),
        s=S(r.name);
    showToken({n:s.n,p:s.p,t:r.token||''});
    $('adminDriverName').value='';
    $('adminDriverPhone')&&($('adminDriverPhone').value='');
    T('Driver created');H();loadUsers();
  }catch(e){T(e.message||'Create failed',1)}
  finally{btn&&(btn.disabled=false)}
}

function init(){
  if(document.body&&document.body.dataset.flAdminUiReady==='1')return;
  if(!$('adminPanel')||!$('btnAdminToggle')||!$('btnAdminCreate')||!$('btnAdminRefresh')||!$('adminDriverName'))return;
  ensurePhone();
  let p=$('adminPanel'),t=R('btnAdminToggle')||$('btnAdminToggle'),c=R('btnAdminCreate')||$('btnAdminCreate'),r=R('btnAdminRefresh')||$('btnAdminRefresh');
  t.textContent='👑 Admin — Easy Driver Management';
  t.onclick=()=>{
    let open=p.style.display!=='none';
    p.style.display=open?'none':'';
    if(!open){
      restoreAdminToken();  // Fill field from sessionStorage on panel open.
      loadUsers();
      // Auto-focus name field so admin can type immediately.
      let nameEl=$('adminDriverName');if(nameEl)setTimeout(()=>nameEl.focus(),80);
    }
  };
  c.onclick=createUser;
  r.onclick=loadUsers;

  // Save token to sessionStorage on change so it persists across panel close/open.
  let tok=$('adminToken');
  if(tok&&!tok.dataset.flAdminBound){
    tok.dataset.flAdminBound='1';
    tok.addEventListener('blur',()=>{saveAdminToken(tok.value.trim());loadUsers()});
    tok.addEventListener('change',()=>saveAdminToken(tok.value.trim()));
  }

  // Allow Enter key on name/phone fields to trigger Create.
  ['adminDriverName','adminDriverPhone'].forEach(id=>{
    let el=$(id);if(!el||el.dataset.flEnterBound)return;
    el.dataset.flEnterBound='1';
    el.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();createUser()}});
  });

  document.body.dataset.flAdminUiReady='1';
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
let n=0,i=setInterval(()=>{if(document.body&&document.body.dataset.flAdminUiReady==='1')return clearInterval(i);init();if(++n>=30)clearInterval(i)},1000);
})();
