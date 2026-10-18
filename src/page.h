#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
</style></head><body>
<header><h1>🛡️ C3 AdBlock <span id=host></span></h1></header><div class=wrap>
<div id=credwarn style="display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px">
⚠️ <b>Default credentials in use.</b> The admin password is still the placeholder from <code>secrets.example.h</code> — anyone can read it in the public repo. Set a real one under <b>Security</b> below.
</div>
<div id=blockbar style="display:flex;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px">
<span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate style=flex:1 data-on=1>Blocking active</b>
<select id=pausedur style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"><option value=30>30s</option><option value=300 selected>5 min</option><option value=1800>30 min</option><option value=0>until I re-enable</option></select>
<button id=pausebtn onclick=togglePause()>Pause</button></div>
<div class=cards id=sys></div>
<h2>CLIENTS</h2><table id=ct><thead><tr><th>Name</th><th>Address</th><th>MAC</th><th>Blocked</th><th>Allowed</th><th>Seen</th><th></th></tr></thead><tbody></tbody></table>
<h2>CUSTOM BLOCKED DOMAINS</h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=30><button onclick=addDom()>Block domain</button></div>
<table id=cl><tbody></tbody></table>
<h2>ALLOWED DOMAINS &mdash; NEVER BLOCKED</h2>
<div style=margin-bottom:8px><input id=adom placeholder="needed.example.com" size=30><button onclick=allowDom()>Allow domain</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:8px">overrides the blocklist and custom blocks for the domain and its subdomains</div>
<table id=al><tbody></tbody></table>
<h2>UPSTREAM DNS</h2>
<div style=margin-bottom:6px><input id=up0 placeholder="primary, e.g. 9.9.9.9" size=16> <input id=up1 placeholder="secondary (optional)" size=16>
<button onclick=saveUp()>Save</button> <span id=upmsg style=color:#8b949e></span></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">queries go to the active one; unanswered ones are retried on the other after 0.7 s, and 3 misses in a row switch over. active: <span id=upact>&mdash;</span></div>
<h2>IPV6</h2>
<div style=margin-bottom:6px>device answers DNS on IPv6 too: <code id=ip6>&mdash;</code></div>
<div style=margin-bottom:6px><label><input type=checkbox id=ra6 onchange=setRa()> announce this device as IPv6 DNS server</label> <span id=ramsg style=color:#8b949e></span></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">sends router advertisements carrying only a DNS server option (router lifetime 0: never used as a gateway). Clients add it next to the router's own IPv6 DNS, so this narrows the IPv6 bypass but can't close it; for that, change the router's IPv6 DNS setting.</div>
<h2>BLOCKLIST &mdash; UPLOAD</h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button>Upload blocklist</button> <span id=upmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">build <code>blocklist.bin</code> with <code>tools/build_blocklist.py</code>, then upload here &mdash; no USB</div>
<h2>BLOCKLIST &mdash; REMOTE AUTO-UPDATE</h2>
<div style=margin-bottom:6px><input id=uurl placeholder="https://host/blocklist.bin" size=40> every <input id=uiv size=2 value=24>h
<button onclick=saveUpd()>Save</button> <button onclick=fetchNow()>Fetch now</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">device pulls a prebuilt <code>blocklist.bin</code> on a schedule (e.g. a GitHub release asset). last: <span id=ustat>&mdash;</span></div>
<h2>FIRMWARE &mdash; OTA UPDATE</h2>
<form id=fwf style=margin-bottom:6px><input type=file id=fwb accept=.bin><button>Flash firmware</button> <span id=fwmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">upload <code>.pio/build/c3/firmware.bin</code> &mdash; device verifies it and reboots into it</div>
<h2>SECURITY</h2>
<div style=margin-bottom:6px><input id=np type=password placeholder="new admin password" size=24 minlength=8><button onclick=setPass()>Change password</button> <span id=pmsg style=color:#8b949e></span></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">used for the dashboard and network OTA; overrides <code>secrets.h</code>. Forgot it? Hold BOOT while powering on to reset it in the setup portal.</div>
<h2>DEVICE</h2>
<div style=margin-bottom:18px><button onclick="if(confirm('Reboot the device? DNS is down for ~10 s.'))reboot()">Reboot</button>
<button onclick="if(confirm('Forget saved WiFi and reboot into the setup portal?'))forgetWifi()">Forget WiFi</button> <span id=rbmsg style=color:#8b949e></span></div>
</div><script>
function fmt(n){return n.toLocaleString()}
function ago(s){return s<60?s+'s':s<3600?Math.floor(s/60)+'m':s<86400?Math.floor(s/3600)+'h':Math.floor(s/86400)+'d'}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// A plain <img>/<form> CSRF can't set a custom header, only same-origin fetch()
// can — so requiring this on every mutating request blocks drive-by CSRF even
// though the server can't otherwise tell a forged request from a real one over
// plain HTTP Basic Auth (browsers auto-replay cached Basic Auth cross-origin).
const CSRF_HDRS={'X-Requested-With':'c3-adblock'}
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load);}
async function load(){let s=await(await fetch('/stats.json')).json();
host.textContent='@ '+s.ip;
credwarn.style.display=s.defcreds?'block':'none';
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
blockstate.textContent=on?'Blocking active':(s.resumeIn>0?'Paused — resumes in '+s.resumeIn+'s':'Paused');
pausebtn.textContent=on?'Pause':'Resume';pausedur.style.display=on?'':'none';
sys.innerHTML=[['Total blocked',fmt(s.blocked),'b'],['Total allowed',fmt(s.allowed),'a'],['Blocklist',fmt(s.domains)+' domains',''],
['Cache hits',fmt(s.cacheHits||0)+(s.allowed?' ('+Math.round(100*(s.cacheHits||0)/s.allowed)+'%)':''),'a'],
['Clients',s.clients.length,''],['WiFi',s.rssi+' dBm',''],['Temp',s.temp+' °C',''],['Free RAM',Math.round(s.heap/1024)+' KB',''],['Uptime',s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${esc(c.name||'')}${c.manual?' <span class=tag>set</span>':''} <button class=ren data-ip="${esc(c.ip)}" data-n="${esc(c.name||'')}" title=rename>&#9998;</button>${c.banned?' <span class=tag style=color:#f85149>BANNED</span>':''}</td>
<td>${esc(c.ip)}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td><td>${ago(c.seen)}</td>
<td><button class=ban data-ip="${esc(c.ip)}">${c.banned?'Unban':'Ban'}</button></td></tr>`).join('');
const rows=l=>l.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=rmbtn data-d="${esc(d)}">remove</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>none yet</td></tr>';
cl.tBodies[0].innerHTML=rows(s.custom);al.tBodies[0].innerHTML=rows(s.allow||[]);
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
ustat.textContent=s.upstat||'—';
ip6.textContent=(s.ip6||[]).join('  ')||'no IPv6 address yet';if(document.activeElement!=ra6)ra6.checked=!!s.ra6;
if(s.up){if(document.activeElement!=up0)up0.value=s.up[0];if(document.activeElement!=up1)up1.value=s.up[1];upact.textContent=s.up[s.upActive]||'—';}}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
ct.addEventListener('click',e=>{let t=e.target;
if(t.classList.contains('ban'))fetch('/ban?ip='+encodeURIComponent(t.dataset.ip),{headers:CSRF_HDRS}).then(load);
if(t.classList.contains('ren')){let n=prompt('Name for '+t.dataset.ip+' (empty = automatic from the router):',t.dataset.n);
if(n!==null)fetch('/setname?ip='+encodeURIComponent(t.dataset.ip)+'&name='+encodeURIComponent(n.trim()),{headers:CSRF_HDRS}).then(load)}});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function allowDom(){let d=adom.value.trim();if(d){fetch('/allow?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{adom.value='';load()})}}
al.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unallow?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24),{headers:CSRF_HDRS}).then(load)}
function fetchNow(){ustat.textContent='fetching...';fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
function setPass(){let p=np.value;if(p.length<8){pmsg.textContent='8+ characters';return}
fetch('/setpass',{method:'POST',headers:{...CSRF_HDRS,'Content-Type':'application/x-www-form-urlencoded'},body:'p='+encodeURIComponent(p)})
.then(async r=>{let t=await r.text();pmsg.textContent=t;np.value='';
if(r.ok&&confirm('Password changed. Reboot now so network OTA uses it too? (DNS is down for ~10 s)'))reboot()})}
function reboot(){fetch('/reboot',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{rbmsg.textContent=t+', reconnecting...';setTimeout(()=>location.reload(),12000)})}
function saveUp(){fetch('/setupstream?p='+encodeURIComponent(up0.value.trim())+'&s='+encodeURIComponent(up1.value.trim()),{headers:CSRF_HDRS})
.then(r=>r.text()).then(t=>{upmsg.textContent=t;load()})}
function setRa(){fetch('/setra6?on='+(ra6.checked?1:0),{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{ramsg.textContent=t;load()})}
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>alert(t))}
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent='flashing '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});fwmsg.textContent=r.ok?'✓ rebooting, reconnect in ~15s':'✗ '+await r.text();}
catch(_){fwmsg.textContent='✓ rebooting, reconnect in ~15s';}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent='uploading '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg.textContent=r.ok?'✓ updated':'✗ '+await r.text();}
catch(_){upmsg.textContent='✗ upload failed';}
blf.value='';setTimeout(load,600);};
load();setInterval(load,3000);
</script></body></html>)HTML";
