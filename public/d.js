(()=>{
const vid=document.currentScript.dataset.vid,T0=performance.now(),now=()=>performance.now();
const b={mv:0,clicks:0,noMove:0,center:0,screenEq:0,untrusted:0,keys:0,inputNoKey:0,progScroll:0,touch:0,jumps:0};
const sp=[],st=[],kd=[],ac=[];let last=null,lastMove=0,lastKey=0,lastWheel=0,down=false,first=null,buf=[],E=null;
const fi=()=>{if(first===null)first=Math.round(now()-T0)};
const cv=a=>{if(a.length<5)return null;const m=a.reduce((x,y)=>x+y,0)/a.length;return Math.sqrt(a.reduce((s,x)=>s+(x-m)**2,0)/a.length)/(m||1)};
const mean=a=>a.length?a.reduce((x,y)=>x+y,0)/a.length:null;
const hash=async s=>{try{const d=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));return[...new Uint8Array(d)].slice(0,8).map(x=>x.toString(16).padStart(2,'0')).join('')}catch{return String(s.length)}};

addEventListener('mousemove',e=>{
  if(!e.isTrusted)b.untrusted++;fi();b.mv++;const t=e.timeStamp;
  if(e.screenX===e.clientX&&e.screenY===e.clientY)b.screenEq++;
  if(last){const dt=t-last.t,d=Math.hypot(e.clientX-last.x,e.clientY-last.y);if(dt>0&&sp.length<500)sp.push(d/dt);if(d>250)b.jumps++}
  buf.push([e.clientX,e.clientY]);
  if(buf.length===10){let L=0;for(let i=1;i<10;i++)L+=Math.hypot(buf[i][0]-buf[i-1][0],buf[i][1]-buf[i-1][1]);
    const D=Math.hypot(buf[9][0]-buf[0][0],buf[9][1]-buf[0][1]);if(L>20&&st.length<200)st.push(D/L);buf=[]}
  last={x:e.clientX,y:e.clientY,t};lastMove=t;
},true);
addEventListener('pointerdown',()=>down=true,true);addEventListener('pointerup',()=>down=false,true);
addEventListener('click',e=>{
  fi();b.clicks++;ac.push(now());if(!e.isTrusted)b.untrusted++;
  if(e.pointerType!=='touch'&&e.timeStamp-lastMove>400)b.noMove++;
  const r=e.target.getBoundingClientRect?e.target.getBoundingClientRect():null;
  if(r&&r.width<600&&Math.abs(e.clientX-(r.left+r.width/2))<1.5&&Math.abs(e.clientY-(r.top+r.height/2))<1.5)b.center++;
},true);
addEventListener('keydown',e=>{
  fi();if(!e.isTrusted)b.untrusted++;b.keys++;const t=now();
  if(lastKey&&t-lastKey<2000&&kd.length<300)kd.push(t-lastKey);
  if(t-lastKey>1000)ac.push(t);lastKey=t;lastWheel=t;
},true);
addEventListener('input',e=>{if(now()-lastKey>150&&e.inputType!=='insertFromPaste')b.inputNoKey++},true);
addEventListener('wheel',()=>{fi();lastWheel=now()},{passive:true,capture:true});
for(const t of['touchstart','touchmove'])addEventListener(t,()=>{fi();b.touch++;lastWheel=now()},{passive:true,capture:true});
addEventListener('scroll',()=>{if(now()-lastWheel>400&&!down)b.progScroll++},{passive:true,capture:true});

async function env(){
  const n=navigator,w=window,e={};
  e.ua=n.userAgent;e.wd=n.webdriver===true;e.plat=n.platform;e.langs=(n.languages||[]).length;e.plugins=n.plugins?n.plugins.length:-1;
  e.hc=n.hardwareConcurrency;e.dm=n.deviceMemory;e.tp=n.maxTouchPoints;e.chrome=!!w.chrome;
  e.scr=[screen.width,screen.height,screen.availWidth,screen.availHeight,screen.colorDepth,devicePixelRatio];
  e.win=[innerWidth,innerHeight,outerWidth,outerHeight];
  e.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;e.rtt=n.connection?n.connection.rtt:null;
  e.brands=((n.userAgentData&&n.userAgentData.brands)||[]).map(x=>x.brand).join(',');
  try{e.voices=speechSynthesis.getVoices().length}catch{}
  const re=/^(\$?cdc_|__playwright|__pw_|_playwright|__puppeteer|puppeteer|_phantom|callPhantom|__nightmare|domAutomation|_selenium|__selenium|__webdriver|webdriver|__driver|_Selenium_IDE|__lastWatir)/i;
  e.auto=[...Object.getOwnPropertyNames(w),...Object.getOwnPropertyNames(document)].filter(k=>re.test(k)).slice(0,5);
  if(document.documentElement.getAttribute('webdriver')!==null)e.auto.push('html[webdriver]');
  e.tamper=['webdriver','languages','plugins','hardwareConcurrency'].filter(k=>Object.getOwnPropertyDescriptor(n,k));
  const nat=f=>{try{return/\[native code\]/.test(Function.prototype.toString.call(f))}catch{return false}};
  e.nonNative=[n.permissions&&n.permissions.query,HTMLCanvasElement.prototype.toDataURL,Function.prototype.toString].filter(f=>f&&!nat(f)).length;
  try{const g=document.createElement('canvas').getContext('webgl'),x=g.getExtension('WEBGL_debug_renderer_info');e.gl=g.getParameter(x.UNMASKED_RENDERER_WEBGL)}catch{e.gl=null}
  try{const c=document.createElement('canvas');c.width=220;c.height=40;const x=c.getContext('2d');x.font='16px Arial';x.fillStyle='#f60';x.fillRect(10,5,80,20);x.fillStyle='#069';x.fillText('Cwm fjordbank 😃',4,28);e.cv=await hash(c.toDataURL())}catch{}
  try{const p=await n.permissions.query({name:'notifications'});e.notif=[Notification.permission,p.state]}catch{}
  let cdp=false;const er=new Error();Object.defineProperty(er,'stack',{get(){cdp=true;return''}});console.debug(er);e.cdp=cdp;
  e.fp=await hash([e.gl,e.cv,e.scr.join(),e.hc,e.plat,e.tz].join('|'));
  return e;
}
function summ(){const g=[];for(let i=1;i<ac.length;i++)g.push(ac[i]-ac[i-1]);
  return{...b,spdCV:cv(sp),straight:mean(st),keyCV:cv(kd),gapN:g.length,gapCV:cv(g),gapMean:mean(g),tFirst:first,tNow:Math.round(now()-T0)}}
let sent=0;
function send(final){if(!E||sent>80)return;sent++;
  const p=JSON.stringify({vid,env:E,beh:summ(),final:!!final});
  try{navigator.sendBeacon('/api/collect',new Blob([p],{type:'application/json'}))}catch{fetch('/api/collect',{method:'POST',body:p,keepalive:true,headers:{'Content-Type':'application/json'}})}}
env().then(e=>{E=e;send();setTimeout(send,2000);setInterval(send,4000)});
addEventListener('pagehide',()=>send(true));
})();
