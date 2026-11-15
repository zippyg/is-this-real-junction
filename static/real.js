'use strict';
/* Is this real? front end. Presentation only: it shows what the server found and never changes it. */
const $=s=>document.querySelector(s);
const el=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!=null)n.textContent=text;return n;};
const body=document.body,sheet=$('#sheet'),doc=$('#doc'),value=$('#value'),consent=$('#consent'),go=$('#check-button'),note=$('#availability');
const reduce=matchMedia('(prefers-reduced-motion: reduce)');
const wide=matchMedia('(min-width: 861px)'),hover=matchMedia('(hover: hover)');
const wait=ms=>new Promise(r=>setTimeout(r,ms));
const EASE='cubic-bezier(.2,.8,.2,1)';

const STEPS=[['Source','Reading it'],['Pressure signs','Wording'],['What others say','Warnings'],['Who is behind it','Who is behind it'],['Copies','Copies'],['How old it is','Site age'],['Too good to be true','Price or pay']];
const CHECK={'Source':'Reading it','Pressure signs':'Wording','What others say':'Warnings and reports','Who is behind it':'Who is behind it','Copies':'Copies','How old it is':'Site age','Too good to be true':'Price or pay'};
const WORD={warning:'Warning',worth:'Worth checking',reassuring:'Reassuring',unknown:'Could not check',found:'Found'};
const TALLY={warning:['warning','warnings'],reassuring:['reassuring','reassuring'],worth:['worth checking','worth checking'],found:['found','found']};
/* strongest first: a warning and a reassurance both say something; a lead says less */
const RANK={warning:0,reassuring:1,worth:2,found:3,unknown:4};
/* first screen: the job and the flat lead; the three shop pages share one row */
const CASE_COPY={'job-scamwatch':['Job','A “pay to unlock tasks” job offer','From a Scamwatch warning, Australia'],'rental-action-fraud':['Flat','A flat that wants a deposit before a viewing','From an Action Fraud warning, UK']};

let live=false,cases=[],run=0,busy=false,last=null,S=null;

const NB=String.fromCharCode(160),DASH=String.fromCharCode(8212),keep=s=>s.split(' ').join(NB);
const D=new Intl.DateTimeFormat('en-GB',{day:'numeric',month:'short',year:'numeric'});
const T=new Intl.DateTimeFormat('en-GB',{hour:'2-digit',minute:'2-digit'});
const MON=['jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec'];
function when(v){
  if(!v)return null;const s=String(v);let m;
  if((m=s.match(/^(\d{4})-(\d{2})-(\d{2})$/)))return new Date(+m[1],m[2]-1,+m[3]);
  if((m=s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::[\d.]+)?\s*(Z|UTC|[+-]\d{2}:?\d{2})?/))){
    if(m[6]&&m[6]!=='Z'&&m[6]!=='UTC'){const d=new Date(s.split(' ')[0]+'T'+s.split(/[ T]/)[1]);if(!isNaN(d))return d;}
    return m[6]?new Date(Date.UTC(+m[1],m[2]-1,+m[3],+m[4],+m[5])):new Date(+m[1],m[2]-1,+m[3],+m[4],+m[5]);}
  if((m=s.match(/^(\d{1,2}) ([A-Za-z]{3})[a-z]* (\d{4})(?: at (\d{2}):(\d{2}) UTC)?/))){const mo=MON.indexOf(m[2].toLowerCase());if(mo<0)return null;
    return m[4]?new Date(Date.UTC(+m[3],mo,+m[1],+m[4],+m[5])):new Date(+m[3],mo,+m[1]);}
  const d=new Date(s);return isNaN(d)?null:d;
}
const day=v=>{const d=when(v);return d?keep(D.format(d)):'';};
const stamp=v=>{const d=when(v);return d?keep(D.format(d))+', '+T.format(d):'';};

function clean(s){return String(s||'').replace(/!\[[^\]]*\]\([^)]*\)/g,' ').replace(/\[([^\]]*)\]\([^)]*\)/g,'$1').replace(/(^|\s)#{1,6}\s*/g,'$1').replace(/\*\*|__/g,'').replace(/https?:\/\/\S{48,}/g,' ').split(DASH).join(',').replace(/\s+/g,' ').trim();}
function safe(u){try{const x=new URL(u);return /^https?:$/.test(x.protocol)?x.href:'';}catch{return '';}}
function host(u){try{return new URL(u).hostname.replace(/^www\./,'');}catch{return '';}}
function shortPath(u){try{const x=new URL(u);const parts=x.pathname.split('/').filter(Boolean);if(!parts.length)return '';let p='/'+parts.join('/');if(p.length>34)p='/'+parts[0].slice(0,24)+(parts.length>1?'/…':'');return p;}catch{return '';}}
const cap=s=>s?s.charAt(0).toUpperCase()+s.slice(1):s;
function polarity(d){
  const p=String(d.polarity||'').toLowerCase().replace(/[\s-]+/g,'_');
  if(p){if(p.startsWith('reassur'))return 'reassuring';if(p.startsWith('warn'))return 'warning';if(p.startsWith('worth')||p==='caution')return 'worth';if(p.startsWith('could')||p.startsWith('unknown')||p.startsWith('not_check'))return 'unknown';return 'found';}
  const t=String(d.finding||d.sentence||'').toLowerCase().split(/[.;]\s/)[0];
  if(/could not|couldn.t|unavailable|unreadable|cannot|not be checked|no named|not extracted|no matching/.test(t))return 'unknown';
  if(d.attention)return 'warning';
  if(/^no\b.*\b(found|match)/.test(t))return 'reassuring';
  return 'found';
}
/* the server's first clause is the line; the rest is the caveat */
function words(d){
  let text=clean(d.sentence||d.finding||d.text||''),title=clean(d.title||'');
  if(!d.sentence&&!title&&d.url&&!d.polarity){const i=text.indexOf(': ');if(i>18&&!/\d/.test(text.slice(i+2,i+4))){title=text.slice(i+2).trim();text=text.slice(0,i);}}
  text=text.replace(/:\s*$/,'');
  const m=text.match(/^(.+?[.;])\s+(\S.+)$/);
  const main=(m?m[1]:text).replace(/;$/,'.');
  return {main:/[.!?)]$/.test(main)?main:main+'.',more:m?cap(m[2]).replace(/;\s+(\w)/g,(x,c)=>'. '+c.toUpperCase()):'',title};
}
function quoteOf(d,title){
  let q=clean(d.quote);
  if(!q||/^user-supplied text/i.test(q))return '';
  if(title&&q.toLowerCase().startsWith(title.toLowerCase()))q=q.slice(title.length).replace(/^[\s|#.,:-]+/,'');
  return q.length<4?'':q.slice(0,700);
}
const norm=s=>String(s||'').replace(/^["“”']+|["“”']+$/g,'').replace(/(\.\.\.|…)$/,'').replace(/\s+/g,' ').trim();

function setAvailability(){
  go.disabled=!live;note.classList.remove('ask');
  note.textContent=live?'':'Live checks are off. Try an example.';
}
function ask(msg,focus){note.textContent=msg;note.classList.add('ask');if(focus)focus.focus();}
function renderCases(){
  const list=$('#cases');list.replaceChildren();
  const play=c=>()=>begin({case_id:c.id},String(c.source||'').trim(),c);
  const lead=cases.filter(c=>CASE_COPY[c.id]),rest=cases.filter(c=>!CASE_COPY[c.id]);
  for(const c of lead){
    const [kind,title,from]=CASE_COPY[c.id];
    const b=el('button','case');b.type='button';b.dataset.id=c.id;
    b.append(el('span','case-title',title),el('span','case-date',from));
    b.onclick=play(c);const li=el('li');li.append(b);list.append(li);
  }
  if(rest.length){
    const li=el('li','case case-shops');
    li.append(el('span','case-title','Online shops named in an official warning'));
    const row=el('span','case-picks');
    for(const c of rest){
      const name=String(c.title||'').split(':')[0].trim()||host(c.source);
      const b=el('button','case-pick',name);b.type='button';b.dataset.id=c.id;b.onclick=play(c);row.append(b);
    }
    li.append(row);list.append(li);
  }
  $('#cases-panel').hidden=!cases.length;
}
go.onclick=()=>{
  const v=value.value.trim();
  if(!live){setAvailability();return;}
  if(!v){ask('Paste a link or a message first.',value);return;}
  if(!consent.checked){$('.consent').classList.add('ask');ask('Remove personal details, then tick the box.',consent);return;}
  begin({value:v,consent:true},v,null);
};
consent.onchange=()=>{$('.consent').classList.remove('ask');if(note.classList.contains('ask'))setAvailability();};
value.addEventListener('input',()=>{if(note.classList.contains('ask'))setAvailability();});
value.addEventListener('keydown',e=>{if(e.key==='Enter'&&(e.metaKey||e.ctrlKey)){e.preventDefault();go.click();}});

async function begin(payload,text,recorded){
  if(busy)return;busy=true;last=[payload,text,recorded];
  const token=++run;
  go.disabled=true;for(const b of document.querySelectorAll('button.case,.case-pick'))b.disabled=true;
  let response;
  try{
    response=await fetch('/api/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    if(!response.ok){let msg='Not available now. Try again in a minute.';try{msg=(await response.json()).detail||msg;}catch{}throw Object.assign(new Error(msg),{early:true});}
  }catch(e){
    busy=false;setAvailability();for(const b of document.querySelectorAll('button.case,.case-pick'))b.disabled=false;
    const msg=e.early?e.message:'Could not reach us. Try again.';
    if(body.classList.contains('result'))fail(msg);else ask(msg);
    return;
  }
  open(text,recorded);
  const reader=response.body.getReader(),decoder=new TextDecoder();let pending='',finished=false;
  const feed=line=>{if(!line.trim())return;let e;try{e=JSON.parse(line);}catch{return;}if(e.type==='done'||e.type==='error')finished=true;enqueue(e,token);};
  try{
    while(true){
      const {done,value:chunk}=await reader.read();if(token!==run){reader.cancel();return;}
      pending+=decoder.decode(chunk||new Uint8Array(),{stream:!done});
      const lines=pending.split('\n');pending=lines.pop();lines.forEach(feed);
      if(done)break;
    }
    feed(pending);
    if(!finished)enqueue({type:'error',data:'Stopped early. Gaps are not reassurance.'},token);
  }catch{
    if(token===run)enqueue({type:'error',data:'Connection dropped. Gaps are not reassurance.'},token);
  }
}

function open(text,recorded){
  S={rows:new Map(),order:[],unk:new Map(),seq:0,host:'',hostEl:null,textEl:null,marks:new Map(),steps:new Map(),
     recordedAt:recorded?recorded.recorded_at:null,recorded:!!recorded,prov:null,unreadable:false};
  window.scrollTo(0,0);
  const before=sheet.getBoundingClientRect();
  body.classList.remove('intake');body.classList.add('result','checking');
  $('#again').hidden=false;$('#cases-panel').hidden=true;$('#ledger').hidden=false;$('#next').hidden=true;$('#verdict').hidden=false;
  value.hidden=true;doc.hidden=false;
  for(const id of ['doc-notes','provenance','found-title','found-none','fold','unchecked-title','compare','peek'])$('#'+id).hidden=true;
  for(const id of ['doc-notes','found','more','unchecked-list','steps','compare','peek'])$('#'+id).replaceChildren();
  S.cav=new Set();S.text=String(text||'').trim();$('#sheet-label').hidden=false;
  $('#fold').open=false;$('#steps').hidden=false;
  setVerdict('Checking','checking',false);
  $('#verdict-sub').textContent='Searching the web.';
  buildDoc(text,recorded);
  for(const [key,name] of STEPS){const li=el('li','step'),m=el('i','m');m.dataset.p='checking';li.append(m,el('span','',name));$('#steps').append(li);S.steps.set(key,{li,m,best:null});}
  const after=sheet.getBoundingClientRect();
  if(!reduce.matches&&Math.abs(before.top-after.top)>2)sheet.animate([{transform:`translateY(${before.top-after.top}px)`},{transform:'none'}],{duration:300,easing:EASE});
}
function buildDoc(text,recorded){
  doc.replaceChildren();
  const t=String(text||'').trim(),u=/^\S+$/.test(t)?safe(t):'';
  if(u){
    S.host=host(u);S.hostEl=el('span','doc-host',S.host);doc.append(S.hostEl);
    S.hostEl.addEventListener('click',e=>{e.stopPropagation();peek(S.hostEl);});S.hostEl.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();peek(S.hostEl);}});const sp=shortPath(u);if(sp){const pe=el('span','doc-path',sp);pe.title=u;doc.append(pe);}
    $('#value-label').textContent=recorded?'The advertised page':'The link you pasted';
  }else{
    S.textEl=el('span','doc-text',t);doc.append(S.textEl);
    $('#value-label').textContent=recorded?'Quoted from the warning':'The message you pasted';
  }
}

const queue=[];let pumping=false;
function enqueue(e,token){queue.push([e,token]);if(!pumping)pump();}
async function pump(){
  pumping=true;
  while(queue.length){
    const [e,token]=queue.shift();if(token!==run)continue;
    const shown=handle(e);
    if(shown&&!reduce.matches)await wait(queue.length>8?60:120);
  }
  pumping=false;
}
function handle(e){
  if(e.type==='recording'){const m=String(e.data||'').match(/\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?/);if(m)S.recordedAt=m[0];S.recorded=true;provenance();}
  else if(e.type==='phase'){if(body.classList.contains('checking'))$('#verdict-sub').textContent=clean(e.data);}
  else if(e.type==='evidence')return finding(e.data||{});
  else if(e.type==='done')finish(e.data||{});
  else if(e.type==='error')fail(clean(e.data)||'The check could not finish.');
  return false;
}

function provenance(){
  const p=$('#provenance');p.replaceChildren();
  if(!S.recorded){p.hidden=true;return;}
  p.append(el('b','','Checked earlier, not live. '));
  if(S.prov){
    const w=words(S.prov),u=safe(S.prov.url);p.append(w.main.replace(/\.$/,'')+'. ');
    if(u){const a=el('a','',host(u));a.href=u;a.target='_blank';a.rel='noopener noreferrer';p.append('Source ',a);}
    const pub=day(S.prov.published_at);if(pub)p.append(', '+pub);
  }
  p.hidden=false;
}
function step(check,p){
  const s=S.steps.get(check);if(!s)return;
  if(!s.best||RANK[p]<RANK[s.best]){s.best=p;s.m.dataset.p=p;}
  s.li.classList.add('done');
}

/* a quote is shown only when it reads as prose: never table rows or infobox markup */
function prose(q){
  if(!q||/[|]/.test(q)||/(^|\s)\/(\s|$)/.test(q)||/[{}<>]|\]\(|^#/.test(q))return false;
  return (q.match(/\p{L}{2,}/gu)||[]).length>=3;
}
function finding(d){
  if(d.check==='Recorded case provenance'){S.prov=d;S.recorded=true;provenance();return false;}
  const p=polarity(d),w=words(d),u=safe(d.url);let q=quoteOf(d,w.title);
  step(d.check,p);
  /* the reading itself is machinery; only an unreadable page earns a line on the sheet */
  if(d.check==='Source'){if(p==='unknown'&&/read/i.test(w.main))docNote(p,w,u);else if(p==='unknown')unchecked(d,w);return p==='unknown';}
  if(p==='unknown'){unchecked(d,w);return true;}
  if(d.positive_mismatch)compare(d);
  if(d.caveat)w.more='';
  if(d.positive_mismatch)w.more='';
  const key=((d.check||'')+'|'+w.main).toLowerCase();
  const date=d.date_label||d.published_label||day(d.published_at||d.date);
  let R=S.rows.get(key);
  if(R){addEvidence(R,q,u,date,w.title);dedupe();if(!reduce.matches)R.li.animate([{backgroundColor:'rgba(236,234,228,.07)'},{backgroundColor:'rgba(236,234,228,0)'}],{duration:600,easing:'ease-out'});return true;}
  const ext=!!(u&&host(u)!==S.host);
  R={key,p,ext,seq:++S.seq,evs:[],check:d.check,primary:d.primary,src:clean(d.source_name||'')};S.rows.set(key,R);
  const mark=anchor(d,p,q,ext);
  /* pinned to the words: the words are already on the sheet, so the line keeps only what they mean */
  let main=w.main;
  if(mark&&mark!==S.hostEl){q='';const said=main.match(/^Your message says\s+["“].*?["”]\s*:\s*(.+)$/);if(said)main=cap(said[1]);}
  if(!prose(q))q='';
  /* origin comes from the server's field; the label is ours, so any matching prefix in the text is dropped */
  main=String(main).replace(/^(Read from your message(\s*\(rule\))?|Found on the web)\s*:\s*/i,'');if(!/^[a-z0-9-]+\.[a-z]/.test(main))main=cap(main);
  const from=d.origin==='message'?'message':(d.origin==='exa'||d.origin==='web_search')?'web':(u&&!/^your message$/i.test(R.src))?'web':'message';
  const li=el('li','f');li.dataset.p=p;li.dataset.from=from;R.li=li;li._R=R;R.main=main;
  R.pins=el('span','pins');const lead=el('span','f-lead');lead.append(R.pins);
  const fb=el('div','f-body'),t=el('p','f-text');t.append(el('span','sr-only',WORD[p]+': '),main);fb.append(t);
  R.list=el('ul','ev');fb.append(R.list);R.same=el('p','f-meta same','Same source as above.');R.same.hidden=true;fb.append(R.same);
  const cav=clean(d.caveat||w.more||'');
  if(cav&&!S.cav.has(cav.toLowerCase())&&!(S.recorded&&/authority-reported pattern/i.test(cav))){S.cav.add(cav.toLowerCase());fb.append(el('p','f-cav',cav));}
  li.addEventListener('animationend',()=>li.classList.add('settled'),{once:true});
  li.append(lead,fb);
  addEvidence(R,q,u,date,w.title,R.src);
  insert(R);
  if(mark){R.mark=mark;(mark._rows||(mark._rows=[])).push(R);
    li.tabIndex=0;li.addEventListener('pointerenter',e=>{if(hover.matches&&e.pointerType==='mouse')light(R,true);});li.addEventListener('pointerleave',()=>light(R,false));li.addEventListener('focus',()=>light(R,true));li.addEventListener('blur',()=>light(R,false));}
  renumber();dedupe();
  $('#found-title').hidden=false;
  if(body.classList.contains('checking'))$('#announce').textContent=S.rows.size+(S.rows.size===1?' finding':' findings')+' so far';
  if(mark)attach(mark,R);
  return true;
}
function addEvidence(R,q,u,date,title,src){
  if(src&&!/^your message$/i.test(src))title=cap(src);
  else if(src&&!u)return;
  if(!q&&!u&&!date)return;
  const sig=(u+'|'+q).toLowerCase();if(R.evs.some(e=>e.sig===sig))return;
  const h=host(u),bare=q&&h&&q.toLowerCase().replace(/^www\./,'')===S.host;
  const item=el('li','ev-i');
  const said=(R.li.querySelector('.f-text')||{}).textContent||'';
  if(q&&!bare&&!(S.host&&q.toLowerCase()===S.host)&&!said.includes(q)&&!said.includes(q.replace(/[.]$/,''))){const bq=el('blockquote','q',q);item.append(bq);clampable(bq);}
  if(u||date){
    const meta=el('p','f-meta');
    if(u){const a=el('a');a.href=u;a.target='_blank';a.rel='noopener noreferrer';
      const same=R.evs.some(e=>e.h===h);const tail=same?decodeURIComponent(new URL(u).pathname.split('/').filter(Boolean)[0]||'').replace(/[-_]+/g,' ').slice(0,32):'';
      a.textContent=title&&title.toLowerCase()!==h?(title.length>64?title.slice(0,62).trim()+'…':title):h;
      if(title&&title.toLowerCase()!==h&&!src)a.append(' ',el('span','host',h));else if(tail)a.append(' ',el('span','host',tail));
      a.setAttribute('aria-label','Source: '+a.textContent+' (opens in a new tab)');meta.append(a);}
    if(date)meta.append(el('span','date',date));
    item.append(meta);
  }
  R.evs.push({sig,h,item,u,q});
  if(R.evs.length>1){item.hidden=true;
    if(!R.more){R.more=el('button','more');R.more.type='button';R.more.onclick=()=>{for(const e of R.evs)e.item.hidden=false;R.more.remove();R.more=null;};R.list.after(R.more);}
    const n=R.evs.length-1;R.more.textContent=n+' more '+(n===1?'source':'sources');}
  R.list.append(item);
}
function clampable(bq){requestAnimationFrame(()=>{if(bq.scrollHeight>bq.clientHeight+2){bq.classList.add('clamped');bq.tabIndex=0;bq.title='Show the full quote';const tog=()=>bq.classList.toggle('open');bq.onclick=tog;bq.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();tog();}};}});}
/* the server ranks the findings; up to three primary lines sit beside the sheet, the rest fold */
const sidePrimary=()=>S.order.some(x=>typeof x.primary==='boolean');
function before(a,b){return a.seq-b.seq;}
function beside(R,i){return sidePrimary()?R.primary===true:i<3;}
function insert(R){
  S.order.push(R);S.order.sort(before);
  const found=$('#found'),more=$('#more'),kids=[...found.children];
  const rects=reduce.matches?null:new Map(kids.map(k=>[k,k.getBoundingClientRect().top]));
  let a=0,b=0;
  S.order.forEach((x,i)=>{const side=beside(x,i)&&a<3,box=side?found:more,at=side?a++:b++;x.side=side;if(box.children[at]!==x.li)box.insertBefore(x.li,box.children[at]||null);});
  if(rects)for(const k of kids){if(k.parentNode!==found)continue;const dy=rects.get(k)-k.getBoundingClientRect().top;if(Math.abs(dy)>1)k.animate([{transform:`translateY(${dy}px)`},{transform:'none'}],{duration:220,easing:EASE});}
  foldCount();
}
/* one source is shown once, under the strongest line that uses it */
function dedupe(){
  const seen=new Set();
  for(const R of S.order){let real=0,dup=0;
    for(const e of R.evs){const qk=e.q?'q:'+e.q.toLowerCase():'';const d=!!(e.u&&seen.has(e.u));const qd=!e.u&&qk&&seen.has(qk);e.item.classList.toggle('dup',d||!!qd);if(e.u){d?dup++:real++;seen.add(e.u);}if(qk)seen.add(qk);}
    R.same.hidden=!(dup&&!real);}
}
function foldCount(){
  const n=S.order.filter(x=>!x.side).length+S.unk.size;
  $('#fold').hidden=!n;$('#fold-count').textContent=n||'';
}
function unchecked(d,w){
  const key=w.main.toLowerCase();
  if(S.unk.has(key))return;
  const li=el('li','u');const t=el('p','',w.main);if(w.more)t.append(' ',el('span','f-more',w.more));
  li.append(el('span','f-check',CHECK[d.check]||d.check||''),t);
  S.unk.set(key,li);$('#unchecked-list').append(li);
  $('#unchecked-title').hidden=false;foldCount();
}
function docNote(p,w,u){
  const box=$('#doc-notes');
  if(p==='unknown'&&/read/i.test(w.main))S.unreadable=true;
  const n=el('p','doc-note');const mk=el('i','m');mk.dataset.p=p==='unknown'?'unknown':'found';
  const s=el('span','',w.main);if(w.more)s.append(' ',el('span','f-more',w.more));
  n.append(mk,s);if(p==='unknown')n.dataset.unknown='1';box.append(n);box.hidden=false;
}

/* pin a finding to the words or the address it concerns */
function anchor(d,p,q,ext){
  if(S.hostEl){
    if(!S.host||!ext)return null;
    if(!(q+' '+clean(d.finding||d.sentence)).toLowerCase().includes(S.host.toLowerCase()))return null;
    S.hostEl.classList.add('anc');S.hostEl.dataset.p=RANK[p]<RANK[S.hostEl.dataset.p||'found']?p:(S.hostEl.dataset.p||p);
    return S.hostEl;
  }
  if(!S.textEl)return null;
  /* exact character span from the server first (UTF-16, as JavaScript counts), else the quoted words */
  const sp=d.span_utf16;let range=null,key;
  if(sp&&Number.isInteger(sp.start)&&sp.end>sp.start&&(!d.span_source||d.span_source==='input')&&S.text.slice(sp.start,sp.end)===String(d.anchor||d.quote||S.text.slice(sp.start,sp.end))){
    key='@'+sp.start+':'+sp.end;if(S.marks.has(key))return S.marks.get(key);range=offsetRange(S.textEl,sp.start,sp.end);
  }else{
    const target=norm(d.anchor||q);if(target.length<4)return null;
    key=target.toLowerCase();if(S.marks.has(key))return S.marks.get(key);range=findRange(S.textEl,target);
  }
  if(!range)return null;
  const mk=el('span','anc');mk.dataset.p=p;
  try{range.surroundContents(mk);}catch{return null;}
  const tail=[...mk.childNodes].reverse().find(x=>x.nodeType===3&&x.data.trim());const wd=tail&&tail.data.match(/\S+\s*$/);
  const nb=el('span','nb');if(wd&&tail.parentNode===mk&&!tail.nextSibling){const rest=tail.splitText(wd.index);rest.replaceWith(nb);nb.append(rest);}else mk.append(nb);
  mk._pins=el('span','pins');nb.append(mk._pins);
  S.marks.set(key,mk);
  mk.addEventListener('pointerenter',e=>{if(e.pointerType!=='mouse')return;e.stopPropagation();for(const r of mk._rows||[])light(r,true,true);});
  mk.addEventListener('pointerleave',()=>{for(const r of mk._rows||[])light(r,false);});
  mk.addEventListener('click',e=>{e.stopPropagation();peek(mk);});
  mk.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();peek(mk);}});
  return mk;
}
/* a range by exact character offsets, ignoring the pin numbers already placed in the text */
function offsetRange(root,start,end){
  const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);let pos=0,n,a=null,b=null;
  while((n=walker.nextNode())){
    if(n.parentElement.closest('.pins'))continue;
    const len=n.data.length;
    if(!a&&start<pos+len)a=[n,start-pos];
    if(!b&&end<=pos+len){b=[n,end-pos];break;}
    pos+=len;
  }
  if(!a||!b)return null;
  const r=document.createRange();r.setStart(a[0],a[1]);r.setEnd(b[0],b[1]);return r;
}
function findRange(root,target){
  const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);const map=[];let flat='',prevSpace=true,n;
  while((n=walker.nextNode())){if(n.parentElement.closest('.pins'))continue;const s=n.data;for(let i=0;i<s.length;i++){const ws=/\s/.test(s[i]);if(ws&&prevSpace)continue;flat+=ws?' ':s[i];map.push([n,i]);prevSpace=ws;}}
  let at=flat.indexOf(target);if(at<0)at=flat.toLowerCase().indexOf(target.toLowerCase());if(at<0)return null;
  const a=map[at],b=map[at+target.length-1];if(!a||!b)return null;
  const r=document.createRange();r.setStart(a[0],a[1]);r.setEnd(b[0],b[1]+1);return r;
}
/* every pinned line gets its own number, in the server's order; a line with no words to pin keeps a plain mark */
function renumber(){
  const byMark=new Map();let n=0;
  S.order.forEach(R=>{
    if(R.mark){R.n=++n;R.pins.replaceChildren(pin(R.n,R.p));(byMark.get(R.mark)||byMark.set(R.mark,[]).get(R.mark)).push(R);}
    else{R.n=null;const m=el('i','m');m.dataset.p=R.p;R.pins.replaceChildren(m);}
  });
  const marks=new Set([...S.marks.values()]);if(S.hostEl)marks.add(S.hostEl);
  for(const mk of marks){
    if(!mk._pins){if(mk!==S.hostEl)continue;mk._pins=mk.appendChild(el('span','pins'));}
    const rows=byMark.get(mk)||[];
    mk._pins.replaceChildren(...rows.map(R=>pin(R.n,R.p)));
    if(rows.length){mk.tabIndex=0;mk.setAttribute('role','button');mk.setAttribute('aria-label',rows.map(R=>R.n+'. '+WORD[R.p]+': '+R.main).join(' '));}
  }
}
function pin(n,p){const s=el('span','pin',String(n));s.dataset.p=p;return s;}
function attach(mark,R){
  requestAnimationFrame(()=>requestAnimationFrame(()=>mark.classList.add('on')));
  if(reduce.matches||!wide.matches||!R.side)return;
  setTimeout(()=>{light(R,true);setTimeout(()=>light(R,false),900);},260);
}

const thread=$('#thread');
function light(R,on,fromMark){
  const mk=R.mark;if(!mk)return;
  R.li.classList.toggle('lit',on);mk.classList.toggle('lit',on);
  if(!on||!wide.matches){thread.classList.remove('on');return;}
  if(!R.n||!R.side||(fromMark&&mk._rows&&mk._rows.find(x=>x.n&&x.side)!==R))return;
  const pins=[...mk.querySelectorAll('.pin')],target=pins.find(x=>x.textContent===String(R.n))||pins[0];
  const r=(target||mk).getBoundingClientRect(),lr=R.li.getBoundingClientRect();
  if(r.bottom<0||r.top>innerHeight||lr.bottom<0||lr.top>innerHeight){thread.classList.remove('on');return;}
  const x1=lr.left-8,y1=lr.top+14,x2=r.right+5,y2=r.top+r.height/2,dx=Math.max(40,(x1-x2)/2);
  thread.setAttribute('d',`M${x1},${y1} C${x1-dx},${y1} ${x2+dx},${y2} ${x2},${y2}`);
  thread.style.setProperty('--tc',getComputedStyle(R.li.querySelector('.pin')||mk).getPropertyValue('--pc'));
  thread.classList.add('on');
  if(!reduce.matches){const len=thread.getTotalLength();thread.animate([{strokeDasharray:len,strokeDashoffset:len},{strokeDasharray:len,strokeDashoffset:0}],{duration:220,easing:EASE});}
}
addEventListener('scroll',()=>thread.classList.remove('on'),{passive:true});

/* any mark on the sheet opens its own lines in place, so folded signs are one tap away */
const pk=$('#peek');let pkMark=null;
function peek(mk){
  if(pkMark===mk&&!pk.hidden){closePeek();return;}
  const rows=(mk._rows||[]).filter(R=>R.n);if(!rows.length)return;
  pk.replaceChildren();
  for(const R of rows){
    const r=el('div','peek-row');const lead=el('span','f-lead');lead.append(pin(R.n,R.p));
    const t=el('div','peek-body');t.append(el('p','peek-text',R.main));
    const src=R.evs.find(e=>e.u);if(src||R.src){const m=el('p','peek-src',R.src&&!/^your message$/i.test(R.src)?cap(R.src):src?host(src.u):'');if(m.textContent)t.append(m);}
    r.append(lead,t);pk.append(r);
  }
  pk.hidden=false;pkMark=mk;
  const box=pk.offsetParent.getBoundingClientRect(),lines=[...mk.getClientRects()],last=lines[lines.length-1]||mk.getBoundingClientRect();
  const w=Math.min(pk.offsetParent.clientWidth-24,352);
  let left=Math.max(12,Math.min(last.right-box.left-w/2-40,box.width-w-12));
  pk.style.width=w+'px';pk.style.left=left+'px';pk.style.top=(last.bottom-box.top+8)+'px';
  pk.style.setProperty('--ox',Math.max(16,Math.min(w-16,last.right-box.left-left-8))+'px');
  if(!reduce.matches)pk.animate([{opacity:0,transform:'translateY(-4px) scale(.98)'},{opacity:1,transform:'none'}],{duration:170,easing:EASE});
  for(const R of rows)light(R,true,true);
}
function closePeek(){if(pk.hidden)return;pk.hidden=true;if(pkMark)for(const R of pkMark._rows||[])light(R,false);pkMark=null;}
document.addEventListener('click',e=>{if(!pk.hidden&&!pk.contains(e.target))closePeek();});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closePeek();});

/* a real address mismatch: the address sent and the organisation's known address, side by side */
function compare(d){
  const box=$('#compare');if(!box.hidden||!d.offered_domain||!d.known_official_domain)return;
  const cell=(label,dom,cls)=>{const c=el('div','cmp '+cls);c.append(el('span','cmp-label',label));const v=el('span','cmp-dom',dom);c.append(v);return [c,v];};
  const [a,av]=cell(S.recorded?'The advertised address':'The link you pasted',d.offered_domain,'cmp-sent');
  const [b]=cell(d.source_name?cap(clean(d.source_name))+' lists this organisation at':'The organisation\'s known address',d.known_official_domain,'cmp-known');
  if(S.hostEl&&S.host===String(d.offered_domain).replace(/^www\./,'')){av.replaceWith(S.hostEl);S.hostEl.classList.add('cmp-dom');const path=doc.querySelector('.doc-path');if(path)path.remove();doc.hidden=true;}
  box.append(a,b);box.hidden=false;$('#sheet-label').hidden=true;
}

function verdictPol(r){
  if(r.polarity)return polarity({polarity:r.polarity});
  const t=String(r.overall||'').toLowerCase();
  if(/do not|don.t|stop/.test(t))return 'warning';
  if(/nothing worrying|no concerns/.test(t))return 'reassuring';
  if(/could not read|incomplete|could not/.test(t))return 'unknown';
  return 'worth';
}
function setVerdict(text,p,animate=true){
  const line=$('#verdict-line');$('#verdict-text').textContent=text;$('#verdict-mark').dataset.p=p;
  if(animate&&!reduce.matches){line.classList.remove('swap');void line.offsetWidth;line.classList.add('swap');}
}
function finish(r){
  busy=false;body.classList.remove('checking');
  const p=verdictPol(r);setVerdict(clean(r.overall)||'Check finished',p);
  $('#steps').hidden=true;
  const counts={};for(const R of S.rows.values())counts[R.p]=(counts[R.p]||0)+1;
  const sub=$('#verdict-sub');sub.replaceChildren();
  const parts=Object.keys(counts).sort((a,b)=>RANK[a]-RANK[b]).map(k=>counts[k]+' '+TALLY[k][counts[k]===1?0:1]);
  if(parts.length){const lead=Object.keys(counts).sort((a,b)=>RANK[a]-RANK[b])[0];
    if(lead==='warning'||lead==='reassuring'){sub.append(el('b','',parts[0]),parts.length>1?', '+parts.slice(1).join(', ')+'.':'.');}else sub.append(cap(parts.join(', '))+'.');}
  const at=r.checked_at||S.recordedAt;const st=stamp(at);
  /* the date only: the server's clock is UTC and a bare time would read as the visitor's own */
  const dd=day(at);if(dd)sub.append(' Checked '+dd+'.');
  if(p==='reassuring')sub.append(el('span','verdict-limit','Nothing found is not proof of safety.'));
  $('#ledger').classList.toggle('calm',p==='reassuring');$('#fold').classList.toggle('calm',p==='reassuring');
  $('#found-title').textContent=p==='reassuring'?'For reference':'What matters here';
  if(p==='unknown'&&S.unreadable){sub.append(el('span','verdict-limit','Many sites block readers. Unknown is not a warning.'));
    for(const n of document.querySelectorAll('.doc-note[data-unknown]'))n.remove();$('#doc-notes').hidden=!$('#doc-notes').children.length;}
  $('#found-none').hidden=S.rows.size>0;$('#found-title').hidden=false;foldCount();
  $('#announce').textContent=clean(r.overall);
  drafts(r);
  $('#verdict-line').focus({preventScroll:true});
  for(const b of document.querySelectorAll('button.case,.case-pick'))b.disabled=false;setAvailability();
}
function fail(msg){
  busy=false;body.classList.remove('checking');
  for(const b of document.querySelectorAll('button.case,.case-pick'))b.disabled=false;setAvailability();
  if(!S){ask(msg);return;}
  setVerdict('Check incomplete','unknown');$('#steps').hidden=true;
  const sub=$('#verdict-sub');sub.replaceChildren(msg+' ');
  const again=el('button','go again','Try again');again.type='button';again.onclick=()=>{const [p,t,rec]=last;reset(false);begin(p,t,rec);};
  sub.append(el('br'),again);
  $('#announce').textContent='The check could not finish. '+msg;
}

const tabs=['reply','report'];let tab='reply';
function fit(ta){ta.style.height='auto';ta.style.height=ta.scrollHeight+2+'px';}
for(const id of ['reply','report'])$('#'+id).addEventListener('input',e=>fit(e.target));
/* one next step: things to confirm yourself when nothing needs asking, otherwise a reply to the sender */
function drafts(r){
  const steps=(Array.isArray(r.next_steps)?r.next_steps:[]).map(clean).filter(Boolean);
  const lines=String(r.reply||'').trim().split('\n'),srcLine=lines.findIndex(l=>/^verification sources:/i.test(l.trim()));
  let srcs=srcLine<0?[]:lines[srcLine].replace(/^[^:]*:/,'').split(/;\s*/).map(x=>safe(x.trim())).filter(Boolean);
  if(srcLine>=0)lines.splice(srcLine,1);
  if(Array.isArray(r.reply_sources))srcs=[...new Set(srcs.concat(r.reply_sources.map(safe).filter(Boolean)))];
  const reply=lines.join('\n').trim();S.replySources=srcs;
  const self=steps.length>0||!reply;
  $('#next-title').textContent=self?'What to confirm yourself':'Ask the sender first';
  $('#panel-checklist').hidden=!self;$('#letter-foot').hidden=self;
  const cl=$('#checklist');cl.replaceChildren();
  if(self){
    for(const line of steps){const li=el('li'),lb=el('label'),cb=el('input');cb.type='checkbox';lb.append(cb,el('span','box'),el('span','cl-text',line));li.append(lb);cl.append(li);}
    $('#tabs').hidden=true;$('#panel-reply').hidden=true;$('#panel-report').hidden=true;$('#next').hidden=false;return;
  }
  const rs=$('#reply-src');rs.replaceChildren();rs.hidden=!srcs.length;
  if(srcs.length){const n=new Set(srcs.map(host)).size;rs.textContent=n===1?'Copies with its source link.':'Copies with its '+n+' source links.';rs.title=srcs.join('\n');}
  const report=String(r.report||'').trim(),hasReport=!!report&&!/^no report/i.test(report);
  $('#report').value=hasReport?report:'';$('#tabs').hidden=!hasReport;
  $('#next').hidden=false;select('reply',false);
  type($('#reply'),reply);
}
function type(ta,text){
  const token=run;ta.value=text;fit(ta);
  if(reduce.matches||!text)return;
  ta.value='';
  const steps=Math.min(48,Math.max(14,Math.ceil(text.length/7))),per=Math.ceil(text.length/steps);let i=0;
  ta.addEventListener('focus',()=>{i=text.length;ta.value=text;},{once:true});
  const tick=()=>{if(token!==run||i>=text.length)return;i=Math.min(text.length,i+per);ta.value=text.slice(0,i);if(i<text.length)requestAnimationFrame(tick);};
  setTimeout(tick,180);
}
function select(name,focus=true){
  tab=name;
  for(const t of tabs){const b=$('#tab-'+t),on=t===name;b.setAttribute('aria-selected',String(on));b.tabIndex=on?0:-1;$('#panel-'+t).hidden=!on;}
  if(focus)$('#tab-'+name).focus();
  if(name==='report')fit($('#report'));
  const copy=$('#copy');copy.classList.remove('done');copy.textContent='Copy '+name;
}
for(const t of tabs)$('#tab-'+t).onclick=()=>select(t,false);
$('.tabs').addEventListener('keydown',e=>{if(e.key==='ArrowRight'||e.key==='ArrowLeft'){e.preventDefault();select(tab==='reply'?'report':'reply');}});
$('#copy').onclick=async()=>{
  const b=$('#copy');
  const text=tab==='reply'?$('#reply').value+(S&&S.replySources&&S.replySources.length?'\nVerification sources: '+S.replySources.join('; '):''):$('#report').value;
  try{await navigator.clipboard.writeText(text);b.textContent='Copied';b.classList.add('done');}
  catch{$('#'+tab).focus();$('#'+tab).select();b.textContent='Press Ctrl+C to copy';}
  setTimeout(()=>{b.classList.remove('done');b.textContent='Copy '+tab;},1800);
};

function reset(clear=true){
  run++;queue.length=0;busy=false;S=null;
  body.classList.remove('result','checking');body.classList.add('intake');
  $('#again').hidden=true;$('#ledger').hidden=true;$('#next').hidden=true;$('#verdict').hidden=true;$('#cases-panel').hidden=!cases.length;
  doc.hidden=true;doc.replaceChildren();value.hidden=false;$('#doc-notes').hidden=true;$('#provenance').hidden=true;
  $('#value-label').textContent='The offer you were sent';thread.classList.remove('on');closePeek();
  for(const id of ['compare'])$('#'+id).hidden=true;$('#sheet-label').hidden=false;
  if(clear&&last&&last[2])value.value='';
  for(const b of document.querySelectorAll('button.case,.case-pick'))b.disabled=false;setAvailability();
}
$('#again').onclick=()=>{reset();window.scrollTo(0,0);value.focus({preventScroll:true});};

fetch('/api/status').then(r=>r.json()).then(s=>{live=!!s.live_enabled;cases=Array.isArray(s.cases)?s.cases:[];renderCases();setAvailability();})
  .catch(()=>{go.disabled=true;note.textContent='Not answering. Reload to try again.';});

/* examples open in place from one quiet link */
(()=>{const t=$('#try-link');if(!t)return;t.onclick=()=>{const on=!body.classList.contains('show-cases');body.classList.toggle('show-cases',on);t.setAttribute('aria-expanded',String(on));if(on)$('#cases-panel').scrollIntoView({block:'nearest',behavior:reduce.matches?'auto':'smooth'});};})();
