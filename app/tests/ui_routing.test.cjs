'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

function harness(platform='windows',request=()=>{}){
 const handlers=new Map(),elements=new Map(),calls=[],timers=new Map();
 const element=()=>({dataset:{ready:'1'},style:{setProperty(){}},classList:{add(){},remove(){}},
  attributes:{},addEventListener(){},setAttribute(k,v){this.attributes[k]=v;},removeAttribute(k){delete this.attributes[k];}});
 const query=s=>{if(!elements.has(s))elements.set(s,element());return elements.get(s);};
 const saved={mode:'proxy',core:'mihomo',bypass_domains:[],bypass_russian_domains:false};
 const snapshot=()=>({platform,settings:{...saved},status:'disconnected',profiles:[],subscriptions:[],cores:{},latency:{},logs:[]});
 const context=vm.createContext({
  document:{documentElement:element(),querySelector:query,querySelectorAll:()=>[],
   addEventListener:(type,fn)=>handlers.set(type,fn)},
  window:{addEventListener(){},__TAURI__:{core:{invoke:async(_,{method,args})=>{
   if(method==='snapshot')return new Promise(()=>{});
   calls.push({method,args:structuredClone(args)});await request(args);
   if(method==='settings')Object.assign(saved,structuredClone(args));
   return snapshot();
  }}}},
  Background:{modes:[['none','Нет']],set(){}},
  localStorage:{getItem(){return null;},setItem(){}},matchMedia:()=>({matches:false,addEventListener(){}}),
  setTimeout:(fn,delay)=>{const id={};timers.set(id,{fn,delay});return id;},clearTimeout:id=>timers.delete(id)
 });
 vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui/app.js'),'utf8'),context);
 context.initial=snapshot();
 const run=code=>vm.runInContext(code,context);
 run("state=initial;tab='settings'");
 const field=Object.assign(query('#settings-form [name="bypass_domains"]'),{
  name:'bypass_domains',type:'textarea',tagName:'TEXTAREA',form:{id:'settings-form'},value:'',checkValidity:()=>true
 });
 return {run,saved,calls,field,elements,emit:type=>handlers.get(type)({target:field}),flush:()=>run('flushSettings()')};
}

test('connection starts collapsed and all bypass settings live in Routing on both platforms',()=>{
 for(const platform of ['windows','android']){
  const ui=harness(platform),html=ui.run('settings()');
  const sections=[...html.matchAll(/<details\b([^>]*)>(.*?)<\/details>/gs)];
  const connection=sections.find(([, ,body])=>body.includes('Подключение</summary>'));
  const routing=sections.find(([, ,body])=>body.includes('Маршрутизация</summary>'));
  assert.ok(connection);assert.ok(routing);
  assert.doesNotMatch(connection[1],/\bopen\b/);
  assert.doesNotMatch(connection[2],/bypass_/);
  assert.match(routing[2],/name="bypass_russian_domains"/);
  assert.match(routing[2],/<textarea name="bypass_domains"/);
  assert.match(routing[2],/все его поддомены/);
 }
});

test('domain lines autosave as a list, restore, delete and clear without duplicate writes',async()=>{
 for(const platform of ['windows','android']){
  const ui=harness(platform);
  ui.field.value=' example.com \r\n\nпример.рф\n';ui.emit('input');
  assert.equal(ui.calls.length,0);
  await ui.flush();
  assert.deepEqual(ui.calls[0],{method:'settings',args:{bypass_domains:['example.com','пример.рф']}});
  assert.match(ui.run('settings()'),/>example.com\nпример.рф<\/textarea>/);
  ui.emit('change');await ui.flush();assert.equal(ui.calls.length,1);
  ui.field.value='пример.рф';ui.emit('change');await ui.flush();
  assert.deepEqual(ui.saved.bypass_domains,['пример.рф']);
  ui.field.value='\n  \n';ui.emit('change');await ui.flush();
  assert.deepEqual(ui.saved.bypass_domains,[]);
 }
});

test('rejected domains keep the draft and show an error until corrected',async()=>{
 const ui=harness('windows',args=>{if(args.bypass_domains?.includes('https://bad.test'))throw Error('Введите домен без ссылки.');});
 ui.field.value='https://bad.test';ui.emit('change');await ui.flush();
 assert.deepEqual(ui.saved.bypass_domains,[]);
 assert.equal(ui.field.attributes['aria-invalid'],'true');
 assert.match(ui.run('settings()'),/>https:\/\/bad.test<\/textarea>/);
 assert.match(ui.elements.get('#setting-error-bypass_domains').textContent,/Введите домен/);
 ui.field.value='good.test';ui.emit('change');await ui.flush();
 assert.deepEqual(ui.saved.bypass_domains,['good.test']);
 assert.equal(ui.field.attributes['aria-invalid'],undefined);
});

test('a newer domain draft wins during an in-flight save and HTML is escaped',async()=>{
 let release;const pending=new Promise(resolve=>release=resolve);
 const ui=harness('windows',async args=>{if(args.bypass_domains?.includes('first.test'))await pending;});
 ui.field.value='first.test';ui.emit('change');await new Promise(setImmediate);
 ui.field.value='latest.test';ui.emit('change');release();await ui.flush();
 assert.deepEqual(ui.saved.bypass_domains,['latest.test']);
 ui.field.value='</textarea><script>bad()</script>';ui.emit('input');
 const html=ui.run('settings()');
 assert.doesNotMatch(html,/<script>bad/);
 assert.match(html,/&lt;\/textarea&gt;&lt;script&gt;bad/);
});
