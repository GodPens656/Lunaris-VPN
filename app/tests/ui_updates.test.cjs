'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

function harness({platform='windows',update,request=()=>{},dialogOpen=false,hidden=false}={}){
 const elements=new Map(),handlers=new Map(),calls=[],timers=new Map();
 const element=()=>({dataset:{},textContent:'',innerHTML:'',attributes:{},style:{setProperty(){}},
  classList:{add(){},remove(){}},addEventListener(type,handler){this[type]=handler;},
  setAttribute(k,v){this.attributes[k]=v;},removeAttribute(k){delete this.attributes[k];}});
 const query=s=>{if(!elements.has(s))elements.set(s,element());return elements.get(s);};
 query('#toast');query('#dialog-title');
 const buttons=[element(),element()];
 query('#dialog-actions').querySelectorAll=()=>buttons;
 const dialog=Object.assign(query('#dialog'),{open:dialogOpen,showModal(){this.open=true;},close(){this.open=false;}});
 query('#view').dataset.ready='1';
 const settings={mode:'proxy',core:'mihomo',ipv6:true,auto_sort_ping:true};
 const snapshot=()=>({version:'0.6.5',platform,settings:{...settings},status:'disconnected',
  profiles:[{key:'test',name:'Test',protocol:'trojan'}],selected:'test',subscriptions:[],stats:{},latency:{},logs:[],cores:{}});
 let updateValue=update===undefined?{version:'0.7.0',current_version:'0.6.5',size:1048576,
  asset_name:platform==='android'?'LunarisClient-0.7.0-arm64.apk':'LunarisClient-0.7.0-windows-x64.zip'}:update;
 let initial=true,start;
 const startup=new Promise(resolve=>start=resolve);
 const context=vm.createContext({
  document:{hidden,documentElement:element(),querySelector:query,querySelectorAll:()=>[],
   addEventListener:(type,handler)=>handlers.set(type,handler)},
  window:{addEventListener(){},__TAURI__:{core:{invoke:async(_,{method,args})=>{
   if(method==='snapshot'&&initial){initial=false;return startup;}
   calls.push({method,args:structuredClone(args)});await request({method,args});
   if(method==='check_app_update')return structuredClone(updateValue);
   if(method==='download_app_update'||method==='take_import_link')return null;
   if(method==='settings')Object.assign(settings,args);
   return snapshot();
  }}}},
  FormData:class {},Background:{modes:[['waves','Волны']],set(){}},
  localStorage:{getItem(){return null;},setItem(){}},matchMedia:()=>({matches:false,addEventListener(){}}),
  setTimeout:(fn,delay)=>{const id={};timers.set(id,{fn,delay});return id;},clearTimeout:id=>timers.delete(id)
 });
 const run=code=>vm.runInContext(code,context);
 run(fs.readFileSync(path.join(__dirname,'../ui/app.js'),'utf8'));
 const drain=async()=>{await new Promise(setImmediate);await new Promise(setImmediate);};
 return {run,calls,elements,dialog,context,buttons,drain,setUpdate:value=>updateValue=value,
  async start(){start(snapshot());await drain();},
  submit:()=>query('#dialog-form').submit({preventDefault(){},target:query('#dialog-form')}),
  visibility:()=>handlers.get('visibilitychange')(),
  click:action=>handlers.get('click')({target:{closest:()=>({dataset:{action},classList:{contains:()=>false}})}})
 };
}

test('startup checks in the background and offers only Later and Download for either platform',async()=>{
 for(const platform of ['windows','android']){
  const ui=harness({platform});await ui.start();
  assert.equal(ui.calls.filter(c=>c.method==='check_app_update').length,1);
  assert.equal(ui.dialog.open,true);
  assert.match(ui.elements.get('#dialog-actions').innerHTML,/>Позже</);
  assert.match(ui.elements.get('#dialog-actions').innerHTML,/>Скачать</);
  assert.match(ui.elements.get('#dialog-body').innerHTML,platform==='android'?/arm64\.apk/:/windows-x64\.zip/);
  assert.equal(ui.run('busy'),false);
  assert.equal(ui.calls.some(c=>c.method==='download_app_update'),false);
  await ui.run('poll()');await ui.run('poll()');
  assert.equal(ui.calls.filter(c=>c.method==='check_app_update').length,1);
 }
});

test('no release or a failed automatic check leaves the app usable without an error dialog',async()=>{
 for(const failure of [false,true]){
  const ui=harness({update:null,request:({method})=>{if(failure&&method==='check_app_update')throw Error('GitHub недоступен');}});
  await ui.start();
  assert.equal(ui.dialog.open,false);assert.equal(ui.elements.get('#toast').textContent,'');
  assert.equal(ui.run('appUpdateChecking'),false);assert.equal(ui.run('busy'),false);
 }
});

test('an existing modal and hidden app defer the offer until it can be shown',async()=>{
 const ui=harness({dialogOpen:true});ui.elements.get('#dialog-title').textContent='Импорт';await ui.start();
 assert.equal(ui.elements.get('#dialog-title').textContent,'Импорт');
 ui.dialog.close();ui.run('showAppUpdate()');assert.equal(ui.dialog.open,true);
 assert.equal(ui.elements.get('#dialog-title').textContent,'Доступно обновление');
 const hidden=harness({hidden:true});await hidden.start();assert.equal(hidden.dialog.open,false);
 hidden.context.document.hidden=false;hidden.visibility();await hidden.drain();
 assert.equal(hidden.dialog.open,true);assert.equal(hidden.calls.filter(c=>c.method==='check_app_update').length,1);
});

test('Later does not download or repeat the offer; a manual check can reopen it',async()=>{
 const ui=harness();await ui.start();await ui.click('close-dialog');
 await ui.run('poll()');assert.equal(ui.dialog.open,false);
 assert.equal(ui.calls.some(c=>c.method==='download_app_update'),false);
 await ui.click('check-app-update');
 assert.equal(ui.dialog.open,true);
 assert.equal(ui.calls.filter(c=>c.method==='check_app_update').length,2);
});

test('Download flushes settings and asks the backend for the displayed version only',async()=>{
 const ui=harness();await ui.start();
 ui.run("const draft={raw:false,value:false,error:''};settingsDrafts.set('ipv6',draft);queueSetting('ipv6',draft)");
 await ui.submit();
 const methods=ui.calls.filter(c=>['settings','download_app_update'].includes(c.method));
 assert.deepEqual(methods,[{method:'settings',args:{ipv6:false}},{method:'download_app_update',args:{version:'0.7.0'}}]);
 assert.equal(ui.dialog.open,false);
 assert.match(ui.elements.get('#toast').textContent,/браузере/);
});

test('a browser launch failure stays in the dialog and allows retry',async()=>{
 let fail=true;
 const ui=harness({request:({method})=>{if(fail&&method==='download_app_update')throw Error('Браузер недоступен');}});
 await ui.start();await ui.submit();
 assert.equal(ui.dialog.open,true);assert.equal(ui.elements.get('#dialog-error').textContent,'Браузер недоступен');
 assert.equal(ui.buttons.every(b=>!b.disabled),true);
 fail=false;await ui.submit();assert.equal(ui.dialog.open,false);
});

test('overlapping checks share the running request and manual errors are visible',async()=>{
 let release;const gate=new Promise(resolve=>release=resolve);
 const ui=harness({request:async({method})=>{if(method==='check_app_update')await gate;}});
 await ui.start();
 assert.equal(ui.run('appUpdateChecking'),true);
 await ui.run('checkAppUpdate(true)');await ui.run('checkAppUpdate()');
 assert.equal(ui.calls.filter(c=>c.method==='check_app_update').length,1);
 assert.equal(ui.elements.get('[data-action="check-app-update"]').disabled,true);
 release();await ui.drain();assert.equal(ui.run('appUpdateChecking'),false);
 const failed=harness({request:({method})=>{if(method==='check_app_update')throw Error('GitHub недоступен');}});
 await failed.start();await failed.run('checkAppUpdate(true)');
 assert.equal(failed.elements.get('#toast').textContent,'GitHub недоступен');
 const latest=harness({update:null});await latest.start();await latest.run('checkAppUpdate(true)');
 assert.match(latest.elements.get('#toast').textContent,/Новых версий/);
});

test('resuming is throttled and a later new version can be offered in the same session',async()=>{
 const ui=harness();ui.context.now=100000;ui.run('Date.now=()=>now');await ui.start();ui.dialog.close();
 ui.context.now+=1000;ui.visibility();await ui.drain();
 assert.equal(ui.calls.filter(c=>c.method==='check_app_update').length,1);
 ui.setUpdate({version:'0.8.0',current_version:'0.6.5',asset_name:'LunarisClient-0.8.0-windows-x64.zip',size:4096});
 ui.context.now+=3600000;ui.visibility();await ui.drain();
 assert.equal(ui.calls.filter(c=>c.method==='check_app_update').length,2);
 assert.equal(ui.dialog.open,true);assert.match(ui.elements.get('#dialog-body').innerHTML,/0\.8\.0/);
});

test('release text is escaped before it is inserted into the dialog',async()=>{
 const ui=harness({update:{version:'<b>0.7.0</b>',current_version:'<script>bad()</script>',asset_name:'<img onerror=bad()>',size:1024}});
 await ui.start();const body=ui.elements.get('#dialog-body').innerHTML;
 assert.doesNotMatch(body,/<script>|<img|<b>/);assert.match(body,/&lt;script&gt;/);
});
