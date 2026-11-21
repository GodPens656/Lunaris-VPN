'use strict';
const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const paths = {
 shield:'<path d="M12 3 4.5 6v5c0 5 7.5 10 7.5 10s7.5-5 7.5-10V6Z"/><path d="m9 12 2 2 4-4"/>',
 servers:'<rect x="4" y="3" width="16" height="7" rx="2"/><rect x="4" y="14" width="16" height="7" rx="2"/><path d="M8 6.5h.01M8 17.5h.01M12 6.5h4M12 17.5h4"/>',
 link:'<path d="m10 13 4-4m-7 6-1 1a4 4 0 0 0 6 6l4-4a4 4 0 0 0 0-6M17 9l1-1a4 4 0 0 0-6-6L8 6a4 4 0 0 0 0 6" transform="translate(0 0) scale(.92)"/>',
 settings:'<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2" fill="var(--surface)"/><circle cx="15" cy="12" r="2" fill="var(--surface)"/><circle cx="9" cy="18" r="2" fill="var(--surface)"/>',
 routing:'<path d="M12 8v5M5 16v-3h14v3"/><circle cx="12" cy="5" r="3"/><rect x="2" y="16" width="6" height="5" rx="1"/><rect x="16" y="16" width="6" height="5" rx="1"/>',
 log:'<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h4"/>',
 moon:'<path d="M20.8 13A9 9 0 0 1 11 3.2 9 9 0 1 0 20.8 13Z"/>',
 plus:'<path d="M12 5v14M5 12h14"/>', refresh:'<path d="M20 7v5h-5M4 17v-5h5M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1"/>',
 arrow:'<path d="m9 5 7 7-7 7"/>', up:'<path d="M12 20V4m-6 6 6-6 6 6"/>', down:'<path d="M12 4v16m-6-6 6 6 6-6"/>',
 clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>', speed:'<path d="M4 19a9 9 0 1 1 16 0M12 13l4-5M5 13h1M18 13h1M12 4v1"/><circle cx="12" cy="14" r="2"/>',
 lock:'<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>', trash:'<path d="M4 6h16M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7M14 10v7"/>'
};
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.servers}</svg>`;
paths.tray='<path d="M12 3v11m-4-4 4 4 4-4M4 15v5h16v-5"/>';
const nav = [['home','Подключение','shield'],['servers','Серверы','servers'],['subscriptions','Подписки','link'],['settings','Настройки','settings'],['logs','Журнал','log']];
const connectionModes = [['proxy','Системный прокси'],['tun','TUN · весь трафик устройства']];
const latencyMethods = [['proxy','PROXY GET · через подключённый VPN'],['tcp','TCP/UDP · до сервера'],['icmp','ICMP']];
// Provider addresses: https://developers.cloudflare.com/1.1.1.1/ip-addresses/
// https://developers.google.com/speed/public-dns/docs/using and https://dns.yandex.ru/
const dnsPresets = {
 cloudflare:{label:'Cloudflare DNS',dns_server:'1.1.1.1',bootstrap_dns:'1.1.1.1',dns_tls_name:'cloudflare-dns.com'},
 google:{label:'Google DNS',dns_server:'8.8.8.8',bootstrap_dns:'8.8.8.8',dns_tls_name:'dns.google'},
 yandex:{label:'Яндекс DNS',dns_server:'77.88.8.8',bootstrap_dns:'77.88.8.8',dns_tls_name:'common.dot.dns.yandex.net'}
};
const dnsKeys = ['dns_server','bootstrap_dns','dns_tls_name'];
let customDns = false;
const statusNames = {disconnected:'Отключено',connecting:'Подключается…',connected:'Подключено',disconnecting:'Отключается…',error:'Ошибка подключения'};
let state = null, tab = 'home', busy = false, search = '', source = 'all', bulkMethod = 'tcp', lastSignature = '', toastTimer, dialogSubmit, startupSeen = false;
let subscriptionsBusy = false;
let appUpdateChecking=false,appUpdateCheckedAt=null,pendingAppUpdate=null,appUpdatePromptedVersion=null;
const subscriptionRequests = new Set();
const settingsDrafts = new Map(), settingsTimers = new Map();
let settingsSaveQueue = Promise.resolve(), settingsSaving = 0;
let navigationId=0, viewAnimation, pendingTab=null;
let appearance;
try { appearance = JSON.parse(localStorage.getItem('lunaris.appearance')) || {}; } catch { appearance = {}; }
if (typeof appearance !== 'object' || Array.isArray(appearance)) appearance = {};
const media = matchMedia('(prefers-color-scheme: dark)');
function applyAppearance(){
  const theme = ['material','amoled','glass','simple'].includes(appearance.theme) ? appearance.theme : 'material';
  const scheme = theme === 'amoled' ? 'dark' : ['light','dark'].includes(appearance.scheme) ? appearance.scheme : media.matches ? 'dark' : 'light';
  const accent = /^#[0-9a-f]{6}$/i.test(appearance.accent) ? appearance.accent : scheme === 'dark' ? '#399d83' : '#167663';
  appearance.background = Background.modes.some(([id])=>id===appearance.background) ? appearance.background : 'waves';
  appearance.backgroundIntensity = Number.isFinite(appearance.backgroundIntensity) ? Math.max(10,Math.min(100,appearance.backgroundIntensity)) : 60;
  document.documentElement.dataset.theme = theme;
  document.documentElement.dataset.scheme = scheme;
  document.documentElement.dataset.background = appearance.background;
  document.documentElement.style.setProperty('--accent',accent);
  Background.set({mode:appearance.background,intensity:appearance.backgroundIntensity/100,accent,dark:scheme==='dark'});
  const slider = $('#background-intensity'), output = $('#background-intensity-value');
  if(slider)slider.disabled=appearance.background==='none';
  if(output)output.textContent=`${appearance.backgroundIntensity}%`;
  try { localStorage.setItem('lunaris.appearance',JSON.stringify(appearance)); } catch { /* WebView storage may be disabled. */ }
}
applyAppearance(); media.addEventListener('change',applyAppearance);
const native = () => window.__TAURI__?.core?.invoke;
async function rpc(method,args={}){
  if(!native()) throw Error('Откройте установленное приложение Lunaris client. В браузере доступен только просмотр интерфейса.');
  return await native()('api',{method,args});
}
function toast(message){ $('#toast').textContent=message;$('#toast').classList.add('visible');clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').classList.remove('visible'),5500); }
function bytes(n){const units=['Б','КБ','МБ','ГБ','ТБ'];let i=0;while(n>=1000&&i<4){n/=1000;i++;}return `${i?n.toFixed(1):n} ${units[i]}`;}
function duration(n){return [Math.floor(n/3600),Math.floor(n/60)%60,n%60].map(x=>String(x).padStart(2,'0')).join(':');}
function subscriptionExpiry(s,now=Date.now()){
 const seconds=s.userinfo?.expire;
 if(typeof seconds!=='number'||!Number.isFinite(seconds)||seconds<=0)return null;
 const date=new Date(seconds*1000);
 if(!Number.isFinite(date.getTime()))return null;
 const remaining=date.getTime()-now,expired=remaining<=0,days=expired?0:Math.ceil(remaining/86400000);
 const status=expired?'expired':days<=3?'soon':'active';
 const message=expired?'Подписка закончилась':status==='soon'?`Подписка заканчивается через ${days} ${days===1?'день':'дня'}`:'';
 return {date,status,days,message};
}
function expiryTime(expiry){return `<time datetime="${expiry.date.toISOString()}">${esc(expiry.date.toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}))}</time>`;}
function subscriptionValidity(s){
 const expiry=subscriptionExpiry(s);
 if(!expiry)return `<p class="subscription-expiry">${icon('clock')}<span>Срок действия не указан</span></p>`;
 return `<p class="subscription-expiry ${expiry.status}">${icon('clock')}<span>${expiry.status==='expired'?'Срок действия истёк':'Действует до'} ${expiryTime(expiry)}${expiry.status==='soon'?`<strong>${esc(expiry.message)}</strong>`:''}</span></p>`;
}
function homeSubscriptionDescription(){
 const profile=state.profiles.find(p=>p.key===state.selected);
 const subscription=state.subscriptions.find(s=>s.id===profile?.source_id);
 if(!subscription)return '';
 return `<div class="card home-subscription-description"><span class="caption">Описание подписки · ${esc(subscription.name)}</span><p class="subscription-description${subscription.description?'':' muted'}">${esc(subscription.description||'Создатель подписки не добавил описание.')}</p></div>`;
}
function subscriptionNotices(){
 return state.subscriptions.map(s=>{
  const expiry=subscriptionExpiry(s);
  if(!expiry||expiry.status==='active')return '';
  return `<div class="subscription-notice ${expiry.status}">${icon('clock')}<div><strong>${esc(expiry.message)}</strong><p>${esc(s.name)} · ${expiry.status==='expired'?'Действовала до':'Действует до'} ${expiryTime(expiry)}</p><button class="text-button" data-tab="subscriptions">Открыть подписки →</button></div></div>`;
 }).join('');
}
function nameHtml(value){return esc(value).replace(/[\u{1f1e6}-\u{1f1ff}]{2}/gu,flag=>{const code=[...flag].map(c=>String.fromCharCode(c.codePointAt(0)-0x1f1e6+65)).join('');return `<img src="flags/${code}.svg" alt="${flag}">`;});}
function btn(label,action,ico='',primary=false,extra=''){return `<button type="button" class="button${primary?' primary':''}" data-action="${action}" ${extra}>${ico?icon(ico):''}${label}</button>`;}
function navHtml(){return nav.map(([id,label,ico])=>`<button class="nav-item${tab===id?' active':''}" data-tab="${id}" ${tab===id?'aria-current="page"':''}>${icon(ico)}<span>${label}</span></button>`).join('');}
function visibleProfiles(){return state.profiles.filter(p=>(`${p.name} ${p.protocol}`).toLocaleLowerCase().includes(search.toLocaleLowerCase())&&(source==='all'||(source==='manual'?!p.source_id:p.source_id===source)));}
function homeProfiles(){
 const selected=state.profiles.find(p=>p.key===state.selected);
 return selected?state.profiles.filter(p=>(p.source_id??null)===(selected.source_id??null)):state.profiles;
}
function bulkLatencySelect(){return `<select id="bulk-method" aria-label="Способ проверки задержки серверов"><option value="tcp" ${bulkMethod==='tcp'?'selected':''}>TCP/UDP</option><option value="icmp" ${bulkMethod==='icmp'?'selected':''}>ICMP</option>${state.platform==='windows'?`<option value="proxy" ${bulkMethod==='proxy'?'selected':''}>PROXY GET</option>`:''}</select>`;}
function sortedProfiles(profiles){
 if(settingValue('auto_sort_ping')===false)return profiles;
 const ping=p=>{const r=state.latency[p.key];return !r?.error&&typeof r?.milliseconds==='number'&&Number.isFinite(r.milliseconds)&&r.milliseconds>=0?r.milliseconds:Infinity;};
 // Sort a copy: equal, unavailable and unmeasured results keep their source order.
 return [...profiles].sort((a,b)=>ping(a)-ping(b));
}
function autoSortControl(){return `<form id="sort-form" class="server-sort-form">${check('Автосортировка по пингу','auto_sort_ping')}</form>`;}
function serverRows(profiles){
  if(!profiles.length) return `<div class="empty">${icon('servers')}<h3>${state.profiles.length?'Ничего не найдено':'Ваш первый сервер'}</h3><p>${state.profiles.length?'Попробуйте другой запрос или источник.':'Добавьте подписку или вставьте ссылку на сервер, чтобы подключиться.'}</p>${state.profiles.length?'':btn('Добавить сервер','import','plus',true)}</div>`;
  const sources = Object.fromEntries(state.subscriptions.map(s=>[s.id,s.name]));
  return sortedProfiles(profiles).map(p=>{const result=state.latency[p.key];return `<div class="server-row${state.selected===p.key?' selected':''}"><button type="button" class="select-server" data-action="select" data-key="${esc(p.key)}" aria-pressed="${state.selected===p.key}"><span class="radio"></span><span class="server-meta"><span class="server-name">${nameHtml(p.name)}</span><span class="caption">${esc(sources[p.source_id] || 'Добавлен вручную')}</span></span></button><span class="protocol">${esc(p.protocol)}</span><span class="latency${result?.milliseconds!=null?' good':''}">${esc(result?.label || (state.measuring?'…':'—'))}</span>${!p.source_id&&tab==='servers'?`<button class="icon-button" data-action="remove-profile" data-key="${esc(p.key)}" title="Удалить сервер" aria-label="Удалить сервер">${icon('trash')}</button>`:''}</div>`;}).join('');
}
function home(){
 const p=state.profiles.find(p=>p.key===state.selected), android=state.platform==='android';
 const profiles=homeProfiles(),subscription=state.subscriptions.find(s=>s.id===p?.source_id);
 return `<section class="card connect-card"><div class="card-topline"><span class="private-label">${icon('lock')}Защищённое подключение</span><span>${esc(state.settings.core)}${android?' · VPN':''}</span></div><form id="settings-form" class="connection-settings"><div class="field-grid">${android?'':select('Способ подключения','mode',connectionModes)}${select('Способ проверки задержки','latency_method',latencyMethods)}</div>${android?'':'<p class="helper">Способ подключения применится при следующем сеансе. TUN требует прав администратора.</p>'}</form><div class="orb-wrap"><button type="button" class="connect-orb ${state.status}" data-action="toggle" aria-label="Подключить VPN" ${!p?'disabled':''}>${icon('shield')}</button></div><h2 class="connection-status" id="connection-status" role="status" aria-live="polite"></h2><div class="connection-latency"><button type="button" class="text-button" id="measure-selected" data-action="measure-selected">${icon('speed')}Проверить задержку</button><span class="connection-latency-result" role="status" aria-live="polite" aria-atomic="true"><strong id="stat-latency">—</strong><span id="latency-method"></span></span></div><div class="selected-server"><span class="server-avatar">${icon('servers')}</span><div class="server-meta"><div class="server-name">${p?nameHtml(p.name):'Сервер не выбран'}</div><div class="caption">${p?esc(p.protocol.toUpperCase()):'Начните с добавления подписки'}</div></div><button class="text-button" data-tab="servers">Изменить →</button></div></section>
 ${homeSubscriptionDescription()}<div class="subscription-notices" role="status" aria-live="polite">${subscriptionNotices()}</div>
 <div class="stats"><div class="card stat"><span class="stat-label">${icon('up')}Отправлено</span><strong id="stat-up">0 Б</strong></div><div class="card stat"><span class="stat-label">${icon('down')}Получено</span><strong id="stat-down">0 Б</strong></div><div class="card stat"><span class="stat-label">${icon('clock')}Время сессии</span><strong id="stat-time">00:00:00</strong></div></div>
 <div id="connection-error"></div><div class="section-heading"><div><h2>Серверы<span class="count">${profiles.length}</span></h2>${p?`<p class="caption home-server-source">${esc(subscription?.name||'Добавлены вручную')}</p>`:''}</div><div class="actions server-actions">${bulkLatencySelect()}${btn(state.measuring?'Остановить':'Проверить','measure','speed')}${btn('Добавить','import','plus')}</div></div>${autoSortControl()}<div id="measure-progress" class="measure-progress"></div><div class="server-list" id="server-list">${serverRows(profiles)}</div>`;
}
function servers(){return `<div class="section-heading"><h2>Все серверы<span class="count">${state.profiles.length}</span></h2>${btn('Импорт','import','plus',true)}</div><div class="toolbar"><input id="search" type="search" placeholder="Поиск по названию и протоколу" aria-label="Поиск серверов" value="${esc(search)}"><select id="source-filter" aria-label="Источник"><option value="all">Все источники</option><option value="manual">Вручную</option>${state.subscriptions.map(s=>`<option value="${esc(s.id)}" ${source===s.id?'selected':''}>${esc(s.name)}</option>`).join('')}</select>${bulkLatencySelect()}${btn(state.measuring?'Остановить':'Проверить все','measure','speed')}</div>${autoSortControl()}<div id="measure-progress" class="measure-progress"></div><div class="server-list" id="server-list">${serverRows(visibleProfiles())}</div>`;}
function subscriptions(){
 return `<div class="section-heading"><h2>Ваши подписки</h2><div class="actions">${btn('Обновить все','update-all','refresh')}${btn('Добавить','subscription','plus',true)}</div></div>${state.subscriptions.length?state.subscriptions.map(s=>`<section class="card subscription">
  <div class="subscription-top"><div><h3>${esc(s.name)}</h3><p class="caption">${s.count} серверов · ${s.last_success?'Обновлено '+new Date(s.last_success*1000).toLocaleString('ru-RU'):'Ещё не обновлялась'}</p>${s.rejected?`<p class="caption">Отклонено профилей: ${s.rejected}</p>`:''}</div><div class="actions"><button class="icon-button" data-action="update-subscription" data-id="${esc(s.id)}" aria-label="Обновить подписку">${icon('refresh')}</button><button class="icon-button" data-action="remove-subscription" data-id="${esc(s.id)}" aria-label="Удалить подписку">${icon('trash')}</button></div></div>
  ${s.description?`<p class="subscription-description">${esc(s.description)}</p>`:''}${subscriptionValidity(s)}
  ${s.error?`<p class="error-box">${esc(s.error)}</p>`:''}${['upload','download','total'].some(key=>s.userinfo?.[key]!=null)?`<p class="caption">Использовано: ${bytes((s.userinfo.upload||0)+(s.userinfo.download||0))}${s.userinfo.total?' из '+bytes(s.userinfo.total):''}</p>`:''}</section>`).join(''):`<div class="empty">${icon('link')}<h3>Все серверы по одной ссылке</h3><p>Подписки обновляются автоматически. Ссылка хранится в защищённом хранилище устройства.</p>${btn('Добавить подписку','subscription','plus',true)}</div>`}`;
}
function settingValue(key){return settingsDrafts.has(key)?settingsDrafts.get(key).raw:state.settings[key];}
function settingError(key){const error=settingsDrafts.get(key)?.error||'';return `<span class="helper field-error" id="setting-error-${key}" ${error?'':'hidden'}>${esc(error)}</span>`;}
function settingAttributes(key){return `aria-describedby="setting-error-${key}"${settingsDrafts.get(key)?.error?' aria-invalid="true"':''}`;}
function input(label,key,type='text',help='',readOnly=false){return `<label class="field">${label}<input name="${key}" type="${type}" value="${esc(settingValue(key))}" ${settingAttributes(key)} ${readOnly?'readonly':''} ${type==='number'?`step="1" min="${key==='update_minutes'?0:1024}" max="${key==='update_minutes'?10080:65535}" required`:type==='url'?'required':''}>${help?`<span class="helper">${help}</span>`:''}${settingError(key)}</label>`;}
function select(label,key,options){return `<label class="field">${label}<select name="${key}" ${settingAttributes(key)}>${options.map(([v,l])=>`<option value="${v}" ${settingValue(key)===v?'selected':''}>${l}</option>`).join('')}</select>${settingError(key)}</label>`;}
function check(label,key,help=''){return `<label class="check-field"><input type="checkbox" name="${key}" ${settingAttributes(key)} ${settingValue(key)?'checked':''}><span>${label}${help?`<small>${help}</small>`:''}${settingError(key)}</span></label>`;}
function section(title,ico,content,open=false){return `<details class="card settings-section" ${open?'open':''}><summary>${icon(ico)}${title}</summary><div class="settings-content">${content}</div></details>`;}
function dnsPreset(){return customDns?'custom':Object.keys(dnsPresets).find(id=>dnsKeys.every(key=>settingValue(key)===dnsPresets[id][key]))||'custom';}
function dnsFields(){
 const readOnly=dnsPreset()!=='custom';
 return `<div class="field-grid">${input('IP DNS-сервера','dns_server','text','',readOnly)}${input('TLS-имя DNS','dns_tls_name','text','',readOnly)}</div>${input('Bootstrap DNS','bootstrap_dns','text','IP для разрешения адреса VPN-сервера до запуска туннеля.',readOnly)}${readOnly?'<p class="helper">Чтобы ввести свои адреса, выберите «Свой вариант».</p>':''}`;
}
function dnsSettings(){return `<label class="field">DNS-сервис<select id="dns-preset">${[...Object.entries(dnsPresets).map(([id,preset])=>[id,preset.label]),['custom','Свой вариант']].map(([id,label])=>`<option value="${id}" ${dnsPreset()===id?'selected':''}>${label}</option>`).join('')}</select></label>${select('Протокол DNS','dns_kind',[['https','HTTPS'],['tls','TLS'],['udp','UDP']])}<div id="dns-fields">${dnsFields()}</div>`;}
function selectDnsPreset(id){
 if(id!=='custom'&&!dnsPresets[id])return;
 customDns=id==='custom';
 if(!customDns){
  const entries=dnsKeys.map(key=>{
   const pending=settingsTimers.get(key);if(pending){clearTimeout(pending.timer);settingsTimers.delete(key);}
   const draft={raw:dnsPresets[id][key],value:dnsPresets[id][key],error:''};settingsDrafts.set(key,draft);
   return [key,draft];
  });
  queueSettings(entries);
 }
 if($('#dns-fields'))$('#dns-fields').innerHTML=dnsFields();
 updateSettingsSaveStatus();
}
function routingSettings(){
 const value=settingValue('bypass_domains')??[],text=Array.isArray(value)?value.join('\n'):value;
 return `${check('Напрямую для доменов .ru, .su и .рф','bypass_russian_domains')}
 <label class="field">Свои домены в обход VPN<textarea name="bypass_domains" rows="6" placeholder="example.com&#10;пример.рф" spellcheck="false" autocapitalize="none" autocomplete="off" ${settingAttributes('bypass_domains')}>${esc(text)}</textarea><span class="helper">По одному домену на строку, без https:// и путей. Домен и все его поддомены будут открываться напрямую. Чтобы убрать обход, удалите домен из списка.</span>${settingError('bypass_domains')}</label>
 <p class="helper">Список работает независимо от переключателя зон. DNS остаётся через VPN. Изменения сохраняются автоматически и применятся при следующем подключении.</p>`;
}
function settings(){
 const a=state.platform==='android';
 return `<form id="settings-form">
 ${section('Подключение','shield',`<div class="field-grid">${!a?select('Режим','mode',connectionModes):''}${select('Ядро','core',[['sing-box','sing-box / Xray'],['mihomo','Mihomo']])}${!a?input('Порт прокси','mixed_port','number')+input('Порт управления','api_port','number'):''}</div>${check('IPv6','ipv6')}${check('Проверять HTTPS при подключении','verify_connection','Подтверждает доступ к интернету перед статусом «Подключено».')}${select('Способ проверки задержки','latency_method',latencyMethods)}${input('Адрес проверки HTTPS','probe_url','url')}${!a?input('Путь к sing-box (необязательно)','core_path')+input('Путь к Mihomo (необязательно)','mihomo_path')+'<p class="helper">Режим TUN требует запуска приложения от имени администратора.</p>':''}`)}
 ${section('Маршрутизация','routing',routingSettings())}
 ${section('Серверы','servers',check('Автосортировка по пингу','auto_sort_ping','Меньший пинг выше; недоступные и непроверенные серверы в конце.'))}
 ${!a?section('Окно и трей','settings',`${check('Сворачивать в трей','minimize_to_tray','При нажатии кнопки сворачивания окно скрывается в трей.')}${check('Оставлять в трее при закрытии окна','close_to_tray','VPN продолжает работать. Для завершения выберите «Выход» в меню трея.')}<p class="helper">Нажмите значок в трее, чтобы открыть приложение; правая кнопка открывает меню управления.</p>`):''}
 ${section('DNS','servers',dnsSettings())}
 ${section('Обновление подписок','link',`${check('Обновлять при запуске','update_on_start')}${input('Интервал обновления, минуты','update_minutes','number','0 — автоматическое обновление выключено.')}`)}
 ${section('Обновление приложения','refresh',`<p class="helper">Новые версии проверяются при запуске. Источник: GitHub · GodPens656/Lunaris-VPN.</p>${btn('Проверить обновление','check-app-update','refresh')}`)}
 <div class="settings-footer"><span id="settings-save-status" class="helper" role="status" aria-live="polite">Настройки сохраняются автоматически.</span><span class="helper">Изменения подключения применятся при следующем сеансе.</span></div></form>
 ${section('Внешний вид','moon','<p class="muted">Тема, цвет и оформление приложения.</p>'+btn('Настроить оформление','appearance','moon'))}
 <p class="muted">Lunaris client 0.7.1 · Tauri 2<br>sing-box ${esc(state.cores['sing-box'])} · Mihomo ${esc(state.cores.mihomo)}</p>`;
}
function logs(){return `<div class="section-heading"><h2>Журнал подключения</h2></div><p class="muted" style="margin-bottom:16px">Последние 300 записей. Ссылки, пароли и ключи скрыты. Журнал хранится в памяти.</p><div class="card log" id="log-lines">${esc(state.logs.join('\n') || 'Записей пока нет.')}</div>`;}
function render(){
 $('#desktop-nav').innerHTML=navHtml();$('#mobile-nav').innerHTML=navHtml();$('#page-title').textContent=nav.find(n=>n[0]===tab)?.[1]||'Подключение';
 if(!state)return;
 $('#view').innerHTML=({home,servers,subscriptions,settings,logs}[tab]||home)();
 if($('#source-filter'))$('#source-filter').value=source;if($('#bulk-method'))$('#bulk-method').value=bulkMethod;
 updateStatus();lastSignature=signature();
 updateSettingsSaveStatus();
}
function signature(){return state?JSON.stringify([state.profiles,state.subscriptions,state.selected,state.latency,state.measuring,state.settings.auto_sort_ping,state.error,state.subscriptions.map(s=>{const expiry=subscriptionExpiry(s);return expiry?[expiry.status,expiry.status==='soon'?expiry.days:0]:null;})]):'';}
function updateStatus(){
 if(!state)return;const s=state.status,running=['connected','connecting','disconnecting'].includes(s);
 const updateButton=$('[data-action="check-app-update"]');
 if(updateButton){updateButton.disabled=appUpdateChecking;updateButton.setAttribute('aria-busy',String(appUpdateChecking));}
 for(const button of document.querySelectorAll('[data-action="update-all"], [data-action="update-subscription"]')){
  button.disabled=subscriptionsBusy;button.setAttribute('aria-busy',String(subscriptionsBusy));
 }
 const trayButton=$('[data-action="tray"]');if(trayButton){trayButton.hidden=state.platform!=='windows';trayButton.innerHTML=icon('tray');}
 $('#status-pill').textContent=statusNames[s]||s;$('#status-pill').className='status-pill '+s;
 if(tab==='home'){
  $('#connection-status').textContent=statusNames[s]||s;
  const connected=s==='connected',result=connected?state.latency[state.selected]:null;
  const measureButton=$('#measure-selected');measureButton.disabled=!connected||!state.selected||state.measuring||busy;
  measureButton.title=connected?'Измерить задержку подключённого сервера':'Подключите VPN, чтобы проверить задержку';
  const orb=$('.connect-orb');orb.className='connect-orb '+s;orb.disabled=!state.selected||s==='disconnecting'||busy;
  orb.setAttribute('aria-label',s==='connecting'?'Отменить подключение VPN':running?'Отключить VPN':'Подключить VPN');
  orb.setAttribute('aria-pressed',String(running));
  $('#stat-up').textContent=bytes(state.stats.upload);$('#stat-down').textContent=bytes(state.stats.download);$('#stat-time').textContent=duration(state.stats.duration);
  $('#latency-method').textContent={tcp:'TCP/UDP',icmp:'ICMP',proxy:'GET'}[state.settings.latency_method];
  const latency=$('#stat-latency');latency.textContent=result?.label||(connected&&state.measuring?'Проверяем…':'—');
  latency.className=result?.error?'error':result?.milliseconds!=null?'good':'';
  measureButton.setAttribute('aria-busy',String(connected&&state.measuring));
  $('#connection-error').innerHTML=state.error?`<div class="error-box">${esc(state.error)} <button class="text-button" data-tab="logs">Открыть журнал →</button></div>`:'';
 }
 if($('#measure-progress'))$('#measure-progress').textContent=state.measuring?`Проверено ${Object.keys(state.latency).length} из ${state.measure_total}`:'';
 if(tab==='logs'&&$('#log-lines'))$('#log-lines').textContent=state.logs.join('\n')||'Записей пока нет.';
}
function accept(value){if(value?.snapshot)value=value.snapshot;if(!value?.profiles)return;const old=lastSignature;state=value;
 if(!$('#view').dataset.ready){$('#view').dataset.ready='1';render();}
 else if(tab!=='settings'&&old!==signature())render();else updateStatus();
}
async function action(method,args={}){
 const subscription=['add_subscription','update_subscription','update_all'].includes(method);
 const request=method==='add_subscription'?`add:${args.url}`:'refresh';
 if(subscription?subscriptionRequests.has(request):busy)return;
 if(subscription){subscriptionRequests.add(request);subscriptionsBusy=true;}else busy=true;
 updateStatus();
 try{await flushSettings();const value=await rpc(method,args);accept(value);return value;}catch(e){toast(typeof e==='string'?e:e.message||'Не удалось выполнить действие.');throw e;}finally{if(subscription){subscriptionRequests.delete(request);subscriptionsBusy=subscriptionRequests.size>0;}else busy=false;updateStatus();}
}
function updateSettingsSaveStatus(){
 const status=$('#settings-save-status');if(!status)return;
 const failed=[...settingsDrafts.values()].some(draft=>draft.error);
 status.textContent=failed?'Некоторые настройки не сохранены. Исправьте отмеченные поля.':settingsSaving||settingsTimers.size?'Сохранение…':'Настройки сохраняются автоматически.';
}
function showSettingError(key,message){
 const control=$(`#settings-form [name="${key}"]`)||$(`#sort-form [name="${key}"]`),error=$(`#setting-error-${key}`);
 if(control){if(message)control.setAttribute('aria-invalid','true');else control.removeAttribute('aria-invalid');}
 if(error){error.textContent=message;error.hidden=!message;}
 updateSettingsSaveStatus();
}
function queueSetting(key,draft){queueSettings([[key,draft]]);}
function queueSettings(entries){
 settingsSaving++;updateSettingsSaveStatus();
 // Save patches in order; a newer edit may supersede a patch before it starts.
 settingsSaveQueue=settingsSaveQueue.then(async()=>{
  const current=entries.filter(([key,draft])=>settingsDrafts.get(key)===draft);
  const patch=Object.fromEntries(current.filter(([key,draft])=>JSON.stringify(draft.value)!==JSON.stringify(state.settings[key])).map(([key,draft])=>[key,draft.value]));
  try{
   if(Object.keys(patch).length)accept(await rpc('settings',patch));
   for(const [key,draft] of current)if(settingsDrafts.get(key)===draft){settingsDrafts.delete(key);showSettingError(key,'');}
  }catch(e){
   for(const [key,draft] of current)if(settingsDrafts.get(key)===draft){draft.error=typeof e==='string'?e:e.message||'Не удалось сохранить настройку.';showSettingError(key,draft.error);}
  }
 }).finally(()=>{settingsSaving--;updateSettingsSaveStatus();});
}
function editSetting(control,immediate=false){
 const key=control.name;if(!['settings-form','sort-form'].includes(control.form?.id)||!state||!(key in state.settings))return;
 const pending=settingsTimers.get(key);if(pending){clearTimeout(pending.timer);settingsTimers.delete(key);}
 const raw=control.type==='checkbox'?control.checked:control.value;
 const value=key==='bypass_domains'?raw.split(/\r?\n/).map(domain=>domain.trim()).filter(Boolean):typeof state.settings[key]==='number'?Number(raw):raw;
 const draft={raw,value,error:''};
 settingsDrafts.set(key,draft);showSettingError(key,'');
 if(!control.checkValidity()){
  draft.error=control.validationMessage;showSettingError(key,draft.error);return;
 }
 if(immediate)queueSetting(key,draft);
 else settingsTimers.set(key,{draft,timer:setTimeout(()=>{settingsTimers.delete(key);queueSetting(key,draft);},500)});
 updateSettingsSaveStatus();
}
async function flushSettings(){
 let queue;
 do{
  for(const [key,{timer,draft}] of settingsTimers){clearTimeout(timer);settingsTimers.delete(key);queueSetting(key,draft);}
  queue=settingsSaveQueue;await queue;
 }while(settingsTimers.size||queue!==settingsSaveQueue);
}
function openDialog(title,body,submit,label='Добавить',cancelLabel='Отмена'){
 $('#dialog-title').textContent=title;$('#dialog-body').innerHTML=body;$('#dialog-error').textContent='';
 $('#dialog-actions').innerHTML=submit?`<button type="button" class="button" data-action="close-dialog">${esc(cancelLabel)}</button><button class="button primary" type="submit">${esc(label)}</button>`:btn('Готово','close-dialog');dialogSubmit=submit;
 if(!$('#dialog').open)$('#dialog').showModal();
}
function showAppUpdate(){
 if(!pendingAppUpdate||$('#dialog').open||document.hidden)return;
 const update=pendingAppUpdate;pendingAppUpdate=null;
 if(update.version===appUpdatePromptedVersion)return;
 appUpdatePromptedVersion=update.version;
 const android=state.platform==='android';
 openDialog('Доступно обновление',`<p>Вышла версия <strong>${esc(update.version)}</strong>. У вас установлена ${esc(update.current_version)}.</p><p class="helper">${esc(update.asset_name)} · ${bytes(update.size)}</p><p class="muted">Скачивание начнётся в системном браузере. ${android?'После загрузки откройте APK, чтобы обновить приложение.':'После загрузки распакуйте весь ZIP-архив и запустите новую версию приложения.'}</p>`,async()=>{
  await flushSettings();await rpc('download_app_update',{version:update.version});toast('Загрузка обновления открыта в браузере.');
 },'Скачать','Позже');
}
async function checkAppUpdate(manual=false){
 if(!state||!native()||appUpdateChecking||(!manual&&appUpdateCheckedAt!==null&&Date.now()-appUpdateCheckedAt<3600000))return;
 appUpdateChecking=true;appUpdateCheckedAt=Date.now();updateStatus();
 try{
  const update=await rpc('check_app_update');
  if(update&&typeof update.version==='string'&&typeof update.asset_name==='string'){
   if(manual)appUpdatePromptedVersion=null;
   pendingAppUpdate=update;showAppUpdate();
  }else{pendingAppUpdate=null;if(manual)toast('Новых версий для вашей платформы нет.');}
 }catch(e){if(manual)toast(typeof e==='string'?e:e.message||'Не удалось проверить обновление.');}
 finally{appUpdateChecking=false;updateStatus();}
}
function importDialog(){openDialog('Добавить сервер',`<div class="dialog-tabs">${btn('Подписка','subscription','link')}${btn('Вставить серверы','manual','servers',true)}</div><label class="field">Ссылки или JSON<textarea name="text" required placeholder="vless://…&#10;trojan://…&#10;hysteria2://…" spellcheck="false"></textarea></label><p class="helper">Поддерживаются несколько ссылок, Base64-подписки и локальная JSON-конфигурация sing-box.</p>`,async form=>{const result=await action('import',{text:form.get('text')});toast(`Импортировано: ${result.imported}. Отклонено: ${result.rejected.length}. Дубликаты: ${result.duplicates}.`);},'Импортировать');}
function subscriptionDialog(url=''){openDialog('Добавить подписку',`<div class="dialog-tabs">${btn('Подписка','subscription','link',true)}${btn('Вставить серверы','manual','servers')}</div><label class="field">Ссылка на подписку<input name="url" required value="${esc(url)}" placeholder="https://…" spellcheck="false" autocomplete="off"></label><label class="field">Название (необязательно)<input name="name" placeholder="Определится автоматически" maxlength="120"></label><p class="helper">Ссылка сохраняется в защищённом хранилище. При добавлении подписка будет загружена.</p>`,async form=>{await action('add_subscription',{url:form.get('url'),name:form.get('name')});toast('Подписка добавлена.');});}
function appearanceDialog(){openDialog('Внешний вид',`<p class="field">Оформление</p><div class="theme-choices">${[['material','Material'],['amoled','AMOLED'],['glass','Liquid glass'],['simple','Simple']].map(([v,l])=>`<button type="button" class="theme-choice ${(appearance.theme||'material')===v?'active':''}" data-theme-choice="${v}">${l}</button>`).join('')}</div><p class="field" style="margin-top:24px">Акцентный цвет</p><div class="color-choices">${['#167663','#6750a4','#336eab','#b75a72','#ad6d30'].map(c=>`<button type="button" class="color-choice" style="background:${c}" data-color="${c}" aria-label="Цвет ${c}"></button>`).join('')}<input type="color" id="accent-color" value="${appearance.accent||'#167663'}" aria-label="Свой цвет"></div><label class="field">Цветовая схема<select id="scheme"><option value="system">Как на устройстве</option><option value="light">Светлая</option><option value="dark">Тёмная</option></select></label><label class="field">Анимированные обои<select id="background-mode">${Background.modes.map(([id,label])=>`<option value="${id}" ${appearance.background===id?'selected':''}>${label}</option>`).join('')}</select></label><label class="field wallpaper-intensity" for="background-intensity"><span>Яркость обоев <output id="background-intensity-value" for="background-intensity">${appearance.backgroundIntensity}%</output></span><input type="range" id="background-intensity" min="10" max="100" step="1" value="${appearance.backgroundIntensity}" ${appearance.background==='none'?'disabled':''}></label><p class="helper">Обои сохраняются автоматически. При уменьшении движения в настройках устройства фон становится статичным.</p>`,null);$('#scheme').value=appearance.scheme||'system';}
async function navigate(next){
 if(!nav.some(([id])=>id===next)||(next===tab&&pendingTab===null))return;
 const id=++navigationId;
 pendingTab=next;viewAnimation?.cancel();
 await flushSettings();
 if(id!==navigationId)return;
 const view=$('#view'),direction=nav.findIndex(n=>n[0]===next)>nav.findIndex(n=>n[0]===tab)?1:-1;
 const animate=typeof view.animate==='function'&&!matchMedia('(prefers-reduced-motion: reduce)').matches;
 if(animate){
  viewAnimation=view.animate([{opacity:1,transform:'translateX(0)'},{opacity:0,transform:`translateX(${-direction*10}px)`}],{duration:80,easing:'ease-in',fill:'forwards'});
  await viewAnimation.finished.catch(()=>{});
  if(id!==navigationId)return;
 }
 tab=next;pendingTab=null;render();view.scrollTop=0;viewAnimation?.cancel();
 view.focus?.({preventScroll:true});
 if(animate)viewAnimation=view.animate([{opacity:0,transform:`translateX(${direction*16}px)`},{opacity:1,transform:'translateX(0)'}],{duration:180,easing:'cubic-bezier(.2,.8,.2,1)'});
}
document.addEventListener('click',async e=>{
 const target=e.target.closest('button,a');if(!target)return;
 if(target.dataset.tab){await navigate(target.dataset.tab);return;}
 if(target.classList.contains('brand')){e.preventDefault();await navigate('home');return;}
 if(target.dataset.themeChoice){appearance.theme=target.dataset.themeChoice;applyAppearance();appearanceDialog();return;}
 if(target.dataset.color){appearance.accent=target.dataset.color;applyAppearance();return;}
 const a=target.dataset.action;
 if(a==='check-app-update'){await checkAppUpdate(true);return;}
 if(a==='tray'){try{await flushSettings();await native()('hide_to_tray');}catch(e){toast(typeof e==='string'?e:e.message);}return;}
 if(a==='retry'){try{accept(await rpc('snapshot'));}catch(e){toast(typeof e==='string'?e:e.message);}return;}
 if(['import','manual'].includes(a)){importDialog();return;}if(a==='subscription'){subscriptionDialog();return;}if(a==='appearance'){appearanceDialog();return;}if(a==='close-dialog'){$('#dialog').close();return;}
 try{
 if(a==='toggle')await action('toggle');
 if(a==='select')await action('select',{key:target.dataset.key});
 if(a==='measure')await action(state.measuring?'cancel_measure':'measure',{method:bulkMethod,keys:(tab==='home'?homeProfiles():visibleProfiles()).map(p=>p.key)});
 if(a==='measure-selected')await action('measure',{selected:true});
 if(a==='update-all')await action('update_all');
 if(a==='update-subscription')await action('update_subscription',{id:target.dataset.id});
 if(a==='remove-subscription'||a==='remove-profile'){
  const subscription=a==='remove-subscription';const id=target.dataset.id,key=target.dataset.key;
  openDialog(subscription?'Удалить подписку?':'Удалить сервер?',`<p class="muted">${subscription?'Подписка и её серверы будут удалены.':'Сервер будет удалён из приложения.'} Активное подключение к удаляемому серверу будет остановлено.</p>`,async()=>{await action(subscription?'remove_subscription':'remove_profile',subscription?{id}:{key});},'Удалить');
 }
 }catch{/* action already displayed a safe error */}
});
document.addEventListener('input',e=>{if(e.target.form?.id==='settings-form'&&e.target.type!=='checkbox'&&e.target.tagName!=='SELECT')editSetting(e.target);if(e.target.id==='search'){search=e.target.value;$('#server-list').innerHTML=serverRows(visibleProfiles());}if(e.target.id==='accent-color'){appearance.accent=e.target.value;applyAppearance();}if(e.target.id==='background-intensity'){appearance.backgroundIntensity=Number(e.target.value);applyAppearance();}});
document.addEventListener('change',e=>{editSetting(e.target,true);if(e.target.id==='source-filter'){source=e.target.value;$('#server-list').innerHTML=serverRows(visibleProfiles());}if(e.target.id==='bulk-method')bulkMethod=e.target.value;if(e.target.id==='dns-preset')selectDnsPreset(e.target.value);if(e.target.id==='scheme'){appearance.scheme=e.target.value;applyAppearance();}if(e.target.id==='background-mode'){appearance.background=e.target.value;applyAppearance();}});
$('#dialog-form').addEventListener('submit',async e=>{e.preventDefault();if(!dialogSubmit)return;const buttons=[...$('#dialog-actions').querySelectorAll('button')];buttons.forEach(b=>b.disabled=true);try{await dialogSubmit(new FormData(e.target));$('#dialog').close();}catch(err){$('#dialog-error').textContent=typeof err==='string'?err:err.message||'Не удалось выполнить действие.';}finally{buttons.forEach(b=>b.disabled=false);}});
document.addEventListener('submit',e=>{if(e.target.id==='settings-form'){e.preventDefault();flushSettings();}});
$('.header-right [data-action="appearance"]').innerHTML=icon('moon');render();
let lastLinkPoll=0;
async function poll(){
 try{
  if(!busy)accept(await rpc('snapshot'));
  if(state&&!startupSeen){startupSeen=true;checkAppUpdate();if(!state.profiles.length&&!state.subscriptions.length&&!$('#dialog').open)subscriptionDialog();}
  if(state)showAppUpdate();
  if(state&&!busy&&!$('#dialog').open&&Date.now()-lastLinkPoll>5000){lastLinkPoll=Date.now();const link=await rpc('take_import_link');if(link)subscriptionDialog(link);}
 }catch(e){if(!state){$('#status-pill').textContent='Недоступно';$('#view').innerHTML=`<div class="empty">${icon('shield')}<h3>${native()?'Не удалось открыть приложение':'Предпросмотр интерфейса'}</h3><p>${esc(typeof e==='string'?e:e.message)}</p>${btn('Повторить','retry','refresh',true)}</div>`;}}
 finally{setTimeout(poll,1200);}
}
document.addEventListener('visibilitychange',()=>{if(document.hidden)flushSettings();else if(state){checkAppUpdate();showAppUpdate();if(!busy)rpc('snapshot').then(accept).catch(()=>{});}});
window.addEventListener('pagehide',()=>{flushSettings();});
if(window.__TAURI__?.event?.listen){
 window.__TAURI__.event.listen('desktop-navigate',event=>{navigate(event.payload);}).catch(()=>{});
 window.__TAURI__.event.listen('desktop-error',event=>{toast(event.payload);}).catch(()=>{});
}
poll();
