'use strict';

// Панель без фреймворка намеренно: четыре экрана, открываются раз в год на
// десять минут. Фреймворк добавил бы сборочный тулчейн в проект на чистом Go и
// не дал бы взамен ничего.

// Ключ панели приходит в адресе один раз, дальше носим его в заголовке и
// вычищаем из строки адреса — чтобы не осел в истории браузера.
let TOKEN = new URLSearchParams(location.search).get('token') || localStorage.getItem('qd_panel_token') || '';
if (new URLSearchParams(location.search).get('token')) {
  localStorage.setItem('qd_panel_token', TOKEN);
  history.replaceState(null, '', location.pathname + location.hash);
}

const $ = (id) => document.getElementById(id);

async function api(path, opts = {}) {
  const headers = { 'X-Qd-Panel': TOKEN };
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (opts.admin) headers['X-Qd-Token'] = opts.admin;

  const rsp = await fetch(path, {
    method: opts.method || (opts.body !== undefined ? 'POST' : 'GET'),
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
  const text = await rsp.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!rsp.ok) throw new Error((data && data.error) || text || `ошибка ${rsp.status}`);
  return data;
}

function say(el, text, kind) {
  el.textContent = text;
  el.className = 'msg' + (kind ? ' ' + kind : '');
  if (text) setTimeout(() => { if (el.textContent === text) el.textContent = ''; }, 4000);
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// --- вкладки ---

function showTab(name) {
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach((t) => { t.hidden = t.id !== 'tab-' + name; });
  document.querySelectorAll('.tabs a').forEach((a) => {
    a.classList.toggle('active', a.dataset.tab === name);
  });
  if (name === 'exits') loadExits();
  if (name === 'sub') loadSub();
  if (name === 'notices') loadNotices(true);
  if (name === 'help') loadHelp();
}

window.addEventListener('hashchange', () => showTab(location.hash.slice(1) || 'rules'));

// --- состояние ---

let lastStatus = null;

async function refreshStatus() {
  try {
    const st = await api('/api/status');
    lastStatus = st;
    renderStatus(st);
  } catch (e) {
    $('stateText').textContent = 'панель не отвечает';
    $('dot').className = 'dot red';
  }
}

function renderStatus(st) {
  // Ненастроенный клиент показывает только экран настройки: остальное
  // опирается на узел, которого ещё нет.
  showSetup(!st.configured);

  const dot = $('dot');
  const text = $('stateText');
  const unread = Number($('unread').dataset.count || 0);

  // Цвета повторяют значок в лотке: пользователь уже знает, что они значат.
  if (st.session === 'connected') {
    dot.className = 'dot ' + (unread > 0 ? 'blue' : 'green');
    text.textContent = 'Подключено';
  } else if (st.session === 'connecting') {
    dot.className = 'dot red';
    text.textContent = 'Связи нет, восстанавливаю';
  } else {
    dot.className = 'dot';
    text.textContent = 'Отключено';
  }

  // Управляющая связь живёт отдельно от перехвата — и это важно показать:
  // «отключено, но узел на связи» штатное состояние, а не половинчатое.
  const c = st.control || {};
  const bits = [];
  if (st.node) bits.push(st.node);
  if (c.online) bits.push('узел на связи' + (c.srtt ? ', ' + c.srtt : ''));
  else if (c.error) bits.push('узел недоступен: ' + c.error);
  else if (!st.configured) bits.push('узел не настроен');
  $('stateNode').textContent = bits.join(' · ');

  // Версия сборки: видно, тот ли файл запущен. «Поправил, пересобрал, а
  // поведение прежнее» почти всегда означает, что запущен другой.
  const v = st.version || {};
  $('ver').textContent = v.revision
    ? v.revision + (v.dirty ? '+' : '') + (v.built ? ' · ' + v.built : '')
    : '';

  const busy = st.session !== 'stopped';
  $('btnConnect').hidden = busy;
  $('btnDisconnect').hidden = !busy;
  $('btnConnect').disabled = !st.configured;
}

$('btnConnect').onclick = async () => {
  $('btnConnect').disabled = true;
  try { renderStatus(await api('/api/connect', { body: {} })); }
  catch (e) { alert('Не подключилось: ' + e.message); }
  finally { $('btnConnect').disabled = false; }
};

$('btnDisconnect').onclick = async () => {
  $('btnDisconnect').disabled = true;
  try { renderStatus(await api('/api/disconnect', { body: {} })); }
  catch (e) { alert('Не отключилось: ' + e.message); }
  finally { $('btnDisconnect').disabled = false; }
};

// --- конфигурация ---

let cfg = null;

async function loadConfig() {
  cfg = await api('/api/config');
  $('rules').value = (cfg.routing?.rules || []).join('\n');
  $('defaultOut').value = cfg.routing?.default || '';
  $('token').value = cfg.node?.token || '';
  renderEntries(cfg.node?.entries || []);

  const cap = cfg.capture || {};
  $('capIPv4').checked = !!cap.ipv4;
  $('capIPv6').checked = !!cap.ipv6;
  $('manageDNS').checked = !!cap.manage_dns;
  $('manageProxy').checked = !!cap.manage_proxy;
  $('nat46').value = cap.nat46 || 'auto';

  const tr = cfg.transport || {};
  $('brutalMbps').value = tr.brutal_mbps || 700;
  $('autoConnect').checked = !!cfg.autoconnect;
  $('autoStart').checked = !!cfg.autostart;

  const logCfg = cfg.logging || {};
  $('logEnabled').checked = !!logCfg.enabled;
  $('logMaxMB').value = logCfg.max_mb || 1;
  $('logLevel').value = logCfg.level || 'info';
}

function renderEntries(entries) {
  const rows = entries.length ? entries : [{ addr: '', sni: '' }];
  $('entries').innerHTML =
    '<tr><th>Адрес</th><th>SNI (домен для TLS)</th><th></th></tr>' +
    rows.map((e, i) => `<tr>
      <td><input class="entry-addr" value="${esc(e.addr)}" placeholder="203.0.113.10:443"></td>
      <td><input class="entry-sni" value="${esc(e.sni || '')}" placeholder="node.example"></td>
      <td><button data-del="${i}" title="убрать">✕</button></td>
    </tr>`).join('');

  $('entries').querySelectorAll('[data-del]').forEach((b) => {
    b.onclick = () => {
      const list = collectEntries();
      list.splice(Number(b.dataset.del), 1);
      renderEntries(list);
    };
  });
}

function collectEntries() {
  const addrs = [...document.querySelectorAll('.entry-addr')].map((i) => i.value.trim());
  const snis = [...document.querySelectorAll('.entry-sni')].map((i) => i.value.trim());
  return addrs.map((addr, i) => ({ addr, sni: snis[i] })).filter((e) => e.addr);
}

$('btnAddEntry').onclick = () => renderEntries([...collectEntries(), { addr: '', sni: '' }]);

// Сохраняем конфиг целиком: сервер проверяет правила до записи, поэтому битый
// набор не может оставить клиента без роутинга.
async function saveConfig(patch, msgEl) {
  const next = JSON.parse(JSON.stringify(cfg || {}));
  patch(next);
  try {
    cfg = await api('/api/config', { method: 'PUT', body: next });
    say(msgEl, 'сохранено', 'ok');
    refreshStatus();
    return true;
  } catch (e) {
    say(msgEl, e.message, 'err');
    return false;
  }
}

$('btnSaveRules').onclick = () => saveConfig((c) => {
  c.routing = c.routing || {};
  c.routing.rules = $('rules').value.split('\n').map((s) => s.trim()).filter(Boolean);
  c.routing.default = $('defaultOut').value.trim() || 'direct';
}, $('rulesMsg'));

$('btnSaveNode').onclick = () => saveConfig((c) => {
  c.node = c.node || {};
  c.node.entries = collectEntries();
  c.node.token = $('token').value.trim();
  c.capture = c.capture || {};
  c.capture.ipv4 = $('capIPv4').checked;
  c.capture.ipv6 = $('capIPv6').checked;
  c.capture.manage_dns = $('manageDNS').checked;
  c.capture.manage_proxy = $('manageProxy').checked;
  c.capture.nat46 = $('nat46').value;

  c.transport = c.transport || {};
  c.transport.brutal_mbps = parseInt($('brutalMbps').value, 10) || 700;
  c.autoconnect = $('autoConnect').checked;
  c.autostart = $('autoStart').checked;

  c.logging = c.logging || {};
  c.logging.enabled = $('logEnabled').checked;
  c.logging.max_mb = parseInt($('logMaxMB').value, 10) || 1;
  c.logging.level = $('logLevel').value || 'info';
}, $('nodeMsg'));

// --- проверка правила ---

async function runTest() {
  const host = $('testHost').value.trim();
  if (!host) return;
  const box = $('testResult');
  try {
    const res = await api('/api/rules/test', {
      body: { host, port: Number($('testPort').value) || 0 },
    });
    const why = res.default
      ? 'ни одно правило не совпало — сработал выход по умолчанию'
      : `строка ${res.rule}: <span class="mono">${esc(res.rule_text)}</span>`;
    box.innerHTML =
      `<div class="out">→ ${esc(res.out)}</div><div class="why">${why}</div>` +
      (res.note ? `<div class="note">${esc(res.note)}</div>` : '');
    box.hidden = false;
  } catch (e) {
    box.innerHTML = `<div class="why">${esc(e.message)}</div>`;
    box.hidden = false;
  }
}

$('btnTest').onclick = runTest;
$('testHost').addEventListener('keydown', (e) => { if (e.key === 'Enter') runTest(); });

// --- выходы ---

async function loadExits() {
  try {
    const list = await api('/api/exits');
    $('exits').innerHTML =
      '<tr><th>Метка</th><th>Имя</th><th>Теги</th><th>Состояние</th></tr>' +
      list.map((e) => `<tr>
        <td class="mono">${esc(e.route)}</td>
        <td>${esc(e.label || '')}${e.self ? ' <span class="hint">(этот узел)</span>' : ''}</td>
        <td class="hint">${esc((e.tags || []).join(', '))}${e.category ? ' · ' + esc(e.category) : ''}</td>
        <td>${e.alive ? '<span style="color:var(--ok)">живой</span>' : '<span style="color:var(--err)">не отвечает</span>'}</td>
      </tr>`).join('');
    // Метки идут в подсказку поля «по умолчанию»: выход выбирают из готового
    // списка, а не вспоминают по памяти.
    document.querySelectorAll('#outs').forEach((d) => d.remove());
    const dl = document.createElement('datalist');
    dl.id = 'outs';
    dl.innerHTML = list.map((e) => `<option value="${esc(e.route)}">`).join('');
    document.body.appendChild(dl);
    say($('exitsMsg'), '', '');
  } catch (e) {
    $('exits').innerHTML = '';
    say($('exitsMsg'), e.message, 'err');
  }
}

$('btnReloadExits').onclick = loadExits;

// --- уведомления ---

async function loadNotices(markSeen) {
  try {
    const v = await api('/api/notifications');
    const badge = $('unread');
    badge.dataset.count = v.unread;
    badge.textContent = v.unread;
    badge.hidden = v.unread === 0;

    $('notices').innerHTML = v.items.length
      ? v.items.map((n) => `<div class="item ${esc(n.level)}${n.read ? '' : ' unread'}">
          <div><b>${esc(n.title)}</b></div>
          ${n.text ? `<div>${esc(n.text)}</div>` : ''}
          <div class="when">${new Date(n.at).toLocaleString('ru')}</div>
        </div>`).join('')
      : '<p class="hint">Пока ничего. Здесь появится то, что стоит знать: недоступный узел, трафик, ушедший не туда, куда просили.</p>';

    if (lastStatus) renderStatus(lastStatus);
  } catch { /* уведомления не критичны для работы панели */ }
}

$('btnReadAll').onclick = async () => { await api('/api/notifications', { body: { id: 0 } }); loadNotices(); };
$('btnClearNotices').onclick = async () => { await api('/api/notifications', { body: { clear: true } }); loadNotices(); };

// --- управление сетью ---

let adminToken = localStorage.getItem('qd_admin_token') || '';

if (adminToken) {
  $('adminToken').value = adminToken;
  setTimeout(() => { $('btnAdminLoad').click(); }, 150);
}

$('btnAdminLoad').onclick = async () => {
  adminToken = $('adminToken').value.trim();
  if (!adminToken) return;
  try {
    await api('/api/node/qd-admin/cluster', { admin: adminToken });
    localStorage.setItem('qd_admin_token', adminToken);
    $('adminBody').hidden = false;
    say($('adminMsg'), 'токен принят', 'ok');
    adminView('nodes');
  } catch (e) {
    localStorage.removeItem('qd_admin_token');
    $('adminBody').hidden = true;
    say($('adminMsg'), e.message, 'err');
  }
};

document.querySelectorAll('[data-admin]').forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll('[data-admin]').forEach((x) => x.classList.remove('primary'));
    b.classList.add('primary');
    adminView(b.dataset.admin);
  };
});

async function adminView(what) {
  const box = $('adminView');
  box.innerHTML = '<p class="hint">загружаю…</p>';
  try {
    if (what === 'nodes') return renderNodes(box, await api('/api/node/qd-admin/nodes', { admin: adminToken }));
    if (what === 'users') return renderUsers(box, await api('/api/node/qd-admin/users', { admin: adminToken }));
    if (what === 'cluster') return renderCluster(box, await api('/api/node/qd-admin/cluster', { admin: adminToken }));
    if (what === 'stats') return renderStats(box, await api('/api/node/qd-admin/stats', { admin: adminToken }));
  } catch (e) {
    box.innerHTML = `<p class="msg err">${esc(e.message)}</p>`;
  }
}

function renderNodes(box, list) {
  box.innerHTML = '<table class="grid"><tr><th>Узел</th><th>Имя</th><th>Роль</th><th>Теги</th><th>Состояние</th></tr>' +
    list.map((n) => `<tr>
      <td class="mono">${esc(n.id)}${n.self ? ' <span class="hint">(этот)</span>' : ''}</td>
      <td>${esc(n.label || '')}</td>
      <td>${esc(n.category || '')}</td>
      <td class="hint">${esc((n.tags || []).join(', '))}</td>
      <td>${n.alive ? '<span style="color:var(--ok)">живой</span>' : '<span style="color:var(--err)">молчит</span>'}</td>
    </tr>`).join('') + '</table>';
}

function gb(n) { return (Number(n || 0) / 1073741824).toFixed(2) + ' ГБ'; }


function renderCluster(box, c) {
  box.innerHTML = `<table class="grid">
    <tr><th>Мастер сети</th><td class="mono">${esc(c.master_id || '—')}</td></tr>
    <tr><th>Поколение</th><td class="num">${esc(c.epoch)}</td></tr>
    <tr><th>Этот узел</th><td class="mono">${esc(c.self)} ${c.is_master ? '— мастер' : '— реплика'}</td></tr>
  </table>
  <p class="hint">Смена мастера делается вручную и осознанно: автоматический выбор при
  сетевом разделении породил бы двух пишущих.</p>`;
}

function renderStats(box, s) {
  const rows = [
    ['Узел', s.node], ['Аптайм', s.uptime],
    ['Клиентов', s.clients?.tokens], ['Активных сессий', s.clients?.active_sessions],
    ['Память', (s.go?.heap_mb ?? '?') + ' МБ'], ['Горутин', s.go?.goroutines],
    ['Соседи', (s.peers || []).join(', ') || '—'],
  ];
  let html = '<table class="grid">' + rows.map(([k, v]) =>
    `<tr><th>${esc(k)}</th><td>${esc(v ?? '—')}</td></tr>`).join('') + '</table>';

  if (s.metrics?.length) {
    html += '<h2>Качество путей до соседей</h2><table class="grid">' +
      '<tr><th>Узел</th><th>Задержка</th><th>Разброс</th><th>Потери</th><th>Оценка</th></tr>' +
      s.metrics.map((m) => `<tr><td class="mono">${esc(m.node)}</td><td class="num">${esc(m.srtt)}</td>
        <td class="num">${esc(m.rtt_var)}</td><td class="num">${(m.loss * 100).toFixed(2)}%</td>
        <td class="num">${esc(m.score)}</td></tr>`).join('') + '</table>' +
      '<p class="hint">Оценка = задержка + 2×разброс + штраф за потери: ровный узел выигрывает у быстрого, но рваного.</p>';
  }
  box.innerHTML = html;
}

// --- справка ---

let helpLoaded = false;
async function loadHelp() {
  if (helpLoaded) return;
  try {
    $('help').innerHTML = await (await fetch('help.html', { headers: { 'X-Qd-Panel': TOKEN } })).text();
    helpLoaded = true;
  } catch { $('help').innerHTML = '<p class="hint">Справка не загрузилась.</p>'; }
}

// --- запуск ---

(async function start() {
  showTab(location.hash.slice(1) || 'rules');
  await loadConfig().catch(() => {});
  await refreshStatus();
  await loadNotices();
  loadExits();
  // Опрос редкий: панель — не дашборд, за ней не следят, её открывают и
  // закрывают. Частый опрос только грел бы машину.
  setInterval(refreshStatus, 3000);
  setInterval(loadNotices, 10000);
})();

// --- подписка и ссылка настройки ---

$('btnBundle').onclick = async () => {
  const link = $('bundle').value.trim();
  if (!link) return;
  try {
    const res = await api('/api/bundle', { body: { link } });
    say($('bundleMsg'), `настроено: ${res.entries} точк(и) входа`, 'ok');
    $('bundle').value = '';
    await loadConfig();
    refreshStatus();
    loadSub();
  } catch (e) {
    say($('bundleMsg'), e.message, 'err');
  }
};

function gbNum(n) { return (Number(n || 0) / 1073741824).toFixed(2) + ' ГБ'; }

async function loadSub(refresh) {
  const box = $('subBody');
  try {
    const sub = await api('/api/subscription' + (refresh ? '?refresh=1' : ''));
    const c = sub.client || {};
    const q = c.quota || {};
    const rows = [
      ['Имя', c.label || '—'],
      ['Устройств', c.devices ?? '—'],
      ['Израсходовано', gbNum(q.used)],
      ['Лимит', q.limit ? gbNum(q.limit) : 'без ограничения'],
    ];
    if (q.reset_at && !q.reset_at.startsWith('0001')) {
      rows.push(['Период до', new Date(q.reset_at).toLocaleDateString('ru')]);
    }
    if (c.expires_at) rows.push(['Доступ до', new Date(c.expires_at).toLocaleDateString('ru')]);

    box.innerHTML =
      '<table class="grid">' + rows.map(([k, v]) =>
        `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('') + '</table>' +
      '<h2>Точки входа</h2>' +
      '<p class="hint">Приезжают от сети. Пробуются по порядку, если первая недоступна.</p>' +
      '<table class="grid"><tr><th>Адрес</th><th>SNI</th><th>Состояние</th></tr>' +
      (sub.entries || []).map((e) => `<tr>
        <td class="mono">${esc(e.addr)}</td><td class="mono">${esc(e.sni || '')}</td>
        <td>${e.alive ? '<span style="color:var(--ok)">живой</span>' : '<span style="color:var(--err)">молчит</span>'}</td>
      </tr>`).join('') + '</table>' +
      `<p class="hint">Обновлено: ${sub.at ? new Date(sub.at).toLocaleString('ru') : '—'}</p>`;
    say($('subMsg'), '', '');
  } catch (e) {
    box.innerHTML = '<p class="hint">Подписка ещё не приходила — она обновляется в фоне.</p>';
    say($('subMsg'), e.message, 'err');
  }
}

$('btnRefreshSub').onclick = () => loadSub(true);

// --- первый запуск ---

// Пока клиент не настроен, интерфейс не показываем: каждый его экран опирается
// на узел, которого нет, и человек оказался бы перед пустыми таблицами вместо
// единственного нужного ему действия.
function showSetup(on) {
  $('setup').hidden = !on;
  document.querySelector('.top').hidden = on;
  document.getElementById('tabs').hidden = on;
  document.querySelector('main').hidden = on;
  if (on) $('setupLink').focus();
}

async function applySetupLink() {
  const link = $('setupLink').value.trim();
  if (!link) return;
  $('setupApply').disabled = true;
  try {
    const res = await api('/api/bundle', { body: { link } });
    say($('setupMsg'), res.name ? `сеть «${res.name}» настроена` : 'настройки приняты', 'ok');

    // Открываем интерфейс СРАЗУ, до подгрузки данных.
    //
    // Настройки уже сохранены — держать человека на экране настройки после
    // этого не за что. Если бы переход стоял в конце, любая заминка следующим
    // шагом (медленный узел, споткнувшийся обработчик) оставляла бы его на том
    // же экране с зелёной надписью «настроено» — и выглядело бы это как
    // «нажал, написало «готово», и ничего не произошло».
    showSetup(false);

    // Остальное подтягиваем уже в открытом интерфейсе; ошибки здесь не должны
    // возвращать человека к вводу ссылки.
    loadConfig().catch(() => {});
    refreshStatus().catch(() => {});
    loadExits();
    loadSub(true);
  } catch (e) {
    say($('setupMsg'), e.message, 'err');
  } finally {
    $('setupApply').disabled = false;
  }
}

$('setupApply').onclick = applySetupLink;
$('setupLink').addEventListener('keydown', (e) => { if (e.key === 'Enter') applySetupLink(); });

// --- управление клиентами ---

// Ссылка выдаётся один раз: в базе только хеш токена, повторно её не собрать.
// Поэтому после создания она не исчезает сама и не прячется за уведомлением —
// висит, пока человек её не заберёт.
let lastIssued = null;

function renderUsers(box, list) {
  box.innerHTML = `
    <div class="row wrap">
      <input id="newLabel" placeholder="имя клиента" style="max-width:200px">
      <input id="newGB" placeholder="лимит, ГБ" class="narrow" inputmode="decimal">
      <input id="newDays" placeholder="период, дн" class="narrow" inputmode="numeric">
      <input id="newDevices" placeholder="устройств" class="narrow" inputmode="numeric">
      <button id="btnNewUser" class="primary">Выдать доступ</button>
      <span id="usersMsg" class="msg"></span>
    </div>
    <div id="issued"></div>
    <table class="grid" id="usersTable">
      <tr><th>Клиент</th><th>Роль</th><th>Расход</th><th>Лимит</th><th>Устройств</th><th></th></tr>
      ${list.map(userRow).join('')}
    </table>`;

  if (lastIssued) showIssued(lastIssued);
  $('btnNewUser').onclick = createUser;
  box.querySelectorAll('[data-act]').forEach((b) => {
    b.onclick = () => userAction(b.dataset.act, b.dataset.hash, b.dataset.label);
  });
}

function userRow(u) {
  const q = u.quota || {};
  const net = u.network_traffic || {};
  const used = gb((net.bytes_in || 0) + (net.bytes_out || 0));
  const over = q.limit && q.used >= q.limit;
  const devices = u.device_count ?? (u.devices || []).length;

  return `<tr${u.revoked ? ' style="opacity:.55"' : ''}>
    <td>${esc(u.label || '—')}<div class="hint mono">${esc(String(u.hash).slice(0, 16))}…</div></td>
    <td>${esc(u.role)}${u.revoked ? ' <span style="color:var(--err)">отозван</span>' : ''}</td>
    <td class="num">${used}${over ? ' <span style="color:var(--err)">исчерпан</span>' : ''}</td>
    <td class="num">${q.limit ? gb(q.limit) : '—'}${q.period_days ? ` / ${q.period_days} дн` : ''}</td>
    <td class="num">${devices || '—'}${u.limits?.devices ? ' / ' + u.limits.devices : ''}</td>
    <td class="row" style="margin:0;gap:6px">
      <button data-act="limit" data-hash="${esc(u.hash)}" data-label="${esc(u.label || '')}">Лимит</button>
      <button data-act="reset" data-hash="${esc(u.hash)}">Сбросить</button>
      ${u.revoked ? '' :
        `<button data-act="revoke" data-hash="${esc(u.hash)}" data-label="${esc(u.label || '')}">Отозвать</button>`}
    </td>
  </tr>`;
}

async function createUser() {
  const label = $('newLabel').value.trim();
  if (!label) { say($('usersMsg'), 'нужно имя', 'err'); return; }

  const body = { label };
  const gbVal = parseFloat($('newGB').value);
  if (gbVal > 0) body.limit_traffic_gb = gbVal;
  const days = parseInt($('newDays').value, 10);
  if (days > 0) body.traffic_period_days = days;
  const dev = parseInt($('newDevices').value, 10);
  if (dev > 0) body.limit_devices = dev;

  $('btnNewUser').disabled = true;
  try {
    const res = await api('/api/node/qd-admin/users', { body, admin: adminToken });
    // Лимиты задаются вторым запросом: создание их не принимает, а разносить
    // это по двум действиям человека — лишний шаг, о котором он забудет.
    if (body.limit_traffic_gb || body.traffic_period_days || body.limit_devices) {
      await api('/api/node/qd-admin/users', {
        method: 'PATCH', admin: adminToken,
        body: {
          hash: res.hash,
          limit_traffic_gb: body.limit_traffic_gb,
          traffic_period_days: body.traffic_period_days,
          limit_devices: body.limit_devices,
        },
      });
    }
    lastIssued = { label, bundle: res.bundle, token: res.token };
    $('newLabel').value = $('newGB').value = $('newDays').value = $('newDevices').value = '';
    adminView('users');
  } catch (e) {
    say($('usersMsg'), e.message, 'err');
  } finally {
    $('btnNewUser').disabled = false;
  }
}

function showIssued(x) {
  $('issued').innerHTML = `
    <div class="result">
      <div><b>Доступ для «${esc(x.label)}» выдан.</b> Ссылка показывается один раз —
        в базе хранится только отпечаток токена, собрать её заново нельзя.</div>
      <textarea id="issuedLink" rows="3" readonly style="margin-top:8px">${esc(x.bundle || '')}</textarea>
      <div class="row">
        <button id="btnCopyLink" class="primary">Скопировать ссылку</button>
        <button id="btnHideIssued">Убрать</button>
        <span id="copyMsg" class="msg"></span>
      </div>
    </div>`;

  $('btnCopyLink').onclick = async () => {
    const text = $('issuedLink').value;
    try {
      await navigator.clipboard.writeText(text);
      say($('copyMsg'), 'скопировано', 'ok');
    } catch {
      // Буфер обмена может быть недоступен — выделяем, чтобы скопировали руками.
      $('issuedLink').select();
      say($('copyMsg'), 'выделено — скопируйте вручную', '');
    }
  };
  $('btnHideIssued').onclick = () => { lastIssued = null; $('issued').innerHTML = ''; };
}

async function userAction(act, hash, label) {
  if (act === 'revoke') {
    // Отзыв необратим: токен помечается надгробием и расходится по сети таким.
    if (!confirm(`Отозвать доступ «${label || hash.slice(0, 12)}»?\n\nЭто необратимо: клиент отключится, и та же ссылка больше не заработает.`)) return;
    try {
      await api(`/api/node/qd-admin/users?hash=${encodeURIComponent(hash)}`,
        { method: 'DELETE', body: {}, admin: adminToken });
      adminView('users');
    } catch (e) { alert('Не отозвалось: ' + e.message); }
    return;
  }

  if (act === 'reset') {
    try {
      await api('/api/node/qd-admin/users', {
        method: 'PATCH', admin: adminToken, body: { hash, reset_traffic: true },
      });
      adminView('users');
    } catch (e) { alert('Не сбросилось: ' + e.message); }
    return;
  }

  if (act === 'limit') {
    const gbVal = prompt(`Лимит трафика для «${label || hash.slice(0, 12)}», ГБ.\n0 — снять ограничение.`);
    if (gbVal === null) return;
    const days = prompt('Период в днях (0 — без сброса, обычно 30):', '30');
    if (days === null) return;
    try {
      await api('/api/node/qd-admin/users', {
        method: 'PATCH', admin: adminToken,
        body: {
          hash,
          limit_traffic_gb: parseFloat(gbVal) || 0,
          traffic_period_days: parseInt(days, 10) || 0,
        },
      });
      adminView('users');
    } catch (e) { alert('Не сохранилось: ' + e.message); }
  }
}

// Ошибка в скрипте не должна оставлять человека перед экраном, который «просто
// не реагирует». Без этого разбор упирается в просьбу открыть F12 — а до неё
// доходит не каждый, и половина случаев остаётся невыясненной.
window.addEventListener('error', (e) => showScriptError(e.message));
window.addEventListener('unhandledrejection', (e) => showScriptError(String(e.reason)));

function showScriptError(text) {
  let box = document.getElementById('scriptErr');
  if (!box) {
    box = document.createElement('div');
    box.id = 'scriptErr';
    box.className = 'script-err';
    document.body.appendChild(box);
  }
  box.textContent = 'Сбой в панели: ' + text;
}
