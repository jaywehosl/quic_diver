'use strict';

// Панель без фреймворка намеренно: четыре экрана, открываются раз в год на
// десять минут. Фреймворк добавил бы сборочный тулчейн в проект на чистом Go и
// не дал бы взамен ничего.

// Ключ панели приходит в адресе один раз, дальше носим его в заголовке и
// вычищаем из строки адреса — чтобы не осел в истории браузера.
const TOKEN = new URLSearchParams(location.search).get('token') || '';
if (TOKEN) history.replaceState(null, '', location.pathname + location.hash);

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

let adminToken = '';

$('btnAdminLoad').onclick = async () => {
  adminToken = $('adminToken').value.trim();
  if (!adminToken) return;
  try {
    await api('/api/node/qd-admin/cluster', { admin: adminToken });
    $('adminBody').hidden = false;
    say($('adminMsg'), 'токен принят', 'ok');
    adminView('nodes');
  } catch (e) {
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

function renderUsers(box, list) {
  box.innerHTML = '<table class="grid"><tr><th>Клиент</th><th>Роль</th><th>Трафик по сети</th><th>Лимит</th><th></th></tr>' +
    list.map((u) => {
      const q = u.quota || {};
      const used = gb((u.network_traffic?.bytes_in || 0) + (u.network_traffic?.bytes_out || 0));
      return `<tr>
        <td>${esc(u.label || '—')}<div class="hint mono">${esc(String(u.hash).slice(0, 16))}…</div></td>
        <td>${esc(u.role)}${u.revoked ? ' <span style="color:var(--err)">отозван</span>' : ''}</td>
        <td class="num">${used}</td>
        <td class="num">${q.limit ? gb(q.limit) : '—'}</td>
        <td>${q.limit && q.used >= q.limit ? '<span style="color:var(--err)">исчерпан</span>' : ''}</td>
      </tr>`;
    }).join('') + '</table>';
}

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
