'use strict';

// Ключ панели из адреса или localStorage
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
  if (!rsp.ok) throw new Error((data && data.error) || text || `Ошибка ${rsp.status}`);
  return data;
}

function say(el, text, kind) {
  if (!el) return;
  el.textContent = text;
  el.className = 'form-msg' + (kind ? ' ' + kind : '');
  if (text) setTimeout(() => { if (el.textContent === text) el.textContent = ''; }, 4500);
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// --- Навигация и вкладки ---

function showTab(name) {
  const targetName = name || 'dashboard';
  document.querySelectorAll('.tab-page').forEach((t) => { 
    t.hidden = t.id !== 'tab-' + targetName; 
  });
  document.querySelectorAll('.app-nav a').forEach((a) => {
    a.classList.toggle('active', a.dataset.tab === targetName);
  });
  
  if (targetName === 'exits') loadExits();
  if (targetName === 'sub') loadSub();
  if (targetName === 'notices') loadNotices(true);
  if (targetName === 'admin') loadAdminView();
}

window.addEventListener('hashchange', () => showTab(location.hash.slice(1) || 'dashboard'));

// --- Состояние и Дашборд ---

let lastStatus = null;

async function refreshStatus() {
  try {
    const st = await api('/api/status');
    lastStatus = st;
    renderStatus(st);
  } catch (e) {
    $('stateText').textContent = 'Панель не отвечает';
    $('dot').className = 'status-dot red';
  }
}

function renderStatus(st) {
  showSetup(!st.configured);

  const dot = $('dot');
  const text = $('stateText');
  const unread = Number($('unread')?.dataset?.count || 0);

  if (st.session === 'connected') {
    dot.className = 'status-dot ' + (unread > 0 ? 'blue' : 'green');
    text.textContent = 'Подключено';
    if ($('dashPulse')) $('dashPulse').className = 'pulse-indicator active';
    if ($('dashStatusTitle')) $('dashStatusTitle').textContent = 'ПОДКЛЮЧЕНО';
    if ($('dashStatusSub')) $('dashStatusSub').textContent = 'Трафик под защитой и ускорен через QUIC Diver';
  } else if (st.session === 'connecting') {
    dot.className = 'status-dot blue';
    text.textContent = 'Восстановление связи...';
    if ($('dashPulse')) $('dashPulse').className = 'pulse-indicator connecting';
    if ($('dashStatusTitle')) $('dashStatusTitle').textContent = 'ПОДКЛЮЧЕНИЕ...';
    if ($('dashStatusSub')) $('dashStatusSub').textContent = 'Соединение с узлом устанавливается';
  } else {
    dot.className = 'status-dot';
    text.textContent = 'Отключено';
    if ($('dashPulse')) $('dashPulse').className = 'pulse-indicator';
    if ($('dashStatusTitle')) $('dashStatusTitle').textContent = 'ОТКЛЮЧЕНО';
    if ($('dashStatusSub')) $('dashStatusSub').textContent = 'Трафик идёт напрямую мимо туннеля';
  }

  const c = st.control || {};
  const bits = [];
  if (st.node) bits.push(st.node);
  if (c.online) bits.push('узел на связи' + (c.srtt ? ' (' + c.srtt + ')' : ''));
  else if (c.error) bits.push('узел недоступен');
  else if (!st.configured) bits.push('узел не настроен');
  $('stateNode').textContent = bits.join(' · ');

  if ($('dashNodeName')) $('dashNodeName').textContent = st.node || '—';
  if ($('dashNodeAddr')) $('dashNodeAddr').textContent = c.online ? 'Онлайн' : 'Офлайн';

  const v = st.version || {};
  if ($('ver')) $('ver').textContent = v.revision ? 'v' + v.revision.slice(0, 7) : 'v2.0';

  const busy = st.session !== 'stopped';
  $('btnConnect').hidden = busy;
  $('btnDisconnect').hidden = !busy;
  $('btnConnect').disabled = !st.configured;
}

$('btnConnect').onclick = async () => {
  $('btnConnect').disabled = true;
  try { renderStatus(await api('/api/connect', { body: {} })); }
  catch (e) { alert('Ошибка подключения: ' + e.message); }
  finally { $('btnConnect').disabled = false; }
};

$('btnDisconnect').onclick = async () => {
  $('btnDisconnect').disabled = true;
  try { renderStatus(await api('/api/disconnect', { body: {} })); }
  catch (e) { alert('Ошибка отключения: ' + e.message); }
  finally { $('btnDisconnect').disabled = false; }
};

// --- Быстрые пресеты правил ---

window.addRulePreset = function(type) {
  const textarea = $('rules');
  if (!textarea) return;

  const presets = {
    youtube: 'dom:youtube.com = auto:de\ndom:googlevideo.com = auto:de\ndom:ytimg.com = auto:de',
    discord: 'dom:discord.com = auto:de\ndom:discord.gg = auto:de\ndom:discordapp.com = auto:de\ndom:discord.media = auto:de',
    telegram: 'dom:telegram.org = auto:de\ndom:t.me = auto:de\nproc:telegram.exe = auto:de',
    steam: 'dom:steampowered.com = auto:de\ndom:steamcommunity.com = auto:de',
    chatgpt: 'dom:openai.com = auto:de\ndom:chatgpt.com = auto:de',
  };

  const code = presets[type];
  if (code) {
    if (textarea.value.trim().length > 0) {
      textarea.value += '\n\n' + code;
    } else {
      textarea.value = code;
    }
  }
};

// --- Конфигурация клиента ---

let cfg = null;

async function loadConfig() {
  cfg = await api('/api/config');
  if ($('rules')) $('rules').value = (cfg.routing?.rules || []).join('\n');
  if ($('defaultOut')) $('defaultOut').value = cfg.routing?.default || '';
  if ($('token')) $('token').value = cfg.node?.token || '';
  renderEntries(cfg.node?.entries || []);

  const cap = cfg.capture || {};
  if ($('capIPv4')) $('capIPv4').checked = !!cap.ipv4;
  if ($('capIPv6')) $('capIPv6').checked = !!cap.ipv6;
  if ($('manageDNS')) $('manageDNS').checked = !!cap.manage_dns;
  if ($('manageProxy')) $('manageProxy').checked = !!cap.manage_proxy;

  const tr = cfg.transport || {};
  if ($('brutalMbps')) $('brutalMbps').value = tr.brutal_mbps || 700;
  if ($('dashBrutalRate')) $('dashBrutalRate').textContent = (tr.brutal_mbps || 700) + ' Мбит/с';
  if ($('autoConnect')) $('autoConnect').checked = !!cfg.autoconnect;
  if ($('autoStart')) $('autoStart').checked = !!cfg.autostart;

  const logCfg = cfg.logging || {};
  if ($('logEnabled')) $('logEnabled').checked = !!logCfg.enabled;
  if ($('logMaxMB')) $('logMaxMB').value = logCfg.max_mb || 1;
  if ($('logLevel')) $('logLevel').value = logCfg.level || 'info';
}

function renderEntries(entries) {
  const rows = entries.length ? entries : [{ addr: '', sni: '' }];
  $('entries').innerHTML =
    '<tr><th>Адрес (IP/Host:Port)</th><th>SNI (Домен)</th><th>Действие</th></tr>' +
    rows.map((e, i) => `<tr>
      <td><input class="entry-addr" value="${esc(e.addr)}" placeholder="45.151.101.168:443"></td>
      <td><input class="entry-sni" value="${esc(e.sni || '')}" placeholder="qdiver1.example.com"></td>
      <td><button type="button" class="btn btn-sm btn-danger" data-del="${i}">Удалить</button></td>
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

if ($('btnAddEntry')) $('btnAddEntry').onclick = () => renderEntries([...collectEntries(), { addr: '', sni: '' }]);

async function saveConfig(patch, msgEl) {
  const next = JSON.parse(JSON.stringify(cfg || {}));
  patch(next);
  try {
    cfg = await api('/api/config', { method: 'PUT', body: next });
    say(msgEl, 'Настройки сохранены', 'ok');
    refreshStatus();
    return true;
  } catch (e) {
    say(msgEl, e.message, 'err');
    return false;
  }
}

if ($('btnSaveRules')) {
  $('btnSaveRules').onclick = () => saveConfig((c) => {
    c.routing = c.routing || {};
    c.routing.rules = $('rules').value.split('\n').map((s) => s.trim()).filter(Boolean);
    c.routing.default = $('defaultOut').value.trim() || 'direct';
  }, $('rulesMsg'));
}

if ($('btnSaveNode')) {
  $('btnSaveNode').onclick = () => saveConfig((c) => {
    c.node = c.node || {};
    c.node.entries = collectEntries();
    c.node.token = $('token').value.trim();
    c.capture = c.capture || {};
    c.capture.ipv4 = $('capIPv4').checked;
    c.capture.ipv6 = $('capIPv6').checked;
    c.capture.manage_dns = $('manageDNS').checked;
    c.capture.manage_proxy = $('manageProxy').checked;
  }, $('nodeMsg'));
}

if ($('btnSaveSettings')) {
  $('btnSaveSettings').onclick = () => saveConfig((c) => {
    c.transport = c.transport || {};
    c.transport.brutal_mbps = parseInt($('brutalMbps').value, 10) || 700;
    c.autoconnect = $('autoConnect').checked;
    c.autostart = $('autoStart').checked;

    c.logging = c.logging || {};
    c.logging.enabled = $('logEnabled').checked;
    c.logging.max_mb = parseInt($('logMaxMB').value, 10) || 1;
    c.logging.level = $('logLevel').value || 'info';
  }, $('settingsMsg'));
}

// --- Бэкап настроек на Сервер БД ---

if ($('btnSaveServerBackup')) {
  $('btnSaveServerBackup').onclick = async () => {
    try {
      await api('/api/node/qd-backup', { method: 'POST', body: cfg });
      say($('backupMsg'), 'Бэкап сохранен в БД сервера!', 'ok');
    } catch (e) {
      say($('backupMsg'), 'Ошибка бэкапа: ' + e.message, 'err');
    }
  };
}

if ($('btnRestoreServerBackup')) {
  $('btnRestoreServerBackup').onclick = async () => {
    try {
      const res = await api('/api/node/qd-backup');
      if (res && res.exists && res.config_json) {
        const restoredCfg = JSON.parse(res.config_json);
        await api('/api/config', { method: 'PUT', body: restoredCfg });
        await loadConfig();
        say($('backupMsg'), 'Настройки успешно восстановлены из БД сервера!', 'ok');
      } else {
        say($('backupMsg'), 'Бэкап для этого токена не найден на сервере', 'err');
      }
    } catch (e) {
      say($('backupMsg'), 'Ошибка восстановления: ' + e.message, 'err');
    }
  };
}

// --- Тестер правил ---

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
      `<div style="color:var(--accent);font-weight:600">→ Направление: ${esc(res.out)}</div><div style="margin-top:4px">${why}</div>` +
      (res.note ? `<div style="color:var(--fg-muted);margin-top:2px">${esc(res.note)}</div>` : '');
    box.hidden = false;
  } catch (e) {
    box.innerHTML = `<div style="color:var(--danger)">${esc(e.message)}</div>`;
    box.hidden = false;
  }
}

if ($('btnTest')) $('btnTest').onclick = runTest;

// --- Выходы и Подписка ---

async function loadExits() {
  try {
    const list = await api('/api/exits');
    $('exits').innerHTML =
      '<tr><th>Метка</th><th>Имя</th><th>Теги / Категория</th><th>Состояние</th></tr>' +
      list.map((e) => `<tr>
        <td class="mono"><b>${esc(e.route)}</b></td>
        <td>${esc(e.label || '')}${e.self ? ' <span style="color:var(--accent)">(этот узел)</span>' : ''}</td>
        <td style="color:var(--fg-secondary)">${esc((e.tags || []).join(', '))}${e.category ? ' · ' + esc(e.category) : ''}</td>
        <td>${e.alive ? '<span style="color:var(--success)">● Живой</span>' : '<span style="color:var(--danger)">○ Не отвечает</span>'}</td>
      </tr>`).join('');
    say($('exitsMsg'), '', '');
  } catch (e) {
    $('exits').innerHTML = '';
    say($('exitsMsg'), e.message, 'err');
  }
}

if ($('btnReloadExits')) $('btnReloadExits').onclick = loadExits;

function gbNum(n) { return (Number(n || 0) / 1073741824).toFixed(2) + ' ГБ'; }

async function loadSub(refresh) {
  const box = $('subBody');
  try {
    const sub = await api('/api/subscription' + (refresh ? '?refresh=1' : ''));
    const c = sub.client || {};
    const q = c.quota || {};

    if ($('dashStatTraffic')) $('dashStatTraffic').textContent = gbNum(q.used);
    if ($('dashStatLimit')) $('dashStatLimit').textContent = q.limit ? gbNum(q.limit) : 'Безлимит';

    const rows = [
      ['Клиент', c.label || '—'],
      ['Привязанные устройства (HWID)', (c.devices ?? '0') + ' / ' + (c.max_devices || 'без ограничений')],
      ['Использовано трафика', gbNum(q.used)],
      ['Лимит трафика', q.limit ? gbNum(q.limit) : 'без ограничений'],
    ];

    box.innerHTML =
      '<table class="grid-table">' + rows.map(([k, v]) =>
        `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('') + '</table>' +
      '<h3 class="mt-16">Узлы подписки</h3>' +
      '<table class="grid-table"><tr><th>Адрес</th><th>SNI</th><th>Состояние</th></tr>' +
      (sub.entries || []).map((e) => `<tr>
        <td class="mono">${esc(e.addr)}</td><td class="mono">${esc(e.sni || '')}</td>
        <td>${e.alive ? '<span style="color:var(--success)">● Онлайн</span>' : '<span style="color:var(--danger)">○ Офлайн</span>'}</td>
      </tr>`).join('') + '</table>';
  } catch (e) {
    box.innerHTML = '<p class="subtitle">Информация подписки подгружается из сети...</p>';
  }
}

if ($('btnRefreshSub')) $('btnRefreshSub').onclick = () => loadSub(true);

// --- Уведомления ---

async function loadNotices(markSeen) {
  try {
    const v = await api('/api/notifications');
    const badge = $('unread');
    if (badge) {
      badge.textContent = v.unread;
      badge.hidden = v.unread === 0;
    }
    $('notices').innerHTML = v.items.length
      ? v.items.map((n) => `<div class="card mb-12">
          <div><b>${esc(n.title)}</b></div>
          ${n.text ? `<div style="color:var(--fg-secondary);margin-top:4px">${esc(n.text)}</div>` : ''}
          <div style="font-size:11px;color:var(--fg-muted);margin-top:4px">${new Date(n.at).toLocaleString('ru')}</div>
        </div>`).join('')
      : '<p class="subtitle">Уведомлений нет.</p>';
  } catch { }
}

if ($('btnReadAll')) $('btnReadAll').onclick = async () => { await api('/api/notifications', { body: { id: 0 } }); loadNotices(); };
if ($('btnClearNotices')) $('btnClearNotices').onclick = async () => { await api('/api/notifications', { body: { clear: true } }); loadNotices(); };

// --- Администрирование сети ---

let adminToken = localStorage.getItem('qd_admin_token') || '';

function loadAdminView() {
  if (adminToken) {
    $('adminToken').value = adminToken;
    $('btnAdminLoad').click();
  }
}

if ($('btnAdminLoad')) {
  $('btnAdminLoad').onclick = async () => {
    adminToken = $('adminToken').value.trim();
    if (!adminToken) return;
    try {
      await api('/api/node/qd-admin/cluster', { admin: adminToken });
      localStorage.setItem('qd_admin_token', adminToken);
      $('adminBody').hidden = false;
      say($('adminMsg'), 'Авторизован в сети', 'ok');
      adminView('nodes');
    } catch (e) {
      localStorage.removeItem('qd_admin_token');
      $('adminBody').hidden = true;
      say($('adminMsg'), e.message, 'err');
    }
  };
}

document.querySelectorAll('[data-admin]').forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll('[data-admin]').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    adminView(b.dataset.admin);
  };
});

async function adminView(what) {
  const box = $('adminView');
  box.innerHTML = '<p class="subtitle">Загрузка данных с мастера...</p>';
  try {
    if (what === 'nodes') return renderNodes(box, await api('/api/node/qd-admin/nodes', { admin: adminToken }));
    if (what === 'users') return renderUsers(box, await api('/api/node/qd-admin/users', { admin: adminToken }));
    if (what === 'cluster') return renderCluster(box, await api('/api/node/qd-admin/cluster', { admin: adminToken }));
    if (what === 'stats') return renderStats(box, await api('/api/node/qd-admin/stats', { admin: adminToken }));
  } catch (e) {
    box.innerHTML = `<p class="form-msg err">${esc(e.message)}</p>`;
  }
}

function renderNodes(box, list) {
  box.innerHTML = `
    <h3>Серверные узлы кластера</h3>
    <table class="grid-table">
      <tr><th>Узел (Домен)</th><th>Категория</th><th>Состояние</th><th>Команда установки</th></tr>
      ${list.map((n) => `<tr>
        <td class="mono"><b>${esc(n.id)}</b>${n.self ? ' <span style="color:var(--accent)">(этот узел)</span>' : ''}</td>
        <td>${esc(n.category || 'Основной')}</td>
        <td>${n.alive ? '<span style="color:var(--success)">● Онлайн</span>' : '<span style="color:var(--danger)">○ Офлайн</span>'}</td>
        <td><input value="bash <(curl -sSL https://raw.githubusercontent.com/jaywehosl/quic_diver/main/deploy/install.sh) --role=worker --master=&quot;https://${esc(n.id)}:443&quot;" readonly style="font-size:11px"></td>
      </tr>`).join('')}
    </table>`;
}

function renderUsers(box, list) {
  box.innerHTML = `
    <h3>Управление пользователями & HWID устройствами</h3>
    <div class="card mt-8">
      <div class="form-row">
        <input id="newLabel" placeholder="Имя клиента" style="max-width:180px">
        <input id="newGB" placeholder="Лимит, ГБ" class="input-sm" inputmode="decimal">
        <input id="newDays" placeholder="Дней" class="input-sm" inputmode="numeric">
        <input id="newDevices" placeholder="Устройств (HWID)" class="input-sm" inputmode="numeric">
        <button id="btnNewUser" class="btn btn-primary">Выдать подписку</button>
      </div>
      <span id="usersMsg" class="form-msg"></span>
    </div>
    <div id="issued" class="mt-12"></div>
    <table class="grid-table mt-12" id="usersTable">
      <tr><th>Клиент</th><th>Роль</th><th>Использовано</th><th>Лимит</th><th>Устройства (HWID)</th><th>Действия</th></tr>
      ${list.map(userRow).join('')}
    </table>`;

  if ($('btnNewUser')) $('btnNewUser').onclick = createUser;
  box.querySelectorAll('[data-act]').forEach((b) => {
    b.onclick = () => userAction(b.dataset.act, b.dataset.hash, b.dataset.label);
  });
}

function userRow(u) {
  const q = u.quota || {};
  const net = u.network_traffic || {};
  const used = gbNum((net.bytes_in || 0) + (net.bytes_out || 0));
  const over = q.limit && q.used >= q.limit;
  const devices = u.device_count ?? (u.devices || []).length;

  return `<tr${u.revoked ? ' style="opacity:.4"' : ''}>
    <td><b>${esc(u.label || '—')}</b><div class="mono" style="font-size:11px;color:var(--fg-muted)">${esc(String(u.hash).slice(0, 16))}...</div></td>
    <td>${esc(u.role)}${u.revoked ? ' <span style="color:var(--danger)">(Отозван)</span>' : ''}</td>
    <td>${used}${over ? ' <span style="color:var(--danger)">(Исчерпан)</span>' : ''}</td>
    <td>${q.limit ? gbNum(q.limit) : 'Безлимит'}</td>
    <td>${devices} / ${u.limits?.devices || 'Безлимит'}</td>
    <td>
      <button class="btn btn-sm btn-secondary" data-act="limit" data-hash="${esc(u.hash)}" data-label="${esc(u.label || '')}">Изменить лимит</button>
      <button class="btn btn-sm btn-secondary" data-act="reset" data-hash="${esc(u.hash)}">Сбросить</button>
      ${u.revoked ? '' : `<button class="btn btn-sm btn-danger" data-act="revoke" data-hash="${esc(u.hash)}" data-label="${esc(u.label || '')}">Отозвать</button>`}
    </td>
  </tr>`;
}

async function createUser() {
  const label = $('newLabel').value.trim();
  if (!label) { say($('usersMsg'), 'Укажите имя клиента', 'err'); return; }

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
    showIssued({ label, bundle: res.bundle, token: res.token });
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
    <div class="card" style="border-color:var(--success)">
      <div style="color:var(--success);font-weight:600">✓ Подписка для «${esc(x.label)}» успешно выгода!</div>
      <p class="subtitle mt-4">Скопируйте ссылку подписки и передайте клиенту:</p>
      <textarea id="issuedLink" rows="2" readonly class="code-editor mt-8">${esc(x.bundle || '')}</textarea>
      <div class="form-row mt-8">
        <button id="btnCopyLink" class="btn btn-primary">Скопировать ссылку</button>
        <span id="copyMsg" class="form-msg"></span>
      </div>
    </div>`;

  $('btnCopyLink').onclick = async () => {
    try {
      await navigator.clipboard.writeText($('issuedLink').value);
      say($('copyMsg'), 'Скопировано в буфер обмена!', 'ok');
    } catch {
      $('issuedLink').select();
    }
  };
}

async function userAction(act, hash, label) {
  if (act === 'revoke') {
    if (!confirm(`Отозвать доступ клиента «${label}»? Ссылка станет недействительной.`)) return;
    try {
      await api(`/api/node/qd-admin/users?hash=${encodeURIComponent(hash)}`, { method: 'DELETE', body: {}, admin: adminToken });
      adminView('users');
    } catch (e) { alert(e.message); }
    return;
  }

  if (act === 'reset') {
    try {
      await api('/api/node/qd-admin/users', { method: 'PATCH', admin: adminToken, body: { hash, reset_traffic: true } });
      adminView('users');
    } catch (e) { alert(e.message); }
    return;
  }

  if (act === 'limit') {
    const gbVal = prompt(`Лимит трафика (ГБ) для «${label}». 0 — безлимит:`);
    if (gbVal === null) return;
    const dev = prompt(`Лимит HWID устройств для «${label}». 0 — безлимит:`, '2');
    if (dev === null) return;
    try {
      await api('/api/node/qd-admin/users', {
        method: 'PATCH', admin: adminToken,
        body: {
          hash,
          limit_traffic_gb: parseFloat(gbVal) || 0,
          limit_devices: parseInt(dev, 10) || 0,
        },
      });
      adminView('users');
    } catch (e) { alert(e.message); }
  }
}

function renderCluster(box, c) {
  box.innerHTML = `
    <h3>Кластер и Синхронизация БД</h3>
    <table class="grid-table">
      <tr><th>Мастер сети</th><td class="mono">${esc(c.master_id || '—')}</td></tr>
      <tr><th>Эпоха (Поколение БД)</th><td>${esc(c.epoch)}</td></tr>
      <tr><th>Роль узла</th><td>${c.is_master ? 'Мастер-сервер' : 'Реплика-узел'}</td></tr>
    </table>
    <div class="mt-16">
      <button id="btnBroadcastCluster" class="btn btn-primary">⚡ Синхронизировать БД на всю сеть</button>
      <span id="clusterMsg" class="form-msg"></span>
    </div>`;

  if ($('btnBroadcastCluster')) {
    $('btnBroadcastCluster').onclick = async () => {
      try {
        await api('/api/node/qd-admin/cluster', { method: 'PUT', body: {}, admin: adminToken });
        say($('clusterMsg'), 'БД мгновенно разослана по всей сети!', 'ok');
      } catch (e) {
        say($('clusterMsg'), e.message, 'err');
      }
    };
  }
}

function renderStats(box, s) {
  box.innerHTML = `
    <h3>Состояние сервера и кластера</h3>
    <table class="grid-table">
      <tr><th>Узел</th><td>${esc(s.node)}</td></tr>
      <tr><th>Время работы (Uptime)</th><td>${esc(s.uptime)}</td></tr>
      <tr><th>Клиентских токенов</th><td>${esc(s.clients?.tokens)}</td></tr>
      <tr><th>Активных сессий</th><td>${esc(s.clients?.active_sessions)}</td></tr>
      <tr><th>Память (Heap)</th><td>${esc(s.go?.heap_mb)} МБ</td></tr>
    </table>`;
}

// --- Импорт первого запуска ---

if ($('btnBundle')) {
  $('btnBundle').onclick = async () => {
    const link = $('bundle').value.trim();
    if (!link) return;
    try {
      const res = await api('/api/bundle', { body: { link } });
      say($('bundleMsg'), `Настроено: ${res.entries} точк(и) входа`, 'ok');
      $('bundle').value = '';
      await loadConfig();
      refreshStatus();
    } catch (e) {
      say($('bundleMsg'), e.message, 'err');
    }
  };
}

function showSetup(on) {
  if ($('setup')) $('setup').hidden = !on;
}

if ($('setupApply')) {
  $('setupApply').onclick = async () => {
    const link = $('setupLink').value.trim();
    if (!link) return;
    $('setupApply').disabled = true;
    try {
      await api('/api/bundle', { body: { link } });
      showSetup(false);
      await loadConfig();
      refreshStatus();
    } catch (e) {
      say($('setupMsg'), e.message, 'err');
    } finally {
      $('setupApply').disabled = false;
    }
  };
}

// --- Инициализация ---

(async function start() {
  showTab(location.hash.slice(1) || 'dashboard');
  await loadConfig().catch(() => {});
  await refreshStatus();
  await loadNotices();
  setInterval(refreshStatus, 3000);
})();
