// Night Tech Sentinel tech console.
'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const main = $('#main');
let me = null;

// ---------------- helpers ----------------
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return el;
}
function show(...nodes) { main.replaceChildren(...nodes.flat().filter(n => n != null)); window.scrollTo(0, 0); }
const when = d => d ? new Date(d).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '-';
const ago = d => {
  if (!d) return 'never';
  const m = Math.round((Date.now() - new Date(d)) / 60000);
  return m < 2 ? 'just now' : m < 90 ? `${m} min ago` : m < 2880 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} days ago`;
};
const bytes = n => n == null ? '-' : n >= 1e12 ? (n / 1e12).toFixed(1) + ' TB' : n >= 1e9 ? (n / 1e9).toFixed(1) + ' GB' : (n / 1e6).toFixed(0) + ' MB';

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method, credentials: 'same-origin',
    headers: { 'X-Sentinel': '1', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) { me = null; route('#login'); throw new Error('Please sign in.'); }
  const type = res.headers.get('content-type') || '';
  const data = type.includes('json') ? await res.json() : await res.text();
  if (!res.ok) throw new Error((data && data.error) || `The server answered ${res.status}.`);
  return data;
}
function errorBox() { return h('p', { class: 'error', role: 'alert' }); }
async function run(box, fn) {
  box.textContent = '';
  try { await fn(); } catch (e) { box.textContent = e.message; }
}

// ---------------- routing ----------------
window.addEventListener('hashchange', () => route(location.hash));
$('#logout').addEventListener('click', async () => { await api('/api/logout', { method: 'POST' }).catch(() => {}); me = null; route('#login'); });

async function route(hash) {
  hash = hash || '#alerts';
  if (location.hash !== hash) history.replaceState(null, '', hash);
  const [page, arg] = hash.slice(1).split('/');
  if (!me && page !== 'login') {
    try { me = await api('/api/me'); } catch { return showLogin(); }
  }
  $('#nav').hidden = !me;
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === '#' + page));
  try {
    if (page === 'login') return showLogin();
    if (page === 'devices') return showDevices();
    if (page === 'device') return showDevice(arg);
    if (page === 'clients') return showClients();
    if (page === 'settings') return showSettings();
    return showAlerts();
  } catch (e) { show(h('p', { class: 'error' }, e.message)); }
}

// ---------------- sign in and first setup ----------------
async function showLogin() {
  $('#nav').hidden = true;
  const setup = await fetch('/api/setup').then(r => r.json()).catch(() => ({ needed: false }));
  if (setup.needed) return showSetup();
  const err = errorBox();
  const form = h('form', { class: 'card narrow', onsubmit: e => { e.preventDefault(); run(err, async () => {
      await api('/api/login', { method: 'POST', body: { user: form.user.value, password: form.password.value, code: form.code.value } });
      me = await api('/api/me');
      route('#alerts');
    }); } },
    h('h1', {}, 'Sign in'),
    h('label', { for: 'user' }, 'User name'), h('input', { id: 'user', name: 'user', autocomplete: 'username', required: true }),
    h('label', { for: 'password' }, 'Password'), h('input', { id: 'password', name: 'password', type: 'password', autocomplete: 'current-password', required: true }),
    h('label', { for: 'code' }, 'Two-step code (NightKey or your phone)'), h('input', { id: 'code', name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', required: true, pattern: '[0-9 ]{6,7}' }),
    h('div', { class: 'actions' }, h('button', { class: 'primary' }, 'Sign in')), err);
  show(form);
}

function showSetup() {
  const err = errorBox();
  const form = h('form', { class: 'card narrow', onsubmit: e => { e.preventDefault(); run(err, async () => {
      const r = await api('/api/setup', { method: 'POST', body: { setupToken: form.token.value, user: form.user.value, name: form.name.value, password: form.password.value } });
      showTotp(r, form.user.value);
    }); } },
    h('h1', {}, 'Set up Sentinel'),
    h('p', { class: 'muted' }, "Create the first technician. The setup code is in the server's log and in setup-token.txt in its data folder."),
    h('label', { for: 'token' }, 'Setup code'), h('input', { id: 'token', name: 'token', required: true, autocomplete: 'off' }),
    h('label', { for: 'user' }, 'User name'), h('input', { id: 'user', name: 'user', required: true, autocomplete: 'username' }),
    h('label', { for: 'name' }, 'Your name (shown to clients)'), h('input', { id: 'name', name: 'name', required: true }),
    h('label', { for: 'password' }, 'Password (12 characters or more)'), h('input', { id: 'password', name: 'password', type: 'password', required: true, minlength: 12, autocomplete: 'new-password' }),
    h('div', { class: 'actions' }, h('button', { class: 'primary' }, 'Create')), err);
  show(form);
}

function showTotp(r, user) {
  show(h('div', { class: 'card narrow' },
    h('h1', {}, 'Turn on two-step sign-in'),
    h('p', {}, `Add this key for "${user}" to NightKey or a phone authenticator app, then sign in with a code from it. It's shown only once.`),
    h('p', { class: 'token' }, r.totpSecret.match(/.{1,4}/g).join(' ')),
    h('p', { class: 'small muted' }, 'Setup link for apps that take one: ', h('span', { class: 'token' }, r.totpUri)),
    h('div', { class: 'actions' }, h('a', { class: 'btn primary', href: '#login' }, 'Go to sign in'))));
}

// ---------------- alerts ----------------
async function showAlerts() {
  const alerts = await api('/api/alerts');
  const rows = alerts.map(a => h('tr', { class: 'click', onclick: () => route('#device/' + a.deviceId) },
    h('td', {}, h('span', { class: a.level }, a.level === 'Critical' ? 'Fix now' : a.level === 'Warning' ? 'Worth fixing' : 'Info'), a.acknowledged ? h('div', { class: 'small muted' }, 'seen') : null),
    h('td', {}, h('b', {}, a.title), h('div', { class: 'small muted' }, a.detail)),
    h('td', {}, a.computer, h('div', { class: 'small muted' }, a.client)),
    h('td', { class: 'hide' }, ago(a.firstSeenUtc))));
  show(h('h1', {}, 'Alerts'),
    alerts.length ? h('table', {}, h('tr', {}, h('th', {}, ''), h('th', {}, 'What'), h('th', {}, 'Computer'), h('th', { class: 'hide' }, 'Since')), rows)
      : h('div', { class: 'card good' }, 'Nothing needs attention. Every computer is healthy.'));
}

// ---------------- computers ----------------
async function showDevices() {
  const list = await api('/api/devices');
  const filter = h('input', { placeholder: 'Find a computer, person or client', 'aria-label': 'Filter' });
  const body = h('tbody');
  const draw = () => {
    const q = filter.value.toLowerCase();
    body.replaceChildren(...list.filter(d => !q || [d.computer, d.user, d.client].join(' ').toLowerCase().includes(q)).map(d =>
      h('tr', { class: 'click', onclick: () => route('#device/' + d.id) },
        h('td', {}, h('b', {}, d.computer), h('div', { class: 'small muted' }, d.user)),
        h('td', {}, d.client),
        h('td', {}, d.critical ? h('span', { class: 'Critical' }, `${d.critical} to fix`) : d.warnings ? h('span', { class: 'Warning' }, `${d.warnings} worth fixing`) : h('span', { class: 'good' }, 'Healthy')),
        h('td', { class: 'hide' }, h('span', { class: 'pill ' + (d.online ? 'on' : 'off') }, d.online ? 'Live' : 'Offline'), ' ', h('span', { class: 'small muted' }, ago(d.lastSeenUtc))))));
  };
  filter.addEventListener('input', draw);
  draw();
  show(h('h1', {}, 'Computers'), h('p', {}, filter),
    list.length ? h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Computer'), h('th', {}, 'Client'), h('th', {}, 'Health'), h('th', { class: 'hide' }, 'Last check-in'))), body)
      : h('p', { class: 'muted' }, 'No computers yet. Add a client, make an enrollment code, and install Sentinel on their PCs.'));
}

// Sign and send a command to one PC.
async function send(deviceId, kind, args = {}, reason = '', minutes = 30) {
  const { command, signed } = await SentinelCrypto.signCommand({ deviceId, kind, args, reason, tech: me.name || me.user, minutes });
  const r = await api(`/api/devices/${deviceId}/commands`, { method: 'POST', body: signed });
  return { command, delivered: r.delivered };
}

async function showDevice(id) {
  const d = await api('/api/devices/' + id);
  const s = d.summary, r = d.latest;
  const tabs = ['Overview', 'Alerts', 'Security', 'Actions', 'History', 'Notes'];
  const body = h('div');
  const tabBar = h('div', { class: 'tabs', role: 'tablist' }, tabs.map(t => h('button', { role: 'tab', onclick: () => open(t) }, t)));
  function open(t) {
    tabBar.querySelectorAll('button').forEach(b => b.classList.toggle('on', b.textContent === t));
    body.replaceChildren(({ Overview: overview, Alerts: alertsTab, Security: securityTab, Actions: actionsTab, History: historyTab, Notes: notesTab })[t]());
  }

  function overview() {
    if (!r) return h('p', { class: 'muted' }, "This PC hasn't checked in yet.");
    const sys = (r.volumes || []).map(v => h('div', {}, `${v.name} ${bytes(v.freeBytes)} free of ${bytes(v.sizeBytes)}`));
    const drives = (r.drives || []).map(x => h('div', {}, `${x.name || 'Drive'}: `, h('span', { class: x.health === 'Healthy' ? 'good' : 'Warning' }, x.health), x.wearPercent != null ? ` · ${x.wearPercent}% worn` : '', x.temperatureC ? ` · ${x.temperatureC}°C` : ''));
    const av = r.antivirus || {};
    return h('div', { class: 'grid' },
      tile('Computer', `${r.make} ${r.model}`, `Serial ${r.serial || '-'}`, `${bytes(r.ramBytes)} memory`),
      tile('Windows', r.windows, `Build ${r.windowsBuild}`, `On since ${when(r.lastBootUtc)}`),
      tile('Signed in', r.loggedOnUser || 'Nobody'),
      tile('Antivirus', h('span', { class: av.enabled ? 'good' : 'Critical' }, av.enabled ? 'On' : 'Off'), (av.products || []).join(', '), av.defenderSignatureAgeDays != null ? `Definitions ${av.defenderSignatureAgeDays} days old` : ''),
      tile('Updates', r.updates?.lastInstalledUtc ? `Last installed ${when(r.updates.lastInstalledUtc)}` : 'Unknown', r.updates?.rebootPending ? h('span', { class: 'Warning' }, 'Restart waiting') : ''),
      tile('Backup', r.backup?.tool ? `${r.backup.tool}` : h('span', { class: 'Warning' }, 'None set up'), r.backup?.lastSuccessUtc ? `Last good backup ${ago(r.backup.lastSuccessUtc)}` : '', r.backup?.destination || ''),
      tile('Disk space', ...sys), tile('Drives', ...drives),
      tile('Firewall', r.firewallOn === false ? h('span', { class: 'Critical' }, 'Off') : r.firewallOn ? h('span', { class: 'good' }, 'On') : 'Unknown'),
      r.batteryHealthPercent != null ? tile('Battery', `${r.batteryHealthPercent}% of original capacity`) : null,
      tile('Last 7 days', `${r.blueScreens7d} blue screens`, `${r.unexpectedShutdowns7d} unexpected shutdowns`, `${r.diskErrors7d} disk errors`),
      tile('This PC allows', r.policy?.unattended ? 'Unattended access' : 'Asks the person first', r.policy?.allowRemoteDesktop ? 'Remote desktop' : 'No remote desktop', r.policy?.allowRemoteShell ? 'Remote shell' : 'No remote shell', r.policy?.allowScripts ? 'Scripts' : 'No scripts'),
      tile('PC key', h('span', { class: 'small token' }, SentinelCrypto.readable(d.keyId)), `Agent ${r.agentVersion}`),
      (r.notes || []).length ? tile("Couldn't check", ...r.notes.map(n => h('div', { class: 'small' }, n))) : null);
  }
  const tile = (title, ...lines) => h('div', { class: 'card tile' }, h('b', {}, title), lines.filter(x => x !== '' && x != null).map(x => h('div', {}, x)));

  function alertsTab() {
    if (!d.alerts.length) return h('p', { class: 'good' }, 'No alerts.');
    return h('table', {}, d.alerts.map(a => h('tr', {},
      h('td', {}, h('span', { class: a.clearedUtc ? 'muted' : a.level }, a.clearedUtc ? 'Cleared' : a.level)),
      h('td', {}, h('b', {}, a.title), h('div', { class: 'small muted' }, a.detail)),
      h('td', { class: 'small' }, `Since ${when(a.firstSeenUtc)}`, a.clearedUtc ? h('div', {}, `Cleared ${when(a.clearedUtc)}`) : null),
      h('td', {}, !a.clearedUtc && !a.acknowledged ? h('button', { onclick: async e => { await api(`/api/devices/${id}/alerts/${encodeURIComponent(a.key)}/ack`, { method: 'POST' }); e.target.replaceWith('Seen'); } }, 'Mark seen') : a.acknowledged ? 'Seen' : ''))));
  }

  function securityTab() {
    const items = r?.security || [];
    const err = errorBox(), msg = h('p');
    if (!items.length) return h('div', {}, h('p', { class: 'good' }, 'Night Tech Shield found nothing.'), h('p', { class: 'small muted' }, `Checked ${when(r?.securityCheckedUtc)}`));
    const boxes = [];
    const rows = items.map(x => {
      const cb = x.fixable ? h('input', { type: 'checkbox', 'aria-label': x.title }) : null;
      if (cb) { cb.checked = x.recommended; boxes.push([cb, x.id]); }
      return h('tr', {}, h('td', {}, cb), h('td', {}, h('span', { class: x.severity === 'Risk' ? 'Critical' : x.severity }, x.severity === 'Risk' ? 'Fix now' : x.severity === 'Warning' ? 'Worth fixing' : 'Info')),
        h('td', {}, h('b', {}, x.title), h('div', { class: 'small muted' }, x.detail)));
    });
    return h('div', {},
      h('p', { class: 'small muted' }, `Night Tech Shield, checked ${when(r.securityCheckedUtc)}. Uninstalls and browser resets need the person at the PC or a remote desktop session.`),
      h('table', {}, rows),
      h('div', { class: 'actions' },
        h('button', { class: 'primary', onclick: () => run(err, async () => {
          const ids = boxes.filter(([cb]) => cb.checked).map(([, i]) => i);
          if (!ids.length) throw new Error('Tick what to fix first.');
          const reason = prompt('Reason (shown to the person at the PC if they are asked):', 'Fixing what Night Tech Shield found') ?? '';
          const res = await send(id, 'ShieldFix', { ids: ids.join('\n') }, reason);
          msg.textContent = res.delivered ? 'Sent. Results show in History in a minute or two.' : 'Queued. It goes at the next check-in.';
        }) }, 'Fix selected'),
        h('button', { onclick: () => run(err, async () => { const res = await send(id, 'ShieldScan'); msg.textContent = res.delivered ? 'Scanning now.' : 'Queued for the next check-in.'; }) }, 'Scan again')),
      msg, err);
  }

  function actionsTab() {
    const err = errorBox(), msg = h('p');
    const act = (label, kind, args = {}, confirmText = '', danger = false) => h('button', { class: danger ? 'danger' : '', onclick: () => run(err, async () => {
      if (confirmText && !confirm(confirmText)) return;
      const res = await send(id, kind, typeof args === 'function' ? args() : args);
      msg.textContent = `${label}: ${res.delivered ? 'sent now' : 'queued for the next check-in'}.`;
    }) }, label);
    const script = h('textarea', { rows: 6, placeholder: 'PowerShell. Runs as SYSTEM; the person at the PC is asked first unless this PC is unattended.', 'aria-label': 'Script' });
    const scriptName = h('input', { placeholder: 'Name, e.g. Clear print queue', 'aria-label': 'Script name' });
    const message = h('textarea', { rows: 3, placeholder: 'A message to show on the screen', 'aria-label': 'Message' });
    return h('div', {},
      h('h2', {}, 'Remote'),
      h('div', { class: 'actions' },
        h('button', { class: 'primary', disabled: !r?.policy?.allowRemoteDesktop, onclick: () => run(err, () => remoteDesktop(d)) }, 'Remote desktop'),
        h('button', { disabled: !r?.policy?.allowRemoteShell, onclick: () => run(err, () => remoteShell(d)) }, 'Remote shell')),
      h('h2', {}, 'Upkeep'),
      h('div', { class: 'actions' },
        act('Check now', 'RefreshNow'), act('Shield scan', 'ShieldScan'), act('Update Defender', 'DefenderUpdate'),
        act('Defender quick scan', 'DefenderQuickScan'), act('Defender full scan', 'DefenderFullScan', {}, 'A full scan can take an hour or more and slows the PC. Start it?'),
        act('Install Windows updates', 'InstallUpdates', {}, 'Install every waiting Windows update? The person at the PC is asked first.'),
        act('Clear temp files', 'CleanTemp'), act('Collect error logs', 'CollectLogs'),
        act('Restart in 5 minutes', 'Restart', { minutes: '5' }, 'Restart this PC? The person at the PC is asked first and gets a 5-minute warning.', true)),
      h('h2', {}, 'Message'),
      message, h('div', { class: 'actions' }, act('Show message', 'ShowMessage', () => ({ title: 'Message from Night Tech Solutions', message: message.value }))),
      h('h2', {}, 'Script'),
      scriptName, h('p'), script,
      h('div', { class: 'actions' }, h('button', { onclick: () => run(err, async () => {
        if (!script.value.trim()) throw new Error('The script is empty.');
        if (!confirm('Run this script as SYSTEM on ' + s.computer + '?')) return;
        const res = await send(id, 'RunScript', { script: script.value, name: scriptName.value, minutes: '10' }, scriptName.value);
        msg.textContent = res.delivered ? 'Sent. Output shows in History.' : 'Queued for the next check-in.';
      }) }, 'Run script')),
      msg, err);
  }

  function historyTab() {
    if (!d.history.length && !d.queue.length) return h('p', { class: 'muted' }, 'Nothing yet.');
    return h('div', {},
      d.queue.filter(q => !q.deliveredUtc).length ? h('p', { class: 'notice' }, `${d.queue.filter(q => !q.deliveredUtc).length} waiting for the next check-in.`) : null,
      h('table', {}, d.history.map(x => h('tr', {},
        h('td', { class: 'small' }, when(x.finishedUtc)),
        h('td', {}, h('b', {}, x.kind), h('div', { class: x.outcome === 'Done' ? 'good' : 'Warning' }, x.outcome), h('div', { class: 'small muted' }, x.detail),
          x.output ? h('details', {}, h('summary', {}, 'Output'), h('pre', {}, x.output)) : null)))));
  }

  function notesTab() {
    const box = h('textarea', { rows: 8, 'aria-label': 'Notes' }); box.value = s.note || '';
    const msg = h('p', { class: 'small muted' });
    return h('div', {}, h('p', { class: 'muted' }, 'Notes for Night Tech only (passwords never go here).'), box,
      h('div', { class: 'actions' }, h('button', { onclick: async () => { await api(`/api/devices/${id}/note`, { method: 'POST', body: { note: box.value } }); msg.textContent = 'Saved.'; } }, 'Save'),
        h('button', { class: 'danger right', onclick: async () => { if (!confirm(`Remove ${s.computer} from Sentinel? It stops checking in. Uninstall Sentinel from the PC too.`)) return; await api(`/api/devices/${id}/retire`, { method: 'POST' }); route('#devices'); } }, 'Remove this computer')),
      msg);
  }

  show(h('div', { class: 'row' }, h('h1', {}, s.computer), h('span', { class: 'pill ' + (s.online ? 'on' : 'off') }, s.online ? 'Live' : 'Offline'), h('span', { class: 'muted' }, `${s.client} · last check-in ${ago(s.lastSeenUtc)}`)),
    tabBar, body);
  open('Overview');
}

// ---------------- remote sessions ----------------
async function startSession(d, kind) {
  const s = await SentinelCrypto.newSession();
  if (!await SentinelCrypto.checkDeviceKey(d.summary.id, d.publicKey))
    throw new Error("This PC's key has changed since this browser last saw it. Don't connect: call Night Tech's lead tech. (Reinstalling Sentinel also changes it.)");
  const reason = prompt('Reason (shown to the person at the PC when they are asked):', kind === 'RemoteDesktop' ? 'Helping with your computer' : 'Maintenance') ?? '';
  const res = await send(d.summary.id, kind, { sessionId: s.sessionId, browserKey: s.publicKey }, reason, 15);
  const ws = new WebSocket(`wss://${location.host}/api/console/session/${s.sessionId}`);
  ws.binaryType = 'arraybuffer';
  const status = h('p', { class: 'notice' }, res.delivered ? 'Waiting for the person at the PC to allow it...' : 'The PC is offline: it will be asked at its next check-in (within 15 minutes).');
  let crypto = null;
  const handlers = { onMessage: () => {}, onEnd: () => {} };
  ws.onmessage = async ev => {
    if (!crypto) {
      if (typeof ev.data !== 'string') return;
      const m = JSON.parse(ev.data);
      if (m.type !== 'answer') return;
      try { crypto = await SentinelCrypto.completeSession(s, d.summary.id, d.publicKey, m); status.textContent = `Connected to ${crypto.computer}. End-to-end encrypted.`; handlers.onOpen?.(); }
      catch (e) { status.textContent = e.message; ws.close(); }
      return;
    }
    try { handlers.onMessage(await crypto.open(ev.data)); }
    catch { status.textContent = 'The connection was tampered with, so it was closed.'; ws.close(); }
  };
  ws.onclose = () => { status.textContent = 'Session ended.'; handlers.onEnd(); };
  const sendInner = async bytes => { if (crypto && ws.readyState === 1) ws.send(await crypto.seal(bytes)); };
  const control = obj => { const j = new TextEncoder().encode(JSON.stringify(obj)); const b = new Uint8Array(j.length + 1); b[0] = 1; b.set(j, 1); return b; };
  return { ws, status, handlers, sendInner, control, end: () => { sendInner(control({ t: 'end' })); setTimeout(() => ws.close(), 300); } };
}

async function remoteShell(d) {
  const out = h('pre', { 'aria-live': 'polite' });
  const input = h('input', { placeholder: 'Type a PowerShell command and press Enter', 'aria-label': 'Command', autocomplete: 'off' });
  const sess = await startSession(d, 'RemoteShell');
  sess.handlers.onMessage = b => {
    if (b[0] !== 1) return;
    const m = JSON.parse(new TextDecoder().decode(b.slice(1)));
    if (m.t === 'out' || m.t === 'end') { out.textContent += m.d; if (out.textContent.length > 400000) out.textContent = out.textContent.slice(-300000); out.scrollTop = out.scrollHeight; }
  };
  const form = h('form', { onsubmit: e => { e.preventDefault(); out.textContent += 'PS> ' + input.value + '\n'; sess.sendInner(sess.control({ t: 'in', d: input.value + '\n' })); input.value = ''; } },
    input, h('button', { class: 'primary' }, 'Run'), h('button', { type: 'button', class: 'danger', onclick: () => sess.end() }, 'End'));
  show(h('h1', {}, `Remote shell: ${d.summary.computer}`), sess.status, h('div', { class: 'term' }, out, form), h('p', {}, h('a', { href: '#device/' + d.summary.id }, 'Back to the computer')));
  sess.handlers.onOpen = () => input.focus();
}

// KeyboardEvent.code to PC scan codes (set 1). [code, extended]
const SCAN = (() => {
  const m = { Escape: [1], Minus: [12], Equal: [13], Backspace: [14], Tab: [15], BracketLeft: [26], BracketRight: [27], Enter: [28], ControlLeft: [29], Semicolon: [39], Quote: [40], Backquote: [41], ShiftLeft: [42], Backslash: [43], Comma: [51], Period: [52], Slash: [53], ShiftRight: [54], NumpadMultiply: [55], AltLeft: [56], Space: [57], CapsLock: [58], NumLock: [69], ScrollLock: [70], NumpadSubtract: [74], NumpadAdd: [78], NumpadDecimal: [83], F11: [87], F12: [88], NumpadEnter: [28, 1], ControlRight: [29, 1], NumpadDivide: [53, 1], AltRight: [56, 1], Home: [71, 1], ArrowUp: [72, 1], PageUp: [73, 1], ArrowLeft: [75, 1], ArrowRight: [77, 1], End: [79, 1], ArrowDown: [80, 1], PageDown: [81, 1], Insert: [82, 1], Delete: [83, 1], MetaLeft: [91, 1], MetaRight: [92, 1], ContextMenu: [93, 1], PrintScreen: [55, 1] };
  '1234567890'.split('').forEach((c, i) => m['Digit' + c] = [2 + i]);
  'QWERTYUIOP'.split('').forEach((c, i) => m['Key' + c] = [16 + i]);
  'ASDFGHJKL'.split('').forEach((c, i) => m['Key' + c] = [30 + i]);
  'ZXCVBNM'.split('').forEach((c, i) => m['Key' + c] = [44 + i]);
  for (let i = 1; i <= 10; i++) m['F' + i] = [58 + i];
  [[7, 71], [8, 72], [9, 73], [4, 75], [5, 76], [6, 77], [1, 79], [2, 80], [3, 81], [0, 82]].forEach(([n, c]) => m['Numpad' + n] = [c]);
  return m;
})();

async function remoteDesktop(d) {
  const canvas = h('canvas', { tabindex: 0, width: 1280, height: 720, 'aria-label': 'Remote screen. Click to control.' });
  const ctx = canvas.getContext('2d');
  const sess = await startSession(d, 'RemoteDesktop');
  sess.handlers.onMessage = async b => {
    if (b[0] === 1) {
      const m = JSON.parse(new TextDecoder().decode(b.slice(1)));
      if (m.t === 'screen') { canvas.width = m.w; canvas.height = m.h; }
      if (m.t === 'end') sess.status.textContent = m.d || 'Session ended.';
      return;
    }
    if (b[0] === 2 && b.length > 9) {
      const v = new DataView(b.buffer, b.byteOffset + 1, 8);
      const x = v.getUint16(0, true), y = v.getUint16(2, true);
      const img = await createImageBitmap(new Blob([b.slice(9)], { type: 'image/jpeg' }));
      ctx.drawImage(img, x, y);
      img.close();
    }
  };
  const pos = e => { const r = canvas.getBoundingClientRect(); return { x: Math.round((e.clientX - r.left) * canvas.width / r.width), y: Math.round((e.clientY - r.top) * canvas.height / r.height) }; };
  let lastMove = 0;
  canvas.addEventListener('mousemove', e => { const now = performance.now(); if (now - lastMove < 30) return; lastMove = now; sess.sendInner(sess.control({ t: 'move', ...pos(e) })); });
  canvas.addEventListener('mousedown', e => { canvas.focus(); e.preventDefault(); sess.sendInner(sess.control({ t: 'down', b: e.button, ...pos(e) })); });
  canvas.addEventListener('mouseup', e => { e.preventDefault(); sess.sendInner(sess.control({ t: 'up', b: e.button, ...pos(e) })); });
  canvas.addEventListener('contextmenu', e => e.preventDefault());
  canvas.addEventListener('wheel', e => { e.preventDefault(); sess.sendInner(sess.control({ t: 'wheel', delta: Math.round(-e.deltaY) })); }, { passive: false });
  const key = up => e => {
    const k = SCAN[e.code];
    if (!k) return;
    e.preventDefault();
    sess.sendInner(sess.control({ t: 'key', code: k[0], ext: !!k[1], up }));
  };
  canvas.addEventListener('keydown', key(false));
  canvas.addEventListener('keyup', key(true));
  const paste = h('input', { placeholder: 'Type text to send (passwords stay on your side only if you never type them here)', 'aria-label': 'Text to type' });
  show(h('div', { class: 'row' }, h('h1', {}, `Remote desktop: ${d.summary.computer}`),
      h('button', { onclick: () => sess.sendInner(sess.control({ t: 'sas' })) }, 'Ctrl+Alt+Del'),
      h('button', { onclick: () => sess.sendInner(sess.control({ t: 'refresh' })) }, 'Refresh'),
      h('button', { onclick: () => canvas.classList.toggle('full') }, 'Actual size'),
      h('button', { class: 'danger', onclick: () => sess.end() }, 'Disconnect')),
    sess.status,
    h('div', { class: 'desk' }, canvas),
    h('form', { class: 'row', onsubmit: e => { e.preventDefault(); sess.sendInner(sess.control({ t: 'text', d: paste.value })); paste.value = ''; } }, paste, h('button', {}, 'Type it')),
    h('p', { class: 'small muted' }, 'Click the screen to control it. The person at the PC sees a banner and can disconnect at any time.'),
    h('p', {}, h('a', { href: '#device/' + d.summary.id }, 'Back to the computer')));
}

// ---------------- clients ----------------
async function showClients() {
  const clients = await api('/api/clients');
  const err = errorBox();
  const form = h('form', { class: 'card', onsubmit: e => { e.preventDefault(); run(err, async () => {
      await api('/api/clients', { method: 'POST', body: { name: form.cname.value, contact: form.contact.value, email: form.email.value } });
      showClients();
    }); } },
    h('h2', {}, 'Add a client'),
    h('div', { class: 'grid' },
      h('div', {}, h('label', { for: 'cname' }, 'Business or family name'), h('input', { id: 'cname', name: 'cname', required: true })),
      h('div', {}, h('label', { for: 'contact' }, 'Contact'), h('input', { id: 'contact', name: 'contact' })),
      h('div', {}, h('label', { for: 'email' }, 'Email for reports'), h('input', { id: 'email', name: 'email', type: 'email' }))),
    h('div', { class: 'actions' }, h('button', { class: 'primary' }, 'Add client')), err);
  const lastMonth = (() => { const n = new Date(); n.setUTCDate(1); n.setUTCMonth(n.getUTCMonth() - 1); return n.toISOString().slice(0, 7); })();
  show(h('h1', {}, 'Clients'),
    clients.map(c => {
      const out = h('div');
      return h('div', { class: 'card' },
        h('div', { class: 'row' }, h('b', {}, c.name), h('span', { class: 'muted' }, `${c.devices} computer${c.devices === 1 ? '' : 's'}`), c.alerts ? h('span', { class: 'Warning' }, `${c.alerts} alerts`) : null,
          h('span', { class: 'right' }),
          h('button', { onclick: () => run(out, () => enrollment(c, out)) }, 'Enrollment code'),
          h('a', { class: 'btn', href: `/api/clients/${c.id}/report?month=${lastMonth}`, target: '_blank', rel: 'noopener' }, 'Last month\'s report')),
        c.contact || c.email ? h('div', { class: 'small muted' }, [c.contact, c.email].filter(Boolean).join(' · ')) : null, out);
    }),
    form);
}

async function enrollment(c, out) {
  const keys = (await api('/api/me')).allKeys;
  if (!keys.length) throw new Error('No technician has a signing key yet. Make one in Settings first.');
  const r = await api(`/api/clients/${c.id}/codes`, { method: 'POST', body: { days: 7, uses: 25 } });
  const json = JSON.stringify({ server: location.origin, code: r.code, keyIds: keys.map(k => k.keyId), client: c.name });
  const token = 'NTS1.' + btoa(unescape(encodeURIComponent(json))).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  out.replaceChildren(h('div', { class: 'notice' },
    h('p', {}, `Install Sentinel on ${c.name}'s computers with this code. It works for ${r.uses} PCs until ${when(r.expiresUtc)}, and makes each PC trust these technicians: ${keys.map(k => `${k.tech} (${SentinelCrypto.readable(k.keyId).slice(0, 9)})`).join(', ')}.`),
    h('p', { class: 'token' }, token),
    h('p', { class: 'small' }, 'Run the installer and paste the code when it asks, or install silently: ', h('span', { class: 'token' }, `NightTechSentinel-Setup.exe /VERYSILENT /CODE=${token}`)),
    h('p', { class: 'small muted' }, 'For a server or a PC nobody sits at, add /UNATTENDED=1 so technicians can connect without someone clicking Allow.')));
}

// ---------------- settings ----------------
async function showSettings() {
  const info = await api('/api/me');
  const local = await SentinelCrypto.signingKey();
  const err = errorBox(), msg = h('p');
  const registered = local && info.keys.some(k => k.keyId === local.keyId);
  const keyCard = h('div', { class: 'card' },
    h('h2', {}, "This browser's signing key"),
    h('p', { class: 'muted' }, 'Commands are signed by a key made in this browser. It never leaves this computer, so the server can never send a command by itself. PCs trust the keys named in their enrollment code.'),
    local ? h('p', {}, 'Key ', h('span', { class: 'token' }, SentinelCrypto.readable(local.keyId)), registered ? h('span', { class: 'good' }, '  registered') : h('span', { class: 'Warning' }, '  not registered')) : h('p', { class: 'Warning' }, 'No key yet.'),
    h('div', { class: 'actions' },
      !local ? h('button', { class: 'primary', onclick: () => run(err, async () => { const k = await SentinelCrypto.makeSigningKey(); await api('/api/keys', { method: 'POST', body: { publicKey: k.publicKey } }); showSettings(); }) }, 'Make a signing key') : null,
      local && !registered ? h('button', { class: 'primary', onclick: () => run(err, async () => { await api('/api/keys', { method: 'POST', body: { publicKey: local.publicKey } }); showSettings(); }) }, 'Register it') : null),
    h('p', { class: 'small muted' }, 'PCs set up before a new key was added keep trusting only their original keys. Clearing this browser\'s data deletes the key.'));
  const all = h('div', { class: 'card' }, h('h2', {}, 'Technician keys'), h('table', {}, info.allKeys.map(k => h('tr', {}, h('td', {}, k.tech), h('td', { class: 'token small' }, SentinelCrypto.readable(k.keyId))))));
  const form = h('form', { class: 'card', onsubmit: e => { e.preventDefault(); run(err, async () => {
      const r = await api('/api/techs', { method: 'POST', body: { user: form.tuser.value, name: form.tname.value, password: form.tpass.value } });
      msg.replaceChildren(h('div', { class: 'notice' }, `Give ${form.tname.value} this two-step key for NightKey or their phone (shown once): `, h('span', { class: 'token' }, r.totpSecret)));
    }); } },
    h('h2', {}, 'Add a technician'),
    h('div', { class: 'grid' },
      h('div', {}, h('label', { for: 'tuser' }, 'User name'), h('input', { id: 'tuser', name: 'tuser', required: true })),
      h('div', {}, h('label', { for: 'tname' }, 'Name'), h('input', { id: 'tname', name: 'tname', required: true })),
      h('div', {}, h('label', { for: 'tpass' }, 'Starting password'), h('input', { id: 'tpass', name: 'tpass', type: 'password', minlength: 12, required: true, autocomplete: 'new-password' }))),
    h('div', { class: 'actions' }, h('button', {}, 'Add technician')));
  const audit = h('details', { class: 'card' }, h('summary', {}, 'Activity log'), h('pre', {}, (await api('/api/audit')).join('\n')));
  show(h('h1', {}, 'Settings'), keyCard, all, form, msg, err, audit);
}

route(location.hash);
