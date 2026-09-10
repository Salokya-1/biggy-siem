/* ==========================================================================
   ARGUS SIEM — console application logic
   ========================================================================== */
(() => {
  'use strict';

  // ---- helpers -----------------------------------------------------------
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const SEV = { 1: 'info', 2: 'low', 3: 'medium', 4: 'high', 5: 'critical' };
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const api = async (url, opts = {}) => {
    const r = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...opts });
    if (r.status === 401) { window.location = '/login'; throw new Error('unauthorized'); }
    if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.detail || r.statusText); }
    return r.status === 204 ? null : r.json();
  };
  const post = (u, b) => api(u, { method: 'POST', body: JSON.stringify(b || {}) });

  const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString('en-GB', { hour12: false });
  const fmtDate = (ts) => new Date(ts * 1000).toLocaleString('en-GB', { hour12: false, day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
  const ago = (ts) => { const s = Date.now() / 1000 - ts; if (s < 60) return `${s | 0}s`; if (s < 3600) return `${s / 60 | 0}m`; if (s < 86400) return `${s / 3600 | 0}h`; return `${s / 86400 | 0}d`; };
  const sevChip = (s) => `<span class="sev sev-${s}">${SEV[s] || 'med'}</span>`;
  const emptyRow = (n, m) => `<tr><td colspan="${n}" class="empty">${esc(m)}</td></tr>`;
  const xn = (count) => (count > 1) ? `<span class="xn">×${count}</span>` : '';
  function aiFmt(t) { return esc(t || '').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/\n/g, '<br>'); }
  const bytes = (n) => { if (!n) return '0 B'; const u = ['B', 'KB', 'MB', 'GB']; const i = Math.min(u.length - 1, Math.log(n) / Math.log(1024) | 0); return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`; };

  function toast(title, msg, kind = '') {
    const t = document.createElement('div');
    t.className = `toast ${kind}`;
    t.innerHTML = `<div class="th">${esc(title)}</div><div class="dim">${esc(msg || '')}</div>`;
    $('#toasts').appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateX(10px)'; t.style.transition = '.3s'; setTimeout(() => t.remove(), 300); }, 4200);
  }

  // ---- routing -----------------------------------------------------------
  const TITLES = {
    overview: ['Overview', 'Real-time security posture'],
    events: ['Event Stream', 'Normalised log & telemetry pipeline'],
    alerts: ['Alerts', 'Correlated detections requiring triage'],
    logs: ['Endpoint Logs', 'Windows Event Log — hover a code to decode it'],
    ai: ['AI Analyst', 'Built-in offline reasoning engine — no external LLM'],
    detections: ['Detection Rules', 'IDS ruleset & active-response policy'],
    scanner: ['Malware Scanner', 'Argus engine · signatures, heuristics & entropy'],
    intel: ['Threat Intelligence', 'VirusTotal reputation lookups'],
    network: ['Network Map', 'Asset discovery, monitoring & port scanning'],
    agents: ['Host Agents', 'Endpoint telemetry & EDR'],
    response: ['Active Response', 'IPS blocklist & containment'],
    cases: ['Investigation Cases', 'Case management & chain of custody'],
    iocs: ['IOC Watchlist', 'Indicators of compromise — auto-matched live'],
    evidence: ['Evidence & Integrity', 'Tamper-evident logs, backups & triage'],
    timeline: ['Entity Timeline', 'Pivot on an IP, host or user'],
  };
  const loaders = {};
  let currentView = 'overview';

  function go(view) {
    currentView = view;
    $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view));
    $$('.view').forEach(v => v.classList.toggle('active', v.id === `view-${view}`));
    const [t, s] = TITLES[view] || [view, ''];
    $('#pageTitle').firstChild.textContent = t;
    $('#pageSub').textContent = s;
    if (view !== 'network' && typeof stopThroughput === 'function') stopThroughput();
    if (loaders[view]) loaders[view]();
    $('#sidebar').classList.remove('open');
  }
  $$('.nav-item').forEach(n => n.addEventListener('click', () => go(n.dataset.view)));
  document.addEventListener('click', e => { const g = e.target.closest('[data-goto]'); if (g) go(g.dataset.goto); });

  // ---- live WebSocket feed ----------------------------------------------
  let feedCount = 0, feedTimestamps = [];
  function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onopen = () => { $('#wsLed').className = 'led live'; $('#wsText').textContent = 'live'; };
    ws.onclose = () => { $('#wsLed').className = 'led off'; $('#wsText').textContent = 'reconnecting'; setTimeout(connectWS, 3000); };
    ws.onmessage = (m) => {
      const { type, data } = JSON.parse(m.data);
      if (type === 'event') onLiveEvent(data);
      else if (type === 'event_update') onEventUpdate(data);
      else if (type === 'alert') onLiveAlert(data);
      else if (type === 'block') toast('IPS · Indicator blocked', `${data.kind}: ${data.indicator}`, 'warn');
      if (type === 'event') onLiveLog(data);
    };
  }
  function onLiveEvent(ev) {
    feedTimestamps.push(Date.now());
    feedTimestamps = feedTimestamps.filter(t => Date.now() - t < 60000);
    $('#feedRate').textContent = `${feedTimestamps.length} evt/min`;
    const feed = $('#liveFeed'); if (!feed) return;
    const row = document.createElement('div');
    row.className = 'feed-row flash clickable';
    row.dataset.eid = ev.id;
    row.innerHTML = `<span class="t">${fmtTime(ev.ts)}</span>${sevChip(ev.severity)}
      <span class="msg"><b>${esc(ev.host || ev.source)}</b> · ${esc(ev.message)}${xn(ev.count)}</span>`;
    feed.prepend(row);
    setTimeout(() => row.classList.remove('flash'), 800);
    while (feed.children.length > 60) feed.lastChild.remove();
    if (currentView === 'events') loaders.events();
    bumpNav('events');
  }
  function onEventUpdate(d) {
    // a repeated (coalesced) event — bump the existing row's ×count instead of adding one
    feedTimestamps.push(Date.now());
    feedTimestamps = feedTimestamps.filter(t => Date.now() - t < 60000);
    $('#feedRate').textContent = `${feedTimestamps.length} evt/min`;
    const feed = $('#liveFeed');
    if (feed) {
      const row = feed.querySelector(`.feed-row[data-eid="${d.id}"]`);
      if (row) {
        row.className = 'feed-row flash clickable';
        row.innerHTML = `<span class="t">${fmtTime(d.last_ts)}</span>${sevChip(d.severity)}
          <span class="msg"><b>${esc(d.host)}</b> · ${esc(d.message)}${xn(d.count)}</span>`;
        feed.prepend(row);
        setTimeout(() => row.classList.remove('flash'), 800);
      }
    }
    // keep the logs view's count live too, if that row is on screen
    const lr = $('#logStream') && $('#logStream').querySelector(`.logrow[data-eid="${d.id}"]`);
    if (lr) { const b = lr.querySelector('.xn'); if (b) b.textContent = `×${d.count}`; else lr.querySelector('.lm').insertAdjacentHTML('beforeend', xn(d.count)); }
  }
  function onLiveAlert(al) {
    toast(`Alert · ${al.title}`, `${al.entity || ''} · ${SEV[al.severity]}${al.response ? ' — ' + al.response : ''}`,
      al.severity >= 5 ? 'bad' : 'warn');
    bumpNav('alerts');
    if (currentView === 'alerts') loaders.alerts();
    if (currentView === 'overview') loaders.overview();
  }
  const navCounts = { events: 0, alerts: 0, logs: 0 };
  function bumpNav(k) { navCounts[k]++; const e = $(`#nav-${k}`); if (e) e.textContent = navCounts[k]; }

  // ---- OVERVIEW ----------------------------------------------------------
  loaders.overview = async () => {
    const needFeed = $('#liveFeed').children.length === 0;
    const [o, alertsR, devR, evsR] = await Promise.all([
      api('/api/overview'),
      api('/api/alerts?limit=6'),
      api('/api/devices'),
      needFeed ? api('/api/events?limit=25') : Promise.resolve(null),
    ]);
    const c = o.counts;
    navCounts.events = c.events_24h; navCounts.alerts = c.open_alerts;
    $('#nav-events').textContent = c.events_24h;
    $('#nav-alerts').textContent = c.open_alerts; $('#nav-alerts').classList.toggle('hot', c.open_alerts > 0);
    $('#nav-agents').textContent = c.agents;
    $('#nav-blocked').textContent = c.blocked;
    $('#nav-cases').textContent = c.open_cases ?? 0;
    $('#nav-iocs').textContent = c.iocs ?? 0;

    const tiles = [
      ['Events · 24h', c.events_24h, 'accent', 'i-pulse', 'ingested & normalised'],
      ['Open Alerts', c.open_alerts, c.critical_alerts ? 'red' : 'gold', 'i-alert', `${c.critical_alerts} critical`],
      ['Monitored Assets', c.devices, 'accent', 'i-net', `${c.devices_down} offline`],
      ['Malware Blocked', c.malicious_files + c.blocked, 'rose', 'i-shield', `${c.blocked} indicators, ${c.malicious_files} files`],
    ];
    $('#statTiles').innerHTML = tiles.map(([k, v, cls, ic, sub]) => `
      <div class="card stat ${cls}">
        <div class="k"><svg style="width:15px;height:15px"><use href="#${ic}"/></svg>${k}</div>
        <div class="v">${v}</div><div class="sub">${sub}</div>
      </div>`).join('');

    const total = Object.values(o.severity).reduce((a, b) => a + (+b), 0) || 1;
    const cols = { 1: 'var(--sev-1)', 2: 'var(--sev-2)', 3: 'var(--sev-3)', 4: 'var(--sev-4)', 5: 'var(--sev-5)' };
    $('#sevBars').innerHTML = [5, 4, 3, 2, 1].map(s => {
      const n = +o.severity[s] || 0;
      return `<div class="sevbar"><span class="label">${SEV[s]}</span>
        <div class="track"><div class="fill" style="width:${(n / total * 100).toFixed(1)}%;background:${cols[s]}"></div></div>
        <span class="n">${n}</span></div>`;
    }).join('');

    renderDonut(o.categories);

    const alerts = alertsR.alerts;
    $('#recentAlerts').innerHTML = alerts.length ? alerts.map(a => `
      <tr><td>${sevChip(a.severity)}</td>
      <td><b>${esc(a.title)}</b><div class="muted" style="font-size:11px">${esc(a.entity || '')}</div></td>
      <td class="mono muted" style="font-size:11px">${ago(a.ts)} ago</td></tr>`).join('')
      : `<tr><td colspan="3" class="empty" style="padding:20px">No alerts — all clear.</td></tr>`;

    const dev = devR;
    const up = dev.devices.filter(d => d.status === 'up').length;
    $('#assetHealth').innerHTML = `
      <div class="row-between" style="margin-bottom:12px">
        <div><div class="mono" style="font-size:26px;font-weight:700">${up}<span class="muted" style="font-size:16px">/${dev.devices.length}</span></div>
          <div class="muted" style="font-size:11px">assets online · ${esc(dev.subnet)}</div></div>
        <div class="score-ring" style="--p:${dev.devices.length ? up / dev.devices.length * 100 : 0};--ring-color:var(--green)">
          <span class="n">${dev.devices.length ? Math.round(up / dev.devices.length * 100) : 0}<small style="font-size:12px">%</small></span></div>
      </div>
      ${dev.devices.slice(0, 5).map(d => `<div class="feed-row" style="grid-template-columns:auto 1fr auto">
        <span class="led ${d.status === 'up' ? 'live' : 'off'}"></span>
        <span class="msg"><b>${esc(d.hostname || d.ip)}</b> <span class="muted mono">${esc(d.ip)}</span></span>
        <span class="pill">${d.status}</span></div>`).join('') || '<div class="empty">No devices yet — run discovery.</div>'}`;

    // seed live feed on first load
    if (needFeed && evsR) {
      $('#liveFeed').innerHTML = evsR.events.map(ev => `<div class="feed-row clickable" data-eid="${ev.id}"><span class="t">${fmtTime(ev.ts)}</span>${sevChip(ev.severity)}
        <span class="msg"><b>${esc(ev.host || ev.source)}</b> · ${esc(ev.message)}${xn(ev.count)}</span></div>`).join('');
    }

    renderIntegrations(o.integrations);
  };

  function renderDonut(cats) {
    const palette = ['#3ad6c0', '#7d9bff', '#f6c453', '#f59e42', '#fb6f92', '#4fc3f7'];
    const total = cats.reduce((a, c) => a + c.c, 0) || 1;
    let off = 0; const R = 46, C = 2 * Math.PI * R;
    const segs = cats.map((c, i) => {
      const frac = c.c / total, len = frac * C;
      const seg = `<circle r="${R}" cx="60" cy="60" fill="none" stroke="${palette[i % palette.length]}"
        stroke-width="14" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}"
        transform="rotate(-90 60 60)"/>`;
      off += len; return seg;
    }).join('');
    $('#catDonut').innerHTML = `<svg width="120" height="120" viewBox="0 0 120 120">
      <circle r="46" cx="60" cy="60" fill="none" stroke="var(--line)" stroke-width="14"/>${segs}
      <text x="60" y="56" text-anchor="middle" fill="#e7eef6" font-size="22" font-family="var(--mono)" font-weight="700">${total}</text>
      <text x="60" y="72" text-anchor="middle" fill="#6a7a8d" font-size="9" letter-spacing="1">EVENTS</text></svg>`;
    $('#catLegend').innerHTML = cats.map((c, i) => `<div class="li"><span class="dot" style="background:${palette[i % palette.length]}"></span>
      ${esc(c.category)} <span class="mono muted" style="margin-left:auto">${c.c}</span></div>`).join('');
  }

  function renderIntegrations(intg) {
    $('#sb-integrations').innerHTML = `
      <span class="tag ${intg.virustotal ? 'ok' : ''}" style="font-size:10px">VT ${intg.virustotal ? 'on' : 'off'}</span>
      <span class="tag ${intg.nmap ? 'ok' : 'info'}" style="font-size:10px">nmap ${intg.nmap ? 'on' : 'py'}</span>`;
    $('#vtStatus').className = `tag ${intg.virustotal ? 'ok' : 'warn'}`;
    $('#vtStatus').textContent = intg.virustotal ? 'VirusTotal · connected' : 'VirusTotal · offline (set API key)';
  }

  // ---- EVENTS ------------------------------------------------------------
  loaders.events = async () => {
    const sev = $('#evtSev').value, q = $('#evtSearch').value.trim();
    const { events } = await api(`/api/events?limit=200&severity=${sev}&q=${encodeURIComponent(q)}`);
    $('#eventsTable').innerHTML = events.map(e => `
      <tr class="clickable" data-eid="${e.id}"><td class="mono" style="font-size:11px;white-space:nowrap">${fmtTime(e.ts)}</td>
      <td>${sevChip(e.severity)}</td>
      <td><span class="pill">${esc(e.source)}</span></td>
      <td class="dim">${esc(e.category)}</td>
      <td>${esc(e.message)}${xn(e.count)}</td>
      <td class="mono dim" style="font-size:11px">${esc(e.host || '—')}</td>
      <td class="mono dim" style="font-size:11px">${esc(e.src_ip || '—')}</td></tr>`).join('')
      || `<tr><td colspan="7" class="empty">No matching events.</td></tr>`;
  };
  $('#evtRefresh').onclick = () => loaders.events();
  $('#evtSev').onchange = () => loaders.events();
  let evtT; $('#evtSearch').oninput = () => { clearTimeout(evtT); evtT = setTimeout(loaders.events, 250); };
  $('#injectBtn').onclick = async () => {
    const samples = [
      { category: 'authentication', severity: 4, message: 'Failed login for administrator from 45.146.164.12', src_ip: '45.146.164.12', user: 'administrator', host: 'WIN-DC01' },
      { category: 'process', severity: 4, message: 'powershell.exe -enc SQBFAFgAKA... executed', host: 'WIN-WKS07', user: 'j.doe' },
      { category: 'network', severity: 3, message: 'connection to port 4444 from 10.0.0.24', src_ip: '10.0.0.24', host: 'FW-EDGE01' },
      { category: 'malware', severity: 5, message: 'malicious file detected: payload.scr (Embedded_PE)', host: 'WIN-WKS07' },
    ];
    const s = samples[Math.floor(Math.random() * samples.length)];
    await post('/api/events', { source: 'manual', ...s });
    toast('Event injected', s.message);
  };

  // ---- ALERTS ------------------------------------------------------------
  loaders.alerts = async () => {
    const f = $('#alertFilter').value;
    const { alerts } = await api(`/api/alerts?limit=200&status=${f}`);
    $('#alertsTable').innerHTML = alerts.map(a => `
      <tr><td class="mono" style="font-size:11px;white-space:nowrap">${fmtDate(a.ts)}</td>
      <td>${sevChip(a.severity)}</td>
      <td><b>${esc(a.title)}</b><div class="muted" style="font-size:11px">${esc(a.description || '')}</div></td>
      <td class="mono dim" style="font-size:11.5px">${esc(a.entity || '—')}</td>
      <td class="mitre">${esc(a.mitre || '')}</td>
      <td><span class="pill">${esc(a.rule_id || '')}</span></td>
      <td><span class="tag ${a.status === 'open' ? 'bad' : a.status === 'closed' ? 'ok' : 'warn'}">${a.status}</span></td>
      <td><select data-alert="${a.id}" class="btn btn-sm status-sel" style="font-size:11px">
        ${['open', 'investigating', 'closed'].map(s => `<option ${s === a.status ? 'selected' : ''}>${s}</option>`).join('')}
      </select></td></tr>`).join('')
      || `<tr><td colspan="8" class="empty">No alerts.</td></tr>`;
    $$('.status-sel').forEach(s => s.onchange = async () => {
      await post(`/api/alerts/${s.dataset.alert}/status`, { status: s.value });
      toast('Alert updated', `→ ${s.value}`); loaders.alerts();
      if (currentView !== 'alerts') return; loaders.overview?.();
    });
  };
  $('#alertFilter').onchange = () => loaders.alerts();
  $('#alertRefresh').onclick = () => loaders.alerts();

  // ---- ENDPOINT LOGS (Windows Event Log) --------------------------------
  const CAT = { authentication: 'c-authentication', malware: 'c-malware', 'defense-evasion': 'c-defense-evasion',
    process: 'c-process', 'account-mgmt': 'c-account-mgmt' };
  function codeBadge(ev) {
    const meta = ev.event_meta || ev.meta;
    if (ev.event_id == null) {
      return `<span class="pill">${esc(ev.provider || ev.source || 'log')}</span>`;
    }
    const name = meta?.name || `Event ${ev.event_id}`;
    const hint = meta?.hint || 'No description on file for this code.';
    const mitre = meta?.mitre ? `\n▸ ATT&CK ${meta.mitre}` : '';
    const tip = `${ev.event_id} · ${name}\n${hint}${mitre}`;
    const cls = CAT[meta?.category] || '';
    return `<span class="code ${cls}" data-tip="${esc(tip)}"><svg><use href="#i-info"/></svg>${ev.event_id}</span>`;
  }
  function logRow(ev) {
    const meta = ev.event_meta || ev.meta;
    const name = (meta && ev.event_id != null) ? meta.name : null;
    let detail = ev.message || '';
    if (name && detail.startsWith(name)) detail = detail.slice(name.length).replace(/^\s*[—-]\s*/, '');
    const headline = name
      ? `<b>${esc(name)}</b>${detail ? ' · ' + esc(detail) : ''}`
      : `<b>${esc(ev.message)}</b>`;
    return `<div class="logrow s${ev.severity} clickable" data-eid="${ev.id}">
      <span class="lt">${fmtTime(ev.last_ts || ev.ts)}</span>
      <span class="ld" title="${esc(ev.host || '')}">${esc(ev.host || '—')}</span>
      <span>${codeBadge(ev)}</span>
      <span class="lm" title="${esc(ev.message)}">${headline}${xn(ev.count)}</span>
      <span class="lsev">${sevChip(ev.severity)}</span></div>`;
  }
  function isLog(ev) { return ev.event_id != null || ['winlog', 'agent', 'auth'].includes(ev.source); }
  function onLiveLog(ev) {
    if (!isLog(ev)) return;
    navCounts.logs = (navCounts.logs || 0) + 1; $('#nav-logs').textContent = navCounts.logs;
    if (currentView !== 'logs') return;
    const host = $('#logHost').value, q = $('#logSearch').value.trim().toLowerCase();
    if (host && ev.host !== host) return;
    if (q && !(`${ev.message} ${ev.event_id}`.toLowerCase().includes(q))) return;
    const stream = $('#logStream'); stream.insertAdjacentHTML('afterbegin', logRow(ev));
    while (stream.children.length > 200) stream.lastChild.remove();
  }
  loaders.logs = async () => {
    const host = $('#logHost').value, q = $('#logSearch').value.trim();
    const r = await api(`/api/logs?limit=250&host=${encodeURIComponent(host)}`);
    navCounts.logs = r.logs.length; $('#nav-logs').textContent = r.logs.length;
    // host filter options
    const sel = $('#logHost'); const cur = sel.value;
    sel.innerHTML = '<option value="">All devices</option>' + r.hosts.map(h => `<option ${h === cur ? 'selected' : ''}>${esc(h)}</option>`).join('');
    sel.value = cur;
    const col = r.collector;
    $('#logCollector').textContent = col.available
      ? `${col.source || 'OS log'} · ${col.ingested} pulled` : 'OS log collector: unavailable';
    $('#logCollector').className = col.available ? 'tag ok' : 'tag warn';
    let logs = r.logs;
    if (q) logs = logs.filter(l => `${l.message} ${l.event_id} ${l.provider}`.toLowerCase().includes(q.toLowerCase()));
    $('#logStream').innerHTML = logs.map(logRow).join('') ||
      `<div class="empty"><svg><use href="#i-logs"/></svg><div>No endpoint logs yet. Click Pull to fetch from the OS log (Windows Event Viewer or Linux syslog/journald).</div></div>`;
  };
  $('#logHost').onchange = () => loaders.logs();
  let logT; $('#logSearch').oninput = () => { clearTimeout(logT); logT = setTimeout(loaders.logs, 250); };
  $('#logPull').onclick = async () => {
    $('#logPull').innerHTML = '<span class="spin"></span> Pulling';
    try { const res = await post('/api/logs/pull', {}); toast('Event Log pulled', res.available ? `${res.ingested} new event(s)` : res.message, res.available ? '' : 'warn'); loaders.logs(); }
    catch (e) { toast('Pull failed', e.message, 'bad'); }
    $('#logPull').innerHTML = '<svg style="width:14px;height:14px"><use href="#i-refresh"/></svg> Pull';
  };

  // ---- DETECTIONS --------------------------------------------------------
  loaders.detections = async () => {
    const { rules } = await api('/api/rules');
    $('#ruleCount').textContent = `${rules.length} rules`;
    $('#rulesTable').innerHTML = rules.map(r => `
      <tr><td class="mono dim">${esc(r.id)}</td>
      <td><b>${esc(r.name)}</b><div class="muted" style="font-size:11px">${esc(r.description || '')}</div>
        <div class="mono muted" style="font-size:10.5px;margin-top:2px">${esc(r.match_field)} ${esc(r.match_type)} "${esc(r.match_value || '')}"${r.match_type === 'threshold' ? ` ≥${r.threshold}/${r.window_sec}s` : ''}</div></td>
      <td class="dim">${esc(r.category)}</td>
      <td>${sevChip(r.severity)}</td>
      <td><span class="tag ${r.action === 'alert' ? 'info' : 'bad'}">${esc(r.action)}</span></td>
      <td class="mitre">${esc(r.mitre || '')}</td>
      <td><span class="toggle ${r.enabled ? 'on' : ''}" data-rule="${esc(r.id)}"></span></td></tr>`).join('');
    $$('[data-rule]').forEach(t => t.onclick = async () => {
      const on = !t.classList.contains('on');
      await api(`/api/rules/${t.dataset.rule}`, { method: 'PATCH', body: JSON.stringify({ enabled: on }) });
      t.classList.toggle('on', on);
    });
  };
  $('#rType').onchange = () => { $('#thresholdRow').style.display = $('#rType').value === 'threshold' ? 'flex' : 'none'; };
  $('#addRule').onclick = async () => {
    const body = {
      name: $('#rName').value || 'Custom rule', match_field: $('#rField').value, match_type: $('#rType').value,
      match_value: $('#rValue').value, severity: +$('#rSev').value, action: $('#rAction').value,
      threshold: +$('#rThreshold').value, window_sec: +$('#rWindow').value, category: 'custom',
    };
    if (!body.match_value) return toast('Rule needs a value', 'Enter a pattern to match', 'warn');
    await post('/api/rules', body);
    toast('Rule deployed', body.name); $('#rName').value = ''; $('#rValue').value = ''; loaders.detections();
  };

  // ---- SCANNER -----------------------------------------------------------
  const dz = $('#dropzone'), fi = $('#fileInput');
  dz.onclick = () => fi.click();
  ['dragover', 'dragenter'].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach(e => dz.addEventListener(e, () => dz.classList.remove('drag')));
  dz.addEventListener('drop', ev => { ev.preventDefault(); if (ev.dataTransfer.files[0]) scanFile(ev.dataTransfer.files[0]); });
  fi.onchange = () => { if (fi.files[0]) scanFile(fi.files[0]); };
  $('#vtToggle').onclick = () => $('#vtToggle').classList.toggle('on');
  $('#deepToggle').onclick = () => $('#deepToggle').classList.toggle('on');

  async function scanFile(file) {
    $('#scanResult').innerHTML = `<div class="empty"><span class="spin"></span> Scanning ${esc(file.name)}…</div>`;
    const fd = new FormData(); fd.append('file', file);
    fd.append('virustotal', $('#vtToggle').classList.contains('on') ? 'true' : 'false');
    try {
      const r = await fetch('/api/scan/file', { method: 'POST', body: fd });
      const rep = await r.json();
      renderScanReport(rep);
      loaders.scanner();
    } catch (e) { $('#scanResult').innerHTML = `<div class="tag bad">Scan failed: ${esc(e.message)}</div>`; }
  }

  function renderScanReport(rep) {
    const ringColor = rep.verdict === 'malicious' ? 'var(--red)' : rep.verdict === 'suspicious' ? 'var(--amber)' : 'var(--green)';
    const vt = rep.virustotal;
    $('#scanResult').innerHTML = `
      <div class="row-between" style="align-items:flex-start;gap:16px">
        <div class="score-ring" style="--p:${rep.score};--ring-color:${ringColor}"><span class="n">${rep.score}</span><span class="lbl">risk</span></div>
        <div style="flex:1">
          <div class="verdict ${rep.verdict}" style="font-size:16px">${rep.verdict}</div>
          <div class="dim" style="margin:6px 0 10px">${esc(rep.name)} · ${bytes(rep.size)} · entropy ${rep.entropy}/8</div>
          <div class="kv">
            <div class="k">SHA-256</div><div class="v">${esc(rep.sha256)}</div>
            <div class="k">MD5</div><div class="v">${esc(rep.md5)}</div>
          </div>
        </div>
      </div>
      ${vt ? `<hr class="hr"><div class="row-between"><b style="font-size:12px">VirusTotal</b>
        <span class="verdict ${vt.verdict}">${vt.verdict}${vt.total ? ` · ${vt.positives}/${vt.total}` : ''}</span></div>
        ${vt.threat_label ? `<div class="mono muted" style="font-size:11px;margin-top:4px">${esc(vt.threat_label)}</div>` : ''}
        ${vt.message ? `<div class="muted" style="font-size:11.5px;margin-top:4px">${esc(vt.message)}</div>` : ''}` : ''}
      <hr class="hr"><div style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-bottom:8px">
        Detections · ${rep.reasons.length}</div>
      ${rep.reasons.length ? rep.reasons.map(x => `<div class="reason"><span class="rt">${esc(x.type)}</span>
        <div><b>${esc(x.name)}</b><div class="muted" style="font-size:11.5px">${esc(x.detail)}</div></div></div>`).join('')
      : '<div class="tag ok">No signatures or heuristics triggered</div>'}`;
  }

  $('#scanFolder').onclick = async () => {
    $('#folderResult').innerHTML = `<div class="empty"><span class="spin"></span> Scanning directory…</div>`;
    try {
      const res = await post('/api/scan/folder', { path: $('#folderPath').value, deep: $('#deepToggle').classList.contains('on') });
      $('#folderResult').innerHTML = `
        <div class="chips" style="margin-bottom:10px">
          <span class="tag">${res.scanned} scanned</span>
          <span class="tag ok">${res.clean || 0} clean</span>
          <span class="tag warn">${res.suspicious || 0} suspicious</span>
          <span class="tag bad">${res.malicious || 0} malicious</span>
          <span class="pill">${res.duration || 0}s</span></div>
        ${(res.findings || []).map(f => `<div class="reason"><span class="rt">${f.verdict}</span>
          <div><b>${esc(f.name)}</b><div class="muted" style="font-size:11px">${esc((f.reasons || []).join(', '))} · score ${f.score}</div></div></div>`).join('')
        || (res.message ? `<div class="tag warn">${esc(res.message)}</div>` : '<div class="tag ok">Nothing malicious found</div>')}`;
      loaders.scanner();
    } catch (e) { $('#folderResult').innerHTML = `<div class="tag bad">${esc(e.message)}</div>`; }
  };

  loaders.scanner = async () => {
    const { scans } = await api('/api/scans?kind=file&limit=40');
    $('#scansTable').innerHTML = scans.map(s => `
      <tr><td class="mono" style="font-size:11px">${fmtTime(s.ts)}</td>
      <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(s.target)}">${esc(s.target.split(/[\\/]/).pop())}</td>
      <td><span class="verdict ${s.verdict}">${esc(s.verdict)}</span></td>
      <td class="dim" style="font-size:11px">${esc(s.engine)}</td>
      <td class="mono">${s.positives}</td></tr>`).join('')
      || `<tr><td colspan="5" class="empty">No scans yet.</td></tr>`;
  };

  // ---- THREAT INTEL ------------------------------------------------------
  $('#eicarHash').onclick = () => { $('#intelType').value = 'hash'; $('#intelValue').value = $('#eicarHash').textContent; $('#intelLookup').click(); };
  $('#intelLookup').onclick = async () => {
    const type = $('#intelType').value, val = $('#intelValue').value.trim();
    if (!val) return;
    $('#intelResult').innerHTML = `<div class="empty"><span class="spin"></span> Querying VirusTotal…</div>`;
    try {
      let res;
      if (type === 'url') res = await post('/api/intel/url', { url: val });
      else res = await api(`/api/intel/${type}/${encodeURIComponent(val)}`);
      renderIntel(res, type, val);
    } catch (e) { $('#intelResult').innerHTML = `<div class="tag bad">${esc(e.message)}</div>`; }
  };
  function renderIntel(res, type, val) {
    const ok = res.enabled !== false;
    const rc = res.verdict === 'malicious' ? 'var(--red)' : res.verdict === 'suspicious' ? 'var(--amber)' : res.verdict === 'clean' ? 'var(--green)' : 'var(--muted)';
    const pct = res.total ? Math.round(res.positives / res.total * 100) : 0;
    $('#intelResult').innerHTML = `
      <div class="card"><div class="card-b"><div class="row-between" style="align-items:flex-start">
        <div style="flex:1">
          <div class="muted" style="font-size:10.5px;letter-spacing:1px;text-transform:uppercase">${esc(type)}</div>
          <div class="mono" style="font-size:13px;word-break:break-all;margin:4px 0 10px">${esc(val)}</div>
          <span class="verdict ${res.verdict}" style="font-size:15px">${esc(res.verdict)}</span>
          ${res.total ? `<span class="dim" style="margin-left:8px">${res.positives}/${res.total} engines flagged</span>` : ''}
          ${res.threat_label ? `<div class="mono" style="color:var(--amber);font-size:12px;margin-top:6px">${esc(res.threat_label)}</div>` : ''}
          ${res.message ? `<div class="muted" style="font-size:12px;margin-top:8px">${esc(res.message)}</div>` : ''}
          ${res.names && res.names.length ? `<div class="chips" style="margin-top:10px">${res.names.map(n => `<span class="pill">${esc(n)}</span>`).join('')}</div>` : ''}
        </div>
        ${res.total ? `<div class="score-ring" style="--p:${pct};--ring-color:${rc}"><span class="n">${res.positives}</span><span class="lbl">/${res.total}</span></div>` : ''}
      </div>
      ${val && (type === 'ip' || type === 'hash') ? `<hr class="hr"><button class="btn btn-danger btn-sm" id="blockFromIntel">Add to blocklist</button>` : ''}
      </div></div>`;
    const b = $('#blockFromIntel');
    if (b) b.onclick = async () => { await post('/api/blocklist', { indicator: val, kind: type === 'ip' ? 'ip' : 'hash', reason: `Flagged by intel (${res.verdict})` }); toast('Blocked', val, 'warn'); };
  }

  // ---- NETWORK -----------------------------------------------------------
  loaders.network = async () => {
    loadInterfaces(); loadQuality(); loadConnections(); startThroughput();
    const d = await api('/api/devices');
    $('#subnetPill').textContent = `${d.subnet} · self ${d.local_ip}`;
    $('#deviceGrid').innerHTML = d.devices.map(dev => `
      <div class="dev ${dev.status}">
        <div class="row-between"><span class="ip">${esc(dev.hostname || dev.ip)}</span><span class="pill">${dev.status}</span></div>
        <div class="meta mono">${esc(dev.ip)}${dev.mac ? ' · ' + esc(dev.mac) : ''}</div>
        <div class="meta">${esc(dev.vendor || dev.os_guess || 'unknown device')} · seen ${ago(dev.last_seen)} ago</div>
        ${(dev.open_ports || []).length ? `<div class="chips" style="margin-top:7px">${dev.open_ports.slice(0, 8).map(p => `<span class="pill">${p.port}/${esc(p.service || '')}</span>`).join('')}</div>` : ''}
        <div style="margin-top:8px"><button class="btn btn-sm scan-dev" data-ip="${esc(dev.ip)}">Port scan</button></div>
      </div>`).join('') || `<div class="empty span-2"><svg><use href="#i-net"/></svg><div>No devices yet — run discovery to map the subnet.</div></div>`;
    $$('.scan-dev').forEach(b => b.onclick = () => { $('#scanTarget').value = b.dataset.ip; $('#portScanBtn').click(); go('network'); });
  };

  // -- network telemetry: interfaces / infrastructure --
  const rate = (bps) => { if (bps < 1024) return `${bps | 0} B/s`; if (bps < 1048576) return `${(bps / 1024).toFixed(1)} KB/s`; return `${(bps / 1048576).toFixed(2)} MB/s`; };
  const num = (n) => (n ?? 0).toLocaleString('en-US');
  const IF_ICON = { 'Wi-Fi': 'i-wifi', Ethernet: 'i-plug', Loopback: 'i-refresh', Virtual: 'i-cpu', Bluetooth: 'i-link', Cellular: 'i-globe' };
  async function loadInterfaces() {
    const d = await api('/api/net/interfaces');
    $('#ifHost').textContent = `${esc(d.hostname)} · gw ${esc(d.gateway || '—')}`;
    $('#ifaceGrid').innerHTML = d.interfaces.map(i => `
      <div class="iface ${i.up ? 'up' : 'down'}">
        <div class="iface-h">
          <span class="ic"><svg><use href="#${IF_ICON[i.type] || 'i-net'}"/></svg></span>
          <div><div class="nm">${esc(i.name)}</div><div class="ty">${esc(i.type)}${i.speed_mbps ? ' · ' + i.speed_mbps + ' Mbps' : ''}</div></div>
          <span class="st"><span class="tag ${i.up ? 'ok' : 'bad'}"><span class="led ${i.up ? 'live' : 'off'}"></span>${i.up ? 'up' : 'down'}</span></span>
        </div>
        ${i.description ? `<div class="desc" title="${esc(i.description)}">${esc(i.description)}</div>` : ''}
        <div class="kv">
          ${i.ipv4 ? `<div class="k">IPv4</div><div class="v">${esc(i.ipv4)}</div>` : ''}
          ${i.mac ? `<div class="k">MAC</div><div class="v">${esc(i.mac)}</div>` : ''}
          ${i.gateway ? `<div class="k">Gateway</div><div class="v">${esc(i.gateway)}</div>` : ''}
          ${i.dns && i.dns.length ? `<div class="k">DNS</div><div class="v">${esc(i.dns.join(', '))}</div>` : ''}
          <div class="k">Traffic</div><div class="v">▲ ${bytes(i.bytes_sent)} · ▼ ${bytes(i.bytes_recv)}</div>
        </div>
      </div>`).join('');
  }
  async function loadQuality() {
    const q = await api('/api/net/quality');
    const g = q.internet, gw = q.gateway;
    $('#linkQuality').innerHTML = `
      <div class="row-between" style="align-items:center;margin-bottom:12px">
        <span class="linkgrade ${q.grade}">${q.grade}</span>
        <span class="led ${q.grade === 'offline' ? 'off' : 'live'}"></span>
      </div>
      <div class="kv" style="grid-template-columns:auto 1fr;gap:7px 12px">
        <div class="k">Internet</div><div class="v">${g.reachable ? g.avg_ms + ' ms · ' + g.loss_pct + '% loss' : 'unreachable'}</div>
        <div class="k">Gateway</div><div class="v">${esc(q.gateway_ip || '—')} ${gw.reachable ? '· ' + gw.avg_ms + ' ms' : '· down'}</div>
      </div>`;
  }
  let connEst = false;
  $('#connEstOnly').onclick = () => { connEst = !connEst; $('#connEstOnly').classList.toggle('on', connEst); loadConnections(); };
  $('#connRefresh').onclick = () => loadConnections();
  async function loadConnections() {
    const d = await api('/api/net/connections?limit=250');
    $('#sockSummary').innerHTML = `
      <div class="row-between"><div><div class="big-num" style="color:var(--green)">${d.established}</div><div class="muted" style="font-size:11px">established</div></div>
        <div style="text-align:right"><div class="big-num" style="color:var(--cyan)">${d.listening}</div><div class="muted" style="font-size:11px">listening</div></div></div>
      <hr class="hr"><div class="row-between"><span class="muted" style="font-size:12px">Total sockets</span><span class="mono">${d.total}</span></div>`;
    let rows = d.connections;
    if (connEst) rows = rows.filter(c => c.status === 'ESTABLISHED');
    $('#connTable').innerHTML = rows.slice(0, 120).map(c => `
      <tr><td class="mono dim" style="font-size:11px">${esc(c.proto)}</td>
      <td class="mono" style="font-size:11px">${esc(c.laddr || '—')}</td>
      <td class="mono" style="font-size:11px">${esc(c.raddr || '—')}</td>
      <td><span class="conn-state ${esc(c.status)}">${esc(c.status)}</span></td>
      <td>${esc(c.process || '—')}</td>
      <td class="mono dim">${c.pid || ''}</td>
      <td>${c.remote_ip && !c.remote_ip.startsWith('127.') && c.remote_ip !== '0.0.0.0' ? `<button class="btn btn-sm intel-ip" data-ip="${esc(c.remote_ip)}" title="Check reputation">intel</button>` : ''}</td></tr>`).join('')
      || `<tr><td colspan="7" class="empty">No connections.</td></tr>`;
    $$('.intel-ip').forEach(b => b.onclick = () => { go('intel'); $('#intelType').value = 'ip'; $('#intelValue').value = b.dataset.ip; $('#intelLookup').click(); });
  }

  // -- live throughput sparkline --
  let tpTimer = null, tpData = [];
  function stopThroughput() { if (tpTimer) { clearInterval(tpTimer); tpTimer = null; } }
  function startThroughput() { stopThroughput(); fetchThroughput(); tpTimer = setInterval(fetchThroughput, 2000); }
  async function fetchThroughput() {
    if (currentView !== 'network') { stopThroughput(); return; }
    try {
      const t = await api('/api/net/throughput');
      $('#tpDown').innerHTML = rate(t.down_bps); $('#tpUp').innerHTML = rate(t.up_bps);
      $('#tpPktsRx').textContent = `rx ${num(t.packets_recv)} pkts`;
      $('#tpPktsTx').textContent = `tx ${num(t.packets_sent)} pkts`;
      $('#tpErr').textContent = `${t.errin + t.errout} err · ${t.dropin + t.dropout} drop`;
      tpData.push({ up: t.up_bps, down: t.down_bps }); if (tpData.length > 40) tpData.shift();
      renderSpark();
    } catch (_) { stopThroughput(); }
  }
  function renderSpark() {
    const W = 300, H = 60, n = tpData.length; if (!n) return;
    const max = Math.max(1, ...tpData.map(d => Math.max(d.up, d.down)));
    const path = (key, i0) => tpData.map((d, i) => `${i === 0 ? 'M' : 'L'} ${(i / Math.max(n - 1, 1)) * W} ${H - (d[key] / max) * (H - 6) - 3}`).join(' ');
    const area = (key, color) => `<path d="${path(key)} L ${W} ${H} L 0 ${H} Z" fill="${color}" opacity=".12"/><path d="${path(key)}" fill="none" stroke="${color}" stroke-width="1.8"/>`;
    $('#tpSpark').innerHTML = area('down', '#3ad6c0') + area('up', '#7d9bff');
  }
  $('#discoverBtn').onclick = async () => {
    $('#discoverBtn').innerHTML = '<span class="spin"></span> Scanning';
    try { const r = await post('/api/network/discover', {}); toast('Discovery complete', `${r.count} hosts (${r.new} new) on ${r.subnet}`); loaders.network(); }
    catch (e) { toast('Discovery failed', e.message, 'bad'); }
    $('#discoverBtn').innerHTML = '<svg style="width:14px;height:14px"><use href="#i-radar"/></svg> Discover';
  };
  $('#monitorBtn').onclick = async () => { const r = await post('/api/network/monitor', {}); toast('Ping sweep', `${r.checked} checked, ${r.changed} changed`); loaders.network(); };
  $('#portScanBtn').onclick = async () => {
    const target = $('#scanTarget').value.trim();
    $('#scanOut').innerHTML = `<div class="empty"><span class="spin"></span> Scanning ${esc(target || 'local host')}…</div>`;
    try {
      const r = await post('/api/network/scan', { target, arguments: $('#scanArgs').value.trim() || null });
      $('#scanEngine').textContent = r.engine;
      $('#scanOut').innerHTML = `
        <div class="card"><div class="card-b">
          <div class="row-between" style="margin-bottom:10px"><b>${esc(r.target)}</b>
            <span class="chips"><span class="tag">${r.open_count} open</span>${r.risky.length ? `<span class="tag bad">${r.risky.length} risky</span>` : '<span class="tag ok">no risky ports</span>'}<span class="pill">${esc(r.engine)}</span></span></div>
          <div class="table-wrap short"><table class="table"><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Note</th></tr></thead>
          <tbody>${(r.ports || []).map(p => { const risk = (r.risky || []).find(x => x.port === p.port);
            return `<tr><td class="mono">${p.port}</td><td class="dim">${esc(p.proto)}</td><td><span class="tag ok">${esc(p.state)}</span></td>
            <td class="mono">${esc(p.service || '')}</td><td>${risk ? `<span class="tag bad">${esc(risk.why)}</span>` : ''}</td></tr>`; }).join('')
          || '<tr><td colspan="5" class="empty">No open ports found.</td></tr>'}</tbody></table></div>
        </div></div>`;
      loaders.network();
    } catch (e) { $('#scanOut').innerHTML = `<div class="tag bad">${esc(e.message)}</div>`; }
  };

  // ---- AGENTS ------------------------------------------------------------
  loaders.agents = async () => {
    const { agents } = await api('/api/agents');
    $('#agentEmpty').style.display = agents.length ? 'none' : 'block';
    $('#nav-agents').textContent = agents.filter(a => a.status === 'active').length;
    $('#agentGrid').innerHTML = agents.map(a => {
      const m = a.metrics || {};
      const bar = (label, v) => `<div class="metric"><div class="ml"><span>${label}</span><span class="mono">${v ?? 0}%</span></div>
        <div class="mt"><div class="mf ${v >= 85 ? 'hot' : ''}" style="width:${Math.min(v || 0, 100)}%"></div></div></div>`;
      return `<div class="card"><div class="card-b">
        <div class="row-between" style="margin-bottom:12px">
          <div><div style="font-weight:600;font-size:14px">${esc(a.hostname)}</div>
            <div class="mono muted" style="font-size:11px">${esc(a.ip || '')} · ${esc(a.os_info || '')}</div></div>
          <span class="tag ${a.status === 'active' ? 'ok' : 'bad'}"><span class="led ${a.status === 'active' ? 'live' : 'off'}"></span> ${a.status}</span>
        </div>
        ${bar('CPU', m.cpu_percent)}${bar('Memory', m.mem_percent)}${bar('Disk', m.disk_percent)}
        <div class="chips" style="margin-top:10px">
          <span class="pill">${m.process_count ?? '—'} procs</span>
          <span class="pill">${m.connection_count ?? '—'} conns</span>
          <span class="pill">up ${m.uptime_sec ? (m.uptime_sec / 3600 | 0) + 'h' : '—'}</span>
          <span class="pill">seen ${ago(a.last_seen)} ago</span>
        </div>
        ${(m.top_processes || []).length ? `<div class="mono muted" style="font-size:10.5px;margin-top:8px">top: ${m.top_processes.map(p => esc(p.name)).join(', ')}</div>` : ''}
      </div></div>`;
    }).join('');
  };
  $('#agentRefresh').onclick = () => loaders.agents();

  // ---- RESPONSE ----------------------------------------------------------
  loaders.response = async () => {
    const { blocklist } = await api('/api/blocklist');
    $('#nav-blocked').textContent = blocklist.filter(b => b.active).length;
    $('#blockTable').innerHTML = blocklist.map(b => `
      <tr><td class="mono" style="font-size:11px">${fmtDate(b.ts)}</td>
      <td class="mono">${esc(b.indicator)}</td>
      <td><span class="pill">${esc(b.kind)}</span></td>
      <td class="dim">${esc(b.reason || '')}</td>
      <td><span class="tag ${b.source === 'ids' ? 'bad' : ''}">${esc(b.source)}</span></td>
      <td>${b.active ? '<span class="tag bad">active</span>' : '<span class="tag ok">lifted</span>'}</td>
      <td>${b.active ? `<button class="btn btn-sm unblock" data-id="${b.id}">Unblock</button>` : ''}</td></tr>`).join('')
      || `<tr><td colspan="7" class="empty">No blocked indicators.</td></tr>`;
    $$('.unblock').forEach(x => x.onclick = async () => { await api(`/api/blocklist/${x.dataset.id}`, { method: 'DELETE' }); toast('Unblocked'); loaders.response(); });
  };
  $('#addBlock').onclick = async () => {
    const ind = $('#blockInd').value.trim(); if (!ind) return;
    await post('/api/blocklist', { indicator: ind, kind: $('#blockKind').value });
    toast('Indicator blocked', ind, 'warn'); $('#blockInd').value = ''; loaders.response();
  };

  // ---- CASES ------------------------------------------------------------
  let selectedCase = null;
  loaders.cases = async () => {
    const { cases } = await api('/api/cases');
    $('#nav-cases').textContent = cases.filter(c => c.status !== 'closed').length;
    $('#casesTable').innerHTML = cases.map(c => `
      <tr data-case="${c.id}" style="cursor:pointer">
        <td class="mono dim">${esc(c.ref)}</td>
        <td><b>${esc(c.title)}</b></td>
        <td>${sevChip(c.severity)}</td>
        <td><span class="tag ${c.status === 'closed' ? 'ok' : c.status === 'active' ? 'bad' : 'warn'}">${esc(c.status)}</span></td>
        <td class="dim">${esc(c.assignee || '—')}</td>
        <td class="mono">${c.item_count}</td>
        <td class="mono muted" style="font-size:11px">${ago(c.updated)} ago</td></tr>`).join('')
      || emptyRow(7, 'No cases yet — open one from an alert or click New case.');
    $$('[data-case]').forEach(r => r.onclick = () => openCase(r.dataset.case));
    if (selectedCase && cases.some(c => String(c.id) === String(selectedCase))) openCase(selectedCase);
  };
  async function openCase(id) {
    selectedCase = id;
    const c = await api(`/api/cases/${id}`);
    $('#caseDetailTitle').textContent = `${c.ref} · ${c.title}`;
    $('#caseDetailTools').innerHTML =
      `<select id="caseStatus" class="btn btn-sm" style="font-family:var(--mono)">${['open', 'active', 'contained', 'closed'].map(s => `<option ${s === c.status ? 'selected' : ''}>${s}</option>`).join('')}</select>
       <button class="btn btn-sm" id="caseExport">Export bundle</button>`;
    $('#caseDetail').innerHTML = `
      <div class="dim" style="font-size:12px;margin-bottom:12px">${esc(c.summary || '')}</div>
      <div style="font-size:10.5px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:8px">Chain of custody · ${c.items.length} item(s)</div>
      ${c.items.map(it => `<div class="case-item">
        <div class="cih"><span class="tk ${esc(it.kind)}">${esc(it.kind)}</span>
          <span class="mono muted" style="font-size:10.5px;margin-left:auto">${ago(it.added_ts)} ago · ${esc(it.added_by)}</span></div>
        <div style="font-size:12.5px">${esc(it.title || it.note || '')}</div>
        ${it.note && it.title ? `<div class="muted" style="font-size:11.5px;margin-top:2px">${esc(it.note)}</div>` : ''}
      </div>`).join('') || '<div class="empty" style="padding:16px">No evidence attached yet.</div>'}
      <hr class="hr">
      <div class="field"><label>Add investigator note</label><input id="caseNote" placeholder="observation / action taken…"></div>
      <button class="btn btn-sm btn-block" id="addNoteBtn">Add note</button>`;
    $('#caseStatus').onchange = async (e) => { await api(`/api/cases/${id}`, { method: 'PATCH', body: JSON.stringify({ status: e.target.value }) }); toast('Case status updated', e.target.value); loaders.cases(); };
    $('#caseExport').onclick = async () => { const r = await post(`/api/cases/${id}/export`, {}); toast('Evidence bundle exported', r.artifact ? r.artifact.name : '', ''); };
    $('#addNoteBtn').onclick = async () => { const n = $('#caseNote').value.trim(); if (!n) return; await post(`/api/cases/${id}/items`, { kind: 'note', note: n, title: 'Investigator note' }); toast('Note added'); openCase(id); };
  }
  $('#newCaseBtn').onclick = async () => {
    const t = window.prompt('New case title:', 'Investigation ' + new Date().toLocaleString());
    if (!t) return;
    await post('/api/cases', { title: t, severity: 3, assignee: $('#userName').textContent });
    toast('Case created'); loaders.cases();
  };

  // ---- IOC WATCHLIST ----------------------------------------------------
  loaders.iocs = async () => {
    const { iocs } = await api('/api/iocs');
    const active = iocs.filter(i => i.active).length;
    $('#iocCount').textContent = `${active} active`;
    $('#nav-iocs').textContent = active;
    $('#iocsTable').innerHTML = iocs.map(i => `
      <tr><td><span class="pill">${esc(i.kind)}</span></td>
      <td class="mono">${esc(i.value)}</td>
      <td>${sevChip(i.severity)}</td>
      <td class="dim">${esc(i.source || '')}</td>
      <td class="mono ${i.hits ? '' : 'muted'}" style="${i.hits ? 'color:var(--rose);font-weight:700' : ''}">${i.hits}</td>
      <td class="mono muted" style="font-size:11px">${i.last_hit ? ago(i.last_hit) + ' ago' : '—'}</td>
      <td><span class="toggle ${i.active ? 'on' : ''}" data-ioc="${i.id}"></span></td>
      <td><button class="btn btn-sm del-ioc" data-id="${i.id}" title="delete">✕</button></td></tr>`).join('')
      || emptyRow(8, 'No indicators on the watchlist.');
    $$('[data-ioc]').forEach(t => t.onclick = async () => { const on = !t.classList.contains('on'); await api(`/api/iocs/${t.dataset.ioc}`, { method: 'PATCH', body: JSON.stringify({ active: on }) }); t.classList.toggle('on', on); });
    $$('.del-ioc').forEach(b => b.onclick = async () => { await api(`/api/iocs/${b.dataset.id}`, { method: 'DELETE' }); loaders.iocs(); });
  };
  $('#addIocBtn').onclick = async () => {
    const v = $('#iocValue').value.trim(); if (!v) return;
    await post('/api/iocs', { kind: $('#iocKind').value, value: v, severity: +$('#iocSev').value, source: $('#iocSource').value });
    toast('Indicator added', v); $('#iocValue').value = ''; loaders.iocs();
  };
  $('#importIocBtn').onclick = async () => {
    const t = $('#iocImport').value.trim(); if (!t) return;
    const r = await post('/api/iocs/import', { text: t }); toast('Indicators imported', `${r.added} added`); $('#iocImport').value = ''; loaders.iocs();
  };

  // ---- EVIDENCE + INTEGRITY ---------------------------------------------
  loaders.evidence = async () => {
    verifyIntegrity();
    const a = await api('/api/forensics/artifacts');
    $('#evidenceDir').textContent = a.evidence_dir;
    $('#artifactsTable').innerHTML = a.artifacts.map(x => `
      <tr><td class="mono" style="font-size:11px;white-space:nowrap">${fmtDate(x.created)}</td>
      <td><span class="tag ${x.kind === 'triage' ? 'bad' : x.kind === 'case-bundle' ? 'info' : x.kind === 'export' ? 'warn' : ''}">${esc(x.kind)}</span></td>
      <td class="mono" style="font-size:11px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(x.name)}">${esc(x.name)}</td>
      <td class="mono">${x.records ?? '—'}</td>
      <td class="mono dim">${bytes(x.size)}</td>
      <td class="hashcell" data-tip="SHA-256\n${esc(x.sha256 || '')}">${(x.sha256 || '').slice(0, 14)}…</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm vrf" data-id="${x.id}">verify</button>
        <button class="btn btn-sm dl" data-id="${x.id}" title="download"><svg style="width:12px;height:12px"><use href="#i-download"/></svg></button>
        <button class="btn btn-sm del-art" data-id="${x.id}" title="delete">✕</button></td></tr>`).join('')
      || emptyRow(7, 'No evidence files yet. Use Backup / Export / Triage above.');
    $$('.vrf').forEach(b => b.onclick = async () => { const r = await api(`/api/forensics/artifacts/${b.dataset.id}/verify`); toast(r.ok ? 'Integrity verified ✓' : 'INTEGRITY FAILED', r.ok ? 'SHA-256 matches the recorded hash' : 'File hash does not match — tampered!', r.ok ? '' : 'bad'); });
    $$('.dl').forEach(b => b.onclick = () => window.open(`/api/forensics/artifacts/${b.dataset.id}/download`, '_blank'));
    $$('.del-art').forEach(b => b.onclick = async () => { await api(`/api/forensics/artifacts/${b.dataset.id}`, { method: 'DELETE' }); loaders.evidence(); });
  };
  async function verifyIntegrity() {
    $('#integrityBanner').innerHTML = `<div class="empty" style="padding:18px"><span class="spin"></span> Verifying audit chain…</div>`;
    try {
      const v = await api('/api/forensics/integrity');
      $('#integrityBanner').innerHTML = `<div class="integrity ${v.ok ? 'ok' : 'bad'}">
        <div class="ic"><svg><use href="#${v.ok ? 'i-check' : 'i-alert'}"/></svg></div>
        <div style="flex:1">
          <h2>${v.ok ? 'Audit chain verified' : 'AUDIT CHAIN BROKEN'}</h2>
          <div class="sub">${v.ok ? `${v.checked} events cryptographically hash-chained — no tampering or deletion detected.` : esc(`${v.break.detail} (event ${v.break.event_id})`)}</div>
          ${v.ok && v.head ? `<div class="hash">chain head · ${esc(v.head)}</div>` : ''}
        </div>
        <button class="btn btn-sm" id="reverifyBtn">Re-verify</button></div>`;
      $('#reverifyBtn').onclick = verifyIntegrity;
    } catch (e) { $('#integrityBanner').innerHTML = `<div class="tag bad">${esc(e.message)}</div>`; }
  }
  $('#backupNowBtn').onclick = async () => { const r = await post('/api/forensics/backup', {}); toast('Backup written', r.backed_up ? `${r.backed_up} events · ${bytes(r.artifact.size)}` : 'nothing new', ''); loaders.evidence(); };
  $('#exportBtn').onclick = async () => { const r = await post('/api/forensics/export', { severity: +$('#exportSev').value, q: $('#exportQ').value.trim() }); toast(r.ok ? 'Evidence exported' : 'Nothing to export', r.ok ? `${r.records} records` : (r.message || ''), r.ok ? '' : 'warn'); loaders.evidence(); };
  $('#triageBtn').onclick = async () => {
    $('#triageBtn').innerHTML = '<span class="spin"></span> Capturing';
    try { const r = await post('/api/forensics/triage', {}); toast('Triage snapshot captured', `${r.process_count} procs · ${r.external_connections} ext conns · ${r.autoruns} autoruns · ${r.duration}s`, ''); loaders.evidence(); }
    catch (e) { toast('Triage failed', e.message, 'bad'); }
    $('#triageBtn').innerHTML = 'Capture triage snapshot';
  };

  // ---- TIMELINE ---------------------------------------------------------
  loaders.timeline = async () => { };
  async function runTimeline() {
    const e = $('#timelineEntity').value.trim(); if (!e) return;
    $('#timelineOut').innerHTML = `<div class="empty"><span class="spin"></span> Reconstructing timeline for ${esc(e)}…</div>`;
    const t = await api(`/api/timeline?entity=${encodeURIComponent(e)}`);
    if (!t.count) { $('#timelineOut').innerHTML = `<div class="empty">Nothing found involving <b>${esc(e)}</b>.</div>`; return; }
    $('#timelineOut').innerHTML = `
      <div class="chips" style="margin-bottom:16px">
        <span class="tag">${t.count} records</span>
        <span class="tag info">${t.by_kind.event} events</span>
        <span class="tag bad">${t.by_kind.alert} alerts</span>
        <span class="tag warn">${t.by_kind.scan} scans</span>
        <span class="pill">span: ${ago(t.first_seen)} → ${ago(t.last_seen)} ago</span>
        ${t.max_severity >= 4 ? `<button class="btn btn-sm btn-danger" id="tlBlock">Block ${esc(e)}</button>` : ''}</div>
      <div class="timeline">${t.items.map(i => `
        <div class="tl-item s${i.severity}">
          <div class="th"><span class="tt">${fmtDate(i.ts)}</span><span class="tk ${i.kind}">${i.kind}</span>${sevChip(i.severity)}<span class="muted" style="font-size:11px">${esc(i.source || '')}</span></div>
          <div class="tmsg">${esc(i.title)}</div>${i.detail ? `<div class="tdet">${esc(i.detail)}</div>` : ''}
        </div>`).join('')}</div>`;
    const tb = $('#tlBlock');
    if (tb) tb.onclick = async () => { await post('/api/blocklist', { indicator: e, kind: /^\d+\.\d+\.\d+\.\d+$/.test(e) ? 'ip' : 'hash', reason: 'Blocked from timeline investigation' }); toast('Blocked', e, 'warn'); };
  }
  $('#timelineBtn').onclick = runTimeline;
  $('#timelineEntity').addEventListener('keydown', e => { if (e.key === 'Enter') runTimeline(); });

  // ---- AI ANALYST -------------------------------------------------------
  let aiGreeted = false;
  loaders.ai = async () => {
    try {
      const s = await api('/api/ai/status');
      $('#aiStatus').textContent = s.kind;
      $('#aiEngine').innerHTML = `<b>${esc(s.engine)}</b> — ${esc(s.note)}`;
    } catch (_) {}
    if (!aiGreeted) {
      aiGreeted = true;
      aiBubble('a', "Hi — I'm Biggy's built-in analyst, running entirely offline on this machine (no external model). Ask me about your events, an IP, malware, the network, or type <b>help</b>.");
      const chips = ['Summarise the last 24 hours', 'What are my top threats?', 'Any brute force activity?', 'What have we blocked?'];
      $('#aiQuick').innerHTML = chips.map(c => `<span class="aichip">${esc(c)}</span>`).join('');
      $$('#aiQuick .aichip').forEach(ch => ch.onclick = () => { $('#aiInput').value = ch.textContent; sendAI(); });
    }
    loadInsights();
  };
  async function loadInsights() {
    $('#aiInsights').innerHTML = `<div class="empty"><span class="spin"></span> analysing…</div>`;
    try {
      const r = await api('/api/ai/insights');
      $('#aiInsights').innerHTML = r.findings.map(f => `<div class="ai-insight s${f.severity}">
        <div class="t">${esc(f.title)}</div><div class="d">${esc(f.detail)}</div>
        ${f.entity ? `<div style="margin-top:7px"><span class="aichip" data-ent="${esc(f.entity)}">investigate ${esc(f.entity)}</span></div>` : ''}</div>`).join('')
        + `<div class="kicker" style="margin-top:6px">model: ${esc(r.model)}</div>`;
      $$('#aiInsights [data-ent]').forEach(x => x.onclick = () => { $('#aiInput').value = 'Tell me about ' + x.dataset.ent; sendAI(); });
    } catch (e) { $('#aiInsights').innerHTML = `<div class="tag bad">${esc(e.message)}</div>`; }
  }
  function aiBubble(role, html) {
    const c = $('#aiChat');
    const who = role === 'a' ? `<div class="who"><svg><use href="#i-spark"/></svg>Biggy Analyst</div>` : '';
    c.insertAdjacentHTML('beforeend', `<div class="bubble ${role}">${who}${html}</div>`);
    c.scrollTop = c.scrollHeight;
  }
  async function sendAI() {
    const q = $('#aiInput').value.trim(); if (!q) return;
    $('#aiInput').value = '';
    aiBubble('u', esc(q));
    const c = $('#aiChat');
    c.insertAdjacentHTML('beforeend', `<div class="ai-typing" id="aiTyping">analysing…</div>`); c.scrollTop = c.scrollHeight;
    try {
      const r = await post('/api/ai/ask', { question: q });
      $('#aiTyping') && $('#aiTyping').remove();
      aiBubble('a', aiFmt(r.answer));
    } catch (e) { $('#aiTyping') && $('#aiTyping').remove(); aiBubble('a', 'Sorry — ' + esc(e.message)); }
  }
  $('#aiSend').onclick = sendAI;
  $('#aiInput').addEventListener('keydown', e => { if (e.key === 'Enter') sendAI(); });
  $('#aiRefresh').onclick = loadInsights;

  // ---- floating AI popup (available on every view) ----------------------
  let aiPopGreeted = false;
  function toggleAiPop(force) {
    const p = $('#aiPop');
    const show = (force !== undefined) ? force : !p.classList.contains('show');
    p.classList.toggle('show', show);
    if (show) {
      if (!aiPopGreeted) {
        aiPopGreeted = true;
        aiPopBubble('a', "Hi — I'm your built-in analyst. Ask me anything about your SIEM data.");
        const chips = ['Summarise last 24h', 'Top threats', 'Any brute force?'];
        $('#aiPopQuick').innerHTML = chips.map(c => `<span class="aichip">${esc(c)}</span>`).join('');
        $$('#aiPopQuick .aichip').forEach(ch => ch.onclick = () => { $('#aiPopInput').value = ch.textContent; sendAiPop(); });
      }
      setTimeout(() => $('#aiPopInput').focus(), 50);
    }
  }
  function aiPopBubble(role, html) {
    const c = $('#aiPopChat');
    const who = role === 'a' ? `<div class="who"><svg><use href="#i-spark"/></svg>Analyst</div>` : '';
    c.insertAdjacentHTML('beforeend', `<div class="bubble ${role}">${who}${html}</div>`);
    c.scrollTop = c.scrollHeight;
  }
  async function sendAiPop() {
    const q = $('#aiPopInput').value.trim(); if (!q) return;
    $('#aiPopInput').value = '';
    aiPopBubble('u', esc(q));
    const c = $('#aiPopChat');
    c.insertAdjacentHTML('beforeend', `<div class="ai-typing" id="aiPopTyping">analysing…</div>`); c.scrollTop = c.scrollHeight;
    try { const r = await post('/api/ai/ask', { question: q }); $('#aiPopTyping') && $('#aiPopTyping').remove(); aiPopBubble('a', aiFmt(r.answer)); }
    catch (e) { $('#aiPopTyping') && $('#aiPopTyping').remove(); aiPopBubble('a', 'Sorry — ' + esc(e.message)); }
  }
  $('#aiFab').onclick = () => toggleAiPop();
  $('#aiPopClose').onclick = () => toggleAiPop(false);
  $('#aiPopSend').onclick = sendAiPop;
  $('#aiPopInput').addEventListener('keydown', e => { if (e.key === 'Enter') sendAiPop(); });

  // ---- EVENT DETAIL MODAL ----------------------------------------------
  function closeModal() { $('#eventModal').style.display = 'none'; }
  $('#modalClose').onclick = closeModal;
  $('#eventModal').onclick = (e) => { if (e.target.id === 'eventModal') closeModal(); };
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

  async function openEventModal(id) {
    const modal = $('#eventModal'), body = $('#modalBody');
    modal.style.display = 'grid';
    body.innerHTML = `<div class="empty"><span class="spin"></span> Loading event #${esc(id)}…</div>`;
    try {
      const e = await api(`/api/events/${id}`);
      const meta = e.event_meta;
      const entity = e.src_ip || e.host || e.user || '';
      $('#modalTitle').textContent = `${meta ? meta.name : e.category} · event #${e.id}`;
      body.innerHTML = `
        <div class="chips">
          ${sevChip(e.severity)}
          ${e.event_id != null ? `<span class="pill">code ${e.event_id}</span>` : ''}
          <span class="pill">${esc(e.source)}</span>
          ${e.count > 1 ? `<span class="xn">×${e.count} occurrences</span>` : ''}
        </div>
        ${meta ? `<div class="meaning" style="margin-top:14px">
          <div class="mn">${esc(meta.name)}${meta.mitre ? ` <span class="mitre">· ATT&CK ${esc(meta.mitre)}</span>` : ''}</div>
          <div class="mh">${esc(meta.hint)}</div></div>` : ''}
        <div class="sec">Message</div>
        <div style="font-size:13px;line-height:1.5">${esc(e.message)}</div>
        <div class="sec">Fields</div>
        <div class="kv2">
          <div class="k">Event #</div><div class="v">${e.id}</div>
          <div class="k">First seen</div><div class="v">${fmtDate(e.ts)}</div>
          ${e.count > 1 ? `<div class="k">Last seen</div><div class="v">${fmtDate(e.last_ts)} · fired ×${e.count}</div>` : ''}
          <div class="k">Source</div><div class="v">${esc(e.source)}</div>
          ${e.provider ? `<div class="k">Provider</div><div class="v">${esc(e.provider)}</div>` : ''}
          ${e.event_id != null ? `<div class="k">Windows code</div><div class="v">${e.event_id}</div>` : ''}
          <div class="k">Category</div><div class="v">${esc(e.category)}</div>
          <div class="k">Severity</div><div class="v">${e.severity} · ${esc(e.severity_label)}</div>
          ${e.host ? `<div class="k">Host</div><div class="v">${esc(e.host)}</div>` : ''}
          ${e.src_ip ? `<div class="k">Source IP</div><div class="v">${esc(e.src_ip)}</div>` : ''}
          ${e.dst_ip ? `<div class="k">Dest IP</div><div class="v">${esc(e.dst_ip)}</div>` : ''}
          ${e.user ? `<div class="k">User</div><div class="v">${esc(e.user)}</div>` : ''}
        </div>
        ${e.alerts && e.alerts.length ? `<div class="sec">Escalated to ${e.alerts.length} alert(s)</div>
          ${e.alerts.map(a => `<div class="reason"><span class="rt">${esc(a.rule_id || '')}</span>
            <div><b>${esc(a.title)}</b> <span class="tag ${a.status === 'open' ? 'bad' : 'ok'}">${esc(a.status)}</span></div></div>`).join('')}` : ''}
        <div class="sec">Audit-chain integrity</div>
        <div class="kv2">
          <div class="k">Chain hash</div><div class="v" style="font-size:11px">${esc(e.chain_hash || '—')}</div>
          <div class="k">Prev hash</div><div class="v" style="font-size:11px">${esc(e.prev_hash || '—')}</div>
        </div>
        <div class="muted" style="font-size:11px;margin-top:5px">Cryptographically linked in the tamper-evident chain — see Evidence → verify.</div>
        <div class="sec">Raw</div>
        <div class="raw">${esc(JSON.stringify(e.raw || {}, null, 2))}</div>
        <div class="modal-actions">
          <button class="btn btn-sm btn-primary" id="maExplain"><svg style="width:12px;height:12px;vertical-align:-2px"><use href="#i-spark"/></svg> Explain with AI</button>
          ${entity ? `<button class="btn btn-sm" id="maTimeline">↪ Timeline for ${esc(entity)}</button>` : ''}
          ${e.src_ip ? `<button class="btn btn-sm" id="maIoc">+ Add IP to IOCs</button>` : ''}
          ${e.src_ip ? `<button class="btn btn-sm btn-danger" id="maBlock">Block ${esc(e.src_ip)}</button>` : ''}
          <button class="btn btn-sm" id="maCase">Attach to a case</button>
        </div>
        <div id="maExplainOut"></div>`;
      const t = $('#maTimeline'); if (t) t.onclick = () => { closeModal(); go('timeline'); $('#timelineEntity').value = entity; runTimeline(); };
      const io = $('#maIoc'); if (io) io.onclick = async () => { await post('/api/iocs', { kind: 'ip', value: e.src_ip, severity: 4, source: 'from-event' }); toast('Added to IOC watchlist', e.src_ip); };
      const bl = $('#maBlock'); if (bl) bl.onclick = async () => { await post('/api/blocklist', { indicator: e.src_ip, kind: 'ip', reason: `Blocked from event #${e.id}` }); toast('Indicator blocked', e.src_ip, 'warn'); };
      const ca = $('#maCase'); if (ca) ca.onclick = async () => { const { cases } = await api('/api/cases'); if (!cases.length) { toast('No open case', 'Create a case first (Forensics → Cases)', 'warn'); return; } const c = cases[0]; await post(`/api/cases/${c.id}/items`, { kind: 'event', ref_id: String(e.id), title: e.message }); toast('Attached to case', c.ref); };
      const ex = $('#maExplain'); if (ex) ex.onclick = async () => {
        ex.disabled = true; const orig = ex.innerHTML; ex.innerHTML = '<span class="spin"></span> Analysing';
        try {
          const r = await post('/api/ai/explain', { kind: 'event', id: e.id });
          $('#maExplainOut').innerHTML = `<div class="ai-explka"><div style="font-family:var(--mono);font-size:9px;letter-spacing:1px;text-transform:uppercase;color:var(--accent);margin-bottom:6px">✦ Biggy Analyst</div>${aiFmt(r.text)}</div>`;
        } catch (err) { $('#maExplainOut').innerHTML = `<div class="tag bad">${esc(err.message)}</div>`; }
        ex.innerHTML = orig; ex.disabled = false;
      };
    } catch (err) { body.innerHTML = `<div class="tag bad">${esc(err.message)}</div>`; }
  }
  // delegated click-to-open across the feed, events table and log stream
  $('#liveFeed').addEventListener('click', e => { const r = e.target.closest('.feed-row[data-eid]'); if (r) openEventModal(r.dataset.eid); });
  $('#eventsTable').addEventListener('click', e => { const r = e.target.closest('tr[data-eid]'); if (r) openEventModal(r.dataset.eid); });
  $('#logStream').addEventListener('click', e => { const r = e.target.closest('.logrow[data-eid]'); if (r) openEventModal(r.dataset.eid); });

  // ---- global search + logout + init ------------------------------------
  let gsT; $('#globalSearch').addEventListener('input', e => {
    clearTimeout(gsT); gsT = setTimeout(() => { if (e.target.value.trim()) { go('events'); $('#evtSearch').value = e.target.value; loaders.events(); } }, 300);
  });
  $('#logoutBtn').onclick = async () => { await post('/api/logout', {}); window.location = '/login'; };
  $('#menuBtn').onclick = () => $('#sidebar').classList.toggle('open');
  $('#avatar').textContent = ($('#userName').textContent || 'A')[0].toUpperCase();

  connectWS();
  loaders.overview();
  setInterval(() => { if (currentView === 'overview') loaders.overview(); if (currentView === 'agents') loaders.agents(); }, 15000);
})();
