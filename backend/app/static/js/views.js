/* VulnScan page views */
(function () {
  'use strict';

  const API = window.API, U = window.U;

  const SEV_ORDER = ['None', 'Low', 'Medium', 'High', 'Critical'];
  const _pollTimers = [];
  let _pollTimer = null;
  let _pollBusy = false;
  function clearTimers() {
    _pollTimers.forEach(t => clearInterval(t));
    _pollTimers.length = 0;
    if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
    _pollBusy = false;
  }
  function stopPolling() { clearTimers(); }

  function overallRisk(counts) {
    for (let i = SEV_ORDER.length - 1; i >= 0; i--) {
      if ((counts || {})[SEV_ORDER[i]]) return SEV_ORDER[i];
    }
    return 'None';
  }

  function ic(label, cls) {
    return `<div class="ic-box ${cls || 'ib-blue'}">${label}</div>`;
  }

  function findIn(list, key, val) { return (list || []).find(x => x[key] === val); }

  async function apiGetJson(path, params) {
    return await API.get(path, params);
  }

  /* ============================================================ LOGIN */
  function loginHtml(params) {
    return `
    <div class="login-wrap">
      <div class="login-left">
        <div class="login-left-inner">
          <div class="brand"><span class="logo">🛡️</span> VulnScan</div>
          <div class="brand-sub">Web Application Vulnerability Scanner</div>
          <h1>Secure. Scan. Strengthen.</h1>
          <p class="lead">VulnScan helps developers and security professionals identify web application
            vulnerabilities, assess their risk and apply remediation guidance from an integrated knowledge base.</p>
        </div>
      </div>
      <div class="login-right">
        <div class="login-card">
          <h2>Welcome Back</h2>
          <p class="sub">Sign in to continue to VulnScan</p>
          <form id="login-form" autocomplete="on">
            <div class="field">
              <label for="email">Email Address</label>
              <input id="email" name="email" type="email" placeholder="you@example.com" required autofocus />
            </div>
            <div class="field">
              <label for="password">Password</label>
              <input id="password" name="password" type="password" placeholder="Enter your password" required />
            </div>
            <div id="login-error" class="error-text"></div>
            <button class="btn btn-primary" type="submit">Sign In →</button>
          </form>
          <div class="divider">OR</div>
          <button id="google-btn" class="btn btn-google" type="button">Sign in with Google</button>
          <div class="form-footer">Don't have an account? Contact your administrator.</div>
        </div>
      </div>
    </div>`;
  }

  function bindLogin(root) {
    const form = root.querySelector('#login-form');
    const errEl = root.querySelector('#login-error');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      errEl.textContent = '';
      const email = root.querySelector('#email').value.trim();
      const password = root.querySelector('#password').value;
      const btn = form.querySelector('button[type=submit]');
      btn.disabled = true;
      try {
        const data = await API.post('/api/auth/login', { email, password });
        API.setAuth(data.access_token, data.user);
        location.hash = '#/dashboard';
      } catch (err) {
        errEl.textContent = err.message || 'Sign in failed.';
        btn.disabled = false;
      }
    });
    root.querySelector('#google-btn').addEventListener('click', async () => {
      try {
        const data = await API.get('/api/auth/google/url');
        if (!data.configured) {
          U.toast('Google Sign-In is not configured on this server.', 'info');
          return;
        }
        location.assign(data.authorize_url);
      } catch (err) {
        U.toast(err.message, 'err');
      }
    });
  }

  /* ============================================================ DASHBOARD */
  async function dashboard(el, params) {
    const user = API.user || {};
    if (user.Role === 'Administrator') return adminDashboard(el);
    return devDashboard(el);
  }

  async function devDashboard(el) {
    el.innerHTML = U.loading('Loading dashboard...');
    const data = await apiGetJson('/api/scans', { per_page: 100 });
    const scans = data.Scans || [];
    let findingTotal = 0, highCritical = 0;
    (scans || []).forEach(s => {
      findingTotal += s.FindingCount || 0;
      const sev = overallRisk(s.SeverityCounts);
      if (sev === 'High' || sev === 'Critical') highCritical += (s.FindingCount || 0);
    });
    const recent = scans.slice(0, 6);
    el.innerHTML = `
      <div class="page-head"><h1>Developer Dashboard</h1>
        <div class="sub">Configure and run vulnerability scans, then review findings and remediation guidance.</div>
      </div>
      <div class="grid-cards">
        <div class="card stat-card">${ic('📡','ib-blue')}
          <div><div class="val">${scans.length}</div><div class="lbl">Total Scans</div></div></div>
        <div class="card stat-card">${ic('🪲','ib-red')}
          <div><div class="val">${highCritical}</div><div class="lbl">High / Critical Findings</div></div></div>
        <div class="card stat-card">${ic('🧾','ib-purple')}
          <div><div class="val">${findingTotal}</div><div class="lbl">Total Vulnerabilities</div></div></div>
        <div class="card stat-card" style="cursor:pointer" onclick="location.hash='#/scans/new'">
          ${ic('➕','ib-green')}<div><div class="val" style="font-size:16px">New Scan</div><div class="lbl">Start assessment</div></div></div>
      </div>
      <div class="grid-2">
        <div class="card card-pad">
          <div class="page-head" style="margin-bottom:6px"><div class="row">
            <h3 style="margin:0">Recent Scans</h3><a href="#/scans">View all scans →</a></div></div>
          ${scans.length ? recentScansTable(recent) : U.empty('No scans yet. Start your first scan.')}
        </div>
        <div class="card card-pad">
          <h3>Quick Start</h3>
          <p style="color:var(--muted);font-size:13px;margin-bottom:14px">
            1. Choose a scan profile that defines which vulnerability modules run.<br/>
            2. Provide the target URL of the web application.<br/>
            3. VulnScan crawls in-scope pages and runs SQL Injection, XSS and HTTP Security Header checks.</p>
          <button class="btn btn-primary" onclick="location.hash='#/scans/new'" style="width:auto">Start a Scan</button>
          <hr style="border:none;border-top:1px solid var(--border);margin:16px 0"/>
          <h3>Knowledge Base</h3>
          <p style="color:var(--muted);font-size:13px">Learn about the vulnerabilities VulnScan detects and how to fix them.</p>
          <a class="btn btn-secondary" href="#/knowledge-base" style="margin-top:10px">Open Knowledge Base</a>
        </div>
      </div>`;
  }

  async function adminDashboard(el) {
    el.innerHTML = U.loading('Loading dashboard...');
    const [scansR, usersR] = await Promise.all([
      apiGetJson('/api/scans', { per_page: 100 }),
      apiGetJson('/api/users')
    ]);
    const scans = scansR.Scans || [];
    const users = usersR.Users || [];
    let totalFindings = 0;
    const counts = { None: 0, Low: 0, Medium: 0, High: 0, Critical: 0 };
    (scans).forEach(s => {
      totalFindings += s.FindingCount || 0;
      SEV_ORDER.forEach(k => counts[k] += (s.SeverityCounts || {})[k] || 0);
    });
    const recentScans = scans.slice(0, 6);
    const recentAudit = (await apiGetJson('/api/audit-logs', { per_page: 8 })).AuditLogs || [];
    el.innerHTML = `
      <div class="page-head"><h1>Administrator Dashboard</h1>
        <div class="sub">Monitor system activity, users, scans and vulnerabilities.</div></div>
      <div class="grid-cards">
        <div class="card stat-card">${ic('👥','ib-blue')}<div><div class="val">${users.length}</div><div class="lbl">Total Users</div></div></div>
        <div class="card stat-card">${ic('📡','ib-purple')}<div><div class="val">${scans.length}</div><div class="lbl">Total Scans</div></div></div>
        <div class="card stat-card">${ic('🪲','ib-red')}<div><div class="val">${totalFindings}</div><div class="lbl">Total Vulnerabilities</div></div></div>
        <div class="card stat-card">${ic('🛡️','ib-green')}<div><div class="val">${counts.High + counts.Critical}</div><div class="lbl">High / Critical</div></div></div>
      </div>
      <div class="grid-2">
        <div class="card card-pad">
          <div class="row" style="margin-bottom:8px"><h3 style="margin:0">Recent Scans</h3><a href="#/scans">View all →</a></div>
          ${scans.length ? recentScansTable(recentScans) : U.empty('No scans yet.')}
        </div>
        <div class="card card-pad">
          <h3>Vulnerabilities by Severity</h3>
          <div class="donut-box"><canvas id="sev-canvas"></canvas></div>
          ${donutLegend(counts, totalFindings)}
        </div>
      </div>
      <div class="grid-2" style="margin-top:16px">
        <div class="card card-pad">
          <h3>Recent System Activities</h3>
          ${recentAudit.length ? auditTable(recentAudit) : U.empty('No recorded activity.')}
        </div>
        <div class="card card-pad">
          <h3>Quick Actions</h3>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
            <button class="btn btn-secondary" onclick="location.hash='#/admin/users'">👥 Add User</button>
            <button class="btn btn-secondary" onclick="location.hash='#/admin/profiles'">📄 Create Scan Profile</button>
            <button class="btn btn-secondary" onclick="location.hash='#/admin/vulnerabilities'">🪲 Manage Vulnerabilities</button>
            <button class="btn btn-secondary" onclick="location.hash='#/admin/audit-logs'">📋 View Audit Logs</button>
          </div>
        </div>
      </div>`;
    drawDonut('sev-canvas', counts);
  }

  function donutLegend(counts, total) {
    const colors = sevColors();
    const rows = SEV_ORDER.map(k => {
      const n = counts[k] || 0;
      const pct = total ? (100 * n / total).toFixed(1) : '0.0';
      return `<div class="row"><span><span class="legend-dot" style="background:${colors[k]}"></span>${k}</span>
        <span>${n} (${pct}%)</span></div>`;
    }).join('');
    return `<div class="donut-legend" style="margin-top:8px"><div class="row" style="font-weight:700"><span>Total</span><span>${total}</span></div>${rows}</div>`;
  }

  function sevColors() {
    return { 'Critical': '#b91c1c', 'High': '#ea580c', 'Medium': '#d97706', 'Low': '#1d4ed8', 'None': '#94a3b8' };
  }

  function drawDonut(canvasId, counts) {
    if (typeof Chart === 'undefined') return;
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const data = SEV_ORDER.map(k => counts[k] || 0);
    new Chart(ctx, {
      type: 'doughnut',
      data: { labels: SEV_ORDER, datasets: [{ data, backgroundColor: SEV_ORDER.map(k => sevColors()[k]) }] },
      options: { cutout: '62%', plugins: { legend: { display: false } }, maintainAspectRatio: false }
    });
  }

  /* ============================================================ NEW SCAN */
  async function newScan(el) {
    el.innerHTML = U.loading('Loading scan profiles...');
    const profilesR = await apiGetJson('/api/scan-profiles');
    const profiles = profilesR.ScanProfiles || [];
    el.innerHTML = `
      <div class="page-head"><div class="row"><div><h1>Create New Scan</h1>
        <div class="sub">Configure scan settings and start a new vulnerability assessment.</div></div></div></div>
      <div class="grid-2">
        <div class="card card-pad">
          <h3>Scan Configuration</h3>
          <div class="field">
            <label>Target URL *</label>
            <input id="target_url" type="text" placeholder="https://example.com" />
            <div class="hint">Base URL of the web application to scan. Only the target's own pages are tested.</div>
          </div>
          <div class="field">
            <label>Scan Name (optional)</label>
            <input id="scan_name" type="text" placeholder="e.g. E-Commerce Website" maxlength="100" />
          </div>
          <div class="field">
            <label>Scan Profile *</label>
            <select id="profile_id"></select>
            <div class="hint" id="profile-info">Select a profile that defines which modules run.</div>
          </div>
          <div style="background:var(--blue-bg);border-radius:8px;padding:10px 12px;font-size:12.5px;color:#1e3a8a;margin:12px 0">
            <b>ℹ About Scan Profiles</b><br/>
            Scan profiles determine which vulnerability modules will be executed during the scan and how deeply the target is crawled.
          </div>
          <div style="display:flex;gap:10px;justify-content:flex-end">
            <button class="btn btn-secondary" id="reset-btn">Reset</button>
            <button class="btn btn-primary" id="start-btn" style="width:auto">Start Scan</button>
          </div>
        </div>
        <div class="card card-pad">
          <h3>Available Scan Profiles</h3>
          <div id="profile-cards"></div>
        </div>
      </div>`;
    const sel = el.querySelector('#profile_id');
    const cards = el.querySelector('#profile-cards');
    profiles.forEach(p => {
      const o = document.createElement('option');
      o.value = p.ScanProfileID; o.textContent = p.Name;
      sel.appendChild(o);
    });
    cards.innerHTML = profiles.map(p => `
      <div class="card" style="padding:12px;margin-bottom:10px;border:1px solid var(--border);box-shadow:none">
        <b>${U.esc(p.Name)}</b>
        <div style="color:var(--muted);font-size:12px;margin:4px 0">Depth ${p.MaxDepth} · Max ${p.MaxPages} pages · Delay ${p.RequestDelayMs} ms</div>
        <div class="pill-list">${(p.Modules || []).map(m => `<span class="chip-mini">${U.esc(m.Name)}</span>`).join('') || '<span style="color:var(--muted)">No modules</span>'}</div>
      </div>`).join('');
    const info = el.querySelector('#profile-info');
    function showInfo() {
      const p = findIn(profiles, 'ScanProfileID', parseInt(sel.value, 10));
      if (p) info.textContent = `${(p.Modules || []).length} module(s): ${(p.Modules || []).map(m => m.Name).join(', ')} · max depth ${p.MaxDepth}`;
    }
    sel.addEventListener('change', showInfo);
    showInfo();
    el.querySelector('#reset-btn').addEventListener('click', () => {
      el.querySelector('#target_url').value = '';
      el.querySelector('#scan_name').value = '';
    });
    el.querySelector('#start-btn').addEventListener('click', startScanNow);
    async function startScanNow() {
      const target_url = el.querySelector('#target_url').value.trim();
      const scan_name = el.querySelector('#scan_name').value.trim();
      const scan_profile_id = parseInt(el.querySelector('#profile_id').value, 10);
      if (!target_url) { U.toast('Target URL is required.', 'err'); return; }
      const btn = el.querySelector('#start-btn');
      btn.disabled = true; btn.textContent = 'Starting…';
      try {
        const data = await API.post('/api/scans', { target_url, scan_name, scan_profile_id });
        U.toast('Scan started - it will run in the background.', 'ok');
        location.hash = '#/scans/' + data.Scan.ScanID;
      } catch (err) {
        U.toast(err.message, 'err'); btn.disabled = false; btn.textContent = 'Start Scan';
      }
    }
  }

  /* ============================================================ SCANS LIST */
  async function scans(el, params) {
    const page = parseInt((params && params.page) || '1', 10);
    const state = { page, status: '', search: '' };
    await render();
    async function render() {
      el.innerHTML = U.loading('Loading scans...');
      const q = { page: state.page, per_page: 12 };
      if (state.status) q.status = state.status;
      if (state.search) q.search = state.search;
      const data = await apiGetJson('/api/scans', q);
      const scans = data.Scans || [];
      const isAdmin = (API.user || {}).Role === 'Administrator';
      const statusOptions = ['', 'Pending', 'Running', 'Completed', 'Failed'];
      el.innerHTML = `
        <div class="page-head"><div class="row"><div><h1>${isAdmin ? 'All Scans' : 'My Scans'}</h1>
          <div class="sub">${isAdmin ? 'Vulnerability scanning activity across all users.' : 'Vulnerability scans performed by you.'}</div></div>
          ${!isAdmin ? '<button class="btn btn-primary" style="width:auto" onclick="location.hash=\'#/scans/new\'">+ New Scan</button>' : ''}</div></div>
        <div class="card">
          <div class="card-pad">
            <div class="toolbar">
              <input type="search" class="grow" id="scan-search" placeholder="Search scan name or target URL…" value="${U.esc(state.search)}"/>
              <select id="scan-status">
                ${statusOptions.map(s => `<option value="${s}" ${state.status === s ? 'selected' : ''}>${s ? ('Status: ' + s) : 'All statuses'}</option>`).join('')}
              </select>
            </div>
            ${scans.length ? scansTable(scans) : U.empty('No scans found.')}
            <div id="pager"></div>
          </div>
        </div>`;
      el.querySelector('#pager').appendChild(U.pager(state.page, 12, data.Total || 0, p => {
        state.page = p; location.hash = '#/scans?page=' + p;
      }));
      el.querySelector('#scan-status').addEventListener('change', e => { state.status = e.target.value; state.page = 1; render(); });
      el.querySelector('#scan-search').addEventListener('input', debounce(e => {
        state.search = e.target.value.trim(); state.page = 1; render();
      }, 350));
    }
  }

  function recentScansTable(scans) {
    return scansTable(scans);
  }

  function scansTable(scans) {
    return `<div class="table-wrap"><table class="tbl">
      <thead><tr><th>Scan</th><th>Target URL</th><th>Profile</th><th>Status</th><th>Risk</th><th>Findings</th><th>Started</th><th class="actions">Actions</th></tr></thead>
      <tbody>${scans.map(s => {
        const risk = overallRisk(s.SeverityCounts);
        return `<tr>
          <td><b>${U.esc(s.ScanName)}</b><div class="mono" style="color:var(--muted)">#${s.ScanID}</div></td>
          <td class="mono">${U.esc(s.TargetURL)}</td>
          <td>${U.esc(s.ScanProfileName || '-')}</td>
          <td>${U.statusBadge(s.Status)}</td>
          <td>${U.sevBadge(risk)}</td>
          <td>${s.FindingCount || 0} <span style="color:var(--muted)">(on ${s.PageCount || 0} pages)</span></td>
          <td class="tbl-nowrap">${U.fmtDT(s.StartedAt)}</td>
          <td class="actions"><a class="btn btn-sm btn-secondary" href="#/scans/${s.ScanID}">View</a></td>
        </tr>`;
      }).join('')}</tbody></table></div>`;
  }

  /* ============================================================ SCAN RESULT */
  /**
   * Poll a running scan until it reaches a terminal state.  The poller owns
   * its own scheduling and survives transient fetch/render errors, so the
   * result page always refreshes to the final state.
   */
  function startPolling(el, id) {
    if (_pollTimer) return;
    _pollTimer = setInterval(async () => {
      if (_pollBusy) return;
      _pollBusy = true;
      let stillRunning = true;
      try {
        const d = (await apiGetJson('/api/scans/' + id)).Scan;
        stillRunning = (d.Status === 'Running' || d.Status === 'Pending');
      } catch (e) {
        stillRunning = true; // transient - retry on next tick
      }
      if (!stillRunning) { clearTimers(); }
      try {
        await scanResult(el, { id: id });
      } catch (e) {
        // A render error must not permanently stop the refresh loop.
      }
      _pollBusy = false;
    }, 3000);
  }

  async function scanResult(el, params) {
    const id = parseInt((params && params.id) || '0', 10);
    el.innerHTML = U.loading('Loading scan result…');
    let scan;
    try {
      const data = await apiGetJson('/api/scans/' + id);
      scan = data.Scan;
    } catch (err) {
      el.innerHTML = `<div class="card card-pad">${U.empty(err.message)}</div>`;
      return;
    }
    const counts = scan.SeverityCounts || {};
    const findings = scan.Findings || [];
    const open = findings.filter(f => f.Status === 'Open').length;
    const resolved = findings.filter(f => f.Status === 'Resolved').length;
    const falsePos = findings.filter(f => f.Status === 'False Positive').length;
    const duration = scanDuration(scan.StartedAt, scan.FinishedAt, scan.Status);
    const isRunning = scan.Status === 'Running' || scan.Status === 'Pending';
    const riskColor = (scan.OverallRisk || 'None').toLowerCase();
    el.innerHTML = `
      <div class="page-head"><div class="row"><div><h1>Scan Result</h1>
        <div class="sub">${U.esc(scan.ScanName)} &nbsp;|&nbsp; <span class="mono">${U.esc(scan.TargetURL)}</span></div></div>
        <div style="display:flex;gap:8px">
          <a class="btn btn-secondary" href="#/scans">← Back</a>
          <button class="btn btn-secondary" id="dl-csv">⬇ CSV</button>
          <button class="btn btn-primary" style="width:auto" id="dl-pdf">⬇ Download PDF Report</button>
        </div></div></div>
      <div class="grid-cards">
        <div class="card stat-card">${ic('🎯', riskColor === 'critical' ? 'ib-red' : riskColor === 'high' ? 'ib-red' : 'ib-amber')}
          <div><div class="val risk-tag">${U.esc(scan.OverallRisk || 'None')}</div><div class="lbl">Overall Risk</div></div></div>
        <div class="card stat-card">${ic('🪲','ib-purple')}
          <div><div class="val">${findings.length}</div><div class="lbl">Vulnerabilities<br/><span style="color:var(--green)">Open ${open}</span> · Resolved ${resolved} · FP ${falsePos}</div></div></div>
        <div class="card stat-card">${ic('📄','ib-blue')}
          <div><div class="val" style="font-size:17px">${U.statusBadge(scan.Status)}</div><div class="lbl">${scan.Status === 'Completed' ? 'Scan completed successfully' : isRunning ? 'Scanning in progress…' : 'See scan details'}</div></div></div>
        <div class="card stat-card">${ic('⏱️','ib-green')}
          <div><div class="val" style="font-size:20px">${duration}</div><div class="lbl">Duration<br/>${U.fmtDT(scan.StartedAt)}</div></div></div>
      </div>
      <div class="grid-2">
        <div class="card card-pad">
          <div class="row" style="margin-bottom:8px">
            <h3 style="margin:0">Findings</h3>
            ${isRunning ? '<span class="badge running">Scanning… refresh to update</span>' : ''}
          </div>
          <div class="toolbar">
            <input type="search" class="grow" id="f-search" placeholder="Search vulnerability…"/>
            <select id="f-sev"><option value="">Severity: All</option>${SEV_ORDER.slice(1).map(s => `<option>${s}</option>`).join('')}</select>
            <select id="f-status"><option value="">Status: All</option><option>Open</option><option>Resolved</option><option>False Positive</option></select>
            <button class="btn btn-sm btn-secondary" id="f-reset">Reset</button>
          </div>
          <div id="findings-box">${U.loading()}</div>
        </div>
        <div>
          <div class="card card-pad" style="margin-bottom:16px">
            <h3>Severity Overview</h3>
            <div class="donut-box"><canvas id="sev-canvas"></canvas></div>
            ${donutLegend(counts, findings.length)}
          </div>
          <div class="card card-pad">
            <h3>Scan Information</h3>
            <div class="kv">
              <span class="k">Scan ID</span><span class="mono">SCAN-${scan.ScanID}</span>
              <span class="k">Target URL</span><span class="mono">${U.esc(scan.TargetURL)}</span>
              <span class="k">Scan Profile</span><span>${U.esc(scan.ScanProfileName || '-')}</span>
              <span class="k">Started By</span><span>${U.esc(scan.Username || '-')}</span>
              <span class="k">Started</span><span>${U.fmtDT(scan.StartedAt)}</span>
              <span class="k">Finished</span><span>${U.fmtDT(scan.FinishedAt)}</span>
              <span class="k">Discovered Pages</span><span>${scan.PageCount || 0}</span>
            </div>
          </div>
        </div>
      </div>
      <div class="card card-pad" style="margin-top:16px">
        <h3>Discovered Pages (${scan.Pages ? scan.Pages.length : 0})</h3>
        ${renderPages(scan.Pages || [])}
      </div>`;
    drawDonut('sev-canvas', counts);
    bindFindings(el.querySelector('#findings-box'), findings, id, { open, resolved, falsePos });
    el.querySelector('#f-search').addEventListener('input', debounce(() => renderFiltered(), 300));
    el.querySelector('#f-sev').addEventListener('change', renderFiltered);
    el.querySelector('#f-status').addEventListener('change', renderFiltered);
    el.querySelector('#f-reset').addEventListener('click', () => {
      el.querySelector('#f-search').value = '';
      el.querySelector('#f-sev').value = '';
      el.querySelector('#f-status').value = '';
      renderFiltered();
    });
    function currentFilters() {
      return {
        q: el.querySelector('#f-search').value.trim().toLowerCase(),
        sev: el.querySelector('#f-sev').value,
        status: el.querySelector('#f-status').value
      };
    }
    function renderFiltered() {
      const box = el.querySelector('#findings-box');
      const f = currentFilters();
      const filtered = findings.filter(x =>
        (!f.q || (x.VulnerabilityName || '').toLowerCase().includes(f.q) || (x.URL || '').toLowerCase().includes(f.q)) &&
        (!f.sev || x.Severity === f.sev) && (!f.status || x.Status === f.status));
      box.innerHTML = findingsTable(filtered, id, null);
      wireFindingRows(box);
    }
    renderFiltered();
    el.querySelector('#dl-pdf').addEventListener('click', () => {
      API.download(`/api/scans/${id}/report?format=pdf`, `vulnscan-scan-${id}.pdf`)
        .then(() => U.toast('PDF report downloaded.', 'ok'))
        .catch(e => U.toast(e.message, 'err'));
    });
    el.querySelector('#dl-csv').addEventListener('click', () => {
      API.download(`/api/scans/${id}/report?format=csv`, `vulnscan-scan-${id}.csv`)
        .then(() => U.toast('CSV report downloaded.', 'ok'))
        .catch(e => U.toast(e.message, 'err'));
    });

    // Auto-refresh while the scan is still running (poller owns scheduling).
    if (isRunning) startPolling(el, id);
  }

  function renderPages(pages) {
    if (!pages.length) return U.empty('No pages were discovered.');
    return `<div class="table-wrap"><table class="tbl">
      <thead><tr><th>#</th><th>URL</th><th>Title</th><th>HTTP</th><th>Depth</th></tr></thead>
      <tbody>${pages.map(p => `<tr>
        <td>${p.DiscoveryOrder}</td><td class="mono">${U.esc(p.URL)}</td>
        <td>${U.esc(p.PageTitle || '-')}</td><td>${p.HTTPStatus || '-'}</td><td>${p.CrawlDepth}</td></tr>`).join('')}
      </tbody></table></div>`;
  }

  function bindFindings(box, findings, scanId, info) {
    // delegate click toggles handled by wireFindingRows
  }

  function findingsTable(findings, scanId, info) {
    if (!findings.length) return U.empty('No findings match your filters.');
    return `<div class="table-wrap"><table class="tbl">
      <thead><tr><th>Vulnerability</th><th>Severity</th><th>Evidence</th><th>Risk</th><th>Status</th><th>Location</th><th>Actions</th></tr></thead>
      <tbody>${findings.map(f => `
        <tr class="finding-row" data-id="${f.FindingID}">
          <td><b>${U.esc(f.VulnerabilityName)}</b><div style="color:var(--muted);font-size:11.5px">${U.esc(f.OWASPCategory || '')}</div></td>
          <td>${U.sevBadge(f.Severity)}</td>
          <td><span class="badge ${(f.Classification || '').toLowerCase()}">${U.esc(f.Classification || '-')}</span><div style="color:var(--muted);font-size:11px">${f.Confidence != null ? Math.round(Number(f.Confidence) * 100) + '% confidence' : ''}</div></td>
          <td>${f.RiskScore != null ? Number(f.RiskScore).toFixed(1) : '-'}</td>
          <td>${U.statusBadge(f.Status)}</td>
          <td class="mono">${U.esc(f.URL || '')}${f.Parameter ? ' <span class="chip-mini">param: ' + U.esc(f.Parameter) + '</span>' : ''}</td>
          <td class="actions">
            <button class="btn btn-xs btn-secondary" data-detail="1" title="Details">👁 Detail</button>
            <select class="status-select" data-status="1">
              <option value="Open" ${f.Status === 'Open' ? 'selected' : ''}>Open</option>
              <option value="Resolved" ${f.Status === 'Resolved' ? 'selected' : ''}>Resolved</option>
              <option value="False Positive" ${f.Status === 'False Positive' ? 'selected' : ''}>False Positive</option>
            </select>
          </td>
        </tr>
        <tr class="detail-row" id="detail-${f.FindingID}" style="display:none">
          <td colspan="7">
            <div class="card" style="padding:12px;box-shadow:none;border-color:var(--border)">
              <div style="font-weight:700">${U.esc(f.VulnerabilityName)} · ${U.esc(f.Severity)} · ${U.esc(f.Classification || '')} (CVSS ${f.RiskScore != null ? Number(f.RiskScore).toFixed(1) : '-'})</div>
              <div class="mono" style="margin:4px 0">${U.esc(f.URL)} ${f.RequestMethod ? '(' + U.esc(f.RequestMethod) + ')' : ''} ${f.Parameter ? '· param ' + U.esc(f.Parameter) : ''}</div>
              ${f.Payload ? `<div style="margin:4px 0"><b>Payload:</b> <span class="mono">${U.esc(f.Payload)}</span></div>` : ''}
              <div class="evidence">${U.esc(f.Evidence || '')}</div>
              ${f.Description ? `<p style="margin-top:8px"><b>Description:</b> ${U.esc(f.Description)}</p>` : ''}
              ${f.Impact ? `<p style="margin-top:6px"><b>Impact:</b> ${U.esc(f.Impact)}</p>` : ''}
              ${f.Recommendation ? `<p style="margin-top:6px"><b>Remediation:</b> ${U.esc(f.Recommendation)}</p>` : ''}
            </div>
          </td>
        </tr>`).join('')}</tbody></table></div>`;
  }

  function wireFindingRows(box) {
    box.querySelectorAll('button[data-detail]').forEach(b => {
      b.addEventListener('click', () => {
        const row = b.closest('tr.finding-row');
        const det = document.getElementById('detail-' + row.dataset.id);
        if (det) det.style.display = det.style.display === 'none' ? '' : 'none';
      });
    });
    box.querySelectorAll('select[data-status]').forEach(sel => {
      sel.addEventListener('change', async () => {
        const row = sel.closest('tr.finding-row');
        const fid = parseInt(row.dataset.id, 10);
        const scanId = parseInt(location.hash.split('/')[2], 10);
        try {
          const data = await API.put(`/api/scans/${scanId}/findings/${fid}`, { status: sel.value });
          U.toast('Finding marked as ' + sel.value + '.', 'ok');
        } catch (err) { U.toast(err.message, 'err'); location.hash = '#/scans/' + scanId + '?r=' + Date.now(); }
      });
    });
  }

  function scanDuration(start, finish, status) {
    if (!start) return '-';
    const s = new Date(start).getTime();
    const f = finish ? new Date(finish).getTime() : Date.now();
    const ms = Math.max(0, f - s);
    const sec = Math.floor(ms / 1000);
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), secs = sec % 60;
    return (h ? String(h).padStart(2, '0') + ':' : '') + String(m).padStart(2, '0') + ':' + String(secs).padStart(2, '0');
  }

  /* ============================================================ KNOWLEDGE BASE */
  async function knowledgeBase(el) {
    el.innerHTML = U.loading('Loading knowledge base…');
    const isAdmin = (API.user || {}).Role === 'Administrator';
    const data = await apiGetJson('/api/vulnerabilities', isAdmin ? { include_disabled: true } : {});
    const vulns = data.Vulnerabilities || [];
    const state = { q: '', cat: '' };
    render();
    function render() {
      const cats = [...new Set(vulns.map(v => v.OWASPCategory))].sort();
      const filtered = vulns.filter(v =>
        (!state.q || (v.Name + ' ' + v.Description).toLowerCase().includes(state.q)) &&
        (!state.cat || v.OWASPCategory === state.cat));
      el.innerHTML = `
        <div class="page-head"><h1>Vulnerability Knowledge Base</h1>
          <div class="sub">Descriptions, impacts, secure coding practices and remediation guidance for each supported vulnerability.</div></div>
        <div class="toolbar">
          <input type="search" class="grow" id="kb-q" placeholder="Search vulnerabilities…" value="${U.esc(state.q)}"/>
          <select id="kb-cat"><option value="">All categories</option>${cats.map(c => `<option ${state.cat === c ? 'selected' : ''}>${U.esc(c)}</option>`).join('')}</select>
        </div>
        <div class="grid-3">${filtered.map(v => `
          <div class="card kb-card card-pad">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
              <h3 style="margin:0">${U.esc(v.Name)}</h3>
              ${v.ModuleKey ? '<span class="badge module">⚙ detection module</span>' : ''}
            </div>
            <div><span class="chip-mini">${U.esc(v.OWASPCategory || '')}</span>
            ${v.IsEnabled ? '<span class="badge enabled">Enabled</span>' : '<span class="badge disabled">Disabled</span>'}</div>
            <p>${U.esc(v.Description || '')}</p>
            <button class="btn btn-sm btn-secondary" data-vid="${v.VulnerabilityID}">Details</button>
          </div>`).join('') || U.empty('No vulnerabilities found.')}
        </div>`;
      el.querySelector('#kb-q').addEventListener('input', debounce(e => { state.q = e.target.value.toLowerCase().trim(); render(); }, 300));
      el.querySelector('#kb-cat').addEventListener('change', e => { state.cat = e.target.value; render(); });
      el.querySelectorAll('button[data-vid]').forEach(b => b.addEventListener('click', () => kbDetail(findIn(vulns, 'VulnerabilityID', parseInt(b.dataset.vid, 10)))));
    }
    function kbDetail(v) {
      if (!v) return;
      U.modal(U.esc(v.Name),
        `<div class="kv" style="grid-template-columns:120px 1fr">
          <span class="k">Category</span><span>${U.esc(v.OWASPCategory)}</span>
          <span class="k">Module</span><span>${v.ModuleKey ? 'Implemented detection module' : 'Knowledge-base only'}</span>
          <span class="k">Status</span><span>${v.IsEnabled ? 'Enabled' : 'Disabled'}</span></div>
          <p style="margin-top:10px"><b>Description</b><br/>${U.esc(v.Description)}</p>
          <p style="margin-top:8px"><b>Impact</b><br/>${U.esc(v.Impact)}</p>
          <p style="margin-top:8px"><b>Remediation</b><br/>${U.esc(v.Recommendation)}</p>
          <p style="margin-top:8px"><b>Secure Coding Practice</b><br/>${U.esc(v.SecurityCodingPractice)}</p>
          <p style="margin-top:8px"><b>References</b><br/>${U.esc(v.OWASPReference)}<br/>
          ${v.ReferenceURL ? `<a href="${U.esc(v.ReferenceURL)}" target="_blank" rel="noopener">${U.esc(v.ReferenceURL)}</a>` : ''}</p>`,
        `<button class="btn btn-secondary" onclick="U.closeModal()">Close</button>`);
    }
  }

  /* ============================================================ PROFILE */
  async function profile(el) {
    const u = API.user || {};
    el.innerHTML = `
      <div class="page-head"><h1>My Profile</h1><div class="sub">Your VulnScan account details.</div></div>
      <div class="card card-pad" style="max-width:560px">
        <div style="display:flex;gap:16px;align-items:center;margin-bottom:16px">
          <div class="avatar" style="width:56px;height:56px;font-size:22px">${U.esc((u.Username || '?')[0].toUpperCase())}</div>
          <div><div style="font-size:18px;font-weight:700">${U.esc(u.Username)}</div>${U.roleBadge(u.Role)}</div>
        </div>
        <div class="kv">
          <span class="k">Username</span><span>${U.esc(u.Username)}</span>
          <span class="k">Email</span><span>${U.esc(u.Email)}</span>
          <span class="k">Role</span><span>${U.esc(u.Role)}</span>
          <span class="k">Last Login</span><span>${U.fmtDT(u.LastLogin)}</span>
          <span class="k">Member Since</span><span>${U.fmtDate(u.CreatedAt)}</span>
        </div>
        <div style="margin-top:18px"><button class="btn btn-secondary" id="signout-btn">Sign Out</button></div>
      </div>`;
    el.querySelector('#signout-btn').addEventListener('click', async () => {
      try { await API.post('/api/auth/logout', {}); } catch (e) { /* token may already be gone */ }
      API.clearAuth();
      location.hash = '#/login';
    });
  }

  /* ============================================================ ADMIN: USERS */
  async function adminUsers(el) {
    el.innerHTML = U.loading('Loading users…');
    const data = await apiGetJson('/api/users');
    const users = data.Users || [];
    el.innerHTML = `
      <div class="page-head"><div class="row"><div><h1>User Management</h1>
        <div class="sub">Create and manage user accounts and roles (${users.length} users).</div></div>
        <button class="btn btn-primary" style="width:auto" id="add-user">+ New User</button></div></div>
      <div class="card card-pad"><div class="table-wrap">
        <table class="tbl"><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th><th class="actions">Actions</th></tr></thead>
        <tbody>${users.map(u => `<tr>
          <td><b>${U.esc(u.Username)}</b></td><td>${U.esc(u.Email)}</td>
          <td>${U.roleBadge(u.Role)}</td><td>${U.activeBadge(u.IsActive)}</td>
          <td>${U.fmtDT(u.LastLogin)}</td>
          <td class="actions">
            <button class="btn btn-xs btn-secondary" data-edit="${u.UserID}">Edit</button>
            ${u.IsActive ? `<button class="btn btn-xs btn-danger" data-disable="${u.UserID}">Disable</button>` : '<span class="chip-mini">disabled</span>'}
          </td></tr>`).join('')}</tbody></table></div></div>`;
    el.querySelector('#add-user').addEventListener('click', () => userModal());
    el.querySelectorAll('[data-edit]').forEach(b => b.addEventListener('click', () => userModal(findIn(users, 'UserID', parseInt(b.dataset.edit, 10)))));
    el.querySelectorAll('[data-disable]').forEach(b => b.addEventListener('click', async () => {
      const u = findIn(users, 'UserID', parseInt(b.dataset.disable, 10));
      if (!u) return;
      if (!(await U.confirmDlg(`Disable the account for ${u.Email}? The user will no longer be able to sign in.`, 'Disable User'))) return;
      try { await API.del('/api/users/' + u.UserID); U.toast('User disabled.', 'ok'); renderRefresh(); }
      catch (err) { U.toast(err.message, 'err'); }
    }));
    function renderRefresh() { location.hash = '#/admin/users?r=' + Date.now(); }
    function userModal(user) {
      const editing = !!user;
      U.modal(editing ? 'Edit User' : 'Create User',
        `<div class="field"><label>Username</label><input id="u-username" value="${U.esc(user ? user.Username : '')}" ${editing ? '' : 'required'}></div>
         <div class="field"><label>Email</label><input id="u-email" type="email" value="${U.esc(user ? user.Email : '')}" required></div>
         <div class="field"><label>Role</label><select id="u-role">
           <option value="Developer" ${user && user.Role === 'Developer' ? 'selected' : ''}>Developer</option>
           <option value="Administrator" ${user && user.Role === 'Administrator' ? 'selected' : ''}>Administrator</option></select></div>
         ${editing ? '' : `<div class="field"><label>Password</label><input id="u-pass" type="password" minlength="8" placeholder="min 8 characters" required>
           <div class="hint">Password is hashed and never stored in plain text.</div></div>`}
         <div class="field"><label><input type="checkbox" id="u-active" ${!user || user.IsActive ? 'checked' : ''}/> Account active</label></div>`,
        `<button class="btn btn-secondary" onclick="U.closeModal()">Cancel</button>
         <button class="btn btn-primary" style="width:auto" id="u-save">${editing ? 'Save' : 'Create'}</button>`);
      document.getElementById('u-save').addEventListener('click', async () => {
        const body = {
          username: document.getElementById('u-username').value.trim(),
          email: document.getElementById('u-email').value.trim(),
          role: document.getElementById('u-role').value,
          is_active: document.getElementById('u-active').checked
        };
        try {
          if (editing) await API.put('/api/users/' + user.UserID, body);
          else {
            const p = document.getElementById('u-pass').value;
            if (!p || p.length < 8) { U.toast('Password must be at least 8 characters.', 'err'); return; }
            await API.post('/api/users', Object.assign({ password: p }, body));
          }
          U.closeModal(); U.toast('User saved.', 'ok'); location.hash = '#/admin/users?r=' + Date.now();
        } catch (err) { U.toast(err.message, 'err'); }
      });
    }
  }

  /* ============================================================ ADMIN: PROFILES */
  async function adminProfiles(el) {
    el.innerHTML = U.loading('Loading scan profiles…');
    const [profR, vulnR] = await Promise.all([
      apiGetJson('/api/scan-profiles'),
      apiGetJson('/api/vulnerabilities', { include_disabled: true })
    ]);
    const profiles = profR.ScanProfiles || [];
    const vulns = (vulnR.Vulnerabilities || []).filter(v => v.ModuleKey); // only module-capable
    el.innerHTML = `
      <div class="page-head"><div class="row"><div><h1>Scan Profiles</h1>
        <div class="sub">Configurable profiles define which vulnerability modules run and crawl limits.</div></div>
        <button class="btn btn-primary" style="width:auto" id="add-prof">+ New Profile</button></div></div>
      <div class="grid-3">${profiles.map(p => `
        <div class="card card-pad">
          <div style="display:flex;justify-content:space-between;align-items:center"><h3 style="margin:0">${U.esc(p.Name)}</h3>
            <div><button class="btn btn-xs btn-secondary" data-edit="${p.ScanProfileID}">Edit</button>
            <button class="btn btn-xs btn-danger" data-del="${p.ScanProfileID}">✕</button></div></div>
          <div style="color:var(--muted);font-size:12px;margin:6px 0">
            Depth ${p.MaxDepth} · Max ${p.MaxPages} pages · Delay ${p.RequestDelayMs} ms
            · ${p.FollowExternalLinks ? 'external links allowed' : 'same-origin only'}</div>
          <div class="pill-list">${(p.Modules || []).map(m => `<span class="chip-mini">${U.esc(m.Name)}</span>`).join('') || '<span style="color:var(--muted)">No modules</span>'}</div>
        </div>`).join('') || U.empty('No profiles.')}
      </div>`;
    el.querySelector('#add-prof').addEventListener('click', () => profileModal());
    el.querySelectorAll('[data-edit]').forEach(b => b.addEventListener('click', () => profileModal(findIn(profiles, 'ScanProfileID', parseInt(b.dataset.edit, 10)))));
    el.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', async () => {
      const p = findIn(profiles, 'ScanProfileID', parseInt(b.dataset.del, 10));
      if (!(await U.confirmDlg(`Delete the scan profile "${p.Name}"? This cannot be undone.`, 'Delete Profile'))) return;
      try { await API.del('/api/scan-profiles/' + p.ScanProfileID); U.toast('Profile deleted.', 'ok'); location.hash = '#/admin/profiles?r=' + Date.now(); }
      catch (err) { U.toast(err.message, 'err'); }
    }));
    function profileModal(profile) {
      const editing = !!profile;
      const selected = (profile ? (profile.Modules || []).map(m => m.VulnerabilityID) : []);
      U.modal(editing ? 'Edit Scan Profile' : 'Create Scan Profile',
        `<div class="field"><label>Profile Name</label><input id="p-name" maxlength="30" value="${U.esc(profile ? profile.Name : '')}" required></div>
         <div class="form-row">
           <div class="field"><label>Max Depth</label><input id="p-depth" type="number" min="0" max="5" value="${profile ? profile.MaxDepth : 2}"></div>
           <div class="field"><label>Max Pages</label><input id="p-pages" type="number" min="1" max="500" value="${profile ? profile.MaxPages : 30}"></div>
           <div class="field"><label>Request Delay (ms)</label><input id="p-delay" type="number" min="0" max="10000" value="${profile ? profile.RequestDelayMs : 200}"></div>
           <div class="field" style="display:flex;align-items:center;gap:8px;padding-top:30px">
             <input type="checkbox" id="p-ext" ${profile && profile.FollowExternalLinks ? 'checked' : ''}/> <label for="p-ext" style="margin:0">Follow same-domain external links</label></div>
         </div>
         <div class="field"><label>Vulnerability Detection Modules</label>
           <div class="check-list">${vulns.map(v => `
             <label><input type="checkbox" class="mod-chk" value="${v.VulnerabilityID}" ${selected.includes(v.VulnerabilityID) ? 'checked' : ''}/>
             <span>${U.esc(v.Name)}</span></label>`).join('')}</div></div>`,
        `<button class="btn btn-secondary" onclick="U.closeModal()">Cancel</button>
         <button class="btn btn-primary" style="width:auto" id="p-save">${editing ? 'Save' : 'Create'}</button>`);
      document.getElementById('p-save').addEventListener('click', async () => {
        const body = {
          name: document.getElementById('p-name').value.trim(),
          max_depth: parseInt(document.getElementById('p-depth').value, 10),
          max_pages: parseInt(document.getElementById('p-pages').value, 10),
          request_delay_ms: parseInt(document.getElementById('p-delay').value, 10),
          follow_external: document.getElementById('p-ext').checked,
          module_vuln_ids: [...document.querySelectorAll('.mod-chk:checked')].map(x => parseInt(x.value, 10))
        };
        try {
          if (editing) await API.put('/api/scan-profiles/' + profile.ScanProfileID, body);
          else await API.post('/api/scan-profiles', body);
          U.closeModal(); U.toast('Scan profile saved.', 'ok'); location.hash = '#/admin/profiles?r=' + Date.now();
        } catch (err) { U.toast(err.message, 'err'); }
      });
    }
  }

  /* ============================================================ ADMIN: VULNERABILITIES */
  async function adminVulns(el) {
    el.innerHTML = U.loading('Loading vulnerabilities…');
    const data = await apiGetJson('/api/vulnerabilities', { include_disabled: true });
    const vulns = data.Vulnerabilities || [];
    const state = { q: '' };
    render();
    function render() {
      const filtered = vulns.filter(v => !state.q || v.Name.toLowerCase().includes(state.q) || v.OWASPCategory.toLowerCase().includes(state.q));
      el.innerHTML = `
        <div class="page-head"><div class="row"><div><h1>Vulnerability Management</h1>
          <div class="sub">Maintain vulnerability definitions and remediation information (${vulns.length} entries).</div></div>
          <button class="btn btn-primary" style="width:auto" id="add-vuln">+ New Definition</button></div></div>
        <div class="toolbar"><input type="search" class="grow" id="v-q" placeholder="Search name or category…" value="${U.esc(state.q)}"/></div>
        <div class="card card-pad"><div class="table-wrap"><table class="tbl">
          <thead><tr><th>Name</th><th>OWASP Category</th><th>Module</th><th>Status</th><th class="actions">Actions</th></tr></thead>
          <tbody>${filtered.map(v => `<tr>
            <td><b>${U.esc(v.Name)}</b></td><td>${U.esc(v.OWASPCategory)}</td>
            <td>${v.ModuleKey ? '<span class="badge module">⚙</span>' : '<span class="chip-mini">KB only</span>'}</td>
            <td>${v.IsEnabled ? '<span class="badge enabled">Enabled</span>' : '<span class="badge disabled">Disabled</span>'}</td>
            <td class="actions">
              <button class="btn btn-xs btn-secondary" data-edit="${v.VulnerabilityID}">Edit</button>
              <button class="btn btn-xs ${v.IsEnabled ? 'btn-danger' : 'btn-secondary'}" data-toggle="${v.VulnerabilityID}">${v.IsEnabled ? 'Disable' : 'Enable'}</button>
            </td></tr>`).join('')}</tbody></table></div></div>`;
      el.querySelector('#add-vuln').addEventListener('click', () => vulnModal());
      el.querySelector('#v-q').addEventListener('input', debounce(e => { state.q = e.target.value.trim().toLowerCase(); render(); }, 300));
      el.querySelectorAll('[data-edit]').forEach(b => b.addEventListener('click', () => vulnModal(findIn(vulns, 'VulnerabilityID', parseInt(b.dataset.edit, 10)))));
      el.querySelectorAll('[data-toggle]').forEach(b => b.addEventListener('click', async () => {
        const v = findIn(vulns, 'VulnerabilityID', parseInt(b.dataset.toggle, 10));
        try { await API.put('/api/vulnerabilities/' + v.VulnerabilityID, { IsEnabled: !v.IsEnabled }); location.hash = '#/admin/vulnerabilities?r=' + Date.now(); }
        catch (err) { U.toast(err.message, 'err'); }
      }));
    }
    function vulnModal(v) {
      const editing = !!v;
      U.modal(editing ? 'Edit Vulnerability' : 'New Vulnerability Definition',
        `<div class="field"><label>Name</label><input id="v-name" maxlength="100" value="${U.esc(v ? v.Name : '')}" ${v && v.ModuleKey ? 'disabled' : ''} />
         ${v && v.ModuleKey ? '<div class="hint">Built-in detection module - name cannot be changed.</div>' : ''}</div>
         <div class="field"><label>OWASP Category</label><input id="v-cat" maxlength="50" value="${U.esc(v ? v.OWASPCategory : '')}"></div>
         <div class="field"><label>Description</label><textarea id="v-desc" rows="3">${U.esc(v ? v.Description : '')}</textarea></div>
         <div class="field"><label>Impact</label><textarea id="v-impact" rows="2">${U.esc(v ? v.Impact : '')}</textarea></div>
         <div class="field"><label>Remediation Recommendation</label><textarea id="v-rec" rows="2">${U.esc(v ? v.Recommendation : '')}</textarea></div>
         <div class="field"><label>Secure Coding Practice</label><textarea id="v-cod" rows="2">${U.esc(v ? v.SecurityCodingPractice : '')}</textarea></div>
         <div class="form-row">
           <div class="field"><label>OWASP Reference</label><input id="v-ref" maxlength="255" value="${U.esc(v ? v.OWASPReference : '')}"></div>
           <div class="field"><label>Reference URL</label><input id="v-url" maxlength="255" value="${U.esc(v ? v.ReferenceURL : '')}"></div>
         </div>
         <div class="field"><label><input type="checkbox" id="v-enabled" ${!v || v.IsEnabled ? 'checked' : ''}/> Enabled</label></div>`,
        `<button class="btn btn-secondary" onclick="U.closeModal()">Cancel</button>
         <button class="btn btn-primary" style="width:auto" id="v-save">${editing ? 'Save' : 'Create'}</button>`);
      document.getElementById('v-save').addEventListener('click', async () => {
        const body = {
          Name: document.getElementById('v-name').value.trim(),
          OWASPCategory: document.getElementById('v-cat').value.trim(),
          Description: document.getElementById('v-desc').value.trim(),
          Impact: document.getElementById('v-impact').value.trim(),
          Recommendation: document.getElementById('v-rec').value.trim(),
          SecurityCodingPractice: document.getElementById('v-cod').value.trim(),
          OWASPReference: document.getElementById('v-ref').value.trim(),
          ReferenceURL: document.getElementById('v-url').value.trim(),
          IsEnabled: document.getElementById('v-enabled').checked
        };
        try {
          if (editing) await API.put('/api/vulnerabilities/' + v.VulnerabilityID, body);
          else await API.post('/api/vulnerabilities', body);
          U.closeModal(); U.toast('Vulnerability saved.', 'ok'); location.hash = '#/admin/vulnerabilities?r=' + Date.now();
        } catch (err) { U.toast(err.message, 'err'); }
      });
    }
  }

  /* ============================================================ ADMIN: AUDIT LOGS */
  async function adminAudit(el) {
    const state = { page: 1, per: 20, category: '', search: '' };
    await render();
    async function render() {
      el.innerHTML = U.loading('Loading audit logs…');
      const q = { page: state.page, per_page: state.per };
      if (state.category) q.category = state.category;
      if (state.search) q.search = state.search;
      const data = await apiGetJson('/api/audit-logs', q);
      const logs = data.AuditLogs || [];
      const cats = data.Categories || [];
      el.innerHTML = `
        <div class="page-head"><h1>Security Audit Logs</h1>
          <div class="sub">Recorded user and system activities for accountability and monitoring (${data.Total}).</div></div>
        <div class="card card-pad">
          <div class="toolbar">
            <input type="search" class="grow" id="a-q" placeholder="Search description or action…" value="${U.esc(state.search)}"/>
            <select id="a-cat"><option value="">All categories</option>${cats.map(c => `<option ${state.category === c ? 'selected' : ''}>${U.esc(c)}</option>`).join('')}</select>
          </div>
          ${logs.length ? auditTable(logs) : U.empty('No audit records.')}
          <div id="pager"></div>
        </div>`;
      el.querySelector('#pager').appendChild(U.pager(state.page, state.per, data.Total || 0, p => { state.page = p; render(); }));
      el.querySelector('#a-cat').addEventListener('change', e => { state.category = e.target.value; state.page = 1; render(); });
      el.querySelector('#a-q').addEventListener('input', debounce(e => { state.search = e.target.value.trim(); state.page = 1; render(); }, 350));
    }
  }

  function auditTable(logs) {
    return `<div class="table-wrap"><table class="tbl">
      <thead><tr><th>Time</th><th>Category</th><th>Action</th><th>User</th><th>Description</th><th>Status</th><th>IP</th></tr></thead>
      <tbody>${logs.map(l => `<tr>
        <td class="tbl-nowrap">${U.fmtDT(l.EventTime)}</td>
        <td><span class="chip-mini">${U.esc(l.Category)}</span></td>
        <td class="mono">${U.esc(l.Action)}</td>
        <td>${U.esc(l.Username || '-')}</td>
        <td style="max-width:420px">${U.esc(l.Description || '')}</td>
        <td>${l.Status === 'Success' ? '<span class="badge active">Success</span>' : '<span class="badge failed">Failure</span>'}</td>
        <td class="mono">${U.esc(l.IPAddress || '-')}</td></tr>`).join('')}</tbody></table></div>`;
  }

  /* misc */
  function debounce(fn, ms) {
    let t;
    return function (...a) { clearTimeout(t); t = setTimeout(() => fn.apply(null, a), ms); };
  }

  window.VIEWS = {
    loginHtml, bindLogin, stopPolling,
    dashboard, newScan, scans, scanResult, knowledgeBase, profile,
    adminUsers, adminProfiles, adminVulns, adminAudit
  };
})();
