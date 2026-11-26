/* VulnScan page views */
(function () {
  'use strict';

  const API = window.API, U = window.U;

  // Only same-app hash routes may be used as a post-login destination.
  function safeNext(next) {
    if (typeof next !== 'string') return '';
    return /^#\/[^\s]*$/.test(next) ? next : '';
  }

  const SEV_ORDER = ['None', 'Low', 'Medium', 'High', 'Critical'];
  const _pollTimers = [];
  let _pollTimer = null;
  let _pollBusy = false;
  /* Counts currently shown on the scan result page; used by the live poller to
     decide when a full re-render is actually needed. */
  let _rendered = { id: null, findings: 0, pages: 0 };
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

  function findIn(list, key, val) { return (list || []).find(x => x[key] === val); }

  async function apiGetJson(path, params) {
    return await API.get(path, params);
  }

  /* ---------------------------------------------------------------- live scan
     monitor (C1): consumes GET /api/scans/<id>/progress and renders only what
     the server can actually measure - unmeasurable values stay "-". */
  const TERMINAL_STATUSES = ['Completed', 'Failed', 'Cancelled'];
  const STAGE_TEXT = {
    queued: 'Queued — waiting for the scan worker',
    crawling: 'Crawling the target — discovering pages',
    analysing: 'Analysing pages — running detection modules',
    finalising: 'Finalising — persisting results',
    completed: 'Completed',
    failed: 'Failed',
    cancelled: 'Cancelled',
    pending: 'Queued — waiting for the scan worker',
    running: 'Running'
  };

  function fmtElapsed(sec) {
    if (sec === null || sec === undefined) return '–';
    const s = Math.max(0, Math.floor(Number(sec)));
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
    return (h ? h + 'h ' : '') + (h || m ? m + 'm ' : '') + ss + 's';
  }

  function livePanelHtml(p) {
    p = p || {};
    return `
      <div class="card card-pad live-panel" id="live-panel" aria-live="polite" aria-busy="true">
        <div class="row" style="justify-content:space-between;align-items:center">
          <h3 style="margin:0"><span class="live-dot"></span> Live Scan Progress</h3>
          <span class="mono" style="color:var(--muted)" data-live="elapsed">${U.esc(fmtElapsed(p.ElapsedSeconds))}</span>
        </div>
        <div class="live-stage" data-live="stage">${U.esc(STAGE_TEXT[p.Stage] || 'Starting…')}</div>
        <div class="live-bar" role="progressbar" aria-label="Pages analysed" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div class="live-bar-fill" data-live="bar-fill"></div></div>
        <div class="live-counters">
          <div><div class="val" data-live="pages">–</div><div class="lbl">Pages analysed / found</div></div>
          <div><div class="val" data-live="findings">–</div><div class="lbl">Finding records so far</div></div>
          <div><div class="val" data-live="requests">–</div><div class="lbl">HTTP requests issued</div></div>
        </div>
        <div class="live-modules" data-live="by-module"></div>
        <div class="live-errors" data-live="errors" style="display:none"></div>
        <div class="live-fallback" data-live="fallback" style="display:none">
          Live telemetry is unavailable for this scan (started before the last server restart, or handled by another
          worker). Counters shown are read from the database; request counts cannot be measured retroactively.
        </div>
      </div>`;
  }

  function updateLivePanel(el, p) {
    if (!p) return;
    const panel = el.querySelector('#live-panel');
    if (!panel) return;
    const set = (key, text) => {
      const n = panel.querySelector(`[data-live="${key}"]`);
      if (n) n.textContent = text;
    };
    set('stage', STAGE_TEXT[p.Stage] || p.Stage || 'Running');
    set('elapsed', fmtElapsed(p.ElapsedSeconds));
    set('pages', (p.PagesAnalysed == null ? '–' : p.PagesAnalysed) + ' / ' + (p.PagesFound == null ? '–' : p.PagesFound));
    set('findings', p.FindingCount == null ? '–' : String(p.FindingCount));
    set('requests', p.RequestsIssued == null ? '–' : String(p.RequestsIssued));
    const byModule = (p.FindingsByModule || []).map(m => U.esc(m.Name) + ': ' + m.Count).join(' · ');
    set('by-module', byModule ? 'Findings by module — ' + byModule : '');
    const pct = (p.PagesFound && p.PagesAnalysed != null)
      ? Math.max(0, Math.min(100, Math.round(p.PagesAnalysed / p.PagesFound * 100))) : 0;
    const fill = panel.querySelector('[data-live="bar-fill"]');
    if (fill) fill.style.width = pct + '%';
    const bar = panel.querySelector('.live-bar');
    if (bar) bar.setAttribute('aria-valuenow', String(pct));
    const errs = panel.querySelector('[data-live="errors"]');
    if (errs) {
      const list = p.Errors || [];
      errs.style.display = list.length ? '' : 'none';
      errs.innerHTML = list.map(e => `<div>Module error: ${U.esc(e)}</div>`).join('');
    }
    const fb = panel.querySelector('[data-live="fallback"]');
    if (fb) fb.style.display = (p.LiveAvailable === false) ? '' : 'none';
    panel.setAttribute('aria-busy', TERMINAL_STATUSES.includes(p.Status) ? 'false' : 'true');
  }

  /* ============================================================ LOGIN */
  /* Friendly text for errors the OAuth callback/Google return via the hash,
     e.g. '#/login?error=...'. Unknown values are shown verbatim. */
  const OAUTH_ERRORS = {
    missing_code: 'Google did not return an authorization code. Please try again.',
    google_network_error: 'Could not reach the server to complete Google sign-in. Please try again.',
    google_auth_failed: 'Google sign-in could not be completed. Please try again.',
    google_not_configured: 'Google Sign-In is not configured on this server.',
    redirect_uri_mismatch: 'Google rejected the callback address. Verify the Authorized redirect URI in Google Cloud Console.',
    access_denied: 'Google sign-in was cancelled.'
  };

  function loginHtml(params) {
    const rawError = (params && params.error) ? String(params.error) : '';
    const oauthError = rawError ? (OAUTH_ERRORS[rawError] || rawError) : '';
    const next = safeNext(params && params.next);
    const inviteNotice = next.indexOf('#/invitations/accept') === 0
      ? `<div style="background:var(--blue-bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:14px;font-size:13px">
           You have been invited to join a VulnScan team. Sign in with the email address the
           invitation was sent to, then accept it on the next screen.
         </div>`
      : '';
    return `
    <div class="login-wrap">
      <section class="login-intro">
        <div class="brand"><span class="logo">${U.icon('shield')}</span> VulnScan</div>
        <h1>Review web security findings</h1>
        <p class="lead">Assess authorised web applications, group recurring issues and decide what to fix.</p>
      </section>
      <div class="login-right">
        <div class="login-card">
          <h2>Sign in</h2>
          ${inviteNotice}
          <form id="login-form" autocomplete="on">
            <div class="field">
              <label for="email">Email address</label>
              <input id="email" name="email" type="email" placeholder="you@example.com" required autofocus />
            </div>
            <div class="field">
              <label for="password">Password</label>
              <input id="password" name="password" type="password" placeholder="Enter your password" required />
            </div>
            <div id="login-error" class="error-text" role="status">${U.esc(oauthError)}</div>
            <button class="btn btn-primary" type="submit">Sign in</button>
          </form>
          <div class="divider">or</div>
          <button id="google-btn" class="btn btn-google" type="button">
            <img src="/static/img/google-g.png" alt="" width="18" height="18" />
            <span>Sign in with Google</span>
          </button>
          <p class="form-footer">Contact your administrator if you need an account.</p>
        </div>
      </div>
      <figure class="assessment-preview" aria-labelledby="assessment-preview-title">
        <figcaption id="assessment-preview-title"><span>Sample assessment</span><span class="badge completed">Completed</span></figcaption>
        <div class="preview-totals">
          <div><strong>6</strong><span>Logical issues</span></div>
          <div><strong>36</strong><span>Finding records</span></div>
        </div>
        <ul class="preview-findings">
          <li><span class="preview-severity medium"></span><span>Missing Content Security Policy</span><span class="mono">6 URLs</span></li>
          <li><span class="preview-severity medium"></span><span>Missing frame protection</span><span class="mono">6 URLs</span></li>
          <li><span class="preview-severity low"></span><span>Missing referrer policy</span><span class="mono">6 URLs</span></li>
        </ul>
      </figure>
    </div>`;
  }

  function bindLogin(root, params) {
    const form = root.querySelector('#login-form');
    const errEl = root.querySelector('#login-error');
    const next = safeNext(params && params.next);
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
        location.hash = next || '#/dashboard';
      } catch (err) {
        errEl.textContent = err.message || 'Sign in failed.';
        btn.disabled = false;
      }
    });
    root.querySelector('#google-btn').addEventListener('click', async () => {
      try {
        const data = await API.get('/api/auth/google/url', { next: next || undefined });
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
    let findingTotal = 0, issueTotal = 0, highCritical = 0;
    (scans || []).forEach(s => {
      findingTotal += s.FindingCount || 0;
      issueTotal += s.IssueCount || 0;
      const sev = overallRisk(s.IssueSeverityCounts || s.SeverityCounts);
      if (sev === 'High' || sev === 'Critical') highCritical += (s.IssueCount || 0);
    });
    const recent = scans.slice(0, 6);
    el.innerHTML = `
      <div class="page-head">
        <h1>Developer dashboard</h1><p class="sub">Review assessment activity and grouped findings</p>
      </div>
      <div class="grid-cards">
        <div class="card stat-card"><div class="lbl">Total scans</div><div class="val">${scans.length}</div></div>
        <div class="card stat-card"><div class="lbl">High / critical issues</div><div class="val">${highCritical}</div></div>
        <div class="card stat-card"><div class="lbl">Logical issues</div><div class="val">${issueTotal}</div>
          <div class="metric-note">${findingTotal} finding records</div></div>
      </div>
      <div class="grid-2 dashboard-grid">
        <section class="card card-pad">
          <div class="panel-head"><h3>Recent scans</h3><a href="#/scans">View all scans</a></div>
          ${scans.length ? recentScansTable(recent) : U.empty('No scans yet')}
        </section>
        <aside class="card card-pad dashboard-help">
          <h3>Project assessments</h3>
          <p>Open an organisation and choose a project to start a scan.</p>
          <a href="#/organisations">View organisations</a>
          <hr />
          <h3>Knowledge base</h3>
          <p>Understand a finding and review its remediation guidance.</p>
          <a href="#/knowledge-base">Open knowledge base</a>
        </aside>
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
    let totalFindings = 0, totalIssues = 0;
    const counts = { None: 0, Low: 0, Medium: 0, High: 0, Critical: 0 };
    (scans).forEach(s => {
      totalFindings += s.FindingCount || 0;
      totalIssues += s.IssueCount || 0;
      SEV_ORDER.forEach(k => counts[k] += (s.IssueSeverityCounts || s.SeverityCounts || {})[k] || 0);
    });
    const recentScans = scans.slice(0, 6);
    const recentAudit = (await apiGetJson('/api/audit-logs', { per_page: 8 })).AuditLogs || [];
    el.innerHTML = `
      <div class="page-head"><h1>Administrator dashboard</h1>
        <p class="sub">Review system activity, users and assessment results</p></div>
      <div class="grid-cards">
        <div class="card stat-card"><div class="lbl">Total users</div><div class="val">${users.length}</div></div>
        <div class="card stat-card"><div class="lbl">Total scans</div><div class="val">${scans.length}</div></div>
        <div class="card stat-card"><div class="lbl">Logical issues</div><div class="val">${totalIssues}</div>
          <div class="metric-note">${totalFindings} finding records</div></div>
        <div class="card stat-card"><div class="lbl">High / critical issues</div><div class="val">${counts.High + counts.Critical}</div></div>
      </div>
      <div class="grid-2 dashboard-grid">
        <section class="card card-pad">
          <div class="panel-head"><h3>Recent scans</h3><a href="#/scans">View all scans</a></div>
          ${scans.length ? recentScansTable(recentScans) : U.empty('No scans yet')}
        </section>
        <section class="card card-pad">
          <h3>Issues by severity</h3>
          ${severityBreakdown(counts)}
        </section>
      </div>
      <div class="grid-2 dashboard-grid">
        <section class="card card-pad">
          <h3>Recent system activity</h3>
          ${recentAudit.length ? `<div class="table-wrap">${auditTable(recentAudit)}</div>` : U.empty('No recorded activity')}
        </section>
        <section class="card card-pad">
          <h3>Quick actions</h3>
          <div class="quick-actions">
            <a class="btn btn-secondary" href="#/admin/users">${U.icon('users')} Add user</a>
            <a class="btn btn-secondary" href="#/admin/profiles">${U.icon('file')} Create scan profile</a>
            <a class="btn btn-secondary" href="#/admin/vulnerabilities">${U.icon('bug')} Manage vulnerabilities</a>
            <a class="btn btn-secondary" href="#/admin/audit-logs">${U.icon('clipboard')} View audit logs</a>
          </div>
        </section>
      </div>`;
  }

  function severityBreakdown(counts) {
    const total = SEV_ORDER.reduce((sum, severity) => sum + (Number(counts[severity]) || 0), 0);
    const rows = SEV_ORDER.slice().reverse().map(severity => {
      const count = Number(counts[severity]) || 0;
      const share = total ? 100 * count / total : 0;
      return `<li class="severity-row ${severity.toLowerCase()}">
        <span>${severity}</span>
        <span class="severity-track" aria-hidden="true"><span style="--share:${share}%"></span></span>
        <span class="severity-count">${count} <small>${share.toFixed(1)}%</small></span>
      </li>`;
    }).join('');
    return `<ul class="severity-list">${rows}</ul><p class="severity-total"><span>Total</span><strong>${total}</strong></p>`;
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
        <div class="page-head"><h1>${isAdmin ? 'All scans' : 'My scans'}</h1>
          <div class="sub">${isAdmin ? 'Assessment activity across all users' : 'Review your previous and active scans'}</div></div>
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
    return `<div class="table-wrap" role="region" aria-label="Recent scans table" tabindex="0"><table class="tbl recent-scans">
      <thead><tr><th scope="col">Scan</th><th scope="col">Status and risk</th><th scope="col">Findings</th><th scope="col">Started</th><th scope="col" class="actions">Actions</th></tr></thead>
      <tbody>${scans.map(scan => `<tr>
        <td><span class="scan-name">${U.esc(scan.ScanName)}</span><span class="mono scan-ref">SCAN-${scan.ScanID}</span>
          <span class="mono scan-host">${U.esc(scan.TargetURL)}</span><span class="metric-note">${U.esc(scan.ScanProfileName || '–')}</span></td>
        <td><div class="scan-status">${U.statusBadge(scan.Status)}${U.sevBadge(overallRisk(scan.IssueSeverityCounts || scan.SeverityCounts))}</div></td>
        <td>${scan.IssueCount ?? '–'} issues<div class="metric-note">${scan.FindingCount || 0} records · ${scan.PageCount || 0} pages</div></td>
        <td>${U.fmtDT(scan.StartedAt)}</td>
        <td class="actions"><a class="btn btn-sm btn-secondary" href="#/scans/${scan.ScanID}">View</a></td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  function scansTable(scans) {
    return `<div class="table-wrap"><table class="tbl">
      <thead><tr><th>Scan</th><th>Target URL</th><th>Profile</th><th>Status</th><th>Risk</th><th>Issues / records</th><th>Started</th><th class="actions">Actions</th></tr></thead>
      <tbody>${scans.map(s => {
        const risk = overallRisk(s.IssueSeverityCounts || s.SeverityCounts);
        return `<tr>
          <td><b>${U.esc(s.ScanName)}</b><div class="mono scan-ref">SCAN-${s.ScanID}</div></td>
          <td class="mono">${U.esc(s.TargetURL)}</td>
          <td>${U.esc(s.ScanProfileName || '-')}</td>
          <td>${U.statusBadge(s.Status)}</td>
          <td>${U.sevBadge(risk)}</td>
          <td>${s.IssueCount != null ? s.IssueCount : '-'} <span style="color:var(--muted)">issue(s) · ${s.FindingCount || 0} record(s) on ${s.PageCount || 0} page(s)</span></td>
          <td class="tbl-nowrap">${U.fmtDT(s.StartedAt)}</td>
          <td class="actions"><a class="btn btn-sm btn-secondary" href="#/scans/${s.ScanID}">View</a></td>
        </tr>`;
      }).join('')}</tbody></table></div>`;
  }

  /* ============================================================ SCAN RESULT */
  /**
   * While a scan is running, poll the live progress endpoint (B1) and update
   * the monitor in place.  A full re-render only happens when the visible
   * counts change or the scan reaches a terminal state, so the page (and any
   * active filters) are not torn down on every tick.  Transient fetch or
   * render errors must never stop the refresh loop.
   */
  function startPolling(el, id) {
    if (_pollTimer) return;
    _pollTimer = setInterval(async () => {
      if (_pollBusy) return;
      _pollBusy = true;
      try {
        let p = null;
        try {
          const body = await apiGetJson('/api/scans/' + id + '/progress');
          p = body && body.Progress;
        } catch (e) { p = null; }
        if (p) {
          updateLivePanel(el, p);
          const terminal = TERMINAL_STATUSES.includes(p.Status);
          const countsChanged = (p.FindingCount != null && p.FindingCount !== _rendered.findings)
            || (p.PageCount != null && p.PageCount !== _rendered.pages);
          if (terminal || countsChanged) {
            if (terminal) clearTimers();
            await scanResult(el, { id: String(id) });
          }
        }
      } catch (e) {
        // transient - retry on next tick
      } finally {
        _pollBusy = false;
      }
    }, 2500);
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
    const issues = scan.FindingGroups || [];
    const open = findings.filter(f => f.Status === 'Open').length;
    const resolved = findings.filter(f => f.Status === 'Resolved').length;
    const falsePos = findings.filter(f => f.Status === 'False Positive').length;
    const openIssues = issues.filter(g => g.Status === 'Open').length;
    const resolvedIssues = issues.filter(g => g.Status === 'Resolved').length;
    const duration = scanDuration(scan.StartedAt, scan.FinishedAt, scan.Status);
    const isRunning = scan.Status === 'Running' || scan.Status === 'Pending';
    let progress = null;
    if (isRunning) {
      try {
        const body = await apiGetJson('/api/scans/' + id + '/progress');
        progress = body && body.Progress;
      } catch (e) { progress = null; }
    }
    el.innerHTML = `
      <div class="page-head row result-head">
        <div class="result-context"><h1>Scan results</h1>
          <p class="sub"><span class="mono scan-ref">SCAN-${scan.ScanID}</span> ${U.esc(scan.ScanName)}</p>
          <div class="mono result-target">${U.esc(scan.TargetURL)}</div>
        </div>
        <div class="result-actions">
          <a class="btn btn-secondary" href="#/scans">${U.icon('arrow-left')} Back</a>
          <button class="btn btn-secondary" id="dl-csv">CSV</button>
          <button class="btn btn-primary btn-action" id="dl-pdf">${U.icon('download')} Download PDF</button>
        </div>
      </div>
        ${isRunning ? livePanelHtml(progress) : ''}
      <div class="grid-cards result-metrics">
        <div class="card stat-card"><div class="lbl">Overall risk</div><div>${U.sevBadge(scan.OverallRisk)}</div></div>
        <div class="card stat-card"><div class="lbl">${issues.length ? 'Logical issues' : 'Finding records'}</div><div class="val">${issues.length || findings.length}</div>
          <div class="metric-note">${issues.length ? `Issues: ${openIssues} open · ${resolvedIssues} resolved<br/>` : ''}
            ${findings.length} records · ${open} open · ${resolved} resolved · ${falsePos} false positive</div></div>
        <div class="card stat-card"><div class="lbl">Scan status</div><div>${U.statusBadge(scan.Status)}</div></div>
        <div class="card stat-card"><div class="lbl">Duration</div><div class="val">${duration}</div><div class="metric-note">${U.fmtDT(scan.StartedAt)}</div></div>
      </div>
      <div class="grid-2 result-grid">
        <section class="card card-pad">
          <div class="panel-head">
            <h3>Findings</h3>
            ${isRunning ? '<span class="badge running">Live — updates automatically</span>' : ''}
            <span class="metric-note">${issues.length} issues · ${findings.length} records</span>
          </div>
          <div class="toolbar finding-filters">
            <input type="search" id="f-search" aria-label="Search findings" placeholder="Search findings" />
            <select id="f-group" aria-label="Group findings"><option value="issue">Group by issue</option><option value="">Show records</option><option value="vuln">Group by vulnerability</option><option value="page">Group by page</option></select>
            <select id="f-sev" aria-label="Severity"><option value="">All severities</option>${SEV_ORDER.slice(1).map(s => `<option>${s}</option>`).join('')}</select>
            <select id="f-class" aria-label="Classification"><option value="">All classes</option><option>Confirmed</option><option>Suspected</option><option>Unclassified</option></select>
            <select id="f-tech" aria-label="Technique"><option value="">All techniques</option></select>
            <select id="f-status" aria-label="Status"><option value="">All statuses</option><option>Open</option><option>Resolved</option><option>False Positive</option></select>
            <button class="btn btn-sm btn-secondary" id="f-reset">Reset</button>
          </div>
          <div id="findings-box">${U.loading()}</div>
        </section>
        <div class="result-secondary">
          <section class="card card-pad">
            <h3>Finding records by severity</h3>
            ${severityBreakdown(counts)}
          </section>
          <div class="card card-pad">
            <h3>Scan information</h3>
            <div class="kv">
              <span class="k">Scan ID</span><span class="mono">SCAN-${scan.ScanID}</span>
              <span class="k">Target URL</span><span class="mono">${U.esc(scan.TargetURL)}</span>
              <span class="k">Scan Profile</span><span>${U.esc(scan.ScanProfileName || '-')}</span>
              <span class="k">Authentication</span><span>${scan.Authentication && scan.Authentication.Mode === 'Authenticated'
                ? `Temporary credential #${scan.Authentication.CredentialID} (${U.esc(scan.Authentication.CredentialName || '')})`
                : 'Anonymous session'}</span>
              <span class="k">Started By</span><span>${U.esc(scan.Username || '-')}</span>
              <span class="k">Started</span><span>${U.fmtDT(scan.StartedAt)}</span>
              <span class="k">Finished</span><span>${U.fmtDT(scan.FinishedAt)}</span>
              <span class="k">Discovered Pages</span><span>${scan.PageCount || 0}</span>
              <span class="k">Pages Analysed</span><span>${scan.AnalysedPages == null ? '–' : scan.AnalysedPages} of ${scan.PageCount || 0}</span>
              <span class="k">Tested Parameters</span><span class="mono">${(scan.TestedParameters && scan.TestedParameters.length) ? U.esc(scan.TestedParameters.join(', ')) : '–'}</span>
            </div>
          </div>
        </div>
      </div>
      <div class="card card-pad" style="margin-top:16px">
        <h3>Coverage and limitations</h3>
        <p style="color:var(--muted);margin:6px 0 0">${U.esc(scan.CoverageNote || 'Coverage details are not available for this scan.')}</p>
        ${(() => {
          const d = scan.Coverage && scan.Coverage.Discovery;
          if (!d || !d.Available) return '';
          const s = d.Sources || {}, r = d.RobotsTxt || {}, m = d.Sitemaps || {}, x = d.Excluded || {};
          const samples = [].concat((x.Samples && x.Samples.Robots) || [], (x.Samples && x.Samples.Scope) || []).slice(0, 10);
          return `<div style="margin-top:10px"><div class="k">Page discovery</div><div class="kv">
            <span class="k">Links followed</span><span>${s.Links || 0}</span>
            <span class="k">Sitemap URLs</span><span>${s.Sitemaps || 0}</span>
            <span class="k">GET form actions</span><span>${s.FormActions || 0}</span>
            <span class="k">robots.txt</span><span>${r.Respected === false ? 'not consulted' : (r.Fetched ? `consulted (HTTP ${r.HTTPStatus})` : 'not usable')}${(r.RulesApplied || 0) ? ` &middot; ${r.RulesApplied} rule(s)` : ''}</span>
            <span class="k">Excluded by robots.txt</span><span>${r.BlockedCount || 0}</span>
            <span class="k">Rejected by scope/safety</span><span>${x.ScopeRejectedCount || 0}</span>
            <span class="k">Sitemaps parsed</span><span>${m.Parsed || 0}${(m.RejectedCount || 0) ? ` (${m.RejectedCount} rejected)` : ''}</span>
          </div>${samples.length ? `<div class="k" style="margin-top:8px">Not requested</div><div class="kv">${samples.map(e => `<span class="k mono">${U.esc(e.URL)}</span><span>${U.esc(e.Reason || '')}</span>`).join('')}</div>` : ''}</div>`;
        })()}
        ${(scan.SkippedPages || []).length ? `<div style="margin-top:10px"><div class="k">Stored but not analysed (${scan.SkippedPages.length})</div><div class="kv">${scan.SkippedPages.map(p => `<span class="k mono">${U.esc(p.URL)}</span><span>HTTP ${p.HTTPStatus == null ? '–' : p.HTTPStatus}</span>`).join('')}</div></div>` : ''}
      </div>
      <div class="card card-pad" style="margin-top:16px">
        <h3>Discovered pages (${scan.Pages ? scan.Pages.length : 0})</h3>
        ${renderPages(scan.Pages || [])}
      </div>`;
    bindFindings(el.querySelector('#findings-box'), findings, id, { open, resolved, falsePos });
    const techSel = el.querySelector('#f-tech');
    [...new Set(findings.map(f => f.Technique).filter(Boolean))].sort().forEach(t => {
      const o = document.createElement('option');
      o.value = t; o.textContent = t;
      techSel.appendChild(o);
    });
    el.querySelector('#f-search').addEventListener('input', debounce(() => renderFiltered(), 300));
    el.querySelector('#f-sev').addEventListener('change', renderFiltered);
    el.querySelector('#f-class').addEventListener('change', renderFiltered);
    el.querySelector('#f-tech').addEventListener('change', renderFiltered);
    el.querySelector('#f-status').addEventListener('change', renderFiltered);
    el.querySelector('#f-group').addEventListener('change', renderFiltered);
    el.querySelector('#f-reset').addEventListener('click', () => {
      el.querySelector('#f-search').value = '';
      el.querySelector('#f-sev').value = '';
      el.querySelector('#f-class').value = '';
      el.querySelector('#f-tech').value = '';
      el.querySelector('#f-status').value = '';
      el.querySelector('#f-group').value = 'issue';
      renderFiltered();
    });
    function currentFilters() {
      return {
        q: el.querySelector('#f-search').value.trim().toLowerCase(),
        sev: el.querySelector('#f-sev').value,
        cls: el.querySelector('#f-class').value,
        tech: el.querySelector('#f-tech').value,
        status: el.querySelector('#f-status').value,
        group: el.querySelector('#f-group').value
      };
    }
    function renderFiltered() {
      const box = el.querySelector('#findings-box');
      const f = currentFilters();
      if (f.group === 'issue') {
        box.innerHTML = issueTable(issues.filter(g => matchesIssue(g, f)), id);
        wireIssueRows(box);
        return;
      }
      const filtered = findings.filter(x =>
        (!f.q || (x.VulnerabilityName || '').toLowerCase().includes(f.q) ||
          (x.URL || '').toLowerCase().includes(f.q) ||
          (x.Technique || '').toLowerCase().includes(f.q)) &&
        (!f.sev || x.Severity === f.sev) &&
        (!f.cls || (x.Classification || '') === f.cls) &&
        (!f.tech || (x.Technique || '') === f.tech) &&
        (!f.status || x.Status === f.status));
      box.innerHTML = f.group
        ? findingsGrouped(filtered, id, f.group)
        : findingsTable(filtered, id, null);
      wireFindingRows(box);
    }
    /* Issue-level filters use the group's worst-member severity and its
       derived status, so filtering never disagrees with what is displayed. */
    function matchesIssue(g, f) {
      const hay = [g.VulnerabilityName, g.GroupKey,
        (g.Parameters || []).join(' '), (g.AffectedURLs || []).join(' ')]
        .join(' ').toLowerCase();
      const techniques = (g.Locations || []).map(l => l.Technique).filter(Boolean);
      return (!f.q || hay.includes(f.q)) &&
        (!f.sev || g.Severity === f.sev) &&
        (!f.cls || g.Classification === f.cls) &&
        (!f.tech || techniques.includes(f.tech)) &&
        (!f.status || g.Status === f.status);
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

    // Seed the live panel (fetch may have raced the first render), remember the
    // counts this render shows, then start refreshing while the scan runs.
    if (isRunning) {
      updateLivePanel(el, progress || {
        Stage: scan.Status === 'Pending' ? 'queued' : 'running',
        Status: scan.Status,
        LiveAvailable: null,
        PagesFound: null, PagesAnalysed: null,
        FindingCount: findings.length, RequestsIssued: null,
        Errors: [], FindingsByModule: []
      });
    }
    _rendered = { id: id, findings: findings.length, pages: (scan.Pages || []).length };
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

  function findingsTable(findings, scanId) {
    if (!findings.length) return U.empty('No findings match your filters.');
    // A minimum width keeps the columns readable instead of letting `.mono`
    // URLs wrap character-by-character; `.table-wrap` scrolls horizontally.
    return `<div class="table-wrap"><table class="tbl" style="min-width:900px">
      <thead><tr><th>Vulnerability</th><th>Severity</th><th>Evidence</th><th>Risk</th><th>Status</th><th>Location</th><th>Actions</th></tr></thead>
      <tbody>${findings.map(f => `
        <tr class="finding-row" data-id="${f.FindingID}">
          <td><b>${U.esc(f.VulnerabilityName)}</b><div style="color:var(--muted);font-size:11.5px">${U.esc(f.OWASPCategory || '')}</div></td>
          <td>${U.sevBadge(f.Severity)}</td>
          <td><span class="badge ${(f.Classification || '').toLowerCase()}">${U.esc(f.Classification || '-')}</span><div style="color:var(--muted);font-size:11px">${f.Confidence != null ? Math.round(Number(f.Confidence) * 100) + '% confidence' : ''}</div></td>
          <td>${f.RiskScore != null ? Number(f.RiskScore).toFixed(1) : '-'}</td>
          <td>${U.statusBadge(f.Status)}</td>
          <td class="mono">${U.esc(f.URL || '')}${f.Parameter ? ' <span class="chip-mini">param: ' + U.esc(f.Parameter) + '</span>' : ''}${f.GroupKey ? ` <span class="chip-mini" data-goto-group="${U.esc(f.GroupKey)}" title="Logical issue: ${U.esc(f.GroupKey)}">issue: ${U.esc(shortKey(f.GroupKey))}</span>` : ''}</td>
          <td class="actions">${findingActions(f)}</td>
        </tr>
        ${findingDetailRow(f)}`).join('')}</tbody></table></div>`;
  }

  function findingActions(f) {
    return `<button class="btn btn-xs btn-secondary" data-detail="1" title="Details">Detail</button>
      <button class="btn btn-xs btn-secondary" data-retest="1" title="Re-run the original detection against this page to verify the finding">Retest</button>
      <select class="status-select" data-status="1">
        <option value="Open" ${f.Status === 'Open' ? 'selected' : ''}>Open</option>
        <option value="Resolved" ${f.Status === 'Resolved' ? 'selected' : ''}>Resolved</option>
        <option value="False Positive" ${f.Status === 'False Positive' ? 'selected' : ''}>False Positive</option>
      </select>`;
  }

  function findingDetailRow(f) {
    return `<tr class="detail-row" id="detail-${f.FindingID}" style="display:none">
          <td colspan="7">
            <div class="card" style="padding:12px;box-shadow:none;border-color:var(--border)">
              <div style="font-weight:700">${U.esc(f.VulnerabilityName)} · ${U.esc(f.Severity)} · ${U.esc(f.Classification || '')} (CVSS ${f.RiskScore != null ? Number(f.RiskScore).toFixed(1) : '-'})</div>
              <div style="margin-top:5px;display:flex;gap:6px;flex-wrap:wrap">
                ${f.Technique ? `<span class="badge module">${U.esc(f.Technique)}</span>` : ''}
                ${f.CVSSVector ? `<span class="chip-mini mono">${U.esc(f.CVSSVector)}</span>` : ''}
                <span class="chip-mini">Confidence ${f.Confidence != null ? Math.round(Number(f.Confidence) * 100) + '%' : '–'}</span>
                <span class="chip-mini">Detected ${U.fmtDT(f.DetectedAt)}</span>
              </div>
              ${(f.Retests || []).length ? beforeAfterHtml(f) : ''}
              <div class="mono" style="margin:6px 0 4px">${U.esc(f.URL)} ${f.RequestMethod ? '(' + U.esc(f.RequestMethod) + ')' : ''} ${f.Parameter ? '· param ' + U.esc(f.Parameter) : ''}</div>
              ${f.Payload ? `<div style="margin:4px 0"><b>Payload:</b> <span class="mono">${U.esc(f.Payload)}</span></div>` : ''}
              <div class="evidence">${evidenceHtml(f.Evidence || '')}</div>
              ${f.Description ? `<p style="margin-top:8px"><b>Description:</b> ${U.esc(f.Description)}</p>` : ''}
              ${f.Impact ? `<p style="margin-top:6px"><b>Impact:</b> ${U.esc(f.Impact)}</p>` : ''}
              ${f.Recommendation ? `<p style="margin-top:6px"><b>Remediation:</b> ${U.esc(f.Recommendation)}</p>` : ''}
            </div>
          </td>
        </tr>`;
  }

  /* Location table used inside an expanded issue: the vulnerability heading and
     group key are already shown, so it focuses on the per-record facts. */
  function locationTable(locations, scanId) {
    if (!locations.length) return U.empty('No records in this issue.');
    return `<div class="table-wrap"><table class="tbl" style="min-width:820px">
      <thead><tr><th>Location</th><th>Method</th><th>Severity</th><th>Evidence</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody>${locations.map(f => `
        <tr class="finding-row" data-id="${f.FindingID}">
          <td class="mono">${U.esc(f.URL || '')}${f.Parameter ? ' <span class="chip-mini">param: ' + U.esc(f.Parameter) + '</span>' : ''}</td>
          <td>${U.esc(f.RequestMethod || 'GET')}</td>
          <td>${U.sevBadge(f.Severity)}</td>
          <td><span class="badge ${(f.Classification || '').toLowerCase()}">${U.esc(f.Classification || '-')}</span><div style="color:var(--muted);font-size:11px">${f.Confidence != null ? Math.round(Number(f.Confidence) * 100) + '% confidence' : ''}</div></td>
          <td>${U.statusBadge(f.Status)}</td>
          <td class="actions">${findingActions(f)}</td>
        </tr>
        ${findingDetailRow(f)}`).join('')}</tbody></table></div>`;
  }

  /* One collapsible row per logical issue (P3).  Expanding it shows the
     underlying finding records with their own evidence, status and per-record
     Retest / Detail / Status controls, so page-level investigation is intact. */
  function issueTable(issues, scanId) {
    if (!issues.length) return U.empty('No issues match your filters.');
    return issues.map(g => {
      const counts = g.StatusCounts || {};
      const conditions = g.ConditionCounts || {};
      const observedOnly = (g.AffectedURLs || []).length > (g.PageCount || 0);
      return `<details class="f-group" data-group="${U.esc(g.GroupKey)}" data-records="${g.RecordCount}">
        <summary>
          <span class="g-title">${U.esc(g.VulnerabilityName || 'Issue')}${(g.Parameters || []).length ? ' · ' + U.esc(g.Parameters.join(', ')) : ''}</span>
          <span class="g-meta"><span class="mono">${g.AffectedURLCount}</span> affected ${g.AffectedURLCount === 1 ? 'URL' : 'URLs'} · <span class="mono">${g.RecordCount}</span> ${g.RecordCount === 1 ? 'record' : 'records'}</span>
          <span class="finding-state">
            ${U.sevBadge(g.Severity)}
            ${U.statusBadge(g.Status)}
            ${g.Mixed ? `<span class="badge suspected">Mixed</span>` : ''}
          </span>
        </summary>
        <div style="padding:8px 0 4px">
          <div class="toolbar" style="gap:8px;flex-wrap:wrap;margin-bottom:6px">
            <button class="btn btn-sm btn-secondary" data-group-retest="1">Retest all ${g.RecordCount} record(s)</button>
            <select class="status-select" data-group-status="1">
              <option value="">Set status for all ${g.RecordCount} record(s)…</option>
              <option value="Open">Open</option>
              <option value="Resolved">Resolved</option>
              <option value="False Positive">False Positive</option>
            </select>
            ${Object.entries(counts).filter(([, n]) => n).map(([k, n]) => `<span class="chip-mini">${U.esc(k)}: ${n}</span>`).join(' ')}
            ${Object.entries(conditions).filter(([, n]) => n).map(([k, n]) => `<span class="chip-mini">${U.esc(k)}: ${n}</span>`).join(' ')}
          </div>
          <div class="mono" style="font-size:11.5px;color:var(--muted)">${U.esc(g.GroupKey)}</div>
          ${observedOnly ? `<div style="margin:6px 0"><b>Observed URLs (${g.AffectedURLs.length}):</b><div class="mono" style="font-size:11.5px">${g.AffectedURLs.map(u => U.esc(u)).join('<br/>')}</div></div>` : ''}
          ${locationTable(g.Locations || [], scanId)}
        </div>
      </details>`;
    }).join('');
  }

  /* Group-level actions: retest the whole issue (bounded server-side) or apply
     one status to every underlying record after an explicit confirmation. */
  function wireIssueRows(box) {
    const scanId = parseInt(location.hash.split('/')[2], 10);
    box.querySelectorAll('button[data-group-retest]').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.preventDefault(); e.stopPropagation();
        const details = btn.closest('details.f-group');
        const key = details.dataset.group;
        const label = btn.textContent;
        btn.disabled = true; btn.textContent = 'Re-verifying…';
        try {
          const data = await API.post(
            `/api/scans/${scanId}/finding-groups/${encodeURIComponent(key)}/retest`, {});
          const r = data.Retest || {};
          U.toast(
            `Group retest: ${r.AggregateVerdict} — ${r.Completed} verified, ` +
            `${r.Failed} failed, ${r.NotAttempted} not attempted` +
            (r.Partial ? ' (partial coverage)' : ''),
            r.AggregateVerdict === 'Resolved' ? 'ok'
              : r.AggregateVerdict === 'Still Detected' ? 'err' : 'info');
        } catch (err) {
          U.toast(err.message, 'err');
        } finally {
          btn.disabled = false; btn.textContent = label;
          location.hash = '#/scans/' + scanId + '?r=' + Date.now();
        }
      });
    });
    box.querySelectorAll('select[data-group-status]').forEach(sel => {
      sel.addEventListener('click', e => e.stopPropagation());
      sel.addEventListener('change', async () => {
        const details = sel.closest('details.f-group');
        const key = details.dataset.group;
        const status = sel.value;
        const count = details.dataset.records;
        if (!status) return;
        const ok = window.confirm(
          `Apply "${status}" to ALL ${count} finding record(s) of this issue?\n\n` +
          'This updates every underlying finding. Individual records keep their ' +
          'own controls and can be changed afterwards.');
        if (!ok) { sel.value = ''; return; }
        try {
          const data = await API.put(
            `/api/scans/${scanId}/finding-groups/${encodeURIComponent(key)}`,
            { status });
          U.toast(`${data.Updated} record(s) updated — issue now reports ${data.Group.Status}.`,
            'ok');
        } catch (err) {
          U.toast(err.message, 'err');
        } finally {
          location.hash = '#/scans/' + scanId + '?r=' + Date.now();
        }
      });
    });
    wireFindingRows(box);
  }

  function shortKey(key) {
    const text = String(key || '').replace(/^v1:/, '');
    return text.length > 40 ? text.slice(0, 37) + '…' : text;
  }

  /* Groups records into collapsible sections by vulnerability or page (C2).
     Each group keeps the regular findings table, so detail toggles and status
     updates are unchanged; this remains the record-based views. */
  function findingsGrouped(findings, scanId, mode) {
    if (!findings.length) return U.empty('No findings match your filters.');
    const groups = new Map();
    findings.forEach(f => {
      const key = mode === 'page' ? (f.URL || '(unknown page)') : (f.VulnerabilityName || '(unknown)');
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(f);
    });
    return [...groups.entries()].map(([name, items]) => {
      const worst = items.slice().sort((a, b) => SEV_ORDER.indexOf(b.Severity) - SEV_ORDER.indexOf(a.Severity))[0].Severity;
      const conf = items.filter(i => i.Classification === 'Confirmed').length;
      const susp = items.filter(i => i.Classification === 'Suspected').length;
      const locations = new Set(items.map(i => i.URL)).size;
      return `<details class="f-group" open>
        <summary>
          <span class="g-title">${U.esc(name)}</span>
          <span class="g-meta">${items.length} finding${items.length === 1 ? '' : 's'} · ${locations} location${locations === 1 ? '' : 's'}</span>
          ${U.sevBadge(worst)}
          ${conf ? `<span class="badge confirmed">${conf} confirmed</span>` : ''}
          ${susp ? `<span class="badge suspected">${susp} suspected</span>` : ''}
        </summary>
        ${findingsTable(items, scanId, null)}
      </details>`;
    }).join('');
  }

  /* Renders stored evidence as escaped text with emphasised section headers. */
  function evidenceHtml(text) {
    return U.esc(text).replace(/^([A-Z][A-Z0-9 /()\-]{2,48}):/gm, '<b>$1:</b>');
  }

  /* Before/after verification comparison (D2) for re-tested findings. */
  function beforeAfterHtml(f) {
    const history = f.Retests || [];
    const r = history[history.length - 1];
    const cls = r.Verdict === 'Resolved' ? 'ba-resolved'
      : r.Verdict === 'Still Detected' ? 'ba-detected' : 'ba-neutral';
    const badgeCls = r.Verdict === 'Resolved' ? 'confirmed'
      : r.Verdict === 'Still Detected' ? 'failed' : 'unclassified';
    const conf = f.Confidence != null ? Math.round(Number(f.Confidence) * 100) + '%' : '–';
    const retestMeta = [
      r.Confidence != null ? 'confidence ' + Math.round(Number(r.Confidence) * 100) + '%' : null,
      r.RequestsIssued != null ? r.RequestsIssued + ' request(s)' : null
    ].filter(Boolean).join(' · ');
    return `
      <div class="ba-grid ${cls}">
        <div class="ba-col">
          <div class="ba-title">Original detection</div>
          <div class="ba-line">${U.esc(f.Classification || '–')} · CVSS ${f.RiskScore != null ? Number(f.RiskScore).toFixed(1) : '–'} · confidence ${conf}</div>
          <div class="ba-line" style="color:var(--muted)">${U.fmtDT(f.DetectedAt)}${f.Technique ? ' · ' + U.esc(f.Technique) : ''}</div>
        </div>
        <div class="ba-arrow">→</div>
        <div class="ba-col">
          <div class="ba-title">Latest verification <span style="color:var(--muted);font-weight:400">${U.esc(r.At)}</span></div>
          <div class="ba-line"><span class="badge ${badgeCls}">${U.esc(r.Verdict)}</span></div>
          ${retestMeta ? `<div class="ba-line" style="color:var(--muted)">${U.esc(retestMeta)}</div>` : ''}
          <div class="ba-line" style="color:var(--muted)">${U.esc(r.Message || '')}</div>
        </div>
      </div>
      ${history.length > 1 ? `<div class="ba-history">${history.map(x => `<span class="chip-mini">${U.esc(x.At)} · ${U.esc(x.Verdict)}</span>`).join('')}</div>` : ''}`;
  }

  function wireFindingRows(box) {
    box.querySelectorAll('[data-goto-group]').forEach(chip => {
      chip.style.cursor = 'pointer';
      chip.addEventListener('click', (e) => {
        e.preventDefault(); e.stopPropagation();
        const select = document.getElementById('f-group');
        if (select) {
          select.value = 'issue';
          select.dispatchEvent(new Event('change'));
        }
        const target = box.querySelector(
          `details.f-group[data-group="${CSS.escape(chip.dataset.gotoGroup)}"]`);
        if (target) {
          target.open = true;
          target.scrollIntoView({ block: 'nearest' });
        }
      });
    });
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
    box.querySelectorAll('button[data-retest]').forEach(b => {
      b.addEventListener('click', async () => {
        const row = b.closest('tr.finding-row');
        const fid = parseInt(row.dataset.id, 10);
        const scanId = parseInt(location.hash.split('/')[2], 10);
        b.disabled = true; b.textContent = 'Verifying…';
        try {
          const data = await API.post(`/api/scans/${scanId}/findings/${fid}/retest`, {});
          const verdict = data.Retest.Verdict;
          U.toast('Retest verdict: ' + verdict + ' — ' + data.Retest.Message,
            verdict === 'Still Detected' ? 'err' : verdict === 'Resolved' ? 'ok' : 'info');
        } catch (err) {
          U.toast(err.message, 'err');
        } finally {
          b.disabled = false; b.textContent = 'Retest';
          location.hash = '#/scans/' + scanId + '?r=' + Date.now();
        }
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
  /* Renders KB practice text: "Unsafe:" / "Safe:" blocks become labelled code
     examples; everything else stays escaped prose. */
  function kbRichText(text) {
    const blocks = String(text || '').split(/\n\s*\n/).filter(b => b.trim());
    if (!blocks.length) return '';
    return blocks.map(b => {
      const m = b.match(/^(Unsafe|Safe):[ \t]*\r?\n?([\s\S]*)$/i);
      if (m) {
        const cls = m[1].toLowerCase();
        return `<div class="kb-example kb-${cls}">
          <div class="kb-ex-label">${cls === 'unsafe' ? 'Unsafe pattern' : 'Safe pattern'}</div>
          <pre class="kb-code">${U.esc((m[2] || '').trim())}</pre></div>`;
      }
      return `<p style="white-space:pre-wrap;margin-top:6px">${U.esc(b)}</p>`;
    }).join('');
  }

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
              ${v.ModuleKey ? '<span class="badge module">Detection module</span>' : ''}
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
          <p style="margin-top:8px"><b>Secure Coding Practice</b></p>${kbRichText(v.SecurityCodingPractice)}
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
            <td>${v.ModuleKey ? '<span class="badge module">Detection module</span>' : '<span class="chip-mini">KB only</span>'}</td>
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
    dashboard, scans, scanResult, knowledgeBase, profile,
    adminUsers, adminProfiles, adminVulns, adminAudit
  };
})();
