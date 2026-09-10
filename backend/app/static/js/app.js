/* VulnScan frontend controller: auth gate, hash router, app shell */
(function () {
  'use strict';

  const API = window.API, U = window.U, VIEWS = window.VIEWS;

  function parseQuery(q) {
    const out = {};
    if (!q) return out;
    new URLSearchParams(q).forEach((v, k) => { out[k] = v; });
    return out;
  }

  function isAuthed() { return !!API.token; }

  function navItems(role) {
    if (role === 'Administrator') {
      return [
        { label: 'Dashboard', href: '#/dashboard', icon: '🏠', active: h => h === 'dashboard' },
        { label: 'Users', href: '#/admin/users', icon: '👥', active: h => h === 'admin/users' },
        { label: 'Scan Profiles', href: '#/admin/profiles', icon: '📄', active: h => h === 'admin/profiles' },
        { label: 'Vulnerabilities', href: '#/admin/vulnerabilities', icon: '🪲', active: h => h === 'admin/vulnerabilities' },
        { label: 'Scans', href: '#/scans', icon: '📡', active: h => h === 'scans' },
        { label: 'Audit Logs', href: '#/admin/audit-logs', icon: '📋', active: h => h === 'admin/audit-logs' },
        { label: 'Knowledge Base', href: '#/knowledge-base', icon: '📚', active: h => h === 'knowledge-base' }
      ];
    }
    return [
      { label: 'Dashboard', href: '#/dashboard', icon: '🏠', active: h => h === 'dashboard' },
      { label: 'New Scan', href: '#/scans/new', icon: '➕', active: h => h === 'scans/new' },
      { label: 'My Scans', href: '#/scans', icon: '🕵️', active: h => h === 'scans' },
      { label: 'Knowledge Base', href: '#/knowledge-base', icon: '📚', active: h => h === 'knowledge-base' }
    ];
  }

  function shellHtml(hashKey, role) {
    const user = API.user || {};
    const items = navItems(role);
    const initials = (user.Username || '?').slice(0, 1).toUpperCase();
    return `
      <div class="shell">
        <aside class="sidebar">
          <div class="brand"><span class="logo">🛡️</span> VulnScan</div>
          <nav class="side-group">
            ${items.map(n => `
              <a class="side-link ${hashKey === n.activeKey ? '' : ''}" data-key="${escapeAttr(n.href)}" href="${n.href}" style="${n.active(hashKey) ? 'background:var(--blue-600);color:#fff' : ''}">
                <span class="ic">${n.icon}</span> ${n.label}</a>`).join('')}
          </nav>
          <div class="side-spacer"></div>
          <div class="side-group">
            <a class="side-link ${hashKey === 'profile' ? 'active' : ''}" href="#/profile"><span class="ic">👤</span> Profile</a>
            <a class="side-link" href="javascript:void(0)" id="logout-link"><span class="ic">🚪</span> Logout</a>
          </div>
        </aside>
        <div class="main">
          <header class="topbar">
            <div class="crumb" id="crumb"></div>
            <div class="user-chip">
              <div class="meta" style="text-align:right"><div class="name">${U.esc(user.Username || '')}</div>
                <div class="role">${U.esc(user.Role || '')}</div></div>
              <div class="avatar">${U.esc(initials)}</div>
            </div>
          </header>
          <div class="content" id="content"></div>
        </div>
      </div>`;
  }

  function escapeAttr(s) { return String(s).replace(/"/g, '&quot;'); }

  function setActive(segments) {
    // highlight nav by constructing a hash key
    const app = document.getElementById('app');
    if (!app) return;
    const key = hashKeyOf(segments);
    app.querySelectorAll('.side-link').forEach(a => {
      const href = a.getAttribute('href') || '';
      const base = href.split('?')[0];
      a.classList.remove('active');
      if (key && key === base) a.classList.add('active');
    });
  }

  function hashKeyOf(segments) {
    if (!segments.length) return '#/dashboard';
    if (segments[0] === 'admin') return '#/admin/' + (segments[1] || '');
    if (segments[0] === 'scans') return segments[1] === 'new' ? '#/scans/new' : (segments[1] ? '#/scans' : '#/scans');
    return '#/' + segments[0];
  }

  async function route() {
    const app = document.getElementById('app');
    const raw = location.hash || '#/dashboard';
    const path = raw.slice(1);
    const qIdx = path.indexOf('?');
    const cleanPath = qIdx >= 0 ? path.slice(0, qIdx) : path;
    const query = qIdx >= 0 ? path.slice(qIdx + 1) : '';
    const segments = cleanPath.split('/').filter(Boolean);
    const params = parseQuery(query);
    const user = API.user || {};

    // Not authenticated -> show the login page.
    if (!isAuthed()) {
      if (segments[0] !== 'login') { location.hash = '#/login'; return; }
      app.innerHTML = VIEWS.loginHtml(params);
      VIEWS.bindLogin(app);
      return;
    }
    // Authenticated user navigating to login -> dashboard.
    if (segments[0] === 'login' || segments.length === 0) {
      location.hash = '#/dashboard';
      return;
    }
    const role = user.Role;

    // Admin-only section guard
    if (segments[0] === 'admin' && role !== 'Administrator') {
      location.hash = '#/dashboard';
      return;
    }

    app.innerHTML = shellHtml(segments, role);
    const content = app.querySelector('#content');
    const crumb = app.querySelector('#crumb');

    document.getElementById('logout-link').addEventListener('click', async (e) => {
      e.preventDefault();
      try { await API.post('/api/auth/logout', {}); } catch (err) { /* ignore */ }
      API.clearAuth();
      location.hash = '#/login';
    });

    // breadcrumb
    let crumbParts = ['VulnScan'];
    if (segments[0] === 'admin') {
      const labels = { users: 'User Management', profiles: 'Scan Profiles', vulnerabilities: 'Vulnerabilities', 'audit-logs': 'Audit Logs' };
      crumbParts.push('Administration', labels[segments[1]] || '');
    } else if (segments[0] === 'scans') {
      crumbParts.push(segments[1] === 'new' ? 'New Scan' : (segments[1] ? 'Scan Result' : 'Scans'));
    } else {
      const labels = { dashboard: 'Dashboard', 'knowledge-base': 'Knowledge Base', profile: 'Profile' };
      crumbParts.push(labels[segments[0]] || segments[0]);
    }
    crumb.textContent = crumbParts.filter(Boolean).join(' › ');

    // Dispatch to the view
    if (VIEWS.stopPolling) VIEWS.stopPolling();
    content.innerHTML = U.loading('Loading…');
    try {
      const key = cleanPath;
      if (key === '/dashboard') return await VIEWS.dashboard(content, params);
      if (key === '/scans/new') return await VIEWS.newScan(content, params);
      if (key === '/scans') return await VIEWS.scans(content, params);
      if (segments[0] === 'scans' && segments[1] && /^\d+$/.test(segments[1])) return await VIEWS.scanResult(content, { id: segments[1] });
      if (key === '/knowledge-base') return await VIEWS.knowledgeBase(content, params);
      if (key === '/profile') return await VIEWS.profile(content, params);
      if (key === '/admin/users') return await VIEWS.adminUsers(content, params);
      if (key === '/admin/profiles') return await VIEWS.adminProfiles(content, params);
      if (key === '/admin/vulnerabilities') return await VIEWS.adminVulns(content, params);
      if (key === '/admin/audit-logs') return await VIEWS.adminAudit(content, params);
      // fallback
      content.innerHTML = U.empty('Page not found.');
    } catch (err) {
      if (!(err instanceof window.ApiError && err.status === 401)) {
        content.innerHTML = `<div class="card card-pad">${U.empty('Error: ' + U.esc(err.message))}</div>`;
      }
    }
    setActive(segments);
  }

  function init() {
    if (!location.hash) {
      location.hash = isAuthed() ? '#/dashboard' : '#/login';
    } else {
      route();
    }
  }

  window.addEventListener('hashchange', route);
  window.addEventListener('DOMContentLoaded', init);
})();
