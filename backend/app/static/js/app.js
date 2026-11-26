/* VulnScan frontend controller: auth gate, hash router, app shell */
(function () {
  'use strict';

  const API = window.API, U = window.U, VIEWS = window.VIEWS, TRUST = window.TRUST_VIEWS;

  function parseQuery(q) {
    const out = {};
    if (!q) return out;
    new URLSearchParams(q).forEach((v, k) => { out[k] = v; });
    return out;
  }

  // Only same-app hash routes may be used as a post-login destination.
  function safeNext(next) {
    if (typeof next !== 'string') return '';
    return /^#\/[^\s]*$/.test(next) ? next : '';
  }

  function isAuthed() { return !!API.token; }

  function navItems(role) {
    const overview = [
      { label: 'Dashboard', href: '#/dashboard', icon: 'dashboard' },
      { label: 'Organisations', href: '#/organisations', icon: 'building' }
    ];
    const knowledge = { label: 'Knowledge base', href: '#/knowledge-base', icon: 'book' };
    if (role === 'Administrator') {
      return [
        ...overview,
        { label: 'Users', href: '#/admin/users', icon: 'users' },
        { label: 'Scan profiles', href: '#/admin/profiles', icon: 'file' },
        { label: 'Vulnerabilities', href: '#/admin/vulnerabilities', icon: 'bug' },
        { label: 'Scans', href: '#/scans', icon: 'radar' },
        { label: 'Audit logs', href: '#/admin/audit-logs', icon: 'clipboard' },
        knowledge
      ];
    }
    return [
      ...overview,
      { label: 'My scans', href: '#/scans', icon: 'radar' },
      knowledge
    ];
  }

  function navLink(item, selectedKey, currentRoute) {
    const selected = item.href === selectedKey;
    const current = item.href === currentRoute ? 'page' : 'location';
    return `<a class="side-link${selected ? ' active' : ''}" href="${item.href}"${selected ? ` aria-current="${current}"` : ''}>
      <span class="ic">${U.icon(item.icon)}</span>${item.label}
    </a>`;
  }

  function shellHtml(segments, role) {
    const user = API.user || {};
    const selectedKey = hashKeyOf(segments);
    const currentRoute = '#/' + segments.join('/');
    const initials = (user.Username || '?').slice(0, 1).toUpperCase();
    return `
      <div class="shell">
        <aside class="sidebar" id="app-sidebar">
          <div class="brand"><span class="logo">${U.icon('shield')}</span> VulnScan</div>
          <nav class="side-group" aria-label="Main navigation">
            ${navItems(role).map(item => navLink(item, selectedKey, currentRoute)).join('')}
          </nav>
          <div class="side-spacer"></div>
          <div class="side-group">
            ${navLink({ label: 'Profile', href: '#/profile', icon: 'user' }, selectedKey, currentRoute)}
            <button class="side-link" type="button" id="logout-link"><span class="ic">${U.icon('logout')}</span>Sign out</button>
          </div>
        </aside>
        <div class="main">
          <header class="topbar">
            <div class="topbar-location">
              <button class="sidebar-toggle" type="button" aria-label="Navigation menu"
                aria-expanded="false" aria-controls="app-sidebar">${U.icon('menu')}</button>
              <div class="crumb" id="crumb"></div>
            </div>
            <div class="user-chip">
              <div class="meta"><div class="name">${U.esc(user.Username || '')}</div>
                <div class="role">${U.esc(user.Role || '')}</div></div>
              <div class="avatar" aria-hidden="true">${U.esc(initials)}</div>
            </div>
          </header>
          <main class="content" id="content" tabindex="-1"></main>
        </div>
      </div>`;
  }

  function bindSidebar(shell) {
    const sidebar = shell.querySelector('#app-sidebar');
    const toggle = shell.querySelector('.sidebar-toggle');
    const isOpen = () => shell.classList.contains('nav-open');
    function setOpen(open) {
      shell.classList.toggle('nav-open', open);
      toggle.setAttribute('aria-expanded', String(open));
    }
    function closeAndFocusToggle() {
      setOpen(false);
      toggle.focus();
    }

    toggle.addEventListener('click', () => {
      if (isOpen()) {
        closeAndFocusToggle();
        return;
      }
      setOpen(true);
      (sidebar.querySelector('[aria-current]') || sidebar.querySelector('a')).focus();
    });
    shell.addEventListener('keydown', event => {
      if (event.key === 'Escape' && isOpen() && !event.defaultPrevented) {
        closeAndFocusToggle();
        event.preventDefault();
      }
    });
    sidebar.addEventListener('click', event => {
      const link = event.target.closest('a.side-link');
      if (isOpen() && link?.hash === location.hash) closeAndFocusToggle();
    });
  }

  function hashKeyOf(segments) {
    if (!segments.length) return '#/dashboard';
    if (segments[0] === 'admin') return '#/admin/' + (segments[1] || '');
    if (segments[0] === 'organisations') return '#/organisations';
    if (segments[0] === 'projects') return '#/organisations';
    if (segments[0] === 'scans') return '#/scans';
    return '#/' + segments[0];
  }

  async function route() {
    const app = document.getElementById('app');
    const raw = location.hash || '#/dashboard';
    const path = raw.slice(1);
    const qIdx = path.indexOf('?');
    const cleanPath = qIdx >= 0 ? path.slice(0, qIdx) : path;
    if (cleanPath === '/scans/new') {
      location.replace('#/organisations');
      return;
    }
    const query = qIdx >= 0 ? path.slice(qIdx + 1) : '';
    const segments = cleanPath.split('/').filter(Boolean);
    const params = parseQuery(query);
    const user = API.user || {};

    // Not authenticated -> show the login page.  The destination the user was
    // trying to reach (e.g. an invitation link) is carried through the login so
    // it is not lost.
    if (!isAuthed()) {
      if (segments[0] !== 'login') {
        location.hash = '#/login?next=' + encodeURIComponent(raw);
        return;
      }
      app.innerHTML = VIEWS.loginHtml(params);
      VIEWS.bindLogin(app, params);
      return;
    }
    // Authenticated user navigating to login -> requested page (or dashboard).
    if (segments[0] === 'login' || segments.length === 0) {
      location.hash = safeNext(params.next) || '#/dashboard';
      return;
    }
    const role = user.Role;

    // Admin-only section guard
    if (segments[0] === 'admin' && role !== 'Administrator') {
      location.hash = '#/dashboard';
      return;
    }

    const navWasOpen = !!app.querySelector('.shell.nav-open');
    app.innerHTML = shellHtml(segments, role);
    bindSidebar(app.querySelector('.shell'));
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
      const labels = { users: 'User management', profiles: 'Scan profiles', vulnerabilities: 'Vulnerabilities', 'audit-logs': 'Audit logs' };
      crumbParts.push('Administration', labels[segments[1]] || '');
    } else if (segments[0] === 'scans') {
      crumbParts.push(segments[1] ? 'Scan result' : 'Scans');
    } else if (segments[0] === 'organisations') {
      crumbParts.push('Organisations');
      if (segments[1]) crumbParts.push('Organisation #' + segments[1]);
    } else if (segments[0] === 'projects') {
      crumbParts.push('Projects');
      if (segments[1]) crumbParts.push('Project #' + segments[1]);
      if (segments[2]) crumbParts.push(segments[2]);
    } else if (segments[0] === 'invitations') {
      crumbParts.push('Invitation');
    } else {
      const labels = { dashboard: 'Dashboard', 'knowledge-base': 'Knowledge base', profile: 'Profile' };
      crumbParts.push(labels[segments[0]] || segments[0]);
    }
    crumb.textContent = crumbParts.filter(Boolean).join(' › ');

    // Dispatch to the view
    if (VIEWS.stopPolling) VIEWS.stopPolling();
    content.innerHTML = U.loading('Loading…');
    if (navWasOpen) content.focus({ preventScroll: true });
    try {
      const key = cleanPath;
      if (key === '/dashboard') return await VIEWS.dashboard(content, params);
      if (key === '/scans') return await VIEWS.scans(content, params);
      if (segments[0] === 'scans' && segments[1] && /^\d+$/.test(segments[1])) return await VIEWS.scanResult(content, { id: segments[1] });
      if (key === '/knowledge-base') return await VIEWS.knowledgeBase(content, params);
      if (key === '/profile') return await VIEWS.profile(content, params);
      if (key === '/admin/users') return await VIEWS.adminUsers(content, params);
      if (key === '/admin/profiles') return await VIEWS.adminProfiles(content, params);
      if (key === '/admin/vulnerabilities') return await VIEWS.adminVulns(content, params);
      if (key === '/admin/audit-logs') return await VIEWS.adminAudit(content, params);
      if (segments[0] === 'organisations' || segments[0] === 'projects' || segments[0] === 'invitations') {
        return await TRUST.route(content, segments, params);
      }
      // fallback
      content.innerHTML = U.empty('Page not found.');
    } catch (err) {
      if (!(err instanceof window.ApiError && err.status === 401)) {
        content.innerHTML = `<div class="card card-pad">${U.empty('Error: ' + U.esc(err.message))}</div>`;
      }
    }
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
