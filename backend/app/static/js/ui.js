/* UI helpers: escaping, badges, toasts, modals, misc rendering */
(function () {
  'use strict';

  const U = {
    esc(v) {
      if (v === null || v === undefined) return '';
      return String(v).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }[c]));
    },
    fmtDT(v) {
      if (!v) return '-';
      const d = new Date(v);
      if (isNaN(d)) return '-';
      return d.toLocaleString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    },
    fmtDate(v) {
      if (!v) return '-';
      const d = new Date(v);
      if (isNaN(d)) return '-';
      return d.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
    },
    sevClass(s) { return (s || '').toLowerCase(); },
    sevBadge(s) { return `<span class="badge ${this.sevClass(s)}">${this.esc(s || 'None')}</span>`; },
    statusClass(s) { return (s || '').toLowerCase().replace(/ /g, ''); },
    statusBadge(s) { return `<span class="badge ${this.statusClass(s)}">${this.esc(s || '-')}</span>`; },
    roleBadge(r) { return `<span class="badge ${(r || '').toLowerCase()}">${this.esc(r)}</span>`; },
    activeBadge(b) { return b ? '<span class="badge active">Active</span>' : '<span class="badge inactive">Disabled</span>'; },
    moduleBadge(key) { return key ? `<span class="badge module">⚙ module</span>` : ''; },
    toast(msg, type) {
      type = type || 'info';
      const t = document.createElement('div');
      t.className = 'toast ' + type;
      t.textContent = msg;
      document.body.appendChild(t);
      setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 320); }, 3400);
    },
    confirmDlg(message, title) {
      return new Promise(resolve => {
        const m = this.modal(
          `<h3>${this.esc(title || 'Confirm')}</h3>`,
          `<p>${this.esc(message)}</p>`,
          `<button class="btn btn-secondary" data-act="cancel">Cancel</button>
           <button class="btn btn-danger" data-act="ok">Confirm</button>`
        );
        m.root.addEventListener('click', e => {
          const act = e.target.closest('[data-act]');
          if (!act) return;
          this.closeModal();
          resolve(act.dataset.act === 'ok');
        });
      });
    },
    modal(titleHtml, bodyHtml, footHtml) {
      const root = document.getElementById('modal-root');
      root.innerHTML = `
        <div class="modal-backdrop">
          <div class="modal">
            <div class="modal-head"><h3>${titleHtml}</h3>
              <button class="btn btn-sm btn-secondary" data-close="1">✕</button></div>
            <div class="modal-body">${bodyHtml}</div>
            ${footHtml ? `<div class="modal-foot">${footHtml}</div>` : ''}
          </div>
        </div>`;
      const m = { root: root.firstElementChild };
      m.root.addEventListener('click', e => {
        if (e.target === m.root || e.target.closest('[data-close]')) this.closeModal();
      });
      document.body.style.overflow = 'hidden';
      return m;
    },
    closeModal() {
      document.getElementById('modal-root').innerHTML = '';
      document.body.style.overflow = '';
    },
    loading(label) {
      return `<div class="center"><div class="spin"></div></div>${label ? `<div class="center" style="color:var(--muted)">${this.esc(label)}</div>` : ''}`;
    },
    empty(msg) {
      return `<div class="empty"><div class="big">🔍</div>${this.esc(msg || 'No items found.')}</div>`;
    },
    pager(page, per, total, onGo) {
      const pages = Math.max(1, Math.ceil(total / per));
      const wrap = document.createElement('div');
      wrap.className = 'pager';
      wrap.innerHTML = `<span>Showing ${total === 0 ? 0 : ((page - 1) * per + 1)}&ndash;${Math.min(page * per, total)} of ${total}</span>
        <button class="btn btn-sm btn-secondary" data-p="${page - 1}" ${page <= 1 ? 'disabled' : ''}>‹ Prev</button>
        <span>Page ${page} / ${pages}</span>
        <button class="btn btn-sm btn-secondary" data-p="${page + 1}" ${page >= pages ? 'disabled' : ''}>Next ›</button>`;
      wrap.addEventListener('click', e => {
        const b = e.target.closest('button[data-p]');
        if (!b || b.disabled) return;
        const p = parseInt(b.dataset.p, 10);
        if (p >= 1 && p <= pages) onGo(p);
      });
      return wrap;
    },
    asset(tag, label) {
      // small inline SVG-ish icon placeholders are plain emoji for simplicity
      return `<span class="ic">${label}</span>`;
    }
  };
  window.U = U;
})();
