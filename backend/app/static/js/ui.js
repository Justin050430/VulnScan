/* UI helpers: escaping, badges, toasts, modals, misc rendering */
(function () {
  'use strict';

  /*
   * Line icon geometry adapted from Lucide (https://lucide.dev).
   * ISC License. Copyright (c) 2026 Lucide Icons and Contributors.
   * Permission to use, copy, modify, and/or distribute this software for any
   * purpose with or without fee is hereby granted, provided that the above
   * copyright notice and this permission notice appear in all copies.
   * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
   *
   * MIT License (Feather-derived icons). Copyright (c) 2013-present Cole Bemis.
   * Permission is hereby granted, free of charge, to any person obtaining a copy
   * of this software and associated documentation files (the "Software"), to deal
   * in the Software without restriction, including without limitation the rights
   * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   * copies of the Software, and to permit persons to whom the Software is
   * furnished to do so, subject to the following conditions:
   * The above copyright notice and this permission notice shall be included in all
   * copies or substantial portions of the Software.
   * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   * SOFTWARE.
   */
  const iconPaths = {
    shield: '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/>',
    dashboard: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
    building: '<rect x="6" y="3" width="12" height="18" rx="2"/><path d="M10 8h.01M14 8h.01M10 12h.01M14 12h.01M10 21v-4h4v4"/>',
    users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m20 0v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/><circle cx="9" cy="7" r="4"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zm0 0v6h6M8 13h8m-8 4h8"/>',
    bug: '<rect x="7" y="6" width="10" height="15" rx="5"/><path d="M9 6 7 3m8 3 2-3M7 12H4m16 0h-3M7 16H4m16 0h-3M7 9 4 7m13 2 3-2m-8 4v10"/>',
    radar: '<path d="M12 12 22 2m-5 5a7 7 0 1 0 2 5m0-7a10 10 0 1 0 3 7"/><circle cx="12" cy="12" r="2"/>',
    clipboard: '<rect x="8" y="3" width="8" height="4" rx="1"/><path d="M16 5h2a2 2 0 0 1 2 2v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2m0 7h8m-8 4h8"/>',
    book: '<path d="M12 7v14M3 18V5h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5v13h-5a4 4 0 0 0-4 4 4 4 0 0 0-4-4Z"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    user: '<circle cx="12" cy="7" r="4"/><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>',
    logout: '<path d="M10 17l5-5-5-5m5 5H3m9-9h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    'arrow-left': '<path d="M19 12H5m7 7-7-7 7-7"/>',
    'arrow-right': '<path d="M5 12h14m-7-7 7 7-7 7"/>',
    download: '<path d="M12 3v12m-5-5 5 5 5-5m4 6v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    x: '<path d="m6 6 12 12M18 6 6 18"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    'chevron-down': '<path d="m6 9 6 6 6-6"/>',
    'chevron-right': '<path d="m9 18 6-6-6-6"/>'
  };

  const U = {
    icon(name) {
      if (!Object.hasOwn(iconPaths, name)) return '';
      return `<svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${iconPaths[name]}</svg>`;
    },
    esc(v) {
      if (v === null || v === undefined) return '';
      return String(v).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }[c]));
    },
    /* The API serialises UTC datetimes without a timezone designator, which
       `new Date()` would read as local time. Treat a bare timestamp as UTC so
       both display and any date comparison use the real instant. */
    parseDT(v) {
      if (v === null || v === undefined || v === '') return null;
      if (v instanceof Date) return isNaN(v) ? null : v;
      let s = String(v);
      if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s += 'Z';
      const d = new Date(s);
      return isNaN(d) ? null : d;
    },
    fmtDT(v) {
      const d = this.parseDT(v);
      if (!d) return '-';
      return d.toLocaleString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    },
    fmtDate(v) {
      const d = this.parseDT(v);
      if (!d) return '-';
      return d.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
    },
    sevClass(s) { return (s || '').toLowerCase(); },
    sevBadge(s) { return `<span class="badge ${this.sevClass(s)}">${this.esc(s || 'None')}</span>`; },
    statusClass(s) { return (s || '').toLowerCase().replace(/ /g, ''); },
    statusBadge(s) { return `<span class="badge ${this.statusClass(s)}">${this.esc(s || '-')}</span>`; },
    roleBadge(r) { return `<span class="badge ${(r || '').toLowerCase()}">${this.esc(r)}</span>`; },
    activeBadge(b) { return b ? '<span class="badge active">Active</span>' : '<span class="badge inactive">Disabled</span>'; },
    moduleBadge(key) { return key ? '<span class=\"badge module\">Module</span>' : ''; },
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
              <button class="btn btn-sm btn-secondary" type="button" data-close="1" aria-label="Close">${this.icon('x')}</button></div>
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
      return `<div class="empty"><div class="big">${this.icon('search')}</div>${this.esc(msg || 'No items found.')}</div>`;
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
    }
  };
  window.U = U;
})();
