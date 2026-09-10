/* VulnScan API client - JWT bearer token handling */
(function () {
  'use strict';

  const TOKEN_KEY = 'vulnscan_token';
  const USER_KEY = 'vulnscan_user';

  class ApiError extends Error {
    constructor(message, status, code) {
      super(message);
      this.status = status;
      this.code = code;
    }
  }

  const API = {
    get token() { return localStorage.getItem(TOKEN_KEY); },
    get user() {
      try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null'); }
      catch (e) { return null; }
    },
    setUser(u) { localStorage.setItem(USER_KEY, JSON.stringify(u)); },
    setAuth(token, user) {
      if (token) localStorage.setItem(TOKEN_KEY, token);
      if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
    },
    clearAuth() {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
    },
    async request(path, opts) {
      opts = opts || {};
      const method = opts.method || 'GET';
      let url = path;
      if (opts.params) {
        const qs = new URLSearchParams();
        Object.keys(opts.params).forEach(k => {
          if (opts.params[k] !== undefined && opts.params[k] !== null && opts.params[k] !== '') qs.set(k, opts.params[k]);
        });
        const s = qs.toString();
        if (s) url += (url.includes('?') ? '&' : '?') + s;
      }
      const headers = { 'Accept': 'application/json' };
      if (this.token) headers['Authorization'] = 'Bearer ' + this.token;
      let body;
      if (opts.body !== undefined) {
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify(opts.body);
      }
      let resp;
      try {
        resp = await fetch(url, { method, headers, body });
      } catch (e) {
        throw new ApiError('Network error - is the VulnScan server running?', 0, 'network');
      }
      const contentType = resp.headers.get('content-type') || '';
      let data = null;
      if (contentType.includes('application/json')) {
        try { data = await resp.json(); } catch (e) { data = null; }
      }
      if (resp.status === 401) {
        // expired / revoked / missing token
        if (location.hash !== '#/login') {
          API.clearAuth();
          location.hash = '#/login';
        }
        throw new ApiError((data && data.message) || 'Authentication required.', 401, (data && data.code) || 'unauthorized');
      }
      if (!resp.ok) {
        throw new ApiError((data && data.message) || ('Request failed (' + resp.status + ')'), resp.status, data && data.code);
      }
      return data;
    },
    get(path, params) { return this.request(path, { params }); },
    post(path, body) { return this.request(path, { method: 'POST', body }); },
    put(path, body) { return this.request(path, { method: 'PUT', body }); },
    del(path) { return this.request(path, { method: 'DELETE' }); },
    // Downloads the report blob (PDF/CSV) using the token.
    async download(path, filename) {
      const headers = {};
      if (this.token) headers['Authorization'] = 'Bearer ' + this.token;
      const resp = await fetch(path, { headers });
      if (!resp.ok) {
        let msg = 'Download failed';
        try { const j = await resp.json(); msg = j.message || msg; } catch (e) { /* ignore */ }
        throw new ApiError(msg, resp.status);
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    }
  };
  window.API = API;
  window.ApiError = ApiError;
})();
