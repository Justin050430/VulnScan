/* Trust Boundary Extension views (organisations, projects, assets, credits, gated scans). */
(function () {
  'use strict';

  const API = window.API, U = window.U;
  const STATUS = ['', 'Unverified', 'PendingVerification', 'Verified', 'Expired', 'Revoked'];

  function err(t) { U.toast(t, 'err'); }

  function statusBadge(status) {
    const cls = (status || '').toLowerCase();
    return `<span class="badge ${cls}">${U.esc(status || '-')}</span>`;
  }

  function can(perms, permission) {
    return Array.isArray(perms) && perms.indexOf(permission) !== -1;
  }

  function empty(text) { return U.empty(text); }

  /* ======================================================== ORGANISATIONS */
  async function organisations(el) {
    el.innerHTML = U.loading('Loading organisations…');
    const body = await API.get('/api/v1/organisations');
    const orgs = body.Organisations || [];
    el.innerHTML = `
      <div class="page-head"><div class="row"><div>
        <h1>Organisations</h1>
        <div class="sub">Each organisation owns projects, verified assets and scan credits.</div>
      </div><button class="btn btn-primary" style="width:auto" id="new-org">+ New Organisation</button></div></div>
      <div class="card card-pad">
        ${orgs.length ? `<div class="table-wrap"><table class="tbl">
          <thead><tr><th>Organisation</th><th>Slug</th><th>Status</th><th class="actions">Actions</th></tr></thead>
          <tbody>${orgs.map(o => `<tr>
            <td><b>${U.esc(o.Name)}</b></td>
            <td class="mono">${U.esc(o.Slug)}</td>
            <td>${statusBadge(o.Status)}</td>
            <td class="actions"><a class="btn btn-sm btn-secondary" href="#/organisations/${o.OrganisationID}">Open</a></td>
          </tr>`).join('')}</tbody></table></div>` : empty('No organisations yet. Create one to get started.')}
      </div>`;
    el.querySelector('#new-org').addEventListener('click', () => organisationModal());
  }

  function organisationModal() {
    const m = U.modal('New organisation',
      `<div class="field"><label>Name</label><input id="org-name" maxlength="120" placeholder="Acme Sdn Bhd"></div>
       <p class="hint">You become the organisation owner. Organisation ownership does not by itself allow scans.</p>`,
      `<button class="btn btn-secondary" onclick="U.closeModal()">Cancel</button>
       <button class="btn btn-primary" style="width:auto" id="org-save">Create</button>`);
    m.root.querySelector('#org-save').addEventListener('click', async () => {
      try {
        const name = m.root.querySelector('#org-name').value.trim();
        if (!name) { err('Name is required.'); return; }
        const data = await API.post('/api/v1/organisations', { name });
        U.closeModal();
        location.hash = '#/organisations/' + data.Organisation.OrganisationID;
      } catch (e) { err(e.message); }
    });
  }

  async function organisationDetail(el, orgId) {
    el.innerHTML = U.loading('Loading organisation…');
    const [orgBody, membersBody, projectsBody] = await Promise.all([
      API.get('/api/v1/organisations/' + orgId),
      API.get('/api/v1/organisations/' + orgId + '/members'),
      API.get('/api/v1/projects?organisation_id=' + orgId)
    ]);
    const org = orgBody.Organisation;
    const members = membersBody.Members || [];
    const projects = projectsBody.Projects || [];
    el.innerHTML = `
      <div class="page-head"><div class="row"><div>
        <h1>${U.esc(org.Name)}</h1>
        <div class="sub">Organisation <span class="mono">${U.esc(org.Slug)}</span> · ${statusBadge(org.Status)}</div>
      </div><button class="btn btn-primary" style="width:auto" id="new-project">+ New Project</button></div></div>
      <div class="grid-2">
        <div class="card card-pad">
          <h3>Projects</h3>
          ${projects.length ? `<div class="table-wrap"><table class="tbl">
            <thead><tr><th>Project</th><th>Role</th><th class="actions">Actions</th></tr></thead>
            <tbody>${projects.map(p => `<tr>
              <td><b>${U.esc(p.Project.Name)}</b><div class="mono" style="color:var(--muted)">${U.esc(p.Project.Slug)}</div></td>
              <td>${U.esc(p.ProjectRole || p.OrgRole || '-')}</td>
              <td class="actions"><a class="btn btn-sm btn-secondary" href="#/projects/${p.Project.ProjectID}">Open</a></td>
            </tr>`).join('')}</tbody></table></div>` : empty('No projects yet.')}
        </div>
        <div class="card card-pad">
          <div class="row" style="justify-content:space-between"><h3 style="margin:0">Members</h3>
            <button class="btn btn-sm btn-secondary" id="invite-org">Invite</button></div>
          <div style="margin-top:10px">${members.length ? members.map(m => `
            <div class="row" style="justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">
              <span>User #${m.UserID}</span>
              <span><span class="chip-mini">${U.esc(m.Role)}</span> ${statusBadge(m.Status)}</span>
            </div>`).join('') : empty('No members.')}</div>
        </div>
      </div>`;
    el.querySelector('#new-project').addEventListener('click', () => projectModal(org.OrganisationID));
    el.querySelector('#invite-org').addEventListener('click', () => inviteModal(
      '/api/v1/organisations/' + org.OrganisationID + '/members', ['ORG_OWNER']));
  }

  function projectModal(orgId) {
    const m = U.modal('New project',
      `<div class="field"><label>Name</label><input id="proj-name" maxlength="120" placeholder="Storefront"></div>
       <p class="hint">You become the project owner.</p>`,
      `<button class="btn btn-secondary" onclick="U.closeModal()">Cancel</button>
       <button class="btn btn-primary" style="width:auto" id="proj-save">Create</button>`);
    m.root.querySelector('#proj-save').addEventListener('click', async () => {
      try {
        const name = m.root.querySelector('#proj-name').value.trim();
        if (!name) { err('Name is required.'); return; }
        const data = await API.post('/api/v1/projects', { organisation_id: orgId, name });
        U.closeModal();
        location.hash = '#/projects/' + data.Project.ProjectID;
      } catch (e) { err(e.message); }
    });
  }

  function inviteModal(path, roles) {
    const m = U.modal('Invite member',
      `<div class="field"><label>Email of an existing VulnScan account</label>
         <input id="inv-email" type="email" placeholder="teammate@example.com"></div>
       <div class="field"><label>Role</label><select id="inv-role">
         ${roles.map(r => `<option value="${r}">${r}</option>`).join('')}</select></div>
       <p class="hint">Viewers and analysts cannot start scans.</p>`,
      `<button class="btn btn-secondary" onclick="U.closeModal()">Cancel</button>
       <button class="btn btn-primary" style="width:auto" id="inv-save">Create invitation</button>`);
    m.root.querySelector('#inv-save').addEventListener('click', async () => {
      try {
        const email = m.root.querySelector('#inv-email').value.trim();
        const role = m.root.querySelector('#inv-role').value;
        const data = await API.post(path, { email, role });
        U.modal('Invitation created',
          `<p>Share this one-time link with the invitee:</p>
           <div class="mono" style="word-break:break-all;background:var(--blue-bg);padding:10px;border-radius:8px">
             #/invitations/accept?token=${U.esc(data.InviteToken)}</div>
           <p class="hint">The token is shown once and stored only as a hash. Invitations expire in 72 hours.</p>`,
          `<button class="btn btn-secondary" onclick="U.closeModal();location.reload()">Close</button>`);
      } catch (e) { err(e.message); }
    });
  }

  async function acceptInvitation(el, params) {
    el.innerHTML = U.loading('Accepting invitation…');
    if (!params || !params.token) { el.innerHTML = empty('Invitation token missing.'); return; }
    try {
      await API.post('/api/v1/invitations/accept', { token: params.token });
      el.innerHTML = `<div class="card card-pad"><h3>Invitation accepted</h3>
        <p>You now have access to the project.</p>
        <a class="btn btn-primary" style="width:auto" href="#/organisations">Go to organisations</a></div>`;
    } catch (e) {
      el.innerHTML = `<div class="card card-pad">${empty(e.message)}</div>`;
    }
  }

  /* ============================================================= PROJECT */
  async function projectDetail(el, projectId) {
    el.innerHTML = U.loading('Loading project…');
    const [projectBody, assetsBody, creditsBody, scansBody] = await Promise.all([
      API.get('/api/v1/projects/' + projectId),
      API.get('/api/v1/projects/' + projectId + '/assets'),
      API.get('/api/v1/projects/' + projectId + '/credits'),
      API.get('/api/v1/projects/' + projectId + '/scans')
    ]);
    const perms = projectBody.Permissions || [];
    const project = projectBody.Project;
    const assets = assetsBody.Assets || [];
    const credits = creditsBody.Credits || [];
    const scans = scansBody.Scans || [];
    const available = credits.filter(c => c.Status === 'Available').length;

    el.innerHTML = `
      <div class="page-head"><div class="row"><div>
        <h1>${U.esc(project.Name)}</h1>
        <div class="sub">${U.esc(projectBody.Organisation.Name)} · your role:
          <span class="chip-mini">${U.esc(projectBody.ProjectRole || projectBody.OrgRole || '-')}</span>
          ${projectBody.ProjectRole === null ? '<span class="chip-mini">organisation-wide access</span>' : ''}</div>
      </div><div style="display:flex;gap:8px">
        ${can(perms, 'credit.purchase') ? '<button class="btn btn-secondary" id="buy-credit">Buy credit</button>' : ''}
        ${can(perms, 'scan.start') ? '<a class="btn btn-primary" href="#/projects/' + projectId + '/scans/new">Start scan</a>' : ''}
      </div></div></div>
      <div class="grid-cards">
        <div class="card stat-card"><div><div class="val">${assets.length}</div><div class="lbl">Registered assets</div></div></div>
        <div class="card stat-card"><div><div class="val">${assets.filter(a => a.VerificationStatus === 'Verified').length}</div><div class="lbl">Verified assets</div></div></div>
        <div class="card stat-card"><div><div class="val">${available}</div><div class="lbl">Available credits</div></div></div>
        <div class="card stat-card"><div><div class="val">${scans.length}</div><div class="lbl">Project scans</div></div></div>
      </div>
      <div class="card card-pad" style="margin-bottom:16px">
        <div class="row" style="justify-content:space-between"><h3 style="margin:0">Assets</h3>
          ${can(perms, 'asset.register') ? '<button class="btn btn-sm btn-secondary" id="add-asset">+ Register asset</button>' : ''}</div>
        ${assets.length ? `<div class="table-wrap"><table class="tbl" style="margin-top:10px">
          <thead><tr><th>Hostname</th><th>Status</th><th>Verified until</th><th class="actions">Actions</th></tr></thead>
          <tbody>${assets.map(a => `<tr>
            <td><b class="mono">${U.esc(a.Hostname)}</b><div style="color:var(--muted);font-size:11.5px">${U.esc(a.Scheme)}</div></td>
            <td>${statusBadge(a.VerificationStatus)}</td>
            <td>${a.VerificationExpiresAt ? U.fmtDT(a.VerificationExpiresAt) : '–'}</td>
            <td class="actions">
              ${can(perms, 'asset.verify') ? `<a class="btn btn-xs btn-secondary" href="#/projects/${projectId}/assets/${a.AssetID}/verify">Verify</a>` : ''}
              ${can(perms, 'attestation.create') && a.VerificationStatus === 'Verified' ? `<a class="btn btn-xs btn-secondary" href="#/projects/${projectId}/assets/${a.AssetID}/attest">Attest</a>` : ''}
              ${can(perms, 'asset.revoke') && a.VerificationStatus === 'Verified' ? `<button class="btn btn-xs btn-danger" data-revoke="${a.AssetID}">Revoke</button>` : ''}
            </td></tr>`).join('')}</tbody></table></div>` : empty('No assets registered yet.')}
      </div>
      <div class="grid-2">
        <div class="card card-pad">
          <div class="row" style="justify-content:space-between"><h3 style="margin:0">Credits</h3>
            <a href="#/projects/${projectId}/credits">History →</a></div>
          <p style="color:var(--muted);font-size:13px;margin-top:8px">Each new scan consumes one credit. Viewing previous results is free.</p>
          <div class="pill-list">${credits.length ? credits.slice(0, 6).map(c => `<span class="chip-mini">${U.esc(c.Status)}</span>`).join('') : empty('No credits purchased yet.')}</div>
        </div>
        <div class="card card-pad">
          <div class="row" style="justify-content:space-between"><h3 style="margin:0">Project scans</h3>
            <a href="#/projects/${projectId}/audit">Audit →</a></div>
          ${scans.length ? `<div class="table-wrap"><table class="tbl" style="margin-top:8px">
            <thead><tr><th>Scan</th><th>Status</th><th class="actions"></th></tr></thead>
            <tbody>${scans.slice(0, 8).map(s => `<tr>
              <td><b>${U.esc(s.ScanName)}</b><div class="mono" style="color:var(--muted)">#${s.ScanID}</div></td>
              <td>${U.statusBadge(s.Status)}</td>
              <td class="actions"><a class="btn btn-xs btn-secondary" href="#/scans/${s.ScanID}">View</a></td>
            </tr>`).join('')}</tbody></table></div>` : empty('No scans yet.')}
        </div>
      </div>`;

    if (can(perms, 'asset.register')) {
      el.querySelector('#add-asset').addEventListener('click', () => assetModal(projectId));
    }
    if (can(perms, 'credit.purchase')) {
      el.querySelector('#buy-credit').addEventListener('click', () => buyCreditModal(projectId, projectId, () => projectDetail(el, projectId)));
    }
    el.querySelectorAll('[data-revoke]').forEach(b => b.addEventListener('click', async () => {
      if (!(await U.confirmDlg('Revoke this asset? Active scans will be blocked immediately.', 'Revoke asset'))) return;
      try {
        await API.post(`/api/v1/projects/${projectId}/assets/${b.dataset.revoke}/revoke`, { reason: 'revoked by project owner' });
        U.toast('Asset revoked.', 'ok');
        projectDetail(el, projectId);
      } catch (e) { err(e.message); }
    }));
  }

  function assetModal(projectId) {
    const m = U.modal('Register asset',
      `<div class="field"><label>Exact hostname</label>
         <input id="asset-host" placeholder="shop.example.com">
         <div class="hint">No wildcards, no IP addresses, no scheme or path. Sub-domains must be registered separately.</div></div>
       <div class="field"><label>Scheme</label><select id="asset-scheme">
         <option value="https">https</option><option value="http">http</option></select></div>`,
      `<button class="btn btn-secondary" onclick="U.closeModal()">Cancel</button>
       <button class="btn btn-primary" style="width:auto" id="asset-save">Register</button>`);
    m.root.querySelector('#asset-save').addEventListener('click', async () => {
      try {
        const hostname = m.root.querySelector('#asset-host').value.trim();
        const scheme = m.root.querySelector('#asset-scheme').value;
        const data = await API.post(`/api/v1/projects/${projectId}/assets`, { hostname, scheme });
        U.closeModal();
        location.hash = `#/projects/${projectId}/assets/${data.Asset.AssetID}/verify`;
      } catch (e) { err(e.message); }
    });
  }

  /* ==================================================== ASSET VERIFICATION */
  async function assetVerify(el, projectId, assetId) {
    el.innerHTML = U.loading('Loading asset…');
    const body = await API.get(`/api/v1/projects/${projectId}/assets/${assetId}`);
    const asset = body.Asset;
    el.innerHTML = `
      <div class="page-head"><div class="row"><div>
        <h1>Verify ${U.esc(asset.Hostname)}</h1>
        <div class="sub">Prove you control this hostname before any active scan. ${statusBadge(asset.VerificationStatus)}</div>
      </div><a class="btn btn-secondary" href="#/projects/${projectId}">← Back</a></div></div>
      <div class="grid-2">
        <div class="card card-pad">
          <h3>1. Choose a method</h3>
          <div class="field"><label>Verification method</label>
            <select id="v-method"><option value="DNS_TXT">DNS TXT record</option>
            <option value="WEB_FILE">/.well-known/vulnscan.txt file</option></select></div>
          <button class="btn btn-primary" style="width:auto" id="v-start">Generate challenge</button>
          <div id="v-challenge" style="margin-top:14px"></div>
        </div>
        <div class="card card-pad">
          <h3>2. Publish and check</h3>
          <p style="color:var(--muted);font-size:13px">After publishing the challenge, run the check. The server fetches DNS or the file itself with strict limits and no redirects.</p>
          <button class="btn btn-primary" style="width:auto" id="v-check">Check now</button>
          <div id="v-result" style="margin-top:14px"></div>
        </div>
      </div>`;
    const challengeBox = el.querySelector('#v-challenge');
    const resultBox = el.querySelector('#v-result');
    el.querySelector('#v-start').addEventListener('click', async () => {
      try {
        const method = el.querySelector('#v-method').value;
        const data = await API.post(`/api/v1/projects/${projectId}/assets/${assetId}/verification`, { method });
        const c = data.Challenge;
        challengeBox.innerHTML = c.RecordName ? `
          <div class="kv" style="grid-template-columns:120px 1fr">
            <span class="k">Record</span><span class="mono">${U.esc(c.RecordName)}</span>
            <span class="k">Type</span><span>${U.esc(c.RecordType)}</span>
            <span class="k">Value</span><span class="mono" style="word-break:break-all">${U.esc(c.RecordValue)}</span>
            <span class="k">Expires</span><span>${U.fmtDT(c.ExpiresAt)}</span>
          </div>` : `
          <div class="kv" style="grid-template-columns:120px 1fr">
            <span class="k">File URL</span><span class="mono">${U.esc(c.FileURL)}</span>
            <span class="k">Content</span><span class="mono" style="word-break:break-all">${U.esc(c.FileContent)}</span>
            <span class="k">Expires</span><span>${U.fmtDT(c.ExpiresAt)}</span>
          </div>`;
        U.toast('Challenge generated. Publish it, then run the check.', 'info');
      } catch (e) { err(e.message); }
    });
    el.querySelector('#v-check').addEventListener('click', async () => {
      try {
        const data = await API.post(`/api/v1/projects/${projectId}/assets/${assetId}/verification/check`, {});
        resultBox.innerHTML = `<div class="card" style="padding:12px;border-color:var(--green)">
          <b>Verified.</b> ${U.esc(data.Verification.Evidence || '')}<br/>
          <span style="color:var(--muted)">Valid until ${U.fmtDT(data.Asset.VerificationExpiresAt)}</span></div>`;
        U.toast('Asset verified.', 'ok');
      } catch (e) {
        resultBox.innerHTML = `<div class="card" style="padding:12px;border-color:var(--red)">
          <b>Not verified.</b> ${U.esc(e.message)}</div>`;
      }
    });
  }

  /* ============================================================ ATTESTATION */
  async function assetAttest(el, projectId, assetId) {
    el.innerHTML = U.loading('Loading attestation…');
    const [assetBody, attestBody] = await Promise.all([
      API.get(`/api/v1/projects/${projectId}/assets/${assetId}`),
      API.get(`/api/v1/projects/${projectId}/assets/${assetId}/attestations`)
    ]);
    const asset = assetBody.Asset;
    const active = (attestBody.Attestations || []).filter(a => a.Status === 'Active')[0];
    el.innerHTML = `
      <div class="page-head"><div class="row"><div>
        <h1>Authorisation attestation</h1>
        <div class="sub">${U.esc(asset.Hostname)} ${statusBadge(asset.VerificationStatus)}</div>
      </div><a class="btn btn-secondary" href="#/projects/${projectId}">← Back</a></div></div>
      <div class="grid-2">
        <div class="card card-pad">
          <h3>Authorisation statement</h3>
          <p style="font-size:13px;color:var(--muted)">By creating this attestation you confirm you are authorised by
            the owner or controller of <b>${U.esc(asset.Hostname)}</b> to run an active vulnerability assessment against it,
            that it is within scope, and that you accept responsibility for the activity.</p>
          <div class="field"><label>Expires in (days, max 90)</label>
            <input id="att-days" type="number" min="1" max="90" value="30"></div>
          <div class="field"><label>Reference (optional)</label>
            <input id="att-ref" maxlength="255" placeholder="e.g. CHG-1234 / maintenance window"></div>
          <button class="btn btn-primary" style="width:auto" id="att-create">Create attestation</button>
        </div>
        <div class="card card-pad">
          <h3>Current attestation</h3>
          ${active ? `<div class="kv">
              <span class="k">Status</span><span>${statusBadge(active.Status)}</span>
              <span class="k">Version</span><span>${U.esc(active.StatementVersion)}</span>
              <span class="k">Hash</span><span class="mono" style="word-break:break-all">${U.esc(active.StatementHash)}</span>
              <span class="k">Expires</span><span>${U.fmtDT(active.ExpiresAt)}</span>
              <span class="k">Reference</span><span>${U.esc(active.Reference || '-')}</span>
            </div>
            <button class="btn btn-danger" style="width:auto;margin-top:12px" id="att-revoke">Revoke</button>`
            : empty('No active attestation. An active attestation is required before scanning.')}
        </div>
      </div>`;
    el.querySelector('#att-create').addEventListener('click', async () => {
      try {
        await API.post(`/api/v1/projects/${projectId}/assets/${assetId}/attestations`, {
          expires_in_days: parseInt(el.querySelector('#att-days').value, 10) || 30,
          reference: el.querySelector('#att-ref').value.trim() || undefined
        });
        U.toast('Attestation created.', 'ok');
        assetAttest(el, projectId, assetId);
      } catch (e) { err(e.message); }
    });
    if (active) {
      el.querySelector('#att-revoke').addEventListener('click', async () => {
        if (!(await U.confirmDlg('Revoke this attestation? Scans will be blocked immediately.', 'Revoke'))) return;
        try {
          await API.post(`/api/v1/projects/${projectId}/assets/${assetId}/attestations/${active.AttestationID}/revoke`, { reason: 'revoked by user' });
          U.toast('Attestation revoked.', 'ok');
          assetAttest(el, projectId, assetId);
        } catch (e) { err(e.message); }
      });
    }
  }

  /* ================================================================ CREDITS */
  async function credits(el, projectId) {
    el.innerHTML = U.loading('Loading credits…');
    const body = await API.get(`/api/v1/projects/${projectId}/credits`);
    const credits = body.Credits || [];
    el.innerHTML = `
      <div class="page-head"><div class="row"><div>
        <h1>Scan credits</h1>
        <div class="sub">One credit is consumed per new scan. Viewing results never consumes a credit.</div>
      </div><div style="display:flex;gap:8px">
        <a class="btn btn-secondary" href="#/projects/${projectId}">← Project</a>
        <button class="btn btn-primary" style="width:auto" id="buy">Buy credit</button>
      </div></div></div>
      <div class="card card-pad">
        <div class="mono" style="margin-bottom:10px">Available: ${body.AvailableCount}</div>
        ${credits.length ? `<div class="table-wrap"><table class="tbl">
          <thead><tr><th>Credit</th><th>Status</th><th>Issued</th><th>Expires</th><th>Price</th></tr></thead>
          <tbody>${credits.map(c => `<tr>
            <td class="mono" style="word-break:break-all">${U.esc(c.CreditUUID)}</td>
            <td>${statusBadge(c.Status)}</td>
            <td>${U.fmtDT(c.IssuedAt)}</td>
            <td>${U.fmtDT(c.ExpiresAt)}</td>
            <td>${(c.PurchasePriceMinor / 100).toFixed(2)} ${U.esc(c.Currency)}</td>
          </tr>`).join('')}</tbody></table></div>` : empty('No credits purchased yet.')}
      </div>`;
    el.querySelector('#buy').addEventListener('click', () => buyCreditModal(projectId, projectId, () => credits(el, projectId)));
  }

  async function buyCreditModal(projectId, _, refresh) {
    let products = [];
    try { products = (await API.get('/api/v1/products')).Products || []; }
    catch (e) { err(e.message); return; }
    const m = U.modal('Buy scan credit',
      `<div class="banner" style="background:#fff4e5;border:1px solid #f0b429;padding:10px;border-radius:8px;font-weight:600;margin-bottom:12px">
         No real money — mock provider.</div>
       <div class="field"><label>Product</label><select id="buy-product">
         ${products.map(p => `<option value="${U.esc(p.ProductCode)}">${U.esc(p.Name)} — ${(p.AmountMinor/100).toFixed(2)} ${U.esc(p.Currency)}</option>`).join('')}
       </select></div>
       <div class="field"><label>Quantity</label><input id="buy-qty" type="number" min="1" max="10" value="1"></div>
       <div id="buy-result"></div>`,
      `<button class="btn btn-secondary" onclick="U.closeModal()">Close</button>
       <button class="btn btn-primary" style="width:auto" id="buy-create">Create mock checkout</button>`);
    m.root.querySelector('#buy-create').addEventListener('click', async () => {
      try {
        const product_code = m.root.querySelector('#buy-product').value;
        const quantity = parseInt(m.root.querySelector('#buy-qty').value, 10) || 1;
        const data = await API.post(`/api/v1/projects/${projectId}/payments/checkout`, { product_code, quantity });
        const payment = data.Payment;
        const result = m.root.querySelector('#buy-result');
        result.innerHTML = `<div class="card" style="padding:12px;margin-top:10px">
          <b>${U.esc(payment.ProductCode)}</b> · ${(payment.AmountMinor/100).toFixed(2)} ${U.esc(payment.Currency)}
          <div class="mono" style="color:var(--muted);font-size:11.5px">${U.esc(payment.PaymentUUID)}</div>
          <div style="margin-top:8px">${statusBadge(payment.Status)}</div>
          <button class="btn btn-primary" style="width:auto;margin-top:10px" id="buy-pay">Pay (mock)</button>
        </div>`;
        result.querySelector('#buy-pay').addEventListener('click', async (ev) => {
          ev.target.disabled = true;
          try {
            const paid = await API.post(`/api/v1/projects/${projectId}/payments/${payment.PaymentUUID}/mock-complete`, { outcome: 'success' });
            U.toast(`Mock payment verified. Credits issued: ${paid.CreditsIssued}`, 'ok');
            U.closeModal();
            if (refresh) refresh();
          } catch (e) { err(e.message); ev.target.disabled = false; }
        });
      } catch (e) { err(e.message); }
    });
  }

  /* ============================================================ GATED SCAN */
  async function newScan(el, projectId) {
    el.innerHTML = U.loading('Loading scan setup…');
    const [projectBody, assetsBody, creditsBody, profilesBody] = await Promise.all([
      API.get('/api/v1/projects/' + projectId),
      API.get(`/api/v1/projects/${projectId}/assets`),
      API.get(`/api/v1/projects/${projectId}/credits?status=Available`),
      API.get('/api/scan-profiles')
    ]);
    const perms = projectBody.Permissions || [];
    const assets = (assetsBody.Assets || []).filter(a => a.VerificationStatus === 'Verified');
    const credits = creditsBody.Credits || [];
    const profiles = profilesBody.ScanProfiles || [];

    if (!can(perms, 'scan.start')) {
      el.innerHTML = `<div class="card card-pad">${empty('You do not have permission to start scans in this project.')}</div>`;
      return;
    }
    el.innerHTML = `
      <div class="page-head"><div class="row"><div>
        <h1>Start a scan</h1>
        <div class="sub">A scan needs a verified asset, an active attestation and one available credit.</div>
      </div><a class="btn btn-secondary" href="#/projects/${projectId}">← Back</a></div></div>
      <div class="grid-2">
        <div class="card card-pad">
          <div class="field"><label>Verified asset</label>
            <select id="s-asset">${assets.map(a => `<option value="${a.AssetID}" data-scheme="${U.esc(a.Scheme)}" data-host="${U.esc(a.Hostname)}">${U.esc(a.Hostname)}</option>`).join('')}</select>
            ${assets.length ? '' : '<div class="hint">No verified assets. Verify one first.</div>'}</div>
          <div class="field"><label>Target URL</label>
            <input id="s-target" placeholder="https://example.com/">
            <div class="hint">The host must match the verified asset exactly.</div></div>
          <div class="field"><label>Scan name (optional)</label><input id="s-name" maxlength="100"></div>
          <div class="field"><label>Scan profile</label>
            <select id="s-profile">${profiles.map(p => `<option value="${p.ScanProfileID}">${U.esc(p.Name)}</option>`).join('')}</select></div>
          <div class="field"><label>Credit</label>
            <select id="s-credit">${credits.map(c => `<option value="${U.esc(c.CreditUUID)}">${U.esc(c.CreditUUID.slice(0, 8))}… expires ${U.fmtDT(c.ExpiresAt)}</option>`).join('')}</select>
            ${credits.length ? '' : '<div class="hint">No available credits. Buy one first.</div>'}</div>
          <button class="btn btn-primary" style="width:auto" id="s-start">Start scan</button>
        </div>
        <div class="card card-pad">
          <h3>Readiness</h3>
          <div id="s-readiness">${U.loading('Checking…')}</div>
        </div>
      </div>`;

    const assetSel = el.querySelector('#s-asset');
    const targetInput = el.querySelector('#s-target');
    const readinessBox = el.querySelector('#s-readiness');

    function syncTarget() {
      const opt = assetSel.selectedOptions[0];
      if (opt && !targetInput.value) {
        targetInput.value = `${opt.dataset.scheme}://${opt.dataset.host}/`;
      }
    }
    async function refreshReadiness() {
      const assetId = assetSel.value;
      if (!assetId) { readinessBox.innerHTML = empty('No verified asset available.'); return; }
      try {
        const data = await API.get(`/api/v1/projects/${projectId}/scan-readiness`, { asset_id: assetId });
        const r = data.Readiness;
        const rows = Object.keys(r.Checks).map(k => {
          const c = r.Checks[k];
          return `<div class="row" style="justify-content:space-between;padding:4px 0">
            <span>${k}</span><span>${c.Ok ? '<span class="badge confirmed">OK</span>' : `<span class="badge failed">${U.esc(c.Code || 'Blocked')}</span>`}</span></div>`;
        }).join('');
        readinessBox.innerHTML = rows + (r.Ready ? '' : `<div class="hint" style="margin-top:8px">Next action: ${U.esc(r.NextAction)}</div>`);
      } catch (e) { readinessBox.innerHTML = U.esc(e.message); }
    }
    assetSel.addEventListener('change', () => { targetInput.value = ''; syncTarget(); refreshReadiness(); });
    syncTarget();
    refreshReadiness();

    el.querySelector('#s-start').addEventListener('click', async () => {
      const btn = el.querySelector('#s-start');
      btn.disabled = true; btn.textContent = 'Starting…';
      try {
        const data = await API.post(`/api/v1/projects/${projectId}/scans`, {
          asset_id: parseInt(assetSel.value, 10),
          scan_profile_id: parseInt(el.querySelector('#s-profile').value, 10),
          scan_name: el.querySelector('#s-name').value.trim() || undefined,
          credit_id: el.querySelector('#s-credit').value || undefined,
          target_url: targetInput.value.trim() || undefined
        });
        U.toast('Scan started.', 'ok');
        location.hash = '#/scans/' + data.Scan.ScanID;
      } catch (e) {
        U.toast(e.message + (e.code ? ` (${e.code})` : ''), 'err');
        btn.disabled = false; btn.textContent = 'Start scan';
      }
    });
  }

  /* ================================================================= AUDIT */
  async function audit(el, projectId) {
    el.innerHTML = U.loading('Loading audit events…');
    const body = await API.get(`/api/v1/projects/${projectId}/audit-events`, { per_page: 100 });
    const events = body.Events || [];
    el.innerHTML = `
      <div class="page-head"><div class="row"><div>
        <h1>Trust audit</h1>
        <div class="sub">Append-only record of membership, verification, attestation, payment,
          credit and scan actions (${events.length} events).</div>
      </div><a class="btn btn-secondary" href="#/projects/${projectId}">← Project</a></div></div>
      <div class="card card-pad">
        ${events.length ? `<div class="table-wrap"><table class="tbl">
          <thead><tr><th>Time</th><th>Event</th><th>Outcome</th><th>Reason</th><th>Actor</th><th>Entity</th></tr></thead>
          <tbody>${events.map(e => `<tr>
            <td class="tbl-nowrap">${U.fmtDT(e.EventTime)}</td>
            <td><b>${U.esc(e.EventType)}</b></td>
            <td>${statusBadge(e.Outcome)}</td>
            <td class="mono">${U.esc(e.ReasonCode || '-')}</td>
            <td>${e.ActorUserID == null ? '–' : '#' + e.ActorUserID}</td>
            <td class="mono">${U.esc(e.EntityType || '-')}${e.EntityID ? ' #' + e.EntityID : ''}</td>
          </tr>`).join('')}</tbody></table></div>` : empty('No audit events.')}
      </div>`;
  }

  /* ================================================================ ROUTER */
  async function route(el, segments, params) {
    if (segments[0] === 'organisations') {
      if (segments.length === 1) return organisations(el);
      return organisationDetail(el, segments[1]);
    }
    if (segments[0] === 'projects') {
      const projectId = segments[1];
      if (segments.length === 2) return projectDetail(el, projectId);
      if (segments[2] === 'assets' && segments[4] === 'verify') {
        return assetVerify(el, projectId, segments[3]);
      }
      if (segments[2] === 'assets' && segments[4] === 'attest') {
        return assetAttest(el, projectId, segments[3]);
      }
      if (segments[2] === 'credits') return credits(el, projectId);
      if (segments[2] === 'scans' && segments[3] === 'new') return newScan(el, projectId);
      if (segments[2] === 'audit') return audit(el, projectId);
      el.innerHTML = empty('Page not found.');
      return;
    }
    if (segments[0] === 'invitations') return acceptInvitation(el, params);
    el.innerHTML = empty('Page not found.');
  }

  window.TRUST_VIEWS = { route, acceptInvitation };
})();
