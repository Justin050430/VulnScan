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
              ${can(perms, 'credential.read') && a.VerificationStatus === 'Verified' ? `<a class="btn btn-xs btn-secondary" href="#/projects/${projectId}/assets/${a.AssetID}/credentials">Credentials</a>` : ''}
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
      const isLocal = /^(localhost|127\.|::1$)/i.test(asset.Hostname);
      if (c.RecordName) {
        challengeBox.innerHTML = `
          <div class="trust-notice">Step 1 — create this DNS TXT record on your domain.</div>
          <div class="kv" style="grid-template-columns:130px 1fr">
            <span class="k">Record name</span><span class="mono" style="word-break:break-all">${U.esc(c.RecordName)}</span>
            <span class="k">Type</span><span>${U.esc(c.RecordType)}</span>
            <span class="k">Value to publish</span><span class="mono" style="word-break:break-all" id="v-value">${U.esc(c.RecordValue)}</span>
            <span class="k">Expires</span><span>${U.fmtDT(c.ExpiresAt)}</span>
          </div>
          <div class="row" style="margin-top:10px;gap:8px">
            <button class="btn btn-sm btn-secondary" id="v-copy">Copy value</button>
          </div>
          <p class="hint" style="margin-top:10px">Step 2 — wait for DNS to propagate (seconds to minutes), then click
            <b>Check now</b> on the right. Do not paste this value into a browser; it is a record, not a link.</p>`;
      } else {
        const helper = isLocal
          ? `<p class="hint" style="margin-top:10px">Step 1b (bundled local target only) — open
               <a href="${U.esc(c.FileURL.replace('/.well-known/vulnscan.txt', '/__test__/verification'))}" target="_blank" rel="noopener">the challenge page</a>,
               paste the value above, and press <b>Publish</b>.</p>`
          : `<p class="hint" style="margin-top:10px">Step 1b — create this file on your web server so the URL below returns exactly that text.</p>`;
        challengeBox.innerHTML = `
          <div class="trust-notice">Step 1 — publish this exact text as a file on your site.</div>
          <div class="kv" style="grid-template-columns:130px 1fr">
            <span class="k">Text to publish</span><span class="mono" style="word-break:break-all" id="v-value">${U.esc(c.FileContent)}</span>
            <span class="k">Expires</span><span>${U.fmtDT(c.ExpiresAt)}</span>
          </div>
          <div class="row" style="margin-top:10px;gap:8px">
            <button class="btn btn-sm btn-secondary" id="v-copy">Copy text</button>
            <a class="btn btn-sm btn-secondary" href="${U.esc(c.FileURL)}" target="_blank" rel="noopener">Open file URL</a>
          </div>
          <p class="hint" style="margin-top:10px">Step 2 — the file must then be readable at
            <span class="mono">${U.esc(c.FileURL)}</span>. The URL is only where VulnScan reads from;
            publishing the <b>text</b> above is what proves ownership.</p>
          ${helper}
          <p class="hint">Step 3 — press <b>Check now</b> on the right.</p>`;
      }
      const copyBtn = challengeBox.querySelector('#v-copy');
      if (copyBtn) {
        copyBtn.addEventListener('click', async () => {
          const value = challengeBox.querySelector('#v-value').textContent;
          try {
            await navigator.clipboard.writeText(value);
            U.toast('Challenge value copied.', 'ok');
          } catch (e) {
            U.toast('Copy failed — select the value manually.', 'err');
          }
        });
      }
      U.toast('Challenge generated. Publish the value, then run the check.', 'info');
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

  /* ================================================= TEMPORARY CREDENTIALS */
  async function assetCredentials(el, projectId, assetId) {
    el.innerHTML = U.loading('Loading credentials…');
    const [assetBody, credsBody, projectBody] = await Promise.all([
      API.get(`/api/v1/projects/${projectId}/assets/${assetId}`),
      API.get(`/api/v1/projects/${projectId}/assets/${assetId}/credentials`),
      API.get('/api/v1/projects/' + projectId)
    ]);
    const asset = assetBody.Asset;
    const credentials = credsBody.Credentials || [];
    const perms = projectBody.Permissions || [];

    const actions = (c) => {
      const out = [];
      if (can(perms, 'credential.create') && ['PendingApproval', 'Approved'].includes(c.Status) && c.HasSecret) {
        out.push(`<button class="btn btn-xs btn-secondary" data-test="${c.CredentialID}">Test login</button>`);
      }
      if (can(perms, 'credential.approve') && c.Status === 'PendingApproval') {
        out.push(`<button class="btn btn-xs btn-primary" data-approve="${c.CredentialID}">Approve</button>`);
        out.push(`<button class="btn btn-xs btn-danger" data-reject="${c.CredentialID}">Reject</button>`);
      }
      if (can(perms, 'credential.revoke') && ['PendingApproval', 'Approved', 'Used'].includes(c.Status)) {
        out.push(`<button class="btn btn-xs btn-danger" data-revoke="${c.CredentialID}">Revoke</button>`);
      }
      return out.join(' ');
    };

    el.innerHTML = `
      <div class="page-head"><div class="row"><div>
        <h1>Temporary scan credentials</h1>
        <div class="sub">${U.esc(asset.Hostname)} · approved test-account logins for authenticated scans</div>
      </div><div style="display:flex;gap:8px">
        <a class="btn btn-secondary" href="#/projects/${projectId}">← Back</a>
        ${can(perms, 'credential.create') ? '<button class="btn btn-primary" style="width:auto" id="cred-new">+ New credential</button>' : ''}
      </div></div></div>
      <div class="trust-notice">Credentials are encrypted at rest, expire automatically and can be used for one scan only.
        Create a dedicated least-privilege test account, never a personal or administrator account. MFA, CAPTCHA and SSO cannot be automated.</div>
      <div class="card card-pad" style="margin-top:16px">
        ${credentials.length ? `<div class="table-wrap"><table class="tbl">
          <thead><tr><th>Name</th><th>Account</th><th>Status</th><th>Expires</th><th>Bound scan</th><th class="actions">Actions</th></tr></thead>
          <tbody>${credentials.map(c => `<tr>
            <td><b>${U.esc(c.Name)}</b><div class="mono" style="color:var(--muted)">#${c.CredentialID} · ${U.esc(c.AuthType)}</div></td>
            <td class="mono">${U.esc(c.Username)}</td>
            <td>${statusBadge(c.Status)}${c.FailureReason ? `<div class="hint" style="color:var(--red)">${U.esc(c.FailureReason)}</div>` : ''}</td>
            <td class="tbl-nowrap">${U.fmtDT(c.ExpiresAt)}</td>
            <td>${c.BoundScanID ? `<a href="#/scans/${c.BoundScanID}">#${c.BoundScanID}</a>` : '–'}</td>
            <td class="actions">${actions(c)}</td>
          </tr>`).join('')}</tbody></table></div>` : empty('No credentials yet for this asset.')}
      </div>`;

    if (can(perms, 'credential.create')) {
      el.querySelector('#cred-new').addEventListener('click', () => credentialModal(projectId, asset, () => assetCredentials(el, projectId, assetId)));
    }

    el.querySelectorAll('[data-test]').forEach(b => b.addEventListener('click', async () => {
      b.disabled = true;
      try {
        const data = await API.post(`/api/v1/projects/${projectId}/credentials/${b.dataset.test}/test-login`, {});
        U.modal('Login test succeeded',
          `<p>The account authenticated successfully.</p>
           <div class="kv"><span class="k">Final URL</span><span class="mono">${U.esc(data.Login.FinalURL)}</span>
           <span class="k">HTTP status</span><span>${data.Login.StatusCode}</span></div>
           <p class="hint">No scan credit was used.</p>`,
          `<button class="btn btn-secondary" onclick="U.closeModal()">Close</button>`);
      } catch (e) {
        U.toast(e.message, 'err');
      } finally {
        b.disabled = false;
      }
    }));

    el.querySelectorAll('[data-approve]').forEach(b => b.addEventListener('click', () => {
      const m = U.modal('Approve temporary credential',
        `<p style="font-size:13px">By approving, the organisation authorises VulnScan to authenticate to
          <b>${U.esc(asset.Hostname)}</b> with this dedicated test account for one scan and the stated expiry window.</p>
         <label style="display:flex;gap:8px;align-items:flex-start;font-size:13px">
           <input type="checkbox" id="cred-ack" style="margin-top:3px">
           <span>I confirm the account was created for this assessment with the least privilege needed,
             and that I am a different project owner from the creator.</span></label>`,
        `<button class="btn btn-secondary" onclick="U.closeModal()">Cancel</button>
         <button class="btn btn-primary" style="width:auto" id="cred-approve">Approve</button>`);
      m.root.querySelector('#cred-approve').addEventListener('click', async () => {
        if (!m.root.querySelector('#cred-ack').checked) {
          U.toast('Tick the approval statement first.', 'err');
          return;
        }
        try {
          await API.post(`/api/v1/projects/${projectId}/credentials/${b.dataset.approve}/approve`, { acknowledge: true });
          U.closeModal();
          U.toast('Credential approved.', 'ok');
          assetCredentials(el, projectId, assetId);
        } catch (e) { U.toast(e.message, 'err'); }
      });
    }));

    el.querySelectorAll('[data-reject]').forEach(b => b.addEventListener('click', async () => {
      const m = U.modal('Reject credential',
        `<div class="field"><label>Reason (optional)</label><input id="cred-reason" maxlength="500"></div>`,
        `<button class="btn btn-secondary" onclick="U.closeModal()">Cancel</button>
         <button class="btn btn-danger" style="width:auto" id="cred-reject">Reject</button>`);
      m.root.querySelector('#cred-reject').addEventListener('click', async () => {
        try {
          await API.post(`/api/v1/projects/${projectId}/credentials/${b.dataset.reject}/reject`, {
            reason: m.root.querySelector('#cred-reason').value.trim() || undefined
          });
          U.closeModal();
          U.toast('Credential rejected and secret destroyed.', 'ok');
          assetCredentials(el, projectId, assetId);
        } catch (e) { U.toast(e.message, 'err'); }
      });
    }));

    el.querySelectorAll('[data-revoke]').forEach(b => b.addEventListener('click', async () => {
      if (!(await U.confirmDlg('Revoke this credential? The stored secret is destroyed immediately and retests on authenticated scans stop working.', 'Revoke credential'))) return;
      try {
        await API.post(`/api/v1/projects/${projectId}/credentials/${b.dataset.revoke}/revoke`, { reason: 'revoked by user' });
        U.toast('Credential revoked.', 'ok');
        assetCredentials(el, projectId, assetId);
      } catch (e) { U.toast(e.message, 'err'); }
    }));
  }

  function credentialModal(projectId, asset, onCreated) {
    const m = U.modal('New temporary credential',
      `<div class="field"><label>Name</label><input id="c-name" maxlength="100" placeholder="Pentest test account"></div>
       <div class="field"><label>Login URL</label>
         <input id="c-url" maxlength="500" value="${U.esc(asset.Scheme + '://' + asset.Hostname + '/login')}">
         <div class="hint">Must stay on the verified asset host. The form must post back to the same host.</div></div>
       <div class="form-row">
         <div class="field"><label>Username / email</label><input id="c-user" maxlength="255"></div>
         <div class="field"><label>Password</label><input id="c-pass" type="password" maxlength="500" autocomplete="new-password"></div>
       </div>
       <div class="form-row">
         <div class="field"><label>Username field (optional)</label><input id="c-userfield" maxlength="64" placeholder="auto-detect"></div>
         <div class="field"><label>Password field (optional)</label><input id="c-passfield" maxlength="64" placeholder="auto-detect"></div>
       </div>
       <div class="form-row">
         <div class="field"><label>Success URL contains</label><input id="c-successurl" maxlength="255" value="/dashboard"></div>
         <div class="field"><label>Success text (optional)</label><input id="c-successtext" maxlength="255"></div>
       </div>
       <div class="field"><label>Expires in (minutes, max 1440)</label><input id="c-expires" type="number" min="5" max="1440" value="240"></div>
       <p class="hint">At least one success indicator is required so a failed login cannot be mistaken for success.
         The secret is encrypted at rest, never returned by the API and destroyed on expiry or revocation.</p>`,
      `<button class="btn btn-secondary" onclick="U.closeModal()">Cancel</button>
       <button class="btn btn-primary" style="width:auto" id="c-save">Create credential</button>`);
    m.root.querySelector('#c-save').addEventListener('click', async () => {
      const payload = {
        name: m.root.querySelector('#c-name').value.trim(),
        auth_type: 'FORM',
        login_url: m.root.querySelector('#c-url').value.trim(),
        username: m.root.querySelector('#c-user').value.trim(),
        password: m.root.querySelector('#c-pass').value,
        username_field: m.root.querySelector('#c-userfield').value.trim() || undefined,
        password_field: m.root.querySelector('#c-passfield').value.trim() || undefined,
        success_url_contains: m.root.querySelector('#c-successurl').value.trim() || undefined,
        success_text: m.root.querySelector('#c-successtext').value.trim() || undefined,
        expires_in_minutes: parseInt(m.root.querySelector('#c-expires').value, 10)
      };
      try {
        await API.post(`/api/v1/projects/${projectId}/assets/${asset.AssetID}/credentials`, payload);
        U.closeModal();
        U.toast('Credential created. A different project owner must approve it.', 'ok');
        onCreated();
      } catch (e) { U.toast(e.message, 'err'); }
    });
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
    const [projectBody, assetsBody, creditsBody, profilesBody, credentialsBody] = await Promise.all([
      API.get('/api/v1/projects/' + projectId),
      API.get(`/api/v1/projects/${projectId}/assets`),
      API.get(`/api/v1/projects/${projectId}/credits?status=Available`),
      API.get('/api/scan-profiles'),
      API.get(`/api/v1/projects/${projectId}/credentials`).catch(() => ({ Credentials: [] }))
    ]);
    const perms = projectBody.Permissions || [];
    const assets = (assetsBody.Assets || []).filter(a => a.VerificationStatus === 'Verified');
    const credits = creditsBody.Credits || [];
    const profiles = profilesBody.ScanProfiles || [];
    const allCredentials = credentialsBody.Credentials || [];

    if (!can(perms, 'scan.start')) {
      el.innerHTML = `<div class="card card-pad">${empty('You do not have permission to start scans in this project.')}</div>`;
      return;
    }
    el.innerHTML = `
      <div class="page-head"><div class="row"><div>
        <h1>Start a scan</h1>
        <div class="sub">A scan needs a verified asset, an active attestation and one available credit.
          Optionally authenticate with an approved temporary credential to reach protected pages.</div>
      </div><a class="btn btn-secondary" href="#/projects/${projectId}">← Back</a></div></div>
      <div class="grid-2">
        <div class="card card-pad">
          <div class="field"><label>Verified asset</label>
            <select id="s-asset">${assets.map(a => `<option value="${a.AssetID}" data-scheme="${U.esc(a.Scheme)}" data-host="${U.esc(a.Hostname)}">${U.esc(a.Hostname)}</option>`).join('')}</select>
            ${assets.length ? '' : '<div class="hint">No verified assets. Verify one first.</div>'}</div>
          <div class="field"><label>Target URL</label>
            <input id="s-target" placeholder="https://example.com/">
            <div class="hint">The host must match the verified asset exactly. For an authenticated scan, start at a post-login page such as /dashboard.</div></div>
          <div class="field"><label>Authentication</label>
            <select id="s-credential"><option value="">Anonymous (no credential)</option></select>
            <div class="hint" id="s-credential-hint">Only approved, unused credentials for the selected asset appear here. One credential = one scan.</div></div>
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
    const credentialSel = el.querySelector('#s-credential');
    const credentialHint = el.querySelector('#s-credential-hint');
    const readinessBox = el.querySelector('#s-readiness');

    function syncTarget() {
      const opt = assetSel.selectedOptions[0];
      if (opt && !targetInput.value) {
        targetInput.value = `${opt.dataset.scheme}://${opt.dataset.host}/`;
      }
    }
    function syncCredentials() {
      const assetId = parseInt(assetSel.value, 10);
      const now = new Date();
      const eligible = allCredentials.filter(c =>
        Number(c.AssetID) === assetId &&
        c.Status === 'Approved' &&
        !c.BoundScanID &&
        c.HasSecret &&
        (!c.ExpiresAt || new Date(c.ExpiresAt) > now)
      );
      credentialSel.innerHTML = '<option value="">Anonymous (no credential)</option>' +
        eligible.map(c => `<option value="${c.CredentialID}">${U.esc(c.Name)} — expires ${U.fmtDT(c.ExpiresAt)}</option>`).join('');
      credentialSel.disabled = eligible.length === 0;
      credentialHint.textContent = eligible.length
        ? 'The scan logs in once with this credential. One credential = one scan; the secret is destroyed on expiry or revocation.'
        : 'No approved, unused credential for this asset. Create one on the asset’s Credentials page, then have a different project owner approve it.';
    }
    async function refreshReadiness() {
      const assetId = assetSel.value;
      if (!assetId) { readinessBox.innerHTML = empty('No verified asset available.'); return; }
      try {
        const data = await API.get(`/api/v1/projects/${projectId}/scan-readiness`, {
          asset_id: assetId,
          credential_id: credentialSel.value || undefined
        });
        const r = data.Readiness;
        const rows = Object.keys(r.Checks).map(k => {
          const c = r.Checks[k];
          return `<div class="row" style="justify-content:space-between;padding:4px 0">
            <span>${k}</span><span>${c.Ok ? '<span class="badge confirmed">OK</span>' : `<span class="badge failed">${U.esc(c.Code || 'Blocked')}</span>`}</span></div>`;
        }).join('');
        readinessBox.innerHTML = rows + (r.Ready ? '' : `<div class="hint" style="margin-top:8px">Next action: ${U.esc(r.NextAction)}</div>`);
      } catch (e) { readinessBox.innerHTML = U.esc(e.message); }
    }
    assetSel.addEventListener('change', () => {
      targetInput.value = '';
      syncTarget();
      syncCredentials();
      refreshReadiness();
    });
    credentialSel.addEventListener('change', refreshReadiness);
    syncTarget();
    syncCredentials();
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
          credential_id: parseInt(credentialSel.value, 10) || undefined,
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
      if (segments[2] === 'assets' && segments[4] === 'credentials') {
        return assetCredentials(el, projectId, segments[3]);
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
