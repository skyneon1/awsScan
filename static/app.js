// ── State ──────────────────────────────────────────────────────────────────
let allResources = [];
let activeFilter = 'all';
let searchQuery  = '';
let activeMethod = 'keys';
let uploadedFile = null;
let credCache    = { ak: '', sk: '' };
let securityData = null;
let costData     = null;
let tagData      = null;

// ── Auth helpers ────────────────────────────────────────────────────────────
function getFormData() {
  const fd = new FormData();
  if (activeMethod === 'keys') {
    fd.append('access_key', credCache.ak);
    fd.append('secret_key', credCache.sk);
  } else if (uploadedFile) {
    fd.append('creds_file', uploadedFile);
  }
  return fd;
}

// ── Login tab switch ─────────────────────────────────────────────────────────
function switchMethod(method, btn) {
  activeMethod = method;
  document.querySelectorAll('.method-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.method-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('panel-' + method).classList.add('active');
}

function toggleSecret(btn) {
  const input = btn.previousElementSibling;
  const isText = input.type === 'text';
  input.type = isText ? 'password' : 'text';
  btn.querySelector('svg').style.opacity = isText ? '1' : '0.5';
}

function handleFile(input) {
  uploadedFile = input.files[0];
  if (uploadedFile) {
    document.getElementById('file-name-label').textContent = uploadedFile.name;
    document.getElementById('file-selected').classList.add('show');
  }
}

// ── Page navigation ──────────────────────────────────────────────────────────
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

function showDashTab(id) {
  document.querySelectorAll('.dash-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`[data-tab="${id}"]`).classList.add('active');
  document.getElementById('tab-' + id).classList.add('active');
}

function goBack() {
  allResources = []; securityData = null; costData = null; tagData = null;
  uploadedFile = null; credCache = { ak: '', sk: '' };
  document.getElementById('access_key').value = '';
  document.getElementById('secret_key').value = '';
  document.getElementById('file-selected').classList.remove('show');
  showPage('login-page');
}

// ── Scanning animation ───────────────────────────────────────────────────────
function animateChips() {
  const chips = ['EC2','Lambda','IAM','S3','RDS'];
  chips.forEach(c => { document.getElementById('chip-' + c).className = 'svc-chip'; });
  let i = 0;
  const iv = setInterval(() => {
    if (i > 0) document.getElementById('chip-' + chips[i - 1]).className = 'svc-chip done';
    if (i < chips.length) {
      document.getElementById('chip-' + chips[i]).className = 'svc-chip scanning';
      i++;
    } else { clearInterval(iv); }
  }, 900);
}

// ── Main scan ────────────────────────────────────────────────────────────────
async function startConnect() {
  const errBox = document.getElementById('login-error');
  errBox.classList.remove('show');

  const ak = document.getElementById('access_key').value.trim();
  const sk = document.getElementById('secret_key').value.trim();

  if (activeMethod === 'keys' && (!ak || !sk)) {
    errBox.textContent = 'Please enter both Access Key ID and Secret Access Key.';
    errBox.classList.add('show'); return;
  }
  if (activeMethod === 'file' && !uploadedFile) {
    errBox.textContent = 'Please upload your AWS credentials file.';
    errBox.classList.add('show'); return;
  }

  credCache = { ak, sk };
  document.getElementById('connect-btn').disabled = true;
  showPage('scan-page');
  document.getElementById('scan-step').textContent = 'Discovering regions…';
  animateChips();

  const fd = new FormData();
  if (activeMethod === 'keys') { fd.append('access_key', ak); fd.append('secret_key', sk); }
  else { fd.append('creds_file', uploadedFile); }

  try {
    const res  = await fetch('/scan', { method: 'POST', body: fd });
    const data = await res.json();

    if (data.error) {
      showPage('login-page');
      errBox.textContent = 'AWS error: ' + data.error;
      errBox.classList.add('show');
      document.getElementById('connect-btn').disabled = false;
      return;
    }

    allResources = data.resources || [];
    buildDashboard(data.summary);
    renderTable();
    ['EC2','Lambda','IAM','S3','RDS'].forEach(c => {
      document.getElementById('chip-' + c).className = 'svc-chip done';
    });
    setTimeout(() => {
      showPage('dashboard-page');
      showDashTab('resources');
      document.getElementById('connect-btn').disabled = false;
    }, 500);

  } catch (err) {
    showPage('login-page');
    errBox.textContent = 'Network error: ' + err.message;
    errBox.classList.add('show');
    document.getElementById('connect-btn').disabled = false;
  }
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
function buildDashboard(summary) {
  const ak = credCache.ak;
  document.getElementById('account-label').textContent =
    ak ? ak.slice(0,8) + '••••' : 'Connected';
  document.getElementById('scan-timestamp').textContent =
    'Scanned at ' + new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });

  // Summary cards
  const byService = summary.by_service || {};
  let cards = `
    <div class="stat-card c-blue"><div class="stat-label">Total Resources</div><div class="stat-val">${summary.total}</div><div class="stat-sub">across all services</div></div>
    <div class="stat-card c-green"><div class="stat-label">Active</div><div class="stat-val">${summary.active}</div><div class="stat-sub">running / available</div></div>
    <div class="stat-card c-red"><div class="stat-label">Inactive</div><div class="stat-val">${summary.inactive}</div><div class="stat-sub">stopped / unused</div></div>
  `;
  for (const [svc, c] of Object.entries(byService)) {
    cards += `<div class="stat-card c-gray"><div class="stat-label">${svc}</div><div class="stat-val">${c.active + c.inactive}</div><div class="stat-sub">${c.active} active</div></div>`;
  }
  document.getElementById('summary-grid').innerHTML = cards;

  // Donut chart — service breakdown
  drawDonut('donut-service', byService, summary.total);

  // Region bar chart
  const byRegion = summary.by_region || {};
  const sorted = Object.entries(byRegion).sort((a,b) => b[1] - a[1]).slice(0, 8);
  const max = sorted[0]?.[1] || 1;
  const barHtml = sorted.length === 0
    ? '<div style="color:var(--muted);font-size:13px;text-align:center">No regional resources</div>'
    : sorted.map(([reg, cnt]) => `
        <div class="bar-item">
          <div class="bar-label" title="${reg}">${reg}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${Math.round(cnt/max*100)}%"></div></div>
          <div class="bar-count">${cnt}</div>
        </div>`).join('');
  document.getElementById('region-bars').innerHTML = barHtml;
}

// ── Donut chart (canvas-free, SVG-based) ─────────────────────────────────────
const PALETTE = ['#5b7fff','#22c55e','#f59e0b','#a855f7','#06b6d4','#ef4444','#6ee7b7','#fbbf24'];

function drawDonut(containerId, byService, total) {
  const container = document.getElementById(containerId);
  if (!container || total === 0) { container && (container.innerHTML = '<div style="color:var(--muted);text-align:center;font-size:13px">No data</div>'); return; }

  const entries = Object.entries(byService).map(([svc, c], i) => ({
    label: svc, value: c.active + c.inactive, color: PALETTE[i % PALETTE.length]
  }));

  const size = 120, r = 50, cx = 60, cy = 60, strokeW = 14;
  const circ = 2 * Math.PI * r;
  let offset = -circ / 4; // start at top
  let paths = '';

  for (const e of entries) {
    const dash = (e.value / total) * circ;
    paths += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${e.color}"
      stroke-width="${strokeW}" stroke-dasharray="${dash} ${circ - dash}"
      stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cy})" style="transition:stroke-dasharray .5s"/>`;
    offset -= dash;
  }

  const svg = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${paths}
    <circle cx="${cx}" cy="${cy}" r="${r - strokeW}" fill="#13151f"/>
    </svg>`;

  const legend = entries.map(e => `
    <div class="legend-item">
      <div class="legend-dot" style="background:${e.color}"></div>
      <div class="legend-label">${e.label}</div>
      <div class="legend-val">${e.value}</div>
    </div>`).join('');

  container.innerHTML = `
    <div class="chart-wrap">
      <div class="donut-wrap">
        ${svg}
        <div class="donut-center"><div class="big">${total}</div><div class="small">total</div></div>
      </div>
      <div class="legend">${legend}</div>
    </div>`;
}

// ── Resource table ────────────────────────────────────────────────────────────
function setFilter(f, btn) {
  activeFilter = f;
  document.querySelectorAll('.pill-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderTable();
}
function setSearch(q) { searchQuery = q.toLowerCase(); renderTable(); }

function renderTable() {
  let rows = allResources;
  if (activeFilter === 'active')   rows = rows.filter(r => r.active);
  if (activeFilter === 'inactive') rows = rows.filter(r => !r.active);
  if (['EC2','Lambda','IAM','S3','RDS'].includes(activeFilter))
    rows = rows.filter(r => r.service === activeFilter);
  if (searchQuery)
    rows = rows.filter(r => r.name?.toLowerCase().includes(searchQuery) || r.id?.toLowerCase().includes(searchQuery));

  const tbody = document.getElementById('resource-tbody');
  const empty = document.getElementById('empty-state');
  if (rows.length === 0) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';

  tbody.innerHTML = rows.map(r => `
    <tr>
      <td><span class="svc-badge svc-${r.service}">${r.service}</span></td>
      <td class="mono">${r.name}</td>
      <td style="color:var(--muted2);font-size:12px">${r.type}</td>
      <td style="color:var(--muted2);font-size:12px">${r.region}</td>
      <td style="color:var(--muted2);font-size:12px">${r.state}</td>
      <td><span class="status-dot ${r.active ? 'active' : 'inactive'}">${r.active ? 'Active' : 'Inactive'}</span></td>
      <td style="color:var(--muted);font-size:12px">${fmtDate(r.launched)}</td>
    </tr>`).join('');
}

// ── Security tab ──────────────────────────────────────────────────────────────
let secFilter = 'ALL';

async function loadSecurity() {
  if (securityData) { renderSecurity(); return; }
  document.getElementById('sec-content').innerHTML = `
    <div class="loading-row"><div class="spinner"></div>Running security audit across all regions…</div>`;

  const fd = getFormData();
  try {
    const res  = await fetch('/scan/security', { method: 'POST', body: fd });
    securityData = await res.json();
    if (securityData.error) {
      document.getElementById('sec-content').innerHTML =
        `<div class="empty-state"><strong>Error</strong><p>${securityData.error}</p></div>`;
      return;
    }
    renderSecurity();
  } catch (e) {
    document.getElementById('sec-content').innerHTML =
      `<div class="empty-state"><strong>Network error</strong><p>${e.message}</p></div>`;
  }
}

function renderSecurity() {
  const d = securityData;
  const counts = d.counts || {};

  // Update tab badge
  const crit = (counts.CRITICAL || 0) + (counts.HIGH || 0);
  const badge = document.getElementById('sec-badge');
  badge.textContent = d.total;
  badge.className = 'tab-badge ' + (crit > 0 ? 'red' : crit > 0 ? 'yellow' : '');

  let findings = d.findings || [];
  if (secFilter !== 'ALL') findings = findings.filter(f => f.severity === secFilter);

  const sevBars = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s => `
    <div class="sev-card sev-${s}" style="cursor:pointer" onclick="setSevFilter('${s}')">
      <div class="sev-count">${counts[s] || 0}</div>
      <div class="sev-label">${s}</div>
    </div>`).join('');

  const cards = findings.length === 0
    ? '<div class="empty-state"><strong>No findings</strong><p>No issues found for this filter.</p></div>'
    : findings.map(f => `
      <div class="finding-card">
        <span class="finding-sev ${f.severity}">${f.severity}</span>
        <div class="finding-body">
          <h4>${f.title}</h4>
          <p>${f.detail}</p>
          <div class="finding-meta">
            <span>${f.category}</span>
            <span>${f.region}</span>
          </div>
        </div>
        <div class="finding-resource">${f.resource}</div>
      </div>`).join('');

  const filterBtns = ['ALL','CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s =>
    `<button class="pill-btn ${secFilter === s ? 'active' : ''}" onclick="setSevFilter('${s}')">${s} ${s!=='ALL'?counts[s]||0:d.total}</button>`
  ).join('');

  document.getElementById('sec-content').innerHTML = `
    <div class="severity-bar">${sevBars}</div>
    <div class="filters-bar" style="margin-bottom:16px">${filterBtns}</div>
    <div class="finding-list">${cards}</div>`;
}

function setSevFilter(f) { secFilter = f; renderSecurity(); }

// ── Cost tab ──────────────────────────────────────────────────────────────────
async function loadCosts() {
  if (costData) { renderCosts(); return; }
  document.getElementById('cost-content').innerHTML =
    `<div class="loading-row"><div class="spinner"></div>Estimating monthly costs…</div>`;

  const fd = getFormData();
  try {
    const res = await fetch('/scan/costs', { method: 'POST', body: fd });
    costData = await res.json();
    if (costData.error) {
      document.getElementById('cost-content').innerHTML =
        `<div class="empty-state"><strong>Error</strong><p>${costData.error}</p></div>`;
      return;
    }
    renderCosts();
  } catch (e) {
    document.getElementById('cost-content').innerHTML =
      `<div class="empty-state"><strong>Network error</strong><p>${e.message}</p></div>`;
  }
}

function renderCosts() {
  const d = costData;
  const breakdown = d.breakdown || {};
  const allRows = [...(d.ec2 || []), ...(d.rds || [])];

  const breakdownCards = Object.entries(breakdown).map(([svc, amt]) => `
    <div class="stat-card c-green">
      <div class="stat-label">${svc}</div>
      <div class="stat-val">$${amt.toFixed(2)}</div>
      <div class="stat-sub">/ month</div>
    </div>`).join('');

  const rows = allRows.map(r => {
    const cost = r.monthly_usd != null
      ? `<span class="cost-val ${r.monthly_usd === 0 ? 'zero' : ''}">$${r.monthly_usd.toFixed(2)}/mo</span>`
      : `<span class="cost-val unknown">—</span>`;
    return `<tr>
      <td><span class="svc-badge svc-${r.service}">${r.service}</span></td>
      <td class="mono">${r.name}</td>
      <td style="color:var(--muted2);font-size:12px">${r.type}</td>
      <td style="color:var(--muted2);font-size:12px">${r.region}</td>
      <td style="color:var(--muted2);font-size:12px">${r.state}</td>
      <td>${cost}</td>
    </tr>`;
  }).join('');

  const badge = document.getElementById('cost-badge');
  badge.textContent = '$' + d.total_monthly_usd.toFixed(2);

  document.getElementById('cost-content').innerHTML = `
    <div class="cost-highlight" style="margin-bottom:20px;display:flex;flex-direction:column;align-items:center">
      <div class="big-cost">$${d.total_monthly_usd.toFixed(2)}</div>
      <div class="big-label">Estimated monthly cost</div>
    </div>
    <div class="summary-grid" style="margin-bottom:20px">${breakdownCards}</div>
    <div class="cost-note">⚠️ Estimates are on-demand Linux us-east-1 pricing. Actual costs depend on region, reserved instances, data transfer, and storage.</div>
    <div style="margin-top:20px">
      <div class="table-card"><table>
        <thead><tr><th>Service</th><th>Name</th><th>Type</th><th>Region</th><th>State</th><th>Est. Cost</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="empty-state">No billable resources found.</td></tr>'}</tbody>
      </table></div>
    </div>`;
}

// ── Tags tab ──────────────────────────────────────────────────────────────────
async function loadTags() {
  if (tagData) { renderTags(); return; }
  document.getElementById('tag-content').innerHTML =
    `<div class="loading-row"><div class="spinner"></div>Checking tag compliance…</div>`;

  const fd = getFormData();
  try {
    const res = await fetch('/scan/tags', { method: 'POST', body: fd });
    tagData = await res.json();
    if (tagData.error) {
      document.getElementById('tag-content').innerHTML =
        `<div class="empty-state"><strong>Error</strong><p>${tagData.error}</p></div>`;
      return;
    }
    renderTags();
  } catch (e) {
    document.getElementById('tag-content').innerHTML =
      `<div class="empty-state"><strong>Network error</strong><p>${e.message}</p></div>`;
  }
}

function renderTags() {
  const d = tagData;
  const rate = d.compliance_rate ?? 100;
  const badge = document.getElementById('tag-badge');
  badge.textContent = Math.round(rate) + '%';
  badge.className = 'tab-badge ' + (rate < 50 ? 'red' : rate < 80 ? 'yellow' : '');

  const nonCompliant = (d.records || []).filter(r => !r.compliant);
  const compliant    = (d.records || []).filter(r => r.compliant);

  const rows = (d.records || []).map(r => {
    const missing = (r.missing_tags || []).map(t => `<span class="tag-badge">${t}</span>`).join('');
    const existing = Object.keys(r.existing_tags || {}).filter(k => !r.missing_tags.includes(k))
      .map(k => `<span class="tag-badge present">${k}</span>`).join('');
    return `<tr>
      <td><span class="svc-badge svc-${r.service}">${r.service}</span></td>
      <td class="mono">${r.name}</td>
      <td style="color:var(--muted2);font-size:12px">${r.region}</td>
      <td><span class="status-dot ${r.compliant ? 'active' : 'inactive'}">${r.compliant ? 'Compliant' : 'Non-compliant'}</span></td>
      <td>${existing}${missing}</td>
    </tr>`;
  }).join('');

  document.getElementById('tag-content').innerHTML = `
    <div class="summary-grid" style="margin-bottom:20px">
      <div class="stat-card c-blue"><div class="stat-label">Total Checked</div><div class="stat-val">${d.total}</div></div>
      <div class="stat-card c-green"><div class="stat-label">Compliant</div><div class="stat-val">${d.compliant}</div></div>
      <div class="stat-card c-red"><div class="stat-label">Non-Compliant</div><div class="stat-val">${d.non_compliant}</div></div>
      <div class="stat-card ${rate>=80?'c-green':rate>=50?'c-yellow':'c-red'}">
        <div class="stat-label">Compliance Rate</div>
        <div class="stat-val">${rate}%</div>
      </div>
    </div>
    <div style="margin-bottom:20px">
      <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:6px"><span>Compliance</span><span>${rate}%</span></div>
      <div class="compliance-bar"><div class="compliance-fill" style="width:${rate}%"></div></div>
    </div>
    <div style="font-size:12px;color:var(--muted);margin-bottom:12px">Required tags: <strong style="color:var(--text)">Name, Environment, Owner, Project</strong> — <span style="color:var(--red)">${d.non_compliant} resources</span> are missing one or more.</div>
    <div class="table-card"><table>
      <thead><tr><th>Service</th><th>Name</th><th>Region</th><th>Status</th><th>Tags</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5" class="empty-state">No resources found.</td></tr>'}</tbody>
    </table></div>`;
}

// ── Exports ───────────────────────────────────────────────────────────────────
function exportJSON() {
  dl(new Blob([JSON.stringify(allResources, null, 2)], { type: 'application/json' }), 'awsScan-resources.json');
}
function exportCSV() {
  const cols = ['service','name','id','type','state','active','region','launched'];
  const lines = [cols.join(','), ...allResources.map(r => cols.map(c => `"${r[c] ?? ''}"`).join(','))];
  dl(new Blob([lines.join('\n')], { type: 'text/csv' }), 'awsScan-resources.csv');
}
function exportSecurityJSON() {
  if (!securityData) return;
  dl(new Blob([JSON.stringify(securityData.findings, null, 2)], { type: 'application/json' }), 'awsScan-security.json');
}
function dl(blob, name) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click();
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function fmtDate(d) {
  if (!d || d === 'N/A') return '—';
  try { return new Date(d).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }); }
  catch { return d; }
}
