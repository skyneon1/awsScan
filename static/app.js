// ── Theme ───────────────────────────────────────────────────────────────────
function initTheme() {
  const theme = localStorage.getItem('theme') || 'dark';
  if (theme === 'light') {
    document.body.classList.add('light-mode');
  }
}
initTheme();

function toggleTheme() {
  const isLight = document.body.classList.toggle('light-mode');
  localStorage.setItem('theme', isLight ? 'light' : 'dark');
}

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
let userData     = null;

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
  allResources = []; securityData = null; costData = null; tagData = null; userData = null;
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
      
      // Proactively load secondary data in the background
      loadSecurity();
      loadCosts();
      loadTags();
      loadUsers();
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
  const svcColors = {
    'EC2': 'c-blue', 'RDS': 'c-cyan', 'Lambda': 'c-purple', 'S3': 'c-yellow',
    'IAM': 'c-teal', 'VPC': 'c-green', 'DynamoDB': 'c-blue', 'CloudFront': 'c-pink'
  };
  for (const [svc, c] of Object.entries(byService)) {
    const cls = svcColors[svc] || 'c-gray';
    cards += `<div class="stat-card ${cls}"><div class="stat-label">${svc}</div><div class="stat-val">${c.active + c.inactive}</div><div class="stat-sub">${c.active} active</div></div>`;
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
    <circle cx="${cx}" cy="${cy}" r="${r - strokeW}" fill="var(--bg2)"/>
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
  if (activeFilter === 'active') rows = rows.filter(r => r.active);
  else if (activeFilter === 'inactive') rows = rows.filter(r => !r.active);
  else if (activeFilter !== 'all') rows = rows.filter(r => r.service === activeFilter);
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
      <td style="color:var(--muted2);font-size:11px">
        ${r.extra ? Object.entries(r.extra).map(([k,v]) => `<div style="white-space:nowrap" title="${v}"><strong style="color:var(--muted)">${k}:</strong> ${String(v).length > 22 ? String(v).substring(0,22)+'...' : v}</div>`).join('') : '<span style="color:var(--border2)">—</span>'}
      </td>
      <td><span class="status-dot ${r.active ? 'active' : 'inactive'}">${r.active ? 'Active' : 'Inactive'}</span></td>
      <td style="color:var(--muted);font-size:12px">${fmtDate(r.launched)}</td>
      <td>
        ${ r.service === 'EC2' && r.state === 'running' ? `<button class="action-btn" onclick="performAction('ec2', 'stop', '${r.id}', '${r.region}')">Stop</button><button class="action-btn" onclick="performAction('ec2', 'reboot', '${r.id}', '${r.region}')">Reboot</button><button class="action-btn" style="color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="performAction('ec2', 'terminate', '${r.id}', '${r.region}')">Terminate</button>` : '' }
        ${ r.service === 'EC2' && r.state === 'stopped' ? `<button class="action-btn" onclick="performAction('ec2', 'start', '${r.id}', '${r.region}')">Start</button><button class="action-btn" style="color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="performAction('ec2', 'terminate', '${r.id}', '${r.region}')">Terminate</button>` : '' }
        ${ r.service === 'RDS' && r.state === 'available' ? `<button class="action-btn" onclick="performAction('rds', 'stop', '${r.id}', '${r.region}')">Stop</button><button class="action-btn" style="color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="performAction('rds', 'delete', '${r.id}', '${r.region}')">Delete</button>` : '' }
        ${ r.service === 'RDS' && r.state === 'stopped' ? `<button class="action-btn" onclick="performAction('rds', 'start', '${r.id}', '${r.region}')">Start</button><button class="action-btn" style="color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="performAction('rds', 'delete', '${r.id}', '${r.region}')">Delete</button>` : '' }
        ${ r.service === 'CloudFront' && r.state === 'Deployed' && r.active === true ? `<button class="action-btn" onclick="performAction('cloudfront', 'stop', '${r.id}', '${r.region}')">Disable</button>` : '' }
        ${ r.service === 'CloudFront' && r.state === 'Deployed' && r.active === false ? `<button class="action-btn" onclick="performAction('cloudfront', 'start', '${r.id}', '${r.region}')">Enable</button>` : '' }
        ${ r.service === 'DynamoDB' && r.state === 'active' ? `<button class="action-btn" style="color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="performAction('dynamodb', 'delete', '${r.id}', '${r.region}')">Delete</button>` : '' }
      </td>
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

// ── Help Modal ────────────────────────────────────────────────────────────────
function openHelpModal() { document.getElementById('help-modal').classList.add('show'); }
function closeHelpModal() { document.getElementById('help-modal').classList.remove('show'); }

// ── Resource Action ───────────────────────────────────────────────────────────
async function performAction(service, action, resourceId, region, extra = '') {
  if(!confirm(`Are you sure you want to ${action} ${resourceId}?`)) return;
  
  if (credCache && credCache.ak === 'DEMO-DATA') {
    optimisticUpdate(service, action, resourceId, extra, true);
    setTimeout(() => { optimisticUpdate(service, action, resourceId, extra, false); }, 2500);
    return;
  }
  
  optimisticUpdate(service, action, resourceId, extra, true);
  
  const fd = getFormData();
  fd.append('service', service);
  fd.append('action', action);
  fd.append('resource_id', resourceId);
  fd.append('region', region);
  fd.append('extra', extra);
  try {
    const res = await fetch('/action', {method: 'POST', body: fd});
    const d = await res.json();
    if(d.error) {
        alert('Error: ' + d.error);
    } else {
        if (service === 'ec2' || service === 'rds' || service === 'cloudfront' || service === 'dynamodb') {
            startPolling(service, resourceId, region);
        } else {
            optimisticUpdate(service, action, resourceId, extra, false);
        }
    }
  } catch(e) {
    alert('Network error: ' + e.message);
  }
}

function optimisticUpdate(service, action, resourceId, extra, isPending = false) {
  if (service === 'ec2' || service === 'rds' || service === 'cloudfront' || service === 'dynamodb') {
    const res = allResources.find(r => r.id === resourceId && r.service.toLowerCase() === service);
    if (res) {
      if (isPending) {
        if (action === 'start') { res.state = 'starting...'; res.active = true; }
        else if (action === 'stop') { res.state = 'stopping...'; res.active = false; }
        else if (action === 'reboot') { res.state = 'rebooting...'; }
        else if (action === 'terminate') { res.state = 'shutting-down...'; res.active = false; }
        else if (action === 'delete') { res.state = 'deleting...'; res.active = false; }
      } else {
        if (action === 'start') { res.state = service === 'ec2' ? 'running' : (service === 'cloudfront' ? 'Deployed' : 'available'); res.active = true; }
        else if (action === 'stop') { res.state = service === 'cloudfront' ? 'Deployed' : 'stopped'; res.active = false; }
        else if (action === 'reboot') { res.state = service === 'ec2' ? 'running' : 'available'; }
        else if (action === 'terminate') { res.state = 'terminated'; res.active = false; }
        else if (action === 'delete') { res.state = 'deleted'; res.active = false; }
      }
      renderTable();
      buildDashboard(computeSummary());
    }
  } else if (service === 'iam_key') {
    if (userData && userData.users) {
      const user = userData.users.find(u => u.username === extra);
      if (user) {
        const key = user.access_keys.find(k => k.key_id === resourceId);
        if (key) {
          if (isPending) {
              key.status = 'Updating...';
          } else {
              key.status = action === 'enable' ? 'Active' : 'Inactive';
          }
          renderUsers();
        }
      }
    }
  }
}

async function startPolling(service, resourceId, region) {
  const fd = getFormData();
  fd.append('service', service);
  fd.append('resource_id', resourceId);
  fd.append('region', region);
  
  const targetStableStates = ['running', 'stopped', 'terminated', 'available', 'deleted', 'Deployed', 'active'];
  let attempts = 0;
  
  const poll = async () => {
    try {
      attempts++;
      const res = await fetch('/status', { method: 'POST', body: fd });
      const d = await res.json();
      
      if (d.error && attempts > 15) return;

      if (d.state && targetStableStates.includes(d.state)) {
         const r = allResources.find(x => x.id === resourceId);
         if (r) {
             r.state = d.state;
             r.active = d.active;
             renderTable();
             buildDashboard(computeSummary());
         }
         return; 
      }
      
      if (attempts < 30) {
        setTimeout(poll, 4000);
      }
    } catch(e) {
      console.error(e);
    }
  };
  
  setTimeout(poll, 4000);
}

function computeSummary() {
  const summary = {
    total: allResources.length,
    active: allResources.filter(r => r.active).length,
    inactive: allResources.filter(r => !r.active).length,
    by_service: {},
    by_region: {}
  };
  for (const r of allResources) {
    const svc = r.service;
    const reg = r.region || 'global';
    if (!summary.by_service[svc]) 
      summary.by_service[svc] = { active: 0, inactive: 0 };
    if (r.active) summary.by_service[svc].active++;
    else summary.by_service[svc].inactive++;
    
    if (reg !== 'global') {
      summary.by_region[reg] = (summary.by_region[reg] || 0) + 1;
    }
  }
  return summary;
}

// ── Users Tab ─────────────────────────────────────────────────────────────────
async function loadUsers() {
  if (userData) { renderUsers(); return; }
  document.getElementById('user-content').innerHTML = `<div class="loading-row"><div class="spinner"></div>Loading detailed IAM data…</div>`;
  const fd = getFormData();
  try {
    const res = await fetch('/scan/users', { method: 'POST', body: fd });
    userData = await res.json();
    if (userData.error) {
      document.getElementById('user-content').innerHTML = `<div class="empty-state"><strong>Error</strong><p>${userData.error}</p></div>`;
      return;
    }
    renderUsers();
  } catch (e) {
    document.getElementById('user-content').innerHTML = `<div class="empty-state"><strong>Network error</strong><p>${e.message}</p></div>`;
  }
}

function renderUsers() {
  const d = userData;
  const badge = document.getElementById('user-badge');
  if (badge) badge.textContent = d.total || 0;
  
  if (!d.users || d.users.length === 0) {
    document.getElementById('user-content').innerHTML = `<div class="empty-state">No users found.</div>`;
    return;
  }
  
  const html = d.users.map(u => {
    const keysHtml = u.access_keys.length > 0 ? u.access_keys.map(k => `
      <div class="key-row">
        <div>
          <div style="font-family:monospace; color:var(--text); font-size:13px">${k.key_id} <span class="status-dot ${k.status==='Active'?'active':'inactive'}">${k.status}</span></div>
          <div style="font-size:11px; margin-top:4px; color:var(--muted)">Last used: ${k.last_used} (${k.last_service} in ${k.last_region}) | Age: ${k.age_days != null ? k.age_days + ' days' : 'N/A'}</div>
        </div>
        <div>
          ${k.status === 'Active' ? `<button class="action-btn" onclick="performAction('iam_key','disable','${k.key_id}','global','${u.username}')">Disable</button>` : `<button class="action-btn" onclick="performAction('iam_key','enable','${k.key_id}','global','${u.username}')">Enable</button>`}
        </div>
      </div>
    `).join('') : '<div style="font-size:12px;color:var(--muted)">No access keys</div>';
    
    return `
      <div class="user-card">
        <div class="user-header">
          <div>
            <div class="user-name">
              ${u.username} 
              ${u.is_admin ? '<span class="admin-badge">ADMIN</span>' : ''}
              ${u.mfa_enabled ? '<span style="color:var(--green);font-size:12px">✓ MFA</span>' : '<span style="color:var(--red);font-size:12px">✗ No MFA</span>'}
            </div>
            <div class="user-meta">ARN: ${u.arn} | Created: ${fmtDate(u.created)} | Last Login: ${u.last_login !== 'Never' ? fmtDate(u.last_login) : 'Never'}</div>
          </div>
        </div>
        <div class="user-grid">
          <div>
            <strong style="display:block; margin-bottom:8px; color:var(--text);">Groups &amp; Policies</strong>
            <div>Groups: ${u.groups.length ? u.groups.map(g => `<li>${g}</li>`).join('') : 'None'}</div>
            <div style="margin-top:8px">Attached: ${u.policies.length ? u.policies.map(p => `<li>${p}</li>`).join('') : 'None'}</div>
            <div style="margin-top:8px">Inline: ${u.inline_policies.length ? u.inline_policies.map(p => `<li>${p}</li>`).join('') : 'None'}</div>
          </div>
          <div>
            <strong style="display:block; margin-bottom:8px; color:var(--text);">Access Keys</strong>
            ${keysHtml}
          </div>
        </div>
      </div>
    `;
  }).join('');
  
  document.getElementById('user-content').innerHTML = html;
}

// ── Demo Mode ─────────────────────────────────────────────────────────────────
function startDemo() {
  document.getElementById('login-error').classList.remove('show');
  credCache = { ak: 'DEMO-DATA', sk: '' };
  
  showPage('scan-page');
  document.getElementById('scan-step').textContent = 'Loading mock data…';
  animateChips();
  
  allResources = [
    { service: 'EC2', name: 'web-node-01', id: 'i-0abcd1234', type: 't3.medium', state: 'running', active: true, region: 'us-east-1', launched: '2025-01-10T10:00:00Z', extra: {'Public IP': '203.0.113.45', 'Private IP': '10.0.1.12', 'VPC ID': 'vpc-abcdef12'} },
    { service: 'EC2', name: 'worker-02', id: 'i-0fced4567', type: 't3.large', state: 'stopped', active: false, region: 'eu-west-1', launched: '2024-11-20T10:00:00Z', extra: {'Public IP': 'None', 'Private IP': '10.0.2.55', 'VPC ID': 'vpc-bcdef123'} },
    { service: 'RDS', name: 'prod-db', id: 'db-XYZ', type: 'db.r6g.large', state: 'available', active: true, region: 'us-east-1', launched: '2023-06-15T08:00:00Z', extra: {'Endpoint': 'prod-01.us-east-1.rds.amazonaws.com', 'Port': 5432, 'VPC ID': 'vpc-abcdef12'} },
    { service: 'CloudFront', name: 'process-uploads', id: 'arn:aws:lambda:...', type: 'Distribution', state: 'Deployed', active: true, region: 'global', launched: '2025-03-01T00:00:00Z', extra: {'Enabled': 'Yes', 'Origins': 2} },
    { service: 'DynamoDB', name: 'users-table', id: 'users-table', type: 'Table', state: 'active', active: true, region: 'us-east-1', launched: '2022-01-10T00:00:00Z', extra: {'Item Count': 1420, 'Size (Bytes)': 20485} },
    { service: 'IAM', name: 'alice-admin', id: 'AIDA123456789', type: 'IAM User', state: 'active', active: true, region: 'global', launched: '2024-05-12T00:00:00Z' }
  ];
  
  const summary = {
    total: 6,
    active: 5,
    inactive: 1,
    by_service: {
      'EC2': { active: 1, inactive: 1 },
      'RDS': { active: 1, inactive: 0 },
      'Lambda': { active: 1, inactive: 0 },
      'S3': { active: 1, inactive: 0 },
      'IAM': { active: 1, inactive: 0 }
    },
    by_region: { 'us-east-1': 3, 'eu-west-1': 1, 'global': 2 }
  };

  securityData = {
    total: 3,
    counts: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 1, INFO: 0 },
    findings: [
      { severity: 'CRITICAL', title: 'Open SSH Port', detail: 'Security group allows inbound SSH (port 22) from highly open IP ranges.', category: 'Security Group', region: 'us-east-1', resource: 'sg-0abcd1234' },
      { severity: 'HIGH', title: 'Root Account Keys Present', detail: 'Root account has active access keys, which is strongly discouraged.', category: 'IAM', region: 'global', resource: 'Root Account' },
      { severity: 'LOW', title: 'Unencrypted S3 Bucket', detail: 'Bucket does not enforce default SSE.', category: 'S3', region: 'global', resource: 'logs-archive-old' }
    ]
  };

  costData = {
    total_monthly_usd: 153.30,
    breakdown: { 'EC2': 43.80, 'RDS': 109.50 },
    ec2: [
      { service: 'EC2', name: 'web-node-01', id: 'i-0abcd1', type: 't3.medium', region: 'us-east-1', state: 'running', monthly_usd: 30.66 },
      { service: 'EC2', name: 'worker-02', id: 'i-0fced4', type: 't3.large', region: 'eu-west-1', state: 'stopped', monthly_usd: 0 }
    ],
    rds: [
      { service: 'RDS', name: 'prod-db', id: 'db-XYZ', type: 'db.r6g.large', region: 'us-east-1', state: 'available', monthly_usd: 109.50 }
    ]
  };

  tagData = {
    total: 3, compliant: 1, non_compliant: 2, compliance_rate: 33.3,
    records: [
      { service: 'EC2', name: 'web-node-01', region: 'us-east-1', compliant: true, missing_tags: [], existing_tags: { 'Name': 'web-node-01', 'Environment': 'prod', 'Owner': 'alice', 'Project': 'marketing' } },
      { service: 'EC2', name: 'worker-02', region: 'eu-west-1', compliant: false, missing_tags: ['Owner', 'Project'], existing_tags: { 'Name': 'worker-02', 'Environment': 'staging' } },
      { service: 'Lambda', name: 'process-uploads', region: 'us-east-1', compliant: false, missing_tags: ['Environment', 'Owner', 'Project'], existing_tags: { 'Name': 'process-uploads' } }
    ]
  };

  userData = {
    total: 2,
    users: [
      { user_id: 'UID1', username: 'alice-admin', arn: 'arn:aws:iam::123:user/alice', created: '2024-05-12T00:00:00Z', last_login: '2026-04-01T10:00:00Z', console_access: true, mfa_enabled: true, is_admin: true, groups: ['Admins'], policies: ['AdministratorAccess'], inline_policies: [], access_keys: [
        { key_id: 'AKIAALICE123', status: 'Active', age_days: 45, last_used: '2026-03-25T08:00:00Z', last_service: 's3', last_region: 'us-east-1' }
      ]},
      { user_id: 'UID2', username: 'bob-dev', arn: 'arn:aws:iam::123:user/bob', created: '2025-01-20T00:00:00Z', last_login: 'Never', console_access: false, mfa_enabled: false, is_admin: false, groups: ['Developers'], policies: ['AmazonEC2FullAccess'], inline_policies: [], access_keys: [
        { key_id: 'AKIABOB456', status: 'Inactive', age_days: 120, last_used: '2025-10-10T00:00:00Z', last_service: 'ec2', last_region: 'us-east-1' }
      ]}
    ]
  };

  setTimeout(() => {
    buildDashboard(summary);
    renderTable();
    ['EC2','Lambda','IAM','S3','RDS','VPC','DynamoDB','CloudFront'].forEach(c => { 
      const el = document.getElementById('chip-' + c);
      if(el) el.className = 'svc-chip done'; 
    });
    
    setTimeout(() => {
      showPage('dashboard-page');
      showDashTab('resources');
      document.getElementById('res-badge').textContent = summary.total;
      
      // Pre-render the tabs to populate their badges immediately
      renderSecurity();
      renderCosts();
      renderTags();
      renderUsers();
    }, 500);
  }, 1200);
}
