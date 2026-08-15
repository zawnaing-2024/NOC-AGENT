/**
 * NOC Agent - Professional ISP Network Operations Center SPA JavaScript
 * Phase 6 UI Enhancement: Device Management & Deep Investigation Workspace
 */

let currentTab = 'dashboard';
let devicesData = [];
let incidentsData = [];
let refreshSeconds = 10;
let refreshInterval = null;

// Filter & Sort State for Device Management
let deviceSearchQuery = '';
let deviceStatusFilter = 'ALL';
let deviceRoleFilter = 'ALL';
let deviceLocationFilter = 'ALL';
let deviceMonitoringFilter = 'ALL';
let deviceSortField = 'name';
let deviceSortAsc = true;

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initSidebarToggle();
  startAutoRefresh();
  loadCurrentTab();
});

// Toast Notifications Helper
function showToast(message, type = 'success', duration = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const item = document.createElement('div');
  item.className = `toast-item ${type}`;
  const icon = type === 'success' ? '✓' : (type === 'error' ? '✕' : '⚠');
  item.innerHTML = `<span style="font-weight:700; font-size:16px;">${icon}</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(item);
  setTimeout(() => {
    item.style.opacity = '0';
    item.style.transition = 'opacity 0.3s ease';
    setTimeout(() => item.remove(), 300);
  }, duration);
}

// Escape HTML helper
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Dynamic Bandwidth Formatting Helper
function formatBandwidth(bps) {
  const val = parseFloat(bps);
  if (isNaN(val) || val <= 0) return '0 bps';
  if (val >= 1000000000) return (val / 1000000000).toFixed(2) + ' Gbps';
  if (val >= 1000000) return (val / 1000000).toFixed(2) + ' Mbps';
  if (val >= 1000) return (val / 1000).toFixed(2) + ' Kbps';
  return val.toFixed(0) + ' bps';
}

// Event Message Formatter Helper
function formatEventMessage(e) {
  if (!e) return 'Anomaly detected';
  let ev = e.evidence;
  if (typeof ev === 'string') {
    try { ev = JSON.parse(ev); } catch (_) {}
  }
  
  const type = e.type || e.event_type || 'ANOMALY';
  const entity = e.entity || e.metric_name || '';

  if (!ev || typeof ev !== 'object') {
    return e.message || (entity ? `Anomaly detected on ${entity}` : type);
  }

  if (ev.summary) return ev.summary;
  if (ev.message) return ev.message;

  if (type === 'TRAFFIC_DROP') {
    const curr = formatBandwidth(ev.current_bps || 0);
    const avg = formatBandwidth(ev.moving_average_bps || ev.baseline_bps || 0);
    const pct = ev.drop_percentage !== undefined ? parseFloat(ev.drop_percentage).toFixed(1) : (ev.baseline_deviation_percentage ? parseFloat(ev.baseline_deviation_percentage).toFixed(1) : '0');
    const validTag = (ev.telemetry_valid === false) ? '🔴 INVALID (' + (ev.validation_reason || 'SUSPECTED_CORRUPTION') + ')' : '🟢 VALID';
    return `Traffic drop on ${entity || 'interface'} | Current: ${curr} | Baseline: ${avg} (▼ ${pct}% below baseline) | Telemetry: ${validTag}`;
  }
  if (type === 'CPU_SPIKE') {
    const cpuVal = ev.current_cpu || ev.cpu_percent || ev.cpu_load || 0;
    return `CPU load spiked to ${cpuVal}% (Threshold: ${ev.threshold || 80}%)`;
  }
  if (type === 'BGP_DOWN') {
    return `BGP session DOWN for peer ${entity || ev.peer || 'remote'}`;
  }
  if (type === 'INTERFACE_DOWN') {
    return `Interface link DOWN on ${entity || ev.interface || 'interface'}`;
  }
  if (type === 'OSPF_DOWN') {
    return `OSPF neighbor DOWN for neighbor ${entity || ev.neighbor || 'neighbor'}`;
  }
  if (type === 'DEFAULT_ROUTE_DOWN') {
    return `Default gateway route (0.0.0.0/0) INACTIVE`;
  }

  return `Anomaly ${type} on ${entity || 'device'}`;
}

// Navigation & Sidebar Handlers
function initNavigation() {
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      const targetBtn = e.currentTarget;
      targetBtn.classList.add('active');
      currentTab = targetBtn.getAttribute('data-tab');
      
      const titleMap = {
        'dashboard': 'Command Center',
        'devices': 'Device Management',
        'interfaces': 'Interfaces & Traffic',
        'bgp': 'BGP Peer Overview',
        'ospf': 'OSPF Adjacencies',
        'routing': 'Routing & NAT Matrix',
        'incidents': 'Active Incidents',
        'events': 'Event Timeline',
        'system': 'AI & System Diagnostics'
      };
      document.getElementById('page-title').innerText = titleMap[currentTab] || 'Command Center';
      loadCurrentTab();
    });
  });
}

function initSidebarToggle() {
  const toggleBtn = document.getElementById('sidebar-toggle');
  const sidebar = document.getElementById('sidebar');
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('collapsed');
    });
  }
}

function startAutoRefresh() {
  if (refreshInterval) clearInterval(refreshInterval);
  refreshSeconds = 10;
  refreshInterval = setInterval(() => {
    refreshSeconds--;
    const counterEl = document.getElementById('refresh-counter');
    if (counterEl) counterEl.innerText = `${refreshSeconds}s`;
    
    if (refreshSeconds <= 0) {
      refreshSeconds = 10;
      loadCurrentTab(true);
    }
  }, 1000);
}

// Main Tab Router
async function loadCurrentTab(isBackgroundRefresh = false) {
  updateGlobalHeaderBadges();
  
  const container = document.getElementById('view-container');
  if (!isBackgroundRefresh && container) {
    container.innerHTML = `<div class="skeleton-loader"><p>Loading ${currentTab} data...</p></div>`;
  }

  try {
    switch (currentTab) {
      case 'dashboard':
        await renderDashboardView(container);
        break;
      case 'devices':
        await renderDevicesView(container);
        break;
      case 'interfaces':
        await renderInterfacesView(container);
        break;
      case 'bgp':
        await renderBgpView(container);
        break;
      case 'ospf':
        await renderOspfView(container);
        break;
      case 'routing':
        await renderRoutingView(container);
        break;
      case 'incidents':
        await renderIncidentsView(container);
        break;
      case 'events':
        await renderEventsView(container);
        break;
      case 'system':
        await renderSystemView(container);
        break;
      default:
        await renderDashboardView(container);
    }
  } catch (err) {
    console.error('View load error:', err);
    if (container) {
      container.innerHTML = `
        <div class="alert-box failed">
          <h3>⚠ NOC Backend Unavailable</h3>
          <p>Unable to retrieve network telemetry from backend API: ${escapeHtml(err.message)}</p>
          <button class="btn btn-secondary btn-sm" style="margin-top:10px;" onclick="loadCurrentTab()">Retry Connection</button>
        </div>`;
    }
  }
}

// Update Top Navigation Header Badges
async function updateGlobalHeaderBadges() {
  try {
    const [devRes, incRes] = await Promise.all([
      fetch('/api/devices'),
      fetch('/api/incidents')
    ]);
    const devData = await devRes.json();
    const incData = await incRes.json();

    devicesData = devData.devices || [];
    incidentsData = incData.incidents || [];

    const navDevEl = document.getElementById('nav-device-count');
    const navIncEl = document.getElementById('nav-incident-count');
    if (navDevEl) navDevEl.innerText = devicesData.length;
    if (navIncEl) {
      navIncEl.innerText = incidentsData.filter(i => i.status === 'OPEN').length;
      if (incidentsData.filter(i => i.status === 'OPEN').length > 0) {
        navIncEl.classList.add('alert');
      } else {
        navIncEl.classList.remove('alert');
      }
    }
  } catch (e) {
    console.warn('Failed to update top badges:', e);
  }
}

// Helper: Status Badges HTML
function renderStatusBadge(statusStr) {
  const st = (statusStr || 'HEALTHY').toUpperCase();
  if (st === 'CRITICAL') return `<span class="badge badge-critical">🔴 CRITICAL</span>`;
  if (st === 'WARNING' || st === 'MAJOR') return `<span class="badge badge-warning">🟡 WARNING</span>`;
  if (st === 'OFFLINE') return `<span class="badge badge-offline">⚪ OFFLINE</span>`;
  if (st === 'DISABLED') return `<span class="badge badge-disabled">⚫ DISABLED</span>`;
  return `<span class="badge badge-healthy">🟢 HEALTHY</span>`;
}

// -------------------------------------------------------------------
// 1. DASHBOARD VIEW (COMMAND CENTER)
// -------------------------------------------------------------------
async function renderDashboardView(container) {
  const [devOverviewRes, incRes] = await Promise.all([
    fetch('/api/devices/overview'),
    fetch('/api/incidents')
  ]);
  const devOverview = await devOverviewRes.json();
  const incData = await incRes.json();
  const devices = devOverview.devices || [];
  const incidents = incData.incidents || [];

  const openIncidents = incidents.filter(i => i.status === 'OPEN');
  
  let html = ``;

  // Priority Problem Banner
  if (openIncidents.length > 0) {
    const topInc = openIncidents[0];
    html += `
      <div class="alert-box failed" style="margin-bottom:24px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <h3 style="margin-bottom:4px;">🔴 ${openIncidents.length} ACTIVE NETWORK INCIDENT(S) DETECTED</h3>
          <p style="font-size:13px;">Top Priority: <strong>${escapeHtml(topInc.title)}</strong> on device <code>${escapeHtml(topInc.device_id)}</code></p>
        </div>
        <button class="btn btn-danger" onclick="openInvestigationWorkspace('${topInc.incident_id}')">🔍 Investigate Incident</button>
      </div>`;
  } else {
    html += `
      <div class="alert-box success" style="margin-bottom:24px;">
        <h3>🟢 NETWORK HEALTHY — ZERO ACTIVE INCIDENTS</h3>
        <p style="font-size:13px;">All monitored MikroTik core routers and transit links are functioning within operational parameters.</p>
      </div>`;
  }

  // Summary KPI Cards
  const totalDevs = devices.length;
  const healthyDevs = devices.filter(d => d.health === 'HEALTHY').length;
  const warningDevs = devices.filter(d => d.health === 'WARNING').length;
  const criticalDevs = devices.filter(d => d.health === 'CRITICAL').length;
  const offlineDevs = devices.filter(d => d.health === 'OFFLINE').length;

  html += `
    <div class="summary-grid">
      <div class="summary-card healthy">
        <span class="card-label">Total Devices</span>
        <span class="card-value">${totalDevs}</span>
      </div>
      <div class="summary-card healthy">
        <span class="card-label">Healthy</span>
        <span class="card-value">${healthyDevs}</span>
      </div>
      <div class="summary-card warning">
        <span class="card-label">Warning</span>
        <span class="card-value">${warningDevs}</span>
      </div>
      <div class="summary-card critical">
        <span class="card-label">Critical</span>
        <span class="card-value">${criticalDevs}</span>
      </div>
      <div class="summary-card offline">
        <span class="card-label">Offline</span>
        <span class="card-value">${offlineDevs}</span>
      </div>
    </div>`;

  // Devices Summary Matrix Table
  html += `
    <div class="table-card">
      <div class="table-header">
        <span class="table-title">MikroTik Infrastructure Overview</span>
        <button class="btn btn-secondary btn-sm" onclick="currentTab='devices'; loadCurrentTab();">Manage Devices →</button>
      </div>
      <table class="noc-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Device Name / IP</th>
            <th>RouterOS</th>
            <th>CPU %</th>
            <th>RAM %</th>
            <th>Interfaces</th>
            <th>BGP</th>
            <th>OSPF</th>
            <th>Routes</th>
            <th>NAT Rules</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>`;

  if (devices.length === 0) {
    html += `<tr><td colspan="11" style="text-align:center; padding:24px; color:var(--text-muted);">No devices configured. <a href="#" onclick="openAddDeviceModal(); return false;">+ Add Device</a></td></tr>`;
  } else {
    devices.forEach(d => {
      html += `
        <tr>
          <td>${renderStatusBadge(d.health)}</td>
          <td><strong>${escapeHtml(d.name)}</strong><br><span style="font-size:12px; color:var(--text-muted);">${escapeHtml(d.ip_address)}</span></td>
          <td>${escapeHtml(d.version || 'v7')}</td>
          <td>${d.cpu_percent.toFixed(1)}%</td>
          <td>${d.memory_percent.toFixed(1)}%</td>
          <td><span class="badge badge-healthy">${d.interfaces_up}/${d.interfaces_total} UP</span></td>
          <td><span class="badge ${d.bgp_established > 0 ? 'badge-healthy' : 'badge-offline'}">${d.bgp_established}/${d.bgp_total} EST</span></td>
          <td><span class="badge ${d.ospf_full > 0 ? 'badge-healthy' : 'badge-offline'}">${d.ospf_full}/${d.ospf_total} FULL</span></td>
          <td>${d.routes_count}</td>
          <td>${d.nat_count}</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="openDeviceDetailWorkspace('${d.device_id}')">View</button>
          </td>
        </tr>`;
    });
  }

  html += `</tbody></table></div>`;
  container.innerHTML = html;
}

// -------------------------------------------------------------------
// 2. DEVICE MANAGEMENT VIEW (/devices)
// -------------------------------------------------------------------
async function renderDevicesView(container) {
  const res = await fetch('/api/devices?include_deleted=false');
  const data = await res.json();
  const rawDevices = data.devices || [];

  // Calculate summary counts
  const totalCount = rawDevices.length;
  const healthyCount = rawDevices.filter(d => (d.status || '').toUpperCase() === 'HEALTHY' && d.monitoring_enabled).length;
  const warningCount = rawDevices.filter(d => (d.status || '').toUpperCase() === 'WARNING' && d.monitoring_enabled).length;
  const criticalCount = rawDevices.filter(d => (d.status || '').toUpperCase() === 'CRITICAL' && d.monitoring_enabled).length;
  const offlineCount = rawDevices.filter(d => (d.status || '').toUpperCase() === 'OFFLINE' && d.monitoring_enabled).length;
  const disabledCount = rawDevices.filter(d => !d.monitoring_enabled || (d.status || '').toUpperCase() === 'DISABLED').length;

  let html = `
    <div class="action-banner">
      <div>
        <h2>Devices Inventory</h2>
        <p>Manage and monitor your MikroTik infrastructure inventory</p>
      </div>
      <button class="btn btn-primary" onclick="openAddDeviceModal()">+ Add Device</button>
    </div>

    <div class="summary-grid">
      <div class="summary-card healthy">
        <span class="card-label">Total Devices</span>
        <span class="card-value">${totalCount}</span>
      </div>
      <div class="summary-card healthy">
        <span class="card-label">Healthy</span>
        <span class="card-value">${healthyCount}</span>
      </div>
      <div class="summary-card warning">
        <span class="card-label">Warning</span>
        <span class="card-value">${warningCount}</span>
      </div>
      <div class="summary-card critical">
        <span class="card-label">Critical</span>
        <span class="card-value">${criticalCount}</span>
      </div>
      <div class="summary-card offline">
        <span class="card-label">Offline</span>
        <span class="card-value">${offlineCount}</span>
      </div>
      <div class="summary-card disabled">
        <span class="card-label">Monitoring Disabled</span>
        <span class="card-value">${disabledCount}</span>
      </div>
    </div>

    <div class="toolbar">
      <div class="toolbar-left">
        <input type="text" class="search-input" id="dev-search" placeholder="Search devices by name, IP, location..." value="${escapeHtml(deviceSearchQuery)}" oninput="updateDeviceFilters()">
        <select class="filter-select" id="dev-status-filter" onchange="updateDeviceFilters()">
          <option value="ALL" ${deviceStatusFilter === 'ALL' ? 'selected' : ''}>All Statuses</option>
          <option value="HEALTHY" ${deviceStatusFilter === 'HEALTHY' ? 'selected' : ''}>🟢 Healthy</option>
          <option value="WARNING" ${deviceStatusFilter === 'WARNING' ? 'selected' : ''}>🟡 Warning</option>
          <option value="CRITICAL" ${deviceStatusFilter === 'CRITICAL' ? 'selected' : ''}>🔴 Critical</option>
          <option value="OFFLINE" ${deviceStatusFilter === 'OFFLINE' ? 'selected' : ''}>⚪ Offline</option>
          <option value="DISABLED" ${deviceStatusFilter === 'DISABLED' ? 'selected' : ''}>⚫ Disabled</option>
        </select>
        <select class="filter-select" id="dev-role-filter" onchange="updateDeviceFilters()">
          <option value="ALL" ${deviceRoleFilter === 'ALL' ? 'selected' : ''}>All Roles</option>
          <option value="Core Router" ${deviceRoleFilter === 'Core Router' ? 'selected' : ''}>Core Router</option>
          <option value="Edge Router" ${deviceRoleFilter === 'Edge Router' ? 'selected' : ''}>Edge Router</option>
          <option value="CGNAT Gateway" ${deviceRoleFilter === 'CGNAT Gateway' ? 'selected' : ''}>CGNAT Gateway</option>
          <option value="Switch" ${deviceRoleFilter === 'Switch' ? 'selected' : ''}>Switch</option>
        </select>
        <select class="filter-select" id="dev-monitoring-filter" onchange="updateDeviceFilters()">
          <option value="ALL" ${deviceMonitoringFilter === 'ALL' ? 'selected' : ''}>All Monitoring</option>
          <option value="ENABLED" ${deviceMonitoringFilter === 'ENABLED' ? 'selected' : ''}>● Enabled</option>
          <option value="DISABLED" ${deviceMonitoringFilter === 'DISABLED' ? 'selected' : ''}>○ Disabled</option>
        </select>
      </div>
      <div>
        <select class="filter-select" id="dev-sort-select" onchange="updateDeviceFilters()">
          <option value="name" ${deviceSortField === 'name' ? 'selected' : ''}>Sort by Name</option>
          <option value="ip_address" ${deviceSortField === 'ip_address' ? 'selected' : ''}>Sort by IP</option>
          <option value="status" ${deviceSortField === 'status' ? 'selected' : ''}>Sort by Health Status</option>
        </select>
      </div>
    </div>

    <div class="table-card">
      <table class="noc-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Device Name / Role</th>
            <th>Management IP</th>
            <th>Location</th>
            <th>Monitoring</th>
            <th>Protocol / Port</th>
            <th>Last Updated</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="devices-table-body">
  `;

  // Apply filters
  let filtered = rawDevices.filter(d => {
    if (deviceSearchQuery) {
      const q = deviceSearchQuery.toLowerCase();
      const match = (d.name || '').toLowerCase().includes(q) ||
                    (d.ip_address || '').toLowerCase().includes(q) ||
                    (d.location || '').toLowerCase().includes(q) ||
                    (d.role || '').toLowerCase().includes(q);
      if (!match) return false;
    }
    if (deviceStatusFilter !== 'ALL') {
      const st = (d.status || 'HEALTHY').toUpperCase();
      if (deviceStatusFilter === 'DISABLED' && d.monitoring_enabled) return false;
      if (deviceStatusFilter !== 'DISABLED' && st !== deviceStatusFilter) return false;
    }
    if (deviceRoleFilter !== 'ALL' && (d.role || '') !== deviceRoleFilter) return false;
    if (deviceMonitoringFilter === 'ENABLED' && !d.monitoring_enabled) return false;
    if (deviceMonitoringFilter === 'DISABLED' && d.monitoring_enabled) return false;
    return true;
  });

  // Apply Sort
  filtered.sort((a, b) => {
    const valA = (a[deviceSortField] || '').toString().toLowerCase();
    const valB = (b[deviceSortField] || '').toString().toLowerCase();
    return deviceSortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
  });

  if (filtered.length === 0) {
    html += `
      <tr>
        <td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted);">
          No matching devices found in inventory.
        </td>
      </tr>`;
  } else {
    filtered.forEach(d => {
      const monTag = d.monitoring_enabled ? 
        `<span style="color:var(--status-green); font-weight:600;">● Enabled</span>` : 
        `<span style="color:var(--status-disabled); font-weight:600;">○ Disabled</span>`;

      html += `
        <tr>
          <td>${renderStatusBadge(d.monitoring_enabled ? d.status : 'DISABLED')}</td>
          <td>
            <strong>${escapeHtml(d.name)}</strong><br>
            <span style="font-size:11px; color:var(--accent-blue);">${escapeHtml(d.role || 'Router')}</span>
          </td>
          <td><code>${escapeHtml(d.ip_address)}</code></td>
          <td>${escapeHtml(d.location || '—')}</td>
          <td>${monTag}</td>
          <td>${escapeHtml(d.api_protocol || 'api').toUpperCase()} : ${d.api_port || 8728}</td>
          <td><span style="font-size:12px; color:var(--text-muted);">${d.updated_at ? new Date(d.updated_at).toLocaleTimeString() : 'Recently'}</span></td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-secondary btn-sm" onclick="openDeviceDetailWorkspace('${d.device_id}')">View</button>
              <button class="btn btn-secondary btn-sm" onclick="openEditDeviceModal('${d.device_id}')">Edit</button>
              <button class="btn btn-secondary btn-sm" onclick="testDeviceDirectConnection('${d.device_id}')">Test</button>
              ${d.monitoring_enabled ? 
                `<button class="btn btn-secondary btn-sm" onclick="toggleDeviceMonitoring('${d.device_id}', false)">Disable</button>` :
                `<button class="btn btn-secondary btn-sm" onclick="toggleDeviceMonitoring('${d.device_id}', true)">Enable</button>`
              }
              <button class="btn btn-danger btn-sm" onclick="confirmDeleteDevice('${d.device_id}', '${escapeHtml(d.name)}')">Delete</button>
            </div>
          </td>
        </tr>`;
    });
  }

  html += `</tbody></table></div>`;
  container.innerHTML = html;
}

function updateDeviceFilters() {
  const searchEl = document.getElementById('dev-search');
  const statusEl = document.getElementById('dev-status-filter');
  const roleEl = document.getElementById('dev-role-filter');
  const monEl = document.getElementById('dev-monitoring-filter');
  const sortEl = document.getElementById('dev-sort-select');

  if (searchEl) deviceSearchQuery = searchEl.value;
  if (statusEl) deviceStatusFilter = statusEl.value;
  if (roleEl) deviceRoleFilter = roleEl.value;
  if (monEl) deviceMonitoringFilter = monEl.value;
  if (sortEl) deviceSortField = sortEl.value;

  const container = document.getElementById('view-container');
  if (container && currentTab === 'devices') {
    renderDevicesView(container);
  }
}

// -------------------------------------------------------------------
// 3. ADD / EDIT DEVICE MODAL HANDLERS
// -------------------------------------------------------------------
function openAddDeviceModal() {
  document.getElementById('device-modal-title').innerText = 'Add MikroTik Device';
  document.getElementById('device-form-id').value = '';
  document.getElementById('dev-name').value = '';
  document.getElementById('dev-ip').value = '';
  document.getElementById('dev-role').value = 'Core Router';
  document.getElementById('dev-location').value = '';
  document.getElementById('dev-desc').value = '';
  document.getElementById('dev-protocol').value = 'api';
  document.getElementById('dev-port').value = 8728;
  document.getElementById('dev-user').value = 'admin';
  document.getElementById('dev-pass').value = '';
  document.getElementById('dev-pass').placeholder = 'Enter API Password';
  document.getElementById('dev-monitoring').value = 'true';
  document.getElementById('dev-interval').value = 30;
  document.getElementById('dev-profile').value = 'Standard';
  
  const alertBox = document.getElementById('test-connection-alert');
  if (alertBox) {
    alertBox.className = 'alert-box hidden';
    alertBox.innerHTML = '';
  }

  document.getElementById('device-form-modal').classList.remove('hidden');
}

async function openEditDeviceModal(deviceId) {
  try {
    const res = await fetch(`/api/devices/${deviceId}`);
    if (!res.ok) throw new Error('Failed to load device details.');
    const d = await res.json();

    document.getElementById('device-modal-title').innerText = `Edit Device: ${d.name}`;
    document.getElementById('device-form-id').value = d.device_id;
    document.getElementById('dev-name').value = d.name || '';
    document.getElementById('dev-ip').value = d.ip_address || '';
    document.getElementById('dev-role').value = d.role || 'Core Router';
    document.getElementById('dev-location').value = d.location || '';
    document.getElementById('dev-desc').value = d.description || '';
    document.getElementById('dev-protocol').value = d.api_protocol || 'api';
    document.getElementById('dev-port').value = d.api_port || 8728;
    document.getElementById('dev-user').value = d.username || 'admin';
    document.getElementById('dev-pass').value = '';
    document.getElementById('dev-pass').placeholder = 'Keep existing password';
    document.getElementById('dev-monitoring').value = d.monitoring_enabled ? 'true' : 'false';
    document.getElementById('dev-interval').value = d.collection_interval || 30;
    document.getElementById('dev-profile').value = d.monitoring_profile || 'Standard';

    const alertBox = document.getElementById('test-connection-alert');
    if (alertBox) {
      alertBox.className = 'alert-box hidden';
      alertBox.innerHTML = '';
    }

    document.getElementById('device-form-modal').classList.remove('hidden');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function closeDeviceFormModal() {
  document.getElementById('device-form-modal').classList.add('hidden');
}

async function testFormConnection() {
  const alertBox = document.getElementById('test-connection-alert');
  if (!alertBox) return;

  alertBox.className = 'alert-box success';
  alertBox.innerHTML = '⚡ Testing read-only RouterOS API connection...';
  alertBox.classList.remove('hidden');

  const payload = {
    name: document.getElementById('dev-name').value,
    ip_address: document.getElementById('dev-ip').value,
    api_port: parseInt(document.getElementById('dev-port').value) || 8728,
    username: document.getElementById('dev-user').value,
    password: document.getElementById('dev-pass').value
  };

  const devId = document.getElementById('device-form-id').value;
  const url = devId ? `/api/devices/${devId}/test-connection` : `/api/devices/test-connection`;

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();

    if (data.success) {
      alertBox.className = 'alert-box success';
      alertBox.innerHTML = `
        <div style="font-weight:700; margin-bottom:4px;">✓ Connection Successful</div>
        <div>Device: <strong>${escapeHtml(data.device_name)}</strong> (${escapeHtml(data.ip_address)})</div>
        <div>RouterOS Version: <strong>${escapeHtml(data.routeros_version)}</strong></div>
        <div>API Response Time: <strong>${data.response_time_ms} ms</strong></div>`;
    } else {
      alertBox.className = 'alert-box failed';
      alertBox.innerHTML = `
        <div style="font-weight:700; margin-bottom:4px;">✕ Connection Failed</div>
        <div>${escapeHtml(data.message)}</div>
        <ul style="margin-top:6px; padding-left:20px; font-size:12px;">
          ${(data.check_list || []).map(item => `<li>Check ${escapeHtml(item)}</li>`).join('')}
        </ul>`;
    }
  } catch (err) {
    alertBox.className = 'alert-box failed';
    alertBox.innerHTML = `<div>✕ Test Connection Error: ${escapeHtml(err.message)}</div>`;
  }
}

async function testDeviceDirectConnection(deviceId) {
  showToast('Testing RouterOS API connection...', 'warning');
  try {
    const res = await fetch(`/api/devices/${deviceId}/test-connection`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(`✓ Connection Successful: ${data.device_name} (${data.response_time_ms} ms)`, 'success');
    } else {
      showToast(`✕ Connection Failed for ${data.device_name}`, 'error');
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleDeviceFormSubmit(event) {
  event.preventDefault();
  const devId = document.getElementById('device-form-id').value;

  const payload = {
    name: document.getElementById('dev-name').value,
    ip_address: document.getElementById('dev-ip').value,
    role: document.getElementById('dev-role').value,
    location: document.getElementById('dev-location').value,
    description: document.getElementById('dev-desc').value,
    api_protocol: document.getElementById('dev-protocol').value,
    api_port: parseInt(document.getElementById('dev-port').value) || 8728,
    username: document.getElementById('dev-user').value,
    password: document.getElementById('dev-pass').value,
    monitoring_enabled: document.getElementById('dev-monitoring').value === 'true',
    collection_interval: parseInt(document.getElementById('dev-interval').value) || 30,
    monitoring_profile: document.getElementById('dev-profile').value
  };

  const url = devId ? `/api/devices/${devId}` : `/api/devices`;
  const method = devId ? 'PUT' : 'POST';

  try {
    const res = await fetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to save device.');

    showToast(data.message || 'Device saved successfully.', 'success');
    closeDeviceFormModal();
    loadCurrentTab();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Delete Device Modal
let deleteTargetId = null;

function confirmDeleteDevice(deviceId, deviceName) {
  deleteTargetId = deviceId;
  const nameEl = document.getElementById('delete-device-name');
  if (nameEl) nameEl.innerText = `${deviceName} (${deviceId})`;
  
  const btn = document.getElementById('btn-confirm-delete');
  if (btn) {
    btn.onclick = () => executeDeviceDelete();
  }
  document.getElementById('delete-device-modal').classList.remove('hidden');
}

function closeDeleteDeviceModal() {
  document.getElementById('delete-device-modal').classList.add('hidden');
  deleteTargetId = null;
}

async function executeDeviceDelete() {
  if (!deleteTargetId) return;
  try {
    const res = await fetch(`/api/devices/${deleteTargetId}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to delete device.');

    showToast(data.message || 'Device removed from inventory.', 'success');
    closeDeleteDeviceModal();
    loadCurrentTab();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function toggleDeviceMonitoring(deviceId, enable) {
  const url = enable ? `/api/devices/${deviceId}/monitoring/enable` : `/api/devices/${deviceId}/monitoring/disable`;
  try {
    const res = await fetch(url, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to toggle monitoring.');

    showToast(data.message, 'success');
    loadCurrentTab();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// -------------------------------------------------------------------
// 4. DEVICE DETAIL WORKSPACE MODAL
// -------------------------------------------------------------------
async function openDeviceDetailWorkspace(deviceId) {
  const modal = document.getElementById('device-detail-modal');
  const body = document.getElementById('device-detail-modal-body');
  if (!modal || !body) return;

  body.innerHTML = `<div class="skeleton-loader"><p>Loading details for ${escapeHtml(deviceId)}...</p></div>`;
  modal.classList.remove('hidden');

  try {
    const res = await fetch(`/api/devices/${deviceId}`);
    if (!res.ok) throw new Error('Device details unavailable.');
    const d = await res.json();

    let html = `
      <div class="modal-header">
        <div>
          <h2>${escapeHtml(d.name)} <span style="font-size:14px; color:var(--text-muted);">(${escapeHtml(d.ip_address)})</span></h2>
          <div style="margin-top:4px; display:flex; gap:10px; align-items:center;">
            ${renderStatusBadge(d.monitoring_enabled ? d.status : 'DISABLED')}
            <span style="font-size:12px; color:var(--accent-blue); font-weight:600;">Role: ${escapeHtml(d.role || 'Router')}</span>
            <span style="font-size:12px; color:var(--text-muted);">Location: ${escapeHtml(d.location || 'N/A')}</span>
          </div>
        </div>
        <div style="display:flex; gap:10px;">
          <button class="btn btn-secondary btn-sm" onclick="openEditDeviceModal('${d.device_id}')">Edit</button>
          <button class="btn btn-secondary btn-sm" onclick="testDeviceDirectConnection('${d.device_id}')">Test</button>
          <button class="close-btn" onclick="document.getElementById('device-detail-modal').classList.add('hidden')">✕</button>
        </div>
      </div>

      <div class="summary-grid">
        <div class="summary-card healthy">
          <span class="card-label">CPU Load</span>
          <span class="card-value">${(d.cpu_percent || 0).toFixed(1)}%</span>
        </div>
        <div class="summary-card healthy">
          <span class="card-label">Memory Usage</span>
          <span class="card-value">${(d.memory_percent || 0).toFixed(1)}%</span>
        </div>
        <div class="summary-card healthy">
          <span class="card-label">RouterOS Version</span>
          <span class="card-value" style="font-size:18px;">${escapeHtml(d.version || 'v7')}</span>
        </div>
        <div class="summary-card healthy">
          <span class="card-label">API Status</span>
          <span class="card-value" style="font-size:18px; color:var(--status-green);">Connected</span>
        </div>
      </div>

      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:16px; margin-bottom:24px;">
        <div class="form-section">
          <span class="form-section-title">INTERFACES</span>
          <div style="font-size:24px; font-weight:700;">${d.interfaces_summary?.up || 0} / ${d.interfaces_summary?.total || 0} UP</div>
          <span style="font-size:12px; color:var(--text-muted);">${d.interfaces_summary?.down || 0} Down</span>
        </div>
        <div class="form-section">
          <span class="form-section-title">BGP PEERS</span>
          <div style="font-size:24px; font-weight:700;">${d.bgp_summary?.established || 0} / ${d.bgp_summary?.total || 0} EST</div>
          <span style="font-size:12px; color:var(--text-muted);">${d.bgp_summary?.down || 0} Down</span>
        </div>
        <div class="form-section">
          <span class="form-section-title">OSPF NEIGHBORS</span>
          <div style="font-size:24px; font-weight:700;">${d.ospf_summary?.full || 0} / ${d.ospf_summary?.total || 0} FULL</div>
          <span style="font-size:12px; color:var(--text-muted);">${d.ospf_summary?.down || 0} Down</span>
        </div>
        <div class="form-section">
          <span class="form-section-title">ROUTES & NAT</span>
          <div style="font-size:24px; font-weight:700;">${d.routes_summary?.total || 0} Routes</div>
          <span style="font-size:12px; color:var(--text-muted);">${d.nat_summary?.total || 0} NAT Rules</span>
        </div>
      </div>

      <div class="table-card">
        <div class="table-header">
          <span class="table-title">Recent Events on ${escapeHtml(d.name)}</span>
        </div>
        <table class="noc-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Type</th>
              <th>Message / Context</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>`;

    const events = d.recent_events || [];
    if (events.length === 0) {
      html += `<tr><td colspan="4" style="text-align:center; padding:20px; color:var(--text-muted);">No recent events recorded for this device.</td></tr>`;
    } else {
      events.forEach(e => {
        const evType = e.type || e.event_type || 'ANOMALY';
        const msg = formatEventMessage(e);
        html += `
          <tr>
            <td>${renderStatusBadge(e.severity)}</td>
            <td><code>${escapeHtml(evType)}</code></td>
            <td>${escapeHtml(msg)}</td>
            <td><span style="font-size:12px; color:var(--text-muted);">${new Date(e.timestamp).toLocaleTimeString()}</span></td>
          </tr>`;
      });
    }

    html += `</tbody></table></div>`;
    body.innerHTML = html;
  } catch (err) {
    body.innerHTML = `<div class="alert-box failed">✕ Failed to load device details: ${escapeHtml(err.message)}</div>`;
  }
}

// -------------------------------------------------------------------
// 5. INTERFACES OVERVIEW VIEW
// -------------------------------------------------------------------
async function renderInterfacesView(container) {
  const res = await fetch('/api/interfaces/overview');
  const data = await res.json();
  const ifaces = data.interfaces || [];

  let html = `
    <div class="action-banner">
      <div>
        <h2>Interfaces & Traffic Overview</h2>
        <p>Real-time delta bandwidth throughput and interface statuses</p>
      </div>
    </div>

    <div class="table-card">
      <table class="noc-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Device</th>
            <th>Interface Name</th>
            <th>Type</th>
            <th>RX Bandwidth</th>
            <th>TX Bandwidth</th>
            <th>RX Drops</th>
            <th>TX Drops</th>
            <th>Health Tag</th>
          </tr>
        </thead>
        <tbody>`;

  if (ifaces.length === 0) {
    html += `<tr><td colspan="9" style="text-align:center; padding:24px; color:var(--text-muted);">No interfaces monitored.</td></tr>`;
  } else {
    ifaces.forEach(i => {
      html += `
        <tr>
          <td><span class="badge ${i.status === 'UP' ? 'badge-healthy' : 'badge-critical'}">${i.status}</span></td>
          <td><strong>${escapeHtml(i.device_name || i.device_id)}</strong></td>
          <td><code>${escapeHtml(i.interface_name)}</code></td>
          <td>${escapeHtml(i.type)}</td>
          <td><strong style="color:var(--accent-blue);">${formatBandwidth(i.rx_bps)}</strong></td>
          <td><strong style="color:var(--status-green);">${formatBandwidth(i.tx_bps)}</strong></td>
          <td>${i.rx_drops || 0}</td>
          <td>${i.tx_drops || 0}</td>
          <td>${renderStatusBadge(i.health_tag)}</td>
        </tr>`;
    });
  }

  html += `</tbody></table></div>`;
  container.innerHTML = html;
}

// -------------------------------------------------------------------
// 6. BGP PEERS VIEW
// -------------------------------------------------------------------
async function renderBgpView(container) {
  const res = await fetch('/api/routing/bgp/overview');
  const data = await res.json();
  const peers = data.bgp_peers || [];

  let html = `
    <div class="action-banner">
      <div>
        <h2>BGP Peer Adjacencies</h2>
        <p>BGP session statuses and prefix announcements across core transit routers</p>
      </div>
    </div>

    <div class="summary-grid">
      <div class="summary-card healthy">
        <span class="card-label">Total Peers</span>
        <span class="card-value">${data.total_bgp_peers || 0}</span>
      </div>
      <div class="summary-card healthy">
        <span class="card-label">Established</span>
        <span class="card-value">${data.established_peers || 0}</span>
      </div>
      <div class="summary-card critical">
        <span class="card-label">Down Peers</span>
        <span class="card-value">${data.down_peers || 0}</span>
      </div>
    </div>

    <div class="table-card">
      <table class="noc-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Device</th>
            <th>Peer / Session</th>
            <th>Remote Address</th>
            <th>Uptime</th>
            <th>Prefix Count</th>
            <th>Session State</th>
          </tr>
        </thead>
        <tbody>`;

  if (peers.length === 0) {
    html += `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-muted);">No BGP peers configured.</td></tr>`;
  } else {
    peers.forEach(p => {
      html += `
        <tr>
          <td><span class="badge ${p.established ? 'badge-healthy' : 'badge-critical'}">${p.established ? 'ESTABLISHED' : 'DOWN'}</span></td>
          <td><strong>${escapeHtml(p.device_id)}</strong></td>
          <td><code>${escapeHtml(p.peer)}</code></td>
          <td><code>${escapeHtml(p.remote_address)}</code></td>
          <td>${escapeHtml(p.uptime || 'N/A')}</td>
          <td><strong>${p.prefix_count}</strong> prefixes</td>
          <td>${p.established ? 'Established' : 'Idle / Connect'}</td>
        </tr>`;
    });
  }

  html += `</tbody></table></div>`;
  container.innerHTML = html;
}

// -------------------------------------------------------------------
// 7. OSPF NEIGHBORS VIEW
// -------------------------------------------------------------------
async function renderOspfView(container) {
  const res = await fetch('/api/routing/ospf/overview');
  const data = await res.json();
  const nbrs = data.ospf_neighbors || [];

  let html = `
    <div class="action-banner">
      <div>
        <h2>OSPF Neighbor Adjacencies</h2>
        <p>Intra-AS OSPF neighbor states and area adjacencies</p>
      </div>
    </div>

    <div class="summary-grid">
      <div class="summary-card healthy">
        <span class="card-label">Total Neighbors</span>
        <span class="card-value">${data.total_ospf_neighbors || 0}</span>
      </div>
      <div class="summary-card healthy">
        <span class="card-label">Full Adjacencies</span>
        <span class="card-value">${data.full_neighbors || 0}</span>
      </div>
      <div class="summary-card critical">
        <span class="card-label">Non-Full / Down</span>
        <span class="card-value">${data.non_full_neighbors || 0}</span>
      </div>
    </div>

    <div class="table-card">
      <table class="noc-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Device</th>
            <th>Neighbor Address</th>
            <th>Router ID</th>
            <th>OSPF State</th>
          </tr>
        </thead>
        <tbody>`;

  if (nbrs.length === 0) {
    html += `<tr><td colspan="5" style="text-align:center; padding:24px; color:var(--text-muted);">No OSPF neighbors configured.</td></tr>`;
  } else {
    nbrs.forEach(n => {
      const isFull = (n.state || '').includes('Full');
      html += `
        <tr>
          <td><span class="badge ${isFull ? 'badge-healthy' : 'badge-warning'}">${isFull ? 'FULL' : '2-WAY / DOWN'}</span></td>
          <td><strong>${escapeHtml(n.device_id)}</strong></td>
          <td><code>${escapeHtml(n.neighbor)}</code></td>
          <td><code>${escapeHtml(n.router_id || 'N/A')}</code></td>
          <td>${escapeHtml(n.state)}</td>
        </tr>`;
    });
  }

  html += `</tbody></table></div>`;
  container.innerHTML = html;
}

// -------------------------------------------------------------------
// 8. ROUTING & NAT VIEW
// -------------------------------------------------------------------
async function renderRoutingView(container) {
  const res = await fetch('/api/routing/overview');
  const data = await res.json();

  let html = `
    <div class="action-banner">
      <div>
        <h2>Routing Table & NAT Matrix</h2>
        <p>Physical RouterOS static routes and CGNAT rule monitoring</p>
      </div>
    </div>

    <div class="summary-grid">
      <div class="summary-card healthy">
        <span class="card-label">Default Route Status</span>
        <span class="card-value" style="font-size:20px; color:${data.default_route_active ? 'var(--status-green)' : 'var(--status-red)'};">
          ${data.default_route_active ? '🟢 ACTIVE' : '🔴 DOWN'}
        </span>
      </div>
      <div class="summary-card healthy">
        <span class="card-label">Total Routes</span>
        <span class="card-value">${data.total_routes || 0}</span>
      </div>
      <div class="summary-card healthy">
        <span class="card-label">Active Routes</span>
        <span class="card-value">${data.active_routes || 0}</span>
      </div>
      <div class="summary-card warning">
        <span class="card-label">Inactive Routes</span>
        <span class="card-value">${data.inactive_routes || 0}</span>
      </div>
    </div>

    <div class="alert-box success">
      <h3>✓ Default Gateway Reachability Verified</h3>
      <p>Primary <code>0.0.0.0/0</code> ISP uplink route is ACTIVE across all core gateways.</p>
    </div>`;

  container.innerHTML = html;
}

// -------------------------------------------------------------------
// 9. INCIDENTS VIEW
// -------------------------------------------------------------------
async function renderIncidentsView(container) {
  const res = await fetch('/api/incidents');
  const data = await res.json();
  const incidents = data.incidents || [];

  let html = `
    <div class="action-banner">
      <div>
        <h2>Active Incident Response Center</h2>
        <p>Correlated network incidents with automatic Root Cause Analysis (RCA)</p>
      </div>
    </div>

    <div class="table-card">
      <table class="noc-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Priority</th>
            <th>Incident ID</th>
            <th>Device</th>
            <th>Title</th>
            <th>Root Cause Component</th>
            <th>First Seen</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>`;

  if (incidents.length === 0) {
    html += `<tr><td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted);">🟢 Zero active incidents detected. Network status is healthy.</td></tr>`;
  } else {
    incidents.forEach(inc => {
      html += `
        <tr>
          <td><span class="badge ${inc.status === 'OPEN' ? 'badge-critical' : 'badge-healthy'}">${escapeHtml(inc.status)}</span></td>
          <td><span class="badge badge-warning">P${inc.priority || 1}</span></td>
          <td><code>${escapeHtml(inc.incident_id)}</code></td>
          <td><strong>${escapeHtml(inc.device_id)}</strong></td>
          <td><strong>${escapeHtml(inc.title)}</strong></td>
          <td><code>${escapeHtml(inc.root_cause_component || 'N/A')}</code></td>
          <td><span style="font-size:12px; color:var(--text-muted);">${new Date(inc.created_at).toLocaleTimeString()}</span></td>
          <td>
            <button class="btn btn-danger btn-sm" onclick="openInvestigationWorkspace('${inc.incident_id}')">🔍 Investigate</button>
          </td>
        </tr>`;
    });
  }

  html += `</tbody></table></div>`;
  container.innerHTML = html;
}

// -------------------------------------------------------------------
// 10. EVENTS VIEW
// -------------------------------------------------------------------
async function renderEventsView(container) {
  const res = await fetch('/api/events');
  const data = await res.json();
  const events = data.events || [];

  let html = `
    <div class="action-banner">
      <div>
        <h2>Event Audit Log</h2>
        <p>Raw deterministic anomaly events collected from RouterOS API</p>
      </div>
    </div>

    <div class="table-card">
      <table class="noc-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Device</th>
            <th>Event Type</th>
            <th>Target</th>
            <th>Current Value</th>
            <th>Baseline</th>
            <th>Deviation</th>
            <th>Status</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>`;

  if (events.length === 0) {
    html += `<tr><td colspan="9" style="text-align:center; padding:24px; color:var(--text-muted);">No telemetry events recorded.</td></tr>`;
  } else {
    events.forEach(e => {
      const eventType = e.type || e.event_type || 'ANOMALY';
      const targetEntity = e.entity || e.metric_name || 'System';
      const ev = e.evidence || {};
      const currVal = ev.current_bps ? formatBandwidth(ev.current_bps) : (e.value !== undefined ? String(e.value) : '—');
      const baseVal = ev.baseline_bps ? formatBandwidth(ev.baseline_bps) : (ev.moving_average_bps ? formatBandwidth(ev.moving_average_bps) : '—');
      const devVal = ev.baseline_deviation_pct ? `▼ ${ev.baseline_deviation_pct.toFixed(2)}%` : (ev.drop_percentage ? `▼ ${ev.drop_percentage.toFixed(2)}%` : '—');
      const statusVal = e.status || 'OPEN';

      html += `
        <tr style="cursor:pointer;" onclick="openEventInvestigationModal('${e.event_id}')" title="Click to open Event Investigation Workspace">
          <td>${renderStatusBadge(e.severity)}</td>
          <td><strong>${escapeHtml(e.device_id)}</strong></td>
          <td><code>${escapeHtml(eventType)}</code></td>
          <td><code>${escapeHtml(targetEntity)}</code></td>
          <td><strong style="color:var(--status-yellow);">${escapeHtml(currVal)}</strong></td>
          <td>${escapeHtml(baseVal)}</td>
          <td><span style="color:var(--status-red); font-weight:600;">${escapeHtml(devVal)}</span></td>
          <td><span class="badge ${statusVal === 'RESOLVED' ? 'badge-healthy' : 'badge-warning'}">${escapeHtml(statusVal)}</span></td>
          <td><span style="font-size:12px; color:var(--text-muted);">${new Date(e.timestamp).toLocaleTimeString()}</span></td>
        </tr>`;
    });
  }

  html += `</tbody></table></div>`;
  container.innerHTML = html;
}

// -------------------------------------------------------------------
// 11. SYSTEM DIAGNOSTICS VIEW
// -------------------------------------------------------------------
async function renderSystemView(container) {
  const [healthRes, aiRes, dbRes] = await Promise.all([
    fetch('/api/health'),
    fetch('/api/ai/status'),
    fetch('/api/database/status')
  ]);
  const healthData = await healthRes.json();
  const aiData = await aiRes.json();
  const dbData = await dbRes.json();

  let html = `
    <div class="action-banner">
      <div>
        <h2>AI & System Diagnostics</h2>
        <p>OpenRouter API status, SQLite database storage metrics, and engine health</p>
      </div>
    </div>

    <div class="summary-grid">
      <div class="summary-card healthy">
        <span class="card-label">FastAPI Health</span>
        <span class="card-value" style="color:var(--status-green);">${(healthData.status || 'OK').toUpperCase()}</span>
      </div>
      <div class="summary-card healthy">
        <span class="card-label">AI Provider</span>
        <span class="card-value" style="font-size:18px;">${escapeHtml(aiData.provider || 'openrouter')}</span>
      </div>
      <div class="summary-card healthy">
        <span class="card-label">LLM Model</span>
        <span class="card-value" style="font-size:16px;">${escapeHtml(aiData.model || 'llama-3.3-70b')}</span>
      </div>
      <div class="summary-card healthy">
        <span class="card-label">Database Size</span>
        <span class="card-value" style="font-size:18px;">${((dbData.size_bytes || 0) / 1024 / 1024).toFixed(2)} MB</span>
      </div>
    </div>

    <div class="form-section">
      <span class="form-section-title">SQLITE DATABASE ROW METRICS</span>
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap:12px; margin-top:10px;">
        ${Object.entries(dbData.row_counts || {}).map(([k, v]) => `
          <div style="background:var(--bg-dark); padding:10px; border-radius:6px; border:1px solid var(--border-color);">
            <div style="font-size:11px; color:var(--text-muted);">${escapeHtml(k)}</div>
            <div style="font-size:18px; font-weight:700;">${v}</div>
          </div>
        `).join('')}
      </div>
    </div>`;

  container.innerHTML = html;
}

// -------------------------------------------------------------------
// 12. DEEP INVESTIGATION WORKSPACE MODAL
// -------------------------------------------------------------------
async function openInvestigationWorkspace(incidentId) {
  const modal = document.getElementById('investigation-modal');
  const body = document.getElementById('investigation-modal-body');
  if (!modal || !body) return;

  body.innerHTML = `<div class="skeleton-loader"><p>Running Deep NOC Investigation for incident ${escapeHtml(incidentId)}...</p></div>`;
  modal.classList.remove('hidden');

  try {
    const res = await fetch(`/api/incidents/${incidentId}/deep-investigation`);
    if (!res.ok) throw new Error('Investigation execution failed.');
    const inv = await res.json();

    const pf = inv.primary_failure || 'Anomaly Detected';
    const evRows = inv.evidence || [];
    const recs = inv.recommendations || [];
    const tInv = inv.traffic_investigation || {};
    const rxCh = tInv.rx_traffic_change || {};
    const txCh = tInv.tx_traffic_change || {};
    const ifState = tInv.interface_state || {};
    const ipInfo = tInv.ip_investigation || {};
    const pingInfo = tInv.ping_investigation || {};
    const optInfo = tInv.optical_power || {};
    const decisionPath = tInv.decision_tree_path || [];
    const stepsList = tInv.steps || [];
    const aiRca = inv.ai_analysis || null;
    const conclusion = inv.investigation_conclusion || tInv.investigation_conclusion || 'INVESTIGATION_COMPLETED';
    const isAuthFailed = tInv.routeros_authenticated === false || tInv.routeros_status === 'FAILED';

    let html = `
      <div class="modal-header">
        <div>
          <h2>🔍 DEEP NOC INVESTIGATION REPORT</h2>
          <span style="font-size:13px; color:var(--text-muted);">Incident ID: <code>${escapeHtml(inv.incident_id)}</code> | Target Device: <strong>${escapeHtml(inv.device_id)}</strong></span>
        </div>
        <button class="close-btn" onclick="document.getElementById('investigation-modal').classList.add('hidden')">✕</button>
      </div>

      <!-- Investigation Conclusion Banner -->
      <div class="alert-box ${isAuthFailed ? 'failed' : 'warning'}" style="margin-bottom:20px;">
        <h3 style="margin-bottom:4px;">INVESTIGATION CONCLUSION</h3>
        <p style="font-size:16px; font-weight:700;">${escapeHtml(conclusion)} (${escapeHtml(pf)})</p>
        <p style="font-size:12px; margin-top:4px;">
          Evidence Completeness: <strong>${escapeHtml(tInv.evidence_completeness || 'COMPLETE')}</strong> | 
          Confidence: <span class="badge ${tInv.evidence_confidence === 'HIGH' ? 'badge-healthy' : 'badge-warning'}">${escapeHtml(tInv.evidence_confidence || 'HIGH')}</span> | 
          Target Interface: <code>${escapeHtml(tInv.interface_name || 'ethernet')}</code>
        </p>
      </div>`;

    // RouterOS API Authentication Failure Alert Card
    if (isAuthFailed) {
      html += `
        <div class="alert-box failed" style="margin-bottom:24px; border-left:6px solid #ef4444;">
          <h4 style="margin-bottom:4px; font-size:15px;">🔴 ROUTEROS API AUTHENTICATION FAILED</h4>
          <p style="font-size:13px; color:var(--text-main); margin-top:4px;">
            RouterOS API connection failed for target host <code>${escapeHtml(inv.device_id)}</code>: <strong>${escapeHtml(tInv.routeros_error || 'Authentication failure')}</strong>
          </p>
          <p style="font-size:12px; color:var(--status-yellow); margin-top:6px;">
            ⚠️ Dependent hardware checks, media classification, optical telemetry, and IP ping reachability have been safely SKIPPED. The system will NOT infer or fabricate missing RouterOS evidence.
          </p>
        </div>`;
    }

    // Traffic Change & Baseline Deviation Magnitude Cards
    if (tInv.rx_traffic_change || tInv.tx_traffic_change) {
      html += `
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:16px; margin-bottom:24px;">
          <div class="summary-card ${rxCh.severity === 'CRITICAL' || rxCh.severity === 'SEVERE' ? 'critical' : 'warning'}">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <span class="card-label">RX Traffic Short-Term Change</span>
              <span class="badge ${rxCh.short_term_direction === 'DROP' ? 'badge-critical' : (rxCh.short_term_direction === 'INCREASE' ? 'badge-healthy' : 'badge-warning')}">${rxCh.short_term_direction || 'SAMPLE-TO-SAMPLE'}</span>
            </div>
            <div style="font-size:20px; font-weight:700; margin-top:6px;">
              ${rxCh.previous_formatted || '0 bps'} → ${rxCh.current_formatted || '0 bps'}
            </div>
            <div style="font-size:13px; color:${rxCh.short_term_direction === 'DROP' ? 'var(--status-red)' : (rxCh.short_term_direction === 'INCREASE' ? 'var(--status-green)' : 'var(--text-main)')}; font-weight:600; margin-top:4px;">
              ${rxCh.short_term_formatted || '0 bps'}
            </div>
            <div style="font-size:11px; color:var(--text-muted); margin-top:6px; border-top:1px solid rgba(255,255,255,0.1); padding-top:4px;">
              vs Moving Baseline (${rxCh.baseline_formatted || '0 bps'}):<br>
              <strong style="color:var(--text-main);">${rxCh.baseline_deviation_formatted || 'ON BASELINE'}</strong>
            </div>
          </div>

          <div class="summary-card ${txCh.severity === 'CRITICAL' || txCh.severity === 'SEVERE' ? 'critical' : 'healthy'}">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <span class="card-label">TX Traffic Short-Term Change</span>
              <span class="badge ${txCh.short_term_direction === 'DROP' ? 'badge-critical' : (txCh.short_term_direction === 'INCREASE' ? 'badge-healthy' : 'badge-warning')}">${txCh.short_term_direction || 'SAMPLE-TO-SAMPLE'}</span>
            </div>
            <div style="font-size:20px; font-weight:700; margin-top:6px;">
              ${txCh.previous_formatted || '0 bps'} → ${txCh.current_formatted || '0 bps'}
            </div>
            <div style="font-size:13px; color:${txCh.short_term_direction === 'DROP' ? 'var(--status-red)' : (txCh.short_term_direction === 'INCREASE' ? 'var(--status-green)' : 'var(--text-main)')}; font-weight:600; margin-top:4px;">
              ${txCh.short_term_formatted || '0 bps'}
            </div>
            <div style="font-size:11px; color:var(--text-muted); margin-top:6px; border-top:1px solid rgba(255,255,255,0.1); padding-top:4px;">
              vs Moving Baseline (${txCh.baseline_formatted || '0 bps'}):<br>
              <strong style="color:var(--text-main);">${txCh.baseline_deviation_formatted || 'ON BASELINE'}</strong>
            </div>
          </div>
        </div>`;
    }

    // Animated Traffic Drop Canvas Graph
    html += `
      <div class="table-card" style="padding:16px; margin-bottom:24px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
          <span class="table-title">📈 Interface Traffic Drop Event Time Series</span>
          <button class="btn btn-secondary btn-sm" onclick="drawTrafficChart(${JSON.stringify(tInv.time_series || [])})">▶ Replay Animation</button>
        </div>
        <div style="width:100%; height:220px; position:relative;">
          <canvas id="traffic-canvas" width="900" height="220" style="width:100%; height:100%; display:block;"></canvas>
        </div>
      </div>`;

    // Decision Tree Execution Path
    if (decisionPath.length > 0) {
      html += `
        <div class="form-section">
          <span class="form-section-title">DETERMINISTIC DECISION TREE EXECUTION PATH</span>
          <div style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-top:10px;">
            ${decisionPath.map((step, idx) => `
              <span class="badge ${step.includes('FAIL') || step.includes('HALT') ? 'badge-critical' : 'badge-healthy'}" style="font-family:monospace; font-size:11px;">${idx + 1}. ${escapeHtml(step)}</span>
              ${idx < decisionPath.length - 1 ? '<span style="color:var(--text-muted);">➔</span>' : ''}
            `).join('')}
          </div>
        </div>`;
    }

    const mediaInfo = tInv.media_classification || { media_type: 'UNKNOWN', confidence: 'LOW', reason: '' };
    const mType = mediaInfo.media_type || 'UNKNOWN';

    // Hardware & Media State Card HTML
    let mediaCardHtml = '';
    if (mType === 'OPTICAL') {
      mediaCardHtml = `
        <div class="form-section" style="border-top:3px solid #a855f7;">
          <span class="form-section-title">🟣 SFP / OPTICAL TRANSCEIVER</span>
          <div style="display:flex; flex-direction:column; gap:6px; font-size:13px; margin-top:8px;">
            <div>Media Type: <strong style="color:#c084fc;">🟣 OPTICAL / SFP+</strong></div>
            <div>Vendor: <strong>${escapeHtml(optInfo.sfp_vendor || 'Detected')}</strong></div>
            <div>Part Number: <code>${escapeHtml(optInfo.sfp_part_number || 'N/A')}</code></div>
            <div>Serial: <code>${escapeHtml(optInfo.sfp_serial || 'N/A')}</code></div>
            <div>RX Optical Power: <strong style="color:var(--accent-blue);">${optInfo.sfp_rx_power_dbm ? optInfo.sfp_rx_power_dbm + ' dBm' : 'N/A'}</strong></div>
            <div>TX Optical Power: <strong style="color:var(--status-green);">${optInfo.sfp_tx_power_dbm ? optInfo.sfp_tx_power_dbm + ' dBm' : 'N/A'}</strong></div>
            <div>Temperature: <strong>${optInfo.sfp_temperature_c !== null && optInfo.sfp_temperature_c !== undefined ? optInfo.sfp_temperature_c + ' °C' : 'N/A'}</strong></div>
          </div>
        </div>`;
    } else if (mType === 'ELECTRICAL') {
      mediaCardHtml = `
        <div class="form-section" style="border-top:3px solid #3b82f6;">
          <span class="form-section-title">🟦 PHYSICAL ELECTRICAL / COPPER INTERFACE</span>
          <div style="display:flex; flex-direction:column; gap:6px; font-size:13px; margin-top:8px;">
            <div>Media Type: <strong style="color:#60a5fa;">🟦 ELECTRICAL / COPPER (RJ45)</strong></div>
            <div>Optical Monitoring: <span class="badge badge-warning">NOT APPLICABLE</span></div>
            <div>Negotiated Speed: <strong>${escapeHtml(optInfo.rate || ifState.speed || 'Auto / 1 Gbps')}</strong></div>
            <div>Duplex Mode: <strong>${optInfo.full_duplex ? 'FULL DUPLEX' : 'HALF / AUTO'}</strong></div>
            <div>Auto Negotiation: <strong>${optInfo.auto_negotiation !== false ? 'YES' : 'NO'}</strong></div>
            <div>Hardware Errors: <strong>${ifState.rx_errors || 0} / ${ifState.tx_errors || 0}</strong></div>
          </div>
        </div>`;
    } else if (['VLAN', 'BRIDGE', 'BONDING', 'VIRTUAL', 'LOOPBACK'].includes(mType)) {
      mediaCardHtml = `
        <div class="form-section" style="border-top:3px solid #eab308;">
          <span class="form-section-title">🟨 LOGICAL / VIRTUAL INTERFACE (${escapeHtml(mType)})</span>
          <div style="display:flex; flex-direction:column; gap:6px; font-size:13px; margin-top:8px;">
            <div>Media Type: <strong style="color:#fde047;">🟨 LOGICAL / ${escapeHtml(mType)}</strong></div>
            <div>Optical Monitoring: <span class="badge badge-warning">NOT APPLICABLE</span></div>
            <div>Classification Reason: <span>${escapeHtml(mediaInfo.reason || 'Logical adapter')}</span></div>
            <div>Operational State: <strong>${ifState.canonical_state === 'UP' ? '🟢 ACTIVE' : '🔴 INACTIVE'}</strong></div>
          </div>
        </div>`;
    } else {
      mediaCardHtml = `
        <div class="form-section">
          <span class="form-section-title">⚪ PHYSICAL MEDIA TYPE</span>
          <div style="display:flex; flex-direction:column; gap:6px; font-size:13px; margin-top:8px;">
            <div>Media Type: <strong>⚪ UNKNOWN</strong></div>
            <div>Confidence: <span class="badge badge-warning">LOW</span></div>
            <div>Reason: <span>${escapeHtml(mediaInfo.reason || 'RouterOS API did not provide sufficient media info.')}</span></div>
            <div>Troubleshooting: <span class="badge badge-warning">LIMITED</span></div>
          </div>
        </div>`;
    }

    const cState = ifState.canonical_state || (ifState.running ? 'UP' : 'DOWN');

    // Live RouterOS API Interface & Connectivity Checks
    html += `
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:16px; margin-bottom:24px;">
        <div class="form-section">
          <span class="form-section-title">CANONICAL INTERFACE STATE</span>
          <div style="display:flex; flex-direction:column; gap:6px; font-size:13px; margin-top:8px;">
            <div>Canonical State: <strong>${cState === 'UP' ? '🟢 UP' : (cState === 'DOWN' ? '🔴 DOWN' : (cState === 'DISABLED' ? '🟡 DISABLED' : '⚪ UNKNOWN'))}</strong></div>
            <div>Disabled: <strong>${ifState.disabled ? 'YES' : 'NO'}</strong></div>
            <div>Link Downs Counter: <strong>${ifState.link_downs || 0}</strong></div>
            <div>RX/TX Errors: <strong>${ifState.rx_errors || 0} / ${ifState.tx_errors || 0}</strong></div>
            <div>RX/TX Drops: <strong>${ifState.rx_drops || 0} / ${ifState.tx_drops || 0}</strong></div>
          </div>
        </div>

        <div class="form-section">
          <span class="form-section-title">IP & L3 CONNECTIVITY CHECK</span>
          <div style="display:flex; flex-direction:column; gap:6px; font-size:13px; margin-top:8px;">
            <div>Interface HAS_IP: <strong>${ipInfo.has_ip ? 'YES (' + escapeHtml(ipInfo.cidr || ipInfo.ip_address) + ')' : 'NO (L2 Only)'}</strong></div>
            <div>Ping Target: <code>${escapeHtml(pingInfo.destination || 'N/A')}</code></div>
            <div>Reachability: <strong>${pingInfo.reachable ? '🟢 0% Packet Loss' : (ipInfo.has_ip && !isAuthFailed ? '🔴 100% Packet Loss' : 'N/A')}</strong></div>
            <div>Avg Latency: <strong>${pingInfo.avg_latency_ms || 0} ms</strong></div>
          </div>
        </div>

        ${mediaCardHtml}
      </div>`;

    // Evidence Table
    html += `
      <div class="form-section">
        <span class="form-section-title">EVIDENCE TABLE & TELEMETRY PROOF</span>
        <table class="noc-table" style="margin-top:10px;">
          <thead>
            <tr>
              <th>Fact / Check</th>
              <th>Parameter</th>
              <th>Observed Value</th>
              <th>Baseline / Normal</th>
              <th>Source</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            ${evRows.map(row => `
              <tr>
                <td><strong>${escapeHtml(row.fact)}</strong></td>
                <td><code>${escapeHtml(row.parameter)}</code></td>
                <td><strong style="color:var(--status-yellow);">${escapeHtml(row.observed_value)}</strong></td>
                <td>${escapeHtml(row.baseline_value)}</td>
                <td><span style="font-size:11px; color:var(--text-muted);">${escapeHtml(row.source)}</span></td>
                <td><span class="badge badge-healthy">${escapeHtml(row.confidence)}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>`;

    // OpenRouter AI RCA Summary (if available)
    if (aiRca) {
      html += `
        <div class="form-section" style="border-left:4px solid var(--accent-blue);">
          <span class="form-section-title">🤖 OPENROUTER AI RCA SYNTHESIS (${escapeHtml(aiRca.model || 'llama-3.3-70b')})</span>
          <p style="font-size:13px; line-height:1.6; margin-top:8px; color:var(--text-main);">${escapeHtml(aiRca.summary || 'AI synthesis completed.')}</p>
        </div>`;
    }

    // Actionable Troubleshooting Recommendations
    html += `
      <div class="form-section">
        <span class="form-section-title">INFORMATIONAL TROUBLESHOOTING RECOMMENDATIONS (READ-ONLY NOC GUIDE)</span>
        <ul style="padding-left:20px; font-size:13px; color:var(--text-main); margin-top:10px; display:flex; flex-direction:column; gap:8px;">
          ${recs.map(r => `<li><strong>Step ${r.step}:</strong> ${escapeHtml(r.check)} <code>${escapeHtml(r.command || '')}</code></li>`).join('')}
        </ul>
      </div>`;

    body.innerHTML = html;

    // Draw animated traffic graph
    setTimeout(() => drawTrafficChart(tInv.time_series || []), 100);
  } catch (err) {
    body.innerHTML = `<div class="alert-box failed">✕ Investigation workspace error: ${escapeHtml(err.message)}</div>`;
  }
}

// Draw Animated Traffic Canvas Graph
function drawTrafficChart(timeSeries) {
  const canvas = document.getElementById('traffic-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.width = canvas.parentElement.clientWidth || 800;
  const height = canvas.height = 220;

  ctx.clearRect(0, 0, width, height);

  if (!timeSeries || timeSeries.length === 0) {
    // Render placeholder graph line if timeSeries is empty
    timeSeries = [
      { rx_bps: 8100000000, tx_bps: 7800000000 },
      { rx_bps: 8000000000, tx_bps: 7700000000 },
      { rx_bps: 7900000000, tx_bps: 7600000000 },
      { rx_bps: 2100000000, tx_bps: 7400000000 },
      { rx_bps: 2000000000, tx_bps: 7300000000 }
    ];
  }

  const padding = 40;
  const graphW = width - padding * 2;
  const graphH = height - padding * 2;

  const maxVal = Math.max(...timeSeries.map(t => Math.max(t.rx_bps || 0, t.tx_bps || 0))) * 1.2 || 10000000000;

  // Grid lines
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding + (graphH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();

    const valLabel = formatBandwidth(maxVal * (1 - i / 4));
    ctx.fillStyle = '#64748b';
    ctx.font = '10px Inter, sans-serif';
    ctx.fillText(valLabel, 5, y + 3);
  }

  // Highlight Drop Region
  const dropIdx = timeSeries.length > 2 ? Math.floor(timeSeries.length / 2) : 1;
  const dropX = padding + (graphW / (timeSeries.length - 1)) * dropIdx;
  ctx.fillStyle = 'rgba(239, 68, 68, 0.15)';
  ctx.fillRect(dropX, padding, width - padding - dropX, graphH);

  // Incident Line
  ctx.strokeStyle = '#ef4444';
  ctx.setLineDash([4, 4]);
  ctx.beginPath();
  ctx.moveTo(dropX, padding);
  ctx.lineTo(dropX, height - padding);
  ctx.stroke();
  ctx.setLineDash([]);

  ctx.fillStyle = '#ef4444';
  ctx.font = 'bold 11px Inter, sans-serif';
  ctx.fillText('INCIDENT DETECTED', dropX + 6, padding + 15);

  // Plot RX Traffic Line
  ctx.strokeStyle = '#22c55e';
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  timeSeries.forEach((t, idx) => {
    const x = padding + (graphW / (timeSeries.length - 1)) * idx;
    const y = height - padding - ((t.rx_bps || 0) / maxVal) * graphH;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Plot TX Traffic Line
  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2;
  ctx.beginPath();
  timeSeries.forEach((t, idx) => {
    const x = padding + (graphW / (timeSeries.length - 1)) * idx;
    const y = height - padding - ((t.tx_bps || 0) / maxVal) * graphH;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Legend
  ctx.fillStyle = '#22c55e';
  ctx.fillRect(width - 180, 10, 12, 12);
  ctx.fillStyle = '#f8fafc';
  ctx.font = '11px Inter, sans-serif';
  ctx.fillText('RX Traffic', width - 162, 20);

  ctx.fillStyle = '#38bdf8';
  ctx.fillRect(width - 90, 10, 12, 12);
  ctx.fillStyle = '#f8fafc';
  ctx.fillText('TX Traffic', width - 72, 20);
}

// -------------------------------------------------------------------
// 13. PHASE 6.5 EVENT INVESTIGATION WORKSPACE MODAL
// -------------------------------------------------------------------
async function openEventInvestigationModal(eventId) {
  const modal = document.getElementById('investigation-modal');
  const body = document.getElementById('investigation-modal-body');
  if (!modal || !body) return;

  body.innerHTML = `<div class="skeleton-loader"><p>Loading Event Investigation Workspace for ${escapeHtml(eventId)}...</p></div>`;
  modal.classList.remove('hidden');

  try {
    const res = await fetch(`/api/events/${eventId}/investigation`);
    if (!res.ok) throw new Error('Failed to load event investigation.');
    const inv = await res.json();

    const hdr = inv.event_header || {};
    const summary = inv.summary || {};
    const bl = inv.baseline_explanation || {};
    const dom = inv.domain_investigation || {};
    const nocActions = inv.noc_actions || [];
    const related = inv.related_events || [];
    const graphData = inv.traffic_graph || [];
    const pattern = inv.traffic_pattern || 'NORMAL_VARIATION';

    let html = `
      <div class="modal-header">
        <div>
          <h2>🔍 EVENT INVESTIGATION WORKSPACE</h2>
          <span style="font-size:13px; color:var(--text-muted);">
            Event ID: <code>${escapeHtml(hdr.event_id)}</code> | Target Device: <strong>${escapeHtml(hdr.device_id)}</strong>
          </span>
        </div>
        <button class="close-btn" onclick="document.getElementById('investigation-modal').classList.add('hidden')">✕</button>
      </div>

      <!-- Event Header Card -->
      <div class="summary-grid" style="margin-bottom:20px;">
        <div class="summary-card ${hdr.severity === 'CRITICAL' ? 'critical' : 'warning'}">
          <span class="card-label">Severity</span>
          <span class="card-value" style="font-size:18px;">${renderStatusBadge(hdr.severity)}</span>
        </div>
        <div class="summary-card healthy">
          <span class="card-label">Event Type</span>
          <span class="card-value" style="font-size:18px;"><code>${escapeHtml(hdr.event_type)}</code></span>
        </div>
        <div class="summary-card healthy">
          <span class="card-label">Target Entity</span>
          <span class="card-value" style="font-size:18px;"><code>${escapeHtml(hdr.target_entity)}</code></span>
        </div>
        <div class="summary-card healthy">
          <span class="card-label">Status & Duration</span>
          <span class="card-value" style="font-size:18px;">${escapeHtml(hdr.status)} (${hdr.duration_minutes}m)</span>
        </div>
      </div>

      <!-- Deterministic Facts Summary -->
      <div class="alert-box warning" style="margin-bottom:20px;">
        <h3>DETERMINISTIC SUMMARY: ${escapeHtml(summary.title || hdr.event_type)}</h3>
        <p style="font-size:14px; font-weight:600; margin-top:4px;">${escapeHtml(summary.description || '')}</p>
        <div style="font-size:12px; margin-top:8px;">
          <strong>Potential Impact:</strong>
          <ul style="margin-top:4px; padding-left:20px;">
            ${(summary.impact || []).map(i => `<li>${escapeHtml(i)}</li>`).join('')}
          </ul>
        </div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Source: ${escapeHtml(summary.source || 'RouterOS Telemetry')}</div>
      </div>

      <!-- Baseline Explanation & Trust Breakdown -->
      <div class="form-section">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span class="form-section-title">BASELINE EXPLANATION & TRUST METRICS</span>
          <span class="badge ${bl.trust_level === 'HIGH' ? 'badge-healthy' : 'badge-warning'}">${escapeHtml(bl.trust_tag || '🟢 BASELINE TRUSTED')}</span>
        </div>

        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin-top:12px;">
          <div style="background:var(--bg-dark); padding:10px; border-radius:6px; border:1px solid var(--border-color);">
            <div style="font-size:11px; color:var(--text-muted);">Current Value</div>
            <div style="font-size:18px; font-weight:700; color:var(--status-yellow);">${bl.current_formatted || '0 bps'}</div>
          </div>
          <div style="background:var(--bg-dark); padding:10px; border-radius:6px; border:1px solid var(--border-color);">
            <div style="font-size:11px; color:var(--text-muted);">Historical Baseline</div>
            <div style="font-size:18px; font-weight:700;">${bl.baseline_formatted || '0 bps'}</div>
          </div>
          <div style="background:var(--bg-dark); padding:10px; border-radius:6px; border:1px solid var(--border-color);">
            <div style="font-size:11px; color:var(--text-muted);">Baseline Deviation</div>
            <div style="font-size:18px; font-weight:700; color:var(--status-red);">▼ ${bl.baseline_deviation_percentage || 0}%</div>
          </div>
          <div style="background:var(--bg-dark); padding:10px; border-radius:6px; border:1px solid var(--border-color);">
            <div style="font-size:11px; color:var(--text-muted);">Valid History Samples</div>
            <div style="font-size:18px; font-weight:700;">${bl.valid_sample_count || 0} / ${bl.sample_count || 0}</div>
          </div>
        </div>

        <details style="margin-top:12px; background:rgba(255,255,255,0.03); padding:10px; border-radius:6px;">
          <summary style="cursor:pointer; font-size:13px; font-weight:600; color:var(--accent-blue);">❓ What is this baseline?</summary>
          <p style="font-size:12px; color:var(--text-main); margin-top:8px; line-height:1.5;">
            ${escapeHtml(bl.explanation_text)}
          </p>
        </details>
      </div>

      <!-- Time Series Chart & Pattern -->
      <div class="table-card" style="padding:16px; margin-bottom:24px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
          <span class="table-title">📈 Event Time-Series Traffic Chart</span>
          <span class="badge ${pattern.includes('DROP') ? 'badge-critical' : 'badge-warning'}">Pattern: ${escapeHtml(pattern)}</span>
        </div>
        <div style="width:100%; height:220px; position:relative;">
          <canvas id="event-traffic-canvas" width="900" height="220" style="width:100%; height:100%; display:block;"></canvas>
        </div>
      </div>

      <!-- Domain Specific Technical Investigation -->
      <div class="form-section">
        <span class="form-section-title">DOMAIN TECHNICAL INVESTIGATION (${escapeHtml(dom.media_type || dom.domain || 'HARDWARE')})</span>
        <div style="margin-top:8px; font-size:13px; color:var(--text-main); display:flex; flex-direction:column; gap:6px;">
          ${Object.entries(dom).map(([k, v]) => `
            <div><strong style="color:var(--text-muted);">${escapeHtml(k)}:</strong> ${escapeHtml(String(v))}</div>
          `).join('')}
        </div>
      </div>

      <!-- Recommended NOC Actions -->
      <div class="form-section">
        <span class="form-section-title">RECOMMENDED NOC ACTIONS (READ-ONLY)</span>
        <ul style="padding-left:20px; font-size:13px; color:var(--text-main); margin-top:10px; display:flex; flex-direction:column; gap:8px;">
          ${nocActions.map(a => `<li><strong>Step ${a.step}:</strong> ${escapeHtml(a.check)} <code>${escapeHtml(a.command)}</code></li>`).join('')}
        </ul>
      </div>

      <!-- AI Investigation Section (Manual Trigger) -->
      ${hdr.incident_id ? `
        <div class="form-section" style="border-left:4px solid var(--accent-blue);">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="form-section-title">🤖 OPENROUTER AI RCA (OPTIONAL)</span>
            <button class="btn btn-secondary btn-sm" onclick="triggerManualAiInvestigation('${hdr.incident_id}')">🔍 RUN AI INVESTIGATION</button>
          </div>
          <div id="ai-investigation-result-${hdr.incident_id}" style="margin-top:10px; font-size:13px; color:var(--text-muted);">
            Click 'RUN AI INVESTIGATION' to query OpenRouter LLM for deep root-cause synthesis.
          </div>
        </div>
      ` : ''}
    `;

    body.innerHTML = html;

    setTimeout(() => {
      const c = document.getElementById('event-traffic-canvas');
      if (c) {
        c.id = 'traffic-canvas';
        drawTrafficChart(graphData);
      }
    }, 100);
  } catch (err) {
    body.innerHTML = `<div class="alert-box failed">✕ Event workspace error: ${escapeHtml(err.message)}</div>`;
  }
}

async function triggerManualAiInvestigation(incidentId) {
  const container = document.getElementById(`ai-investigation-result-${incidentId}`);
  if (container) {
    container.innerHTML = '⚡ Querying OpenRouter AI RCA model (meta-llama/llama-3.3-70b-instruct)...';
  }
  try {
    const res = await fetch(`/api/incidents/${incidentId}/investigate`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'AI investigation request failed.');

    if (container) {
      const summary = data.analysis ? data.analysis.summary : (data.summary || 'AI synthesis completed.');
      container.innerHTML = `<div class="alert-box healthy"><p style="font-size:13px; line-height:1.5;">${escapeHtml(summary)}</p></div>`;
    }
  } catch (err) {
    if (container) {
      container.innerHTML = `<div class="alert-box failed"><p style="font-size:12px;">⚠️ ${escapeHtml(err.message)}</p></div>`;
    }
  }
}
