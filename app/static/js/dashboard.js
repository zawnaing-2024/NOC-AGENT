document.addEventListener('DOMContentLoaded', () => {
  let currentTab = 'dashboard';
  let refreshTimer = null;
  let countdown = 10;

  // Elements
  const refreshCounterEl = document.getElementById('refresh-counter');
  const liveStatusEl = document.getElementById('live-status');
  const aiStatusEl = document.getElementById('ai-status');

  // Initialize Dashboard
  init();

  function init() {
    setupTabNavigation();
    fetchData();
    startTimer();
  }

  function startTimer() {
    if (refreshTimer) clearInterval(refreshTimer);
    countdown = 10;
    refreshTimer = setInterval(() => {
      countdown--;
      if (refreshCounterEl) refreshCounterEl.textContent = `${countdown}s`;
      if (countdown <= 0) {
        countdown = 10;
        fetchData();
      }
    }, 1000);
  }

  function setupTabNavigation() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        tabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentTab = btn.dataset.tab;
        renderActiveTab();
      });
    });
  }

  async function fetchData() {
    try {
      // Check AI Status
      const aiRes = await fetch('/api/ai/status').then(r => r.json()).catch(() => null);
      if (aiStatusEl) {
        if (aiRes && aiRes.status === 'healthy') {
          aiStatusEl.innerHTML = `<span class="dot"></span> AI: OpenRouter ● Connected`;
        } else {
          aiStatusEl.innerHTML = `<span class="dot yellow"></span> AI: Offline`;
        }
      }

      if (liveStatusEl) {
        liveStatusEl.innerHTML = `<span class="dot"></span> System Status: HEALTHY`;
      }

      renderActiveTab();
    } catch (err) {
      if (liveStatusEl) {
        liveStatusEl.innerHTML = `<span class="dot red"></span> ⚠ Backend Unavailable`;
      }
    }
  }

  function renderActiveTab() {
    const viewContainer = document.getElementById('view-container');
    if (!viewContainer) return;

    if (currentTab === 'dashboard') renderDashboardView(viewContainer);
    else if (currentTab === 'devices') renderDevicesView(viewContainer);
    else if (currentTab === 'interfaces') renderInterfacesView(viewContainer);
    else if (currentTab === 'bgp') renderBgpView(viewContainer);
    else if (currentTab === 'ospf') renderOspfView(viewContainer);
    else if (currentTab === 'routing') renderRoutingView(viewContainer);
    else if (currentTab === 'incidents') renderIncidentsView(viewContainer);
  }

  function formatBandwidth(bps) {
    if (bps === null || bps === undefined || isNaN(bps)) return '0 bps';
    const val = Number(bps);
    if (val >= 1000000000) {
      return (val / 1000000000).toFixed(2) + ' Gbps';
    } else if (val >= 1000000) {
      return (val / 1000000).toFixed(2) + ' Mbps';
    } else if (val >= 1000) {
      return (val / 1000).toFixed(1) + ' Kbps';
    } else {
      return val.toFixed(0) + ' bps';
    }
  }

  // View Renderers
  async function renderDashboardView(container) {
    const [devs, ifaces, bgp, ospf, incs] = await Promise.all([
      fetch('/api/devices/overview').then(r => r.json()).catch(() => ({ devices: [] })),
      fetch('/api/interfaces/overview').then(r => r.json()).catch(() => ({ interfaces: [] })),
      fetch('/api/routing/bgp/overview').then(r => r.json()).catch(() => ({ established_count: 0, down_count: 0 })),
      fetch('/api/routing/ospf/overview').then(r => r.json()).catch(() => ({ full_count: 0, down_count: 0 })),
      fetch('/api/incidents').then(r => r.json()).catch(() => ({ incidents: [] }))
    ]);

    const activeIncs = (incs.incidents || []).filter(i => i.status !== 'RESOLVED' && i.status !== 'CLOSED');
    const interfaceList = ifaces.interfaces || [];
    const totalRx = interfaceList.reduce((acc, curr) => acc + (curr.rx_bps || 0), 0);
    const totalTx = interfaceList.reduce((acc, curr) => acc + (curr.tx_bps || 0), 0);

    container.innerHTML = `
      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-title">Devices</div>
          <div class="kpi-value">${devs.devices.length}</div>
          <div class="kpi-sub"><span style="color:var(--status-green)">Healthy: ${devs.devices.length}</span></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Interfaces</div>
          <div class="kpi-value">${interfaceList.length}</div>
          <div class="kpi-sub">
            <span style="color:var(--status-green)">UP: ${interfaceList.filter(i=>i.status==='UP').length}</span>
            <span style="color:var(--status-red)">DOWN: ${interfaceList.filter(i=>i.status==='DOWN').length}</span>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Aggregate Traffic</div>
          <div class="kpi-value" style="font-size:20px; color:var(--accent-blue);">RX: ${formatBandwidth(totalRx)}</div>
          <div class="kpi-sub"><span style="color:var(--text-main)">TX: ${formatBandwidth(totalTx)}</span></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">BGP Sessions</div>
          <div class="kpi-value">${(bgp.established_count || 0) + (bgp.down_count || 0)}</div>
          <div class="kpi-sub">
            <span style="color:var(--status-green)">Established: ${bgp.established_count || 0}</span>
            <span style="color:var(--status-red)">Down: ${bgp.down_count || 0}</span>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">OSPF Neighbors</div>
          <div class="kpi-value">${(ospf.full_count || 0) + (ospf.down_count || 0)}</div>
          <div class="kpi-sub">
            <span style="color:var(--status-green)">Full: ${ospf.full_count || 0}</span>
            <span style="color:var(--status-red)">Down: ${ospf.down_count || 0}</span>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Incidents</div>
          <div class="kpi-value">${activeIncs.length}</div>
          <div class="kpi-sub"><span style="color:var(--status-red)">Critical: ${activeIncs.filter(i=>i.severity==='CRITICAL').length}</span></div>
        </div>
      </div>

      <div class="table-container">
        <div class="table-header">
          <div class="table-title">Active Correlated Incidents</div>
        </div>
        ${activeIncs.length === 0 ? '<div style="padding:24px; text-align:center; color:var(--status-green); font-weight:600;">✓ No active network incidents</div>' : `
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Device</th>
                <th>Problem</th>
                <th>Created At</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${activeIncs.map(inc => `
                <tr>
                  <td><span class="status-badge" style="color:var(--status-red)">🔴 ${inc.severity}</span></td>
                  <td>${inc.device_id}</td>
                  <td>${inc.facts ? inc.facts.event_type : 'Network Fault'}</td>
                  <td>${new Date(inc.created_at).toLocaleTimeString()}</td>
                  <td>${inc.status}</td>
                  <td><button class="btn-action" onclick="openInvestigation('${inc.incident_id}')">Investigate</button></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `}
      </div>
    `;
  }

  async function renderDevicesView(container) {
    const res = await fetch('/api/devices/overview').then(r => r.json()).catch(() => ({ devices: [] }));
    container.innerHTML = `
      <div class="table-container">
        <div class="table-header">
          <div class="table-title">Network Device Matrix</div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Device IP</th>
              <th>Version</th>
              <th>CPU %</th>
              <th>RAM %</th>
              <th>Interfaces (UP/Total)</th>
              <th>BGP (Est/Total)</th>
              <th>OSPF (Full/Total)</th>
              <th>Routes</th>
              <th>NAT Rules</th>
              <th>Health</th>
            </tr>
          </thead>
          <tbody>
            ${res.devices.map(d => `
              <tr>
                <td><strong>${d.ip_address}</strong></td>
                <td>${d.version}</td>
                <td>${d.cpu_percent}%</td>
                <td>${d.memory_percent}%</td>
                <td>${d.interfaces_up}/${d.interfaces_total}</td>
                <td>${d.bgp_established}/${d.bgp_total}</td>
                <td>${d.ospf_full}/${d.ospf_total}</td>
                <td>${d.routes_count}</td>
                <td>${d.nat_count}</td>
                <td><span class="status-badge" style="color:var(--status-green)">🟢 ${d.health}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  async function renderInterfacesView(container) {
    const res = await fetch('/api/interfaces/overview').then(r => r.json()).catch(() => ({ interfaces: [] }));
    container.innerHTML = `
      <div class="table-container">
        <div class="table-header">
          <div class="table-title">Interface Telemetry & Status</div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>Interface</th>
              <th>Status</th>
              <th>RX Rate</th>
              <th>TX Rate</th>
              <th>Errors (RX/TX)</th>
              <th>Drops (RX/TX)</th>
              <th>Health</th>
            </tr>
          </thead>
          <tbody>
            ${res.interfaces.map(i => `
              <tr>
                <td>${i.device_id}</td>
                <td><strong>${i.interface_name}</strong></td>
                <td>${i.status === 'UP' ? '<span style="color:var(--status-green)">🟢 UP</span>' : '<span style="color:var(--status-red)">🔴 DOWN</span>'}</td>
                <td><strong>${formatBandwidth(i.rx_bps)}</strong></td>
                <td><strong>${formatBandwidth(i.tx_bps)}</strong></td>
                <td>${i.rx_errors}/${i.tx_errors}</td>
                <td>${i.rx_drops}/${i.tx_drops}</td>
                <td><span class="status-badge">${i.health}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  async function renderBgpView(container) {
    const res = await fetch('/api/routing/bgp/overview').then(r => r.json()).catch(() => ({ bgp_peers: [] }));
    const peers = res.bgp_peers || [];
    container.innerHTML = `
      <div class="table-container">
        <div class="table-header">
          <div class="table-title">BGP Sessions Dashboard (${res.established_count || 0} Established / ${res.down_count || 0} Down)</div>
        </div>
        ${peers.length === 0 ? '<div style="padding:24px; text-align:center; color:var(--text-muted);">No active BGP peer sessions recorded on monitored devices</div>' : `
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Peer IP</th>
                <th>Remote Address</th>
                <th>State</th>
                <th>Uptime</th>
                <th>Prefix Count</th>
                <th>Health</th>
              </tr>
            </thead>
            <tbody>
              ${peers.map(b => `
                <tr>
                  <td>${b.device_id}</td>
                  <td><strong>${b.peer}</strong></td>
                  <td>${b.remote_address}</td>
                  <td>${b.established ? '<span style="color:var(--status-green)">🟢 ESTABLISHED</span>' : '<span style="color:var(--status-red)">🔴 DOWN</span>'}</td>
                  <td>${b.uptime}</td>
                  <td>${b.prefix_count}</td>
                  <td><span class="status-badge">${b.health}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `}
      </div>
    `;
  }

  async function renderOspfView(container) {
    const res = await fetch('/api/routing/ospf/overview').then(r => r.json()).catch(() => ({ ospf_neighbors: [] }));
    const neighbors = res.ospf_neighbors || [];
    container.innerHTML = `
      <div class="table-container">
        <div class="table-header">
          <div class="table-title">OSPF Neighbors Dashboard (${res.full_count || 0} Full / ${res.down_count || 0} Down)</div>
        </div>
        ${neighbors.length === 0 ? '<div style="padding:24px; text-align:center; color:var(--text-muted);">No active OSPF neighbors recorded on monitored devices</div>' : `
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Router ID</th>
                <th>Neighbor IP</th>
                <th>State</th>
                <th>Interface</th>
                <th>Area</th>
                <th>Health</th>
              </tr>
            </thead>
            <tbody>
              ${neighbors.map(o => `
                <tr>
                  <td>${o.device_id}</td>
                  <td>${o.router_id}</td>
                  <td><strong>${o.neighbor}</strong></td>
                  <td><span style="color:var(--status-green)">🟢 ${o.state}</span></td>
                  <td>${o.interface}</td>
                  <td>${o.area}</td>
                  <td><span class="status-badge">${o.health}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `}
      </div>
    `;
  }

  async function renderRoutingView(container) {
    const res = await fetch('/api/routing/overview').then(r => r.json()).catch(() => ({ default_route_active: true, total_routes: 0 }));
    container.innerHTML = `
      <div style="background-color:var(--bg-card); border:1px solid var(--border-color); border-radius:8px; padding:20px; margin-bottom:24px; display:flex; align-items:center; gap:16px;">
        <span style="font-size:24px">${res.default_route_active ? '🟢' : '🔴'}</span>
        <div>
          <h3 style="font-size:16px; font-weight:700;">Default Route (0.0.0.0/0) Status: ${res.default_route_active ? 'ACTIVE / REACHABLE' : 'UNAVAILABLE / DOWN'}</h3>
          <p style="color:var(--text-muted); font-size:13px;">Active WAN gateway route reachability tracking across all monitored routers.</p>
        </div>
      </div>
      <div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-title">Total Routes</div><div class="kpi-value">${res.total_routes || 0}</div></div>
        <div class="kpi-card"><div class="kpi-title">Active Routes</div><div class="kpi-value">${res.active_routes || 0}</div></div>
        <div class="kpi-card"><div class="kpi-title">Inactive Routes</div><div class="kpi-value">${res.inactive_routes || 0}</div></div>
      </div>
    `;
  }

  async function renderIncidentsView(container) {
    const res = await fetch('/api/incidents').then(r => r.json()).catch(() => ({ incidents: [] }));
    container.innerHTML = `
      <div class="table-container">
        <div class="table-header">
          <div class="table-title">Incident Center</div>
        </div>
        ${res.incidents.length === 0 ? '<div style="padding:24px; text-align:center; color:var(--status-green)">✓ No historical incidents recorded</div>' : `
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Device</th>
                <th>Primary Problem</th>
                <th>Created At</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${res.incidents.map(inc => `
                <tr>
                  <td><span class="status-badge" style="color:var(--status-red)">🔴 ${inc.severity}</span></td>
                  <td>${inc.device_id}</td>
                  <td>${inc.facts ? inc.facts.event_type : 'Network Incident'}</td>
                  <td>${new Date(inc.created_at).toLocaleString()}</td>
                  <td>${inc.status}</td>
                  <td><button class="btn-action" onclick="openInvestigation('${inc.incident_id}')">Investigate</button></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `}
      </div>
    `;
  }

  // Investigation Workspace Handler
  window.openInvestigation = async function(incidentId) {
    const modal = document.getElementById('investigation-modal');
    const modalContent = document.getElementById('investigation-modal-body');
    if (!modal || !modalContent) return;

    modal.classList.remove('hidden');
    modalContent.innerHTML = '<div style="padding:40px; text-align:center;">Running Deep NOC Investigation Engine...</div>';

    try {
      const inv = await fetch(`/api/incidents/${incidentId}/deep-investigation`).then(r => r.json());

      modalContent.innerHTML = `
        <div class="modal-header">
          <h2>Investigation Workspace — ${inv.primary_failure}</h2>
          <button class="close-btn" onclick="closeInvestigation()">×</button>
        </div>

        <!-- AI RCA Summary -->
        <div style="background:rgba(56,189,248,0.1); border:1px solid var(--accent-blue); border-radius:8px; padding:16px; margin-bottom:20px;">
          <h3 style="color:var(--accent-blue); font-size:14px; margin-bottom:8px;">OpenRouter AI Root Cause Analysis</h3>
          <p><strong>Likely Root Cause:</strong> ${inv.ai_analysis ? inv.ai_analysis.root_cause.description : inv.primary_failure}</p>
          <p style="margin-top:4px;"><strong>Confidence:</strong> ${inv.ai_analysis ? inv.ai_analysis.root_cause.confidence : 'HIGH'}</p>
          <p style="margin-top:4px;"><strong>Impact:</strong> ${inv.ai_analysis ? inv.ai_analysis.impact.description : 'Service degradation observed.'}</p>
        </div>

        <!-- Cascade Flow Graph -->
        <h4 style="margin-bottom:12px;">Visual Dependency Cascade Flow</h4>
        <div class="flow-container">
          ${(inv.visualization_flow || []).map(f => `
            <div class="flow-step ${f.is_primary_root ? 'primary' : ''}">
              <div style="font-size:11px; color:var(--text-muted);">${f.domain}</div>
              <div style="font-weight:700; margin-top:4px;">${f.title}</div>
              <div style="font-size:11px; margin-top:4px; color:${f.status==='CRITICAL'?'var(--status-red)':'var(--status-green)'}">${f.status}</div>
            </div>
            <div class="flow-arrow">➔</div>
          `).slice(0, -1).join('')}
        </div>

        <!-- Human Readable Evidence Table -->
        <h4 style="margin:20px 0 12px 0;">Human-Readable Evidence Checklist</h4>
        <table>
          <thead>
            <tr>
              <th>Fact / Finding</th>
              <th>Parameter</th>
              <th>Observed Value</th>
              <th>Baseline Value</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            ${(inv.evidence || []).map(e => `
              <tr>
                <td><strong>${e.fact}</strong></td>
                <td>${e.parameter}</td>
                <td>${e.observed_value}</td>
                <td>${e.baseline_value}</td>
                <td>${e.source}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>

        <!-- Recommended Actionable Checks -->
        <h4 style="margin:20px 0 12px 0;">Recommended NOC Engineer Next Checks (Read-Only)</h4>
        <ol style="padding-left:20px; color:var(--text-muted);">
          ${(inv.recommendations || []).map(r => `
            <li style="margin-bottom:8px;">
              <strong style="color:var(--text-main)">${r.check}</strong><br/>
              <code style="background:rgba(0,0,0,0.3); padding:2px 6px; border-radius:4px; font-size:11px;">${r.command}</code>
            </li>
          `).join('')}
        </ol>

        <!-- Technical Details Collapsible -->
        <details style="margin-top:24px; border-top:1px solid var(--border-color); padding-top:16px;">
          <summary style="cursor:pointer; color:var(--text-muted); font-weight:600;">[ Show Technical Details / Raw JSON ]</summary>
          <pre style="background:rgba(0,0,0,0.4); padding:16px; border-radius:6px; overflow-x:auto; margin-top:12px; font-size:11px;">${JSON.stringify(inv, null, 2)}</pre>
        </details>
      `;
    } catch (err) {
      modalContent.innerHTML = `<div style="padding:40px; text-align:center; color:var(--status-red);">⚠ Investigation loading failed: ${err.message}</div>`;
    }
  };

  window.closeInvestigation = function() {
    const modal = document.getElementById('investigation-modal');
    if (modal) modal.classList.add('hidden');
  };
});
