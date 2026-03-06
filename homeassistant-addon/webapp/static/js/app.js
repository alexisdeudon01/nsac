/**
 * NSAC - Network Security Audit Console
 * Frontend JavaScript
 */

const API = '';
let socket = null;
let currentLogFilter = 'all';

// =====================================================
// Navigation
// =====================================================

function navigate(pageId) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const page = document.getElementById('page-' + pageId);
    const nav = document.querySelector(`[data-page="${pageId}"]`);
    if (page) page.classList.add('active');
    if (nav) nav.classList.add('active');

    // Stop live intervals when leaving pages
    if (pageId !== 'cartography') stopCartoLive();
    if (pageId !== 'highlevel') stopHighLevelLive();

    const refreshMap = {
        'dashboard': refreshDashboard,
        'containers': refreshContainers,
        'devices': refreshDevices,
        'audit': refreshReports,
        'logs': refreshLogs,
        'config': loadConfig,
        'cartography': startCartoLive,
        'highlevel': startHighLevelLive,
    };
    if (refreshMap[pageId]) refreshMap[pageId]();
}

// =====================================================
// API Helpers
// =====================================================

async function api(endpoint, options = {}) {
    try {
        const resp = await fetch(API + endpoint, {
            headers: { 'Content-Type': 'application/json', ...options.headers },
            ...options,
        });
        return await resp.json();
    } catch (e) {
        console.error('API error:', e);
        addLog('error', `API ${endpoint}: ${e.message}`);
        return null;
    }
}

async function apiPost(endpoint, body = {}) {
    return api(endpoint, { method: 'POST', body: JSON.stringify(body) });
}

// =====================================================
// Dashboard
// =====================================================

async function refreshDashboard() {
    const [containers, devices, status, reports] = await Promise.all([
        api('/api/containers'),
        api('/api/devices'),
        api('/api/system/status'),
        api('/api/audit/reports'),
    ]);

    const running = containers ? containers.filter(c => c.State === 'running').length : 0;
    setText('stat-containers', running);
    setText('stat-devices', devices ? devices.length : 0);
    setText('stat-reports', reports ? reports.length : 0);

    updateServiceStatus('mobsf-status', containers, 'mobsf');
    updateServiceStatus('mitmproxy-status', containers, 'mitmproxy');

    const netStatus = await api('/api/network/status');
    if (netStatus) {
        setToggle('toggle-proxy', netStatus.transparent_proxy);
    }

    refreshProbesSummary();
}

function updateServiceStatus(elementId, containers, name) {
    const el = document.getElementById(elementId);
    if (!el || !containers) return;
    const container = containers.find(c => c.Names && c.Names.includes(name));
    if (container && container.State === 'running') {
        el.innerHTML = '<span class="badge badge-success">Running</span>';
    } else {
        el.innerHTML = '<span class="badge badge-danger">Stopped</span>';
    }
}

// =====================================================
// Containers
// =====================================================

async function refreshContainers() {
    const containers = await api('/api/containers');
    const tbody = document.getElementById('containers-tbody');
    if (!tbody || !containers) return;

    tbody.innerHTML = containers.map(c => `
        <tr>
            <td><strong>${esc(c.Names || 'N/A')}</strong></td>
            <td><code>${esc(c.Image || '')}</code></td>
            <td>${c.State === 'running'
                ? '<span class="badge badge-success">Running</span>'
                : '<span class="badge badge-danger">Stopped</span>'}</td>
            <td>${esc(c.Ports || '')}</td>
            <td>
                <div class="btn-group">
                    ${c.State === 'running'
                        ? `<button class="btn btn-danger btn-sm" onclick="containerAction('stop','${esc(c.Names)}')">Stop</button>
                           <button class="btn btn-warning btn-sm" onclick="containerAction('restart','${esc(c.Names)}')">Restart</button>`
                        : `<button class="btn btn-success btn-sm" onclick="containerAction('start','${esc(c.Names)}')">Start</button>`}
                    <button class="btn btn-outline btn-sm" onclick="containerLogs('${esc(c.Names)}')">Logs</button>
                </div>
            </td>
        </tr>
    `).join('');
}

async function containerAction(action, service) {
    addLog('info', `${action} ${service}...`);
    await apiPost(`/api/containers/${action}`, { service });
    setTimeout(refreshContainers, 2000);
}

async function containerLogs(service) {
    const data = await apiPost('/api/containers/logs', { service });
    if (data && data.stdout) {
        document.getElementById('container-logs-output').textContent = data.stdout;
        document.getElementById('container-logs-modal').style.display = 'block';
    }
}

function startAllContainers() {
    containerAction('start', '');
}

function stopAllContainers() {
    containerAction('stop', '');
}

// =====================================================
// Devices
// =====================================================

async function refreshDevices() {
    const devices = await api('/api/devices');
    const container = document.getElementById('devices-list');
    if (!container || !devices) return;

    if (devices.length === 0) {
        container.innerHTML = `
            <div class="card" style="text-align:center;padding:40px;">
                <p style="color:var(--text-secondary);">Aucun appareil connecte</p>
                <p style="font-size:13px;color:var(--text-secondary);margin-top:8px;">
                    Connectez un appareil via ADB (USB ou WiFi)
                </p>
            </div>`;
        return;
    }

    container.innerHTML = devices.map(d => `
        <div class="card">
            <div class="card-header">
                <span class="card-title">${esc(d.model || d.serial)}</span>
                <span class="badge badge-success">${esc(d.state)}</span>
            </div>
            <p style="font-family:var(--font-mono);font-size:13px;color:var(--text-secondary);">
                ${esc(d.serial)}
            </p>
            <div class="btn-group" style="margin-top:16px;">
                <button class="btn btn-primary btn-sm" onclick="loadPackages('${esc(d.serial)}')">Packages</button>
                <button class="btn btn-outline btn-sm" onclick="takeScreenshot('${esc(d.serial)}')">Screenshot</button>
            </div>
            <div id="packages-${esc(d.serial)}" style="margin-top:12px;"></div>
        </div>
    `).join('');
}

async function loadPackages(serial) {
    const packages = await api(`/api/devices/${serial}/packages`);
    const container = document.getElementById(`packages-${serial}`);
    if (!container || !packages) return;

    container.innerHTML = `
        <select class="form-select" id="pkg-select-${serial}" style="margin-bottom:8px;">
            ${packages.map(p => `<option value="${esc(p)}">${esc(p)}</option>`).join('')}
        </select>
        <div class="btn-group">
            <button class="btn btn-primary btn-sm" onclick="startAudit('${esc(serial)}')">Audit IPC</button>
            <button class="btn btn-warning btn-sm" onclick="startFrida('${esc(serial)}')">Frida Bypass</button>
        </div>
    `;
}

function takeScreenshot(serial) {
    window.open(`/api/devices/${serial}/screenshot`, '_blank');
}

function startAudit(serial) {
    const select = document.getElementById(`pkg-select-${serial}`);
    if (select) launchIpcAudit(select.value);
}

function startFrida(serial) {
    const select = document.getElementById(`pkg-select-${serial}`);
    if (select) launchFrida(select.value);
}

// =====================================================
// Audit
// =====================================================

async function launchIpcAudit(pkg) {
    if (!pkg) pkg = document.getElementById('audit-package-input').value;
    if (!pkg) return alert('Entrez un nom de package');

    addLog('info', `Lancement audit IPC: ${pkg}`);
    await apiPost('/api/audit/ipc', { package: pkg });
}

async function refreshReports() {
    const reports = await api('/api/audit/reports');
    const container = document.getElementById('reports-list');
    if (!container || !reports) return;

    if (reports.length === 0) {
        container.innerHTML = '<p style="color:var(--text-secondary);">Aucun rapport disponible</p>';
        return;
    }

    container.innerHTML = reports.map(r => `
        <div class="card">
            <div class="card-header">
                <span class="card-title">${esc(r.package)}</span>
                <span class="badge badge-info">${r.files.length} fichiers</span>
            </div>
            <div style="margin-top:8px;">
                ${r.files.map(f => `
                    <a href="/api/audit/reports/${esc(r.package)}/${esc(f)}"
                       target="_blank"
                       style="display:block;color:var(--accent);font-size:13px;font-family:var(--font-mono);padding:4px 0;">
                        ${esc(f)}
                    </a>
                `).join('')}
            </div>
        </div>
    `).join('');
}

// =====================================================
// Frida
// =====================================================

async function launchFrida(pkg) {
    if (!pkg) pkg = document.getElementById('frida-package-input').value;
    if (!pkg) return alert('Entrez un nom de package');

    addLog('info', `Frida SSL bypass: ${pkg}`);
    await apiPost('/api/frida/start', { package: pkg });
}

async function refreshFridaStatus() {
    const data = await api('/api/frida/status');
    if (data) {
        const el = document.getElementById('frida-status-badge');
        if (el) {
            el.innerHTML = data.active
                ? '<span class="badge badge-success">Active</span>'
                : '<span class="badge badge-danger">Inactive</span>';
        }
    }
}

// =====================================================
// Network
// =====================================================

async function toggleProxy() {
    const toggle = document.getElementById('toggle-proxy');
    const enable = toggle ? toggle.checked : false;
    await apiPost('/api/network/transparent', { enable });
    addLog('info', `Proxy transparent: ${enable ? 'ON' : 'OFF'}`);
}

// =====================================================
// MobSF Upload
// =====================================================

async function uploadApk() {
    const input = document.getElementById('apk-file-input');
    if (!input || !input.files.length) return alert('Selectionnez un fichier APK');

    const formData = new FormData();
    formData.append('file', input.files[0]);

    addLog('info', `Upload APK: ${input.files[0].name}`);
    const resp = await fetch('/api/mobsf/upload', { method: 'POST', body: formData });
    const data = await resp.json();
    addLog('info', `MobSF upload: ${data.status || 'done'}`);
}

// =====================================================
// Config
// =====================================================

const CONFIG_FIELDS = {
    text: ['listen_host', 'listen_port', 'web_host', 'web_port', 'stream_large_bodies'],
    select: ['connection_strategy'],
    checkbox: ['ssl_insecure', 'upstream_cert', 'http2', 'anticache', 'anticomp', 'showhost', 'web_open_browser'],
};

async function loadConfig() {
    const config = await api('/api/config/mitmproxy');
    if (!config) return;
    applyConfigToForm(config);
}

async function loadDefaultConfig() {
    const config = await api('/api/config/mitmproxy/default');
    if (!config) return;
    applyConfigToForm(config);
    showConfigStatus('Configuration par defaut chargee', 'info');
}

function applyConfigToForm(config) {
    for (const field of CONFIG_FIELDS.text) {
        const el = document.getElementById('cfg-' + field);
        if (el && config[field] !== undefined) el.value = config[field];
    }
    for (const field of CONFIG_FIELDS.select) {
        const el = document.getElementById('cfg-' + field);
        if (el && config[field] !== undefined) el.value = config[field];
    }
    for (const field of CONFIG_FIELDS.checkbox) {
        const el = document.getElementById('cfg-' + field);
        if (el && config[field] !== undefined) el.checked = config[field];
    }
}

async function saveConfig() {
    const config = {};
    for (const field of CONFIG_FIELDS.text) {
        const el = document.getElementById('cfg-' + field);
        if (el) {
            config[field] = el.type === 'number' ? parseInt(el.value, 10) : el.value;
        }
    }
    for (const field of CONFIG_FIELDS.select) {
        const el = document.getElementById('cfg-' + field);
        if (el) config[field] = el.value;
    }
    for (const field of CONFIG_FIELDS.checkbox) {
        const el = document.getElementById('cfg-' + field);
        if (el) config[field] = el.checked;
    }

    const result = await apiPost('/api/config/mitmproxy', config);
    if (result && result.status === 'saved') {
        showConfigStatus('Configuration sauvegardee. Redemarrez mitmproxy pour appliquer.', 'success');
    } else {
        showConfigStatus('Erreur: ' + (result?.error || 'Echec sauvegarde'), 'error');
    }
}

function showConfigStatus(msg, level) {
    const el = document.getElementById('config-status');
    if (!el) return;
    el.style.display = 'block';
    el.innerHTML = `<div class="badge badge-${level === 'success' ? 'success' : level === 'error' ? 'danger' : 'info'}">${esc(msg)}</div>`;
    setTimeout(() => { el.style.display = 'none'; }, 5000);
}

// =====================================================
// Logs (live streaming from all containers)
// =====================================================

let allContainerLogs = [];

async function refreshLogs() {
    const [appLogs, containerLogs] = await Promise.all([
        api('/api/logs?limit=100'),
        api('/api/container-logs'),
    ]);

    allContainerLogs = [];

    if (appLogs) {
        appLogs.forEach(l => {
            allContainerLogs.push({ ...l, source: 'app' });
        });
    }
    if (containerLogs) {
        containerLogs.forEach(l => {
            allContainerLogs.push({ ...l, source: l.container || 'unknown' });
        });
    }

    allContainerLogs.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
    renderFullLogs();
}

function setLogFilter(filter) {
    currentLogFilter = filter;
    document.querySelectorAll('.log-filter-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.filter === filter);
    });
    renderFullLogs();
}

function renderFullLogs() {
    const el = document.getElementById('log-console-full');
    if (!el) return;

    const filtered = allContainerLogs.filter(l => {
        if (currentLogFilter === 'all') return true;
        if (currentLogFilter === 'app') return l.source === 'app';
        return l.source === currentLogFilter;
    });

    el.innerHTML = filtered.map(l => {
        const time = l.timestamp ? l.timestamp.split('T')[1]?.split('.')[0] || '' : '';
        const cls = `log-${l.level || 'info'}`;
        const src = l.source && l.source !== 'app' ? `<span class="log-source">[${esc(l.source)}]</span> ` : '';
        return `<div class="log-entry"><span class="log-time">${time}</span>${src}<span class="${cls}">${esc(l.message)}</span></div>`;
    }).join('');

    if (document.getElementById('log-autoscroll')?.checked) {
        el.scrollTop = el.scrollHeight;
    }
}

function clearLogs() {
    allContainerLogs = [];
    const el = document.getElementById('log-console-full');
    if (el) el.innerHTML = '';
}

function addLog(level, message) {
    // Add to mini console on dashboard
    const el = document.getElementById('log-console');
    if (el) {
        const time = new Date().toTimeString().split(' ')[0];
        const cls = `log-${level}`;
        el.innerHTML += `<div class="log-entry"><span class="log-time">${time}</span><span class="${cls}">${esc(message)}</span></div>`;
        el.scrollTop = el.scrollHeight;
    }

    // Add to full log view if visible
    const entry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        source: 'app',
    };
    allContainerLogs.push(entry);

    const fullEl = document.getElementById('log-console-full');
    if (fullEl && (currentLogFilter === 'all' || currentLogFilter === 'app')) {
        const time = entry.timestamp.split('T')[1]?.split('.')[0] || '';
        fullEl.innerHTML += `<div class="log-entry"><span class="log-time">${time}</span><span class="log-${level}">${esc(message)}</span></div>`;
        if (document.getElementById('log-autoscroll')?.checked) {
            fullEl.scrollTop = fullEl.scrollHeight;
        }
    }
}

// =====================================================
// Topology Graph (Canvas)
// =====================================================

let topoData = null;

async function refreshTopology() {
    topoData = await api('/api/topology');
    if (topoData) drawTopology();
}

function drawTopology() {
    const canvas = document.getElementById('topology-canvas');
    if (!canvas || !topoData) return;

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    const W = rect.width;
    const H = rect.height;

    // Clear
    ctx.fillStyle = '#0a0e17';
    ctx.fillRect(0, 0, W, H);

    // Assign positions to nodes
    const positions = {};
    const nodes = topoData.nodes || [];
    const edges = topoData.edges || [];

    // Layout: infrastructure in a flow left-to-right, devices on top, intercepted at bottom
    const infraNodes = nodes.filter(n => ['infrastructure', 'container', 'tool'].includes(n.type));
    const deviceNodes = nodes.filter(n => n.type === 'device');
    const interceptedNodes = nodes.filter(n => n.type === 'intercepted');

    // Position infrastructure nodes in a flow
    const infraOrder = ['wifi_ap', 'host', 'iptables', 'mitmproxy', 'mobsf', 'frida'];
    const orderedInfra = [];
    for (const id of infraOrder) {
        const node = infraNodes.find(n => n.id === id);
        if (node) orderedInfra.push(node);
    }
    // Add any remaining infra nodes
    for (const node of infraNodes) {
        if (!orderedInfra.includes(node)) orderedInfra.push(node);
    }

    const infraY = H * 0.45;
    const infraSpacing = W / (orderedInfra.length + 1);
    orderedInfra.forEach((n, i) => {
        positions[n.id] = { x: infraSpacing * (i + 1), y: infraY };
    });

    // Devices above wifi_ap
    const wifiPos = positions['wifi_ap'] || { x: W * 0.15, y: infraY };
    deviceNodes.forEach((n, i) => {
        positions[n.id] = {
            x: wifiPos.x + (i - (deviceNodes.length - 1) / 2) * 120,
            y: infraY - 140,
        };
    });

    // Intercepted devices below mitmproxy
    const mitmPos = positions['mitmproxy'] || { x: W * 0.6, y: infraY };
    interceptedNodes.forEach((n, i) => {
        positions[n.id] = {
            x: mitmPos.x + (i - (interceptedNodes.length - 1) / 2) * 120,
            y: infraY + 160,
        };
    });

    // Draw edges
    for (const edge of edges) {
        const from = positions[edge.from];
        const to = positions[edge.to];
        if (!from || !to) continue;

        ctx.beginPath();
        ctx.strokeStyle = '#2a3a4e';
        ctx.lineWidth = 2;
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.stroke();

        // Arrow head
        const angle = Math.atan2(to.y - from.y, to.x - from.x);
        const arrowLen = 10;
        const midX = (from.x + to.x) / 2 + (to.x - from.x) * 0.15;
        const midY = (from.y + to.y) / 2 + (to.y - from.y) * 0.15;
        ctx.beginPath();
        ctx.fillStyle = '#4a5a6e';
        ctx.moveTo(midX, midY);
        ctx.lineTo(midX - arrowLen * Math.cos(angle - 0.4), midY - arrowLen * Math.sin(angle - 0.4));
        ctx.lineTo(midX - arrowLen * Math.cos(angle + 0.4), midY - arrowLen * Math.sin(angle + 0.4));
        ctx.closePath();
        ctx.fill();

        // Edge label
        if (edge.label || edge.speed) {
            const labelX = (from.x + to.x) / 2;
            const labelY = (from.y + to.y) / 2 - 10;
            ctx.font = '11px Inter, sans-serif';
            ctx.fillStyle = '#666';
            ctx.textAlign = 'center';
            const label = edge.speed ? `${edge.label || ''} (${edge.speed})` : edge.label;
            ctx.fillText(label, labelX, labelY);
        }
    }

    // Draw nodes
    for (const node of nodes) {
        const pos = positions[node.id];
        if (!pos) continue;

        const statusColors = {
            healthy: '#10b981',
            error: '#ef4444',
            warning: '#f59e0b',
            inactive: '#666',
            stopped: '#666',
        };
        const color = statusColors[node.status] || '#666';
        const radius = node.type === 'device' || node.type === 'intercepted' ? 28 : 34;

        // Glow for errors
        if (node.status === 'error') {
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, radius + 8, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(239, 68, 68, 0.15)';
            ctx.fill();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
        ctx.fillStyle = '#1a2332';
        ctx.fill();
        ctx.strokeStyle = color;
        ctx.lineWidth = 3;
        ctx.stroke();

        // Icon text
        ctx.fillStyle = color;
        ctx.font = 'bold 14px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        const icons = {
            wifi_ap: 'WiFi',
            host: 'HOST',
            iptables: 'NAT',
            mitmproxy: 'MITM',
            mobsf: 'MOBSF',
            frida: 'FRIDA',
        };
        const iconText = icons[node.id] || (node.type === 'device' ? 'DEV' : node.type === 'intercepted' ? 'INT' : '?');
        ctx.fillText(iconText, pos.x, pos.y);

        // Label below
        ctx.font = '12px Inter, sans-serif';
        ctx.fillStyle = '#e2e8f0';
        ctx.fillText(node.label, pos.x, pos.y + radius + 16);

        // Details
        if (node.details) {
            ctx.font = '10px JetBrains Mono, monospace';
            ctx.fillStyle = '#94a3b8';
            ctx.fillText(node.details, pos.x, pos.y + radius + 30);
        }

        // Status dot
        ctx.beginPath();
        ctx.arc(pos.x + radius - 4, pos.y - radius + 4, 5, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
    }
}

// =====================================================
// High Level View + Probes
// =====================================================

let probesData = null;
let hlInterval = null;

function startHighLevelLive() {
    refreshHighLevel();
    if (hlInterval) clearInterval(hlInterval);
    hlInterval = setInterval(refreshHighLevel, 5000);
}

function stopHighLevelLive() {
    if (hlInterval) { clearInterval(hlInterval); hlInterval = null; }
}

async function refreshHighLevel() {
    probesData = await api('/api/probes');
    if (!probesData) return;
    document.getElementById('hl-last-update').textContent =
        'Maj: ' + new Date().toLocaleTimeString();
    renderProbesTable();
    refreshTopology();
}

async function refreshProbesSummary() {
    const data = await api('/api/probes');
    if (!data) return;
    probesData = data;
    const el = document.getElementById('probes-summary');
    if (!el) return;

    const entities = Object.entries(data.entities);
    el.innerHTML = entities.map(([key, e]) => {
        const statusColors = { ok: 'success', error: 'danger', warning: 'warning', inactive: 'info' };
        const badge = statusColors[e.status] || 'info';
        const req = e.required ? '<span style="color:var(--accent);font-size:10px;">REQUIS</span>' : '<span style="color:#666;font-size:10px;">OPT</span>';
        return `<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 10px;border:1px solid var(--border);border-radius:8px;background:var(--bg-primary);">
            <div style="display:flex;align-items:center;gap:8px;">
                <span class="topo-legend-dot" style="background:var(--${badge});"></span>
                <span style="font-size:12px;font-weight:600;">${esc(e.label)}</span>
            </div>
            <div style="display:flex;align-items:center;gap:6px;">
                ${req}
                <span class="badge badge-${badge}" style="font-size:10px;padding:2px 6px;">${esc(e.status)}</span>
                ${e.auth ? `<span class="badge badge-${e.auth === 'ok' ? 'success' : 'danger'}" style="font-size:9px;padding:1px 5px;">AUTH</span>` : ''}
            </div>
        </div>`;
    }).join('');
}

function renderProbesTable() {
    const tbody = document.getElementById('probes-tbody');
    if (!tbody || !probesData) return;

    const entities = Object.entries(probesData.entities);
    tbody.innerHTML = entities.map(([key, e]) => {
        const statusColors = { ok: 'success', error: 'danger', warning: 'warning', inactive: 'info' };
        const badge = statusColors[e.status] || 'info';
        const authBadge = e.auth
            ? `<span class="badge badge-${e.auth === 'ok' ? 'success' : 'danger'}">${e.auth === 'ok' ? 'OK' : 'FAIL'}</span>`
            : '<span style="color:#555;">-</span>';
        return `<tr>
            <td><strong>${esc(e.label)}</strong></td>
            <td><span style="font-size:12px;color:var(--text-secondary);">${esc(e.category)}</span></td>
            <td>${e.required
                ? '<span class="badge badge-info">Obligatoire</span>'
                : '<span style="color:#666;font-size:12px;">Optionnel</span>'}</td>
            <td><span class="badge badge-${badge}">${esc(e.status)}</span></td>
            <td>${authBadge}</td>
            <td><code style="font-size:11px;">${e.latency_ms || 0}ms</code></td>
            <td style="font-size:12px;color:var(--text-secondary);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(e.detail || '')}</td>
        </tr>`;
    }).join('');
}

// =====================================================
// Cartography - Business Process Maps
// =====================================================

let cartoData = null;
let cartoInterval = null;

async function refreshCartography() {
    cartoData = await api('/api/cartography');
    if (!cartoData) return;
    document.getElementById('carto-last-update').textContent =
        'Maj: ' + new Date().toLocaleTimeString();
    drawBP1();
    drawBP2();
    drawBP3();
    drawBP4();
}

function startCartoLive() {
    refreshCartography();
    if (cartoInterval) clearInterval(cartoInterval);
    cartoInterval = setInterval(refreshCartography, 5000);
}

function stopCartoLive() {
    if (cartoInterval) { clearInterval(cartoInterval); cartoInterval = null; }
}

// --- Generic drawing helpers ---

function initCartoCanvas(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.fillStyle = '#080c14';
    ctx.fillRect(0, 0, rect.width, rect.height);
    return { ctx, W: rect.width, H: rect.height };
}

const CARTO_COLORS = {
    input: '#3b82f6',
    process: '#06b6d4',
    output: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
    inactive: '#555',
    bg: '#131a28',
    border: '#2a3a4e',
    text: '#e2e8f0',
    textDim: '#94a3b8',
};

function drawCartoNode(ctx, x, y, w, h, label, sublabel, type, status, opts = {}) {
    const colors = {
        input: CARTO_COLORS.input,
        process: CARTO_COLORS.process,
        output: CARTO_COLORS.output,
    };
    let borderColor = colors[type] || CARTO_COLORS.process;
    if (status === 'error') borderColor = CARTO_COLORS.error;
    else if (status === 'warning') borderColor = CARTO_COLORS.warning;
    else if (status === 'inactive') borderColor = CARTO_COLORS.inactive;

    // Glow for errors
    if (status === 'error') {
        ctx.shadowColor = 'rgba(239,68,68,0.4)';
        ctx.shadowBlur = 16;
    } else if (status === 'warning') {
        ctx.shadowColor = 'rgba(245,158,11,0.3)';
        ctx.shadowBlur = 10;
    }

    // Box
    const r = 10;
    ctx.beginPath();
    ctx.roundRect(x - w/2, y - h/2, w, h, r);
    ctx.fillStyle = CARTO_COLORS.bg;
    ctx.fill();
    // Mandatory = solid thick border, Optional = dashed thinner
    if (opts.required === false) {
        ctx.setLineDash([5, 3]);
        ctx.lineWidth = 1.5;
    } else {
        ctx.setLineDash([]);
        ctx.lineWidth = 3;
    }
    ctx.strokeStyle = borderColor;
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.shadowBlur = 0;

    // Status indicator dot
    const dotR = 5;
    ctx.beginPath();
    ctx.arc(x + w/2 - 12, y - h/2 + 12, dotR, 0, Math.PI * 2);
    ctx.fillStyle = borderColor;
    ctx.fill();

    // Required/optional badge top-right
    if (opts.required !== undefined) {
        ctx.font = 'bold 8px Inter, sans-serif';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'top';
        ctx.fillStyle = opts.required ? CARTO_COLORS.process : '#555';
        ctx.fillText(opts.required ? 'REQ' : 'OPT', x + w/2 - 22, y - h/2 + 6);
    }

    // Auth badge if applicable
    if (opts.auth) {
        const authOk = opts.auth === 'ok';
        ctx.font = 'bold 8px Inter, sans-serif';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'top';
        ctx.fillStyle = authOk ? CARTO_COLORS.output : CARTO_COLORS.error;
        ctx.fillText(authOk ? 'AUTH OK' : 'AUTH FAIL', x - w/2 + 10, y + h/2 - 14);
    }

    // Type label top-left
    ctx.font = 'bold 9px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillStyle = borderColor;
    const typeLabels = { input: 'INPUT', process: 'PROCESS', output: 'OUTPUT' };
    ctx.fillText(typeLabels[type] || 'NODE', x - w/2 + 10, y - h/2 + 6);

    // Probe latency
    if (opts.latency_ms !== undefined) {
        ctx.font = '8px JetBrains Mono, monospace';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'bottom';
        ctx.fillStyle = opts.latency_ms > 500 ? CARTO_COLORS.warning : CARTO_COLORS.textDim;
        ctx.fillText(opts.latency_ms + 'ms', x + w/2 - 8, y + h/2 - 4);
    }

    // Main label
    ctx.font = 'bold 13px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = CARTO_COLORS.text;
    ctx.fillText(label, x, y - 4);

    // Sublabel
    if (sublabel) {
        ctx.font = '10px JetBrains Mono, monospace';
        ctx.fillStyle = CARTO_COLORS.textDim;
        ctx.fillText(sublabel, x, y + 14);
    }
}

function drawCartoArrow(ctx, x1, y1, x2, y2, label, status) {
    let color = CARTO_COLORS.border;
    let dash = [];
    if (status === 'active') color = CARTO_COLORS.process;
    else if (status === 'error') { color = CARTO_COLORS.error; dash = [6, 4]; }
    else if (status === 'warning') { color = CARTO_COLORS.warning; dash = [4, 3]; }
    else if (status === 'success') color = CARTO_COLORS.output;

    ctx.save();
    ctx.setLineDash(dash);
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.stroke();
    ctx.setLineDash([]);

    // Arrow head
    const angle = Math.atan2(y2 - y1, x2 - x1);
    const aLen = 10;
    ctx.beginPath();
    ctx.fillStyle = color;
    ctx.moveTo(x2, y2);
    ctx.lineTo(x2 - aLen * Math.cos(angle - 0.35), y2 - aLen * Math.sin(angle - 0.35));
    ctx.lineTo(x2 - aLen * Math.cos(angle + 0.35), y2 - aLen * Math.sin(angle + 0.35));
    ctx.closePath();
    ctx.fill();

    // Label
    if (label) {
        const mx = (x1 + x2) / 2;
        const my = (y1 + y2) / 2 - 10;
        ctx.font = '10px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillStyle = color;
        ctx.fillText(label, mx, my);
    }
    ctx.restore();
}

function drawCartoWarningBadge(ctx, x, y, count) {
    if (!count) return;
    ctx.beginPath();
    ctx.arc(x, y, 11, 0, Math.PI * 2);
    ctx.fillStyle = count > 5 ? CARTO_COLORS.error : CARTO_COLORS.warning;
    ctx.fill();
    ctx.font = 'bold 9px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#000';
    ctx.fillText(count > 99 ? '99+' : String(count), x, y);
}

// --- BP1: Interception Reseau ---

function drawBP1() {
    const r = initCartoCanvas('carto-bp1');
    if (!r) return;
    const { ctx, W, H } = r;
    const d = cartoData.bp1_network;
    const p = cartoData.probes || {};
    const nw = 140, nh = 70;
    const cy = H * 0.45;

    const nodes = [
        { x: W*0.08, y: cy, label: 'Android Device', sub: d.device_count + ' connecte(s)', type: 'input', status: d.device_count > 0 ? 'ok' : 'inactive', required: false, probe: 'adb_devices' },
        { x: W*0.24, y: cy, label: 'WiFi AP', sub: d.wifi_ok ? 'Actif' : 'Non detecte', type: 'process', status: d.wifi_ok ? 'ok' : 'error', required: false, probe: 'wifi_ap' },
        { x: W*0.40, y: cy, label: 'NSAC Host', sub: 'IP Fwd: ' + (d.ip_forward ? 'ON' : 'OFF'), type: 'process', status: d.ip_forward ? 'ok' : 'warning', required: true, probe: 'ip_forwarding' },
        { x: W*0.56, y: cy, label: 'iptables NAT', sub: d.iptables_active ? 'PREROUTING :8080' : 'Inactif', type: 'process', status: d.iptables_active ? 'ok' : 'inactive', required: true, probe: 'iptables' },
        { x: W*0.74, y: cy, label: 'Mitmproxy', sub: d.flow_count + ' flows', type: 'process', status: d.mitmproxy_error ? 'error' : (d.mitmproxy_running ? 'ok' : 'inactive'), required: true, probe: 'mitmproxy', auth: d.mitmproxy_auth },
        { x: W*0.92, y: cy, label: 'Internet', sub: d.intercepted_hosts.slice(0,2).join(', ') || 'Aucun host', type: 'output', status: d.flow_count > 0 ? 'ok' : 'inactive', required: false },
    ];

    // Arrows
    const labels = ['WiFi 802.11', 'Ethernet/Bridge', 'NAT Redirect', 'TCP :8080', 'HTTPS'];
    for (let i = 0; i < nodes.length - 1; i++) {
        const from = nodes[i], to = nodes[i + 1];
        const fromOk = from.status !== 'inactive' && from.status !== 'error';
        const toOk = to.status !== 'inactive' && to.status !== 'error';
        let arrowStatus = (fromOk && toOk) ? 'active' : (from.status === 'error' || to.status === 'error') ? 'error' : 'inactive';
        drawCartoArrow(ctx, from.x + nw/2, from.y, to.x - nw/2, to.y, labels[i], arrowStatus);
    }

    for (const n of nodes) {
        const probeInfo = n.probe && p[n.probe] ? p[n.probe] : {};
        drawCartoNode(ctx, n.x, n.y, nw, nh, n.label, n.sub, n.type, n.status === 'ok' ? null : n.status, {
            required: n.required, auth: n.auth, latency_ms: probeInfo.latency_ms,
        });
    }

    const bpOk = d.mitmproxy_running && d.iptables_active;
    const el = document.getElementById('bp1-status');
    if (el) {
        el.className = 'badge ' + (bpOk ? 'badge-success' : d.mitmproxy_error ? 'badge-danger' : 'badge-warning');
        el.textContent = bpOk ? 'Operationnel' : d.mitmproxy_error ? 'Erreur' : 'Partiel';
    }
}

// --- BP2: Analyse Statique MobSF ---

function drawBP2() {
    const r = initCartoCanvas('carto-bp2');
    if (!r) return;
    const { ctx, W, H } = r;
    const d = cartoData.bp2_mobsf;
    const p = cartoData.probes || {};
    const nw = 140, nh = 70;
    const cy = H * 0.5;

    const nodes = [
        { x: W*0.10, y: cy, label: 'APK / IPA File', sub: 'Upload utilisateur', type: 'input', status: 'ok', required: true },
        { x: W*0.28, y: cy, label: 'NSAC Upload', sub: 'POST /api/mobsf/upload', type: 'process', status: 'ok', required: true, probe: 'nsac_host' },
        { x: W*0.46, y: cy, label: 'MobSF Engine', sub: d.mobsf_running ? 'Running :8000' : 'Stopped', type: 'process', status: d.mobsf_error ? 'error' : (d.mobsf_running ? 'ok' : 'inactive'), required: true, probe: 'mobsf', auth: d.mobsf_auth },
        { x: W*0.64, y: cy, label: 'Static Analysis', sub: 'Decompile + Scan', type: 'process', status: d.mobsf_running ? 'ok' : 'inactive', required: true },
        { x: W*0.82, y: cy, label: 'Security Report', sub: d.report_count + ' rapport(s)', type: 'output', status: d.report_count > 0 ? 'ok' : 'inactive', required: true },
    ];

    const mitmNode = { x: W*0.46, y: cy - 100, label: 'Mitmproxy', sub: 'Dynamic Analysis', type: 'process', status: d.mitmproxy_running ? 'ok' : 'inactive', required: false, probe: 'mitmproxy' };

    const labels = ['HTTP POST', 'REST API', 'Decompile + Rules', 'PDF / JSON'];
    for (let i = 0; i < nodes.length - 1; i++) {
        const fromOk = nodes[i].status !== 'inactive' && nodes[i].status !== 'error';
        const toOk = nodes[i+1].status !== 'inactive' && nodes[i+1].status !== 'error';
        drawCartoArrow(ctx, nodes[i].x + nw/2, nodes[i].y, nodes[i+1].x - nw/2, nodes[i+1].y, labels[i],
            (fromOk && toOk) ? 'active' : nodes[i+1].status === 'error' ? 'error' : 'inactive');
    }

    drawCartoArrow(ctx, mitmNode.x, mitmNode.y + nh/2, nodes[2].x, nodes[2].y - nh/2, 'Traffic data', d.mitmproxy_running ? 'active' : 'inactive');

    const mitmProbe = p['mitmproxy'] || {};
    drawCartoNode(ctx, mitmNode.x, mitmNode.y, nw, nh, mitmNode.label, mitmNode.sub, mitmNode.type, mitmNode.status === 'ok' ? null : mitmNode.status, { required: false, latency_ms: mitmProbe.latency_ms });
    for (const n of nodes) {
        const probeInfo = n.probe && p[n.probe] ? p[n.probe] : {};
        drawCartoNode(ctx, n.x, n.y, nw, nh, n.label, n.sub, n.type, n.status === 'ok' ? null : n.status, {
            required: n.required, auth: n.auth, latency_ms: probeInfo.latency_ms,
        });
    }
    drawCartoWarningBadge(ctx, nodes[2].x + nw/2 - 4, nodes[2].y - nh/2 - 4, d.warnings);

    const el = document.getElementById('bp2-status');
    if (el) {
        const ok = d.mobsf_running;
        el.className = 'badge ' + (ok ? 'badge-success' : d.mobsf_error ? 'badge-danger' : 'badge-warning');
        el.textContent = ok ? 'Operationnel' : d.mobsf_error ? 'Erreur' : 'MobSF Arrete';
    }
}

// --- BP3: SSL Bypass Frida ---

function drawBP3() {
    const r = initCartoCanvas('carto-bp3');
    if (!r) return;
    const { ctx, W, H } = r;
    const d = cartoData.bp3_frida;
    const p = cartoData.probes || {};
    const nw = 140, nh = 70;
    const cy = H * 0.4;

    const nodes = [
        { x: W*0.08, y: cy, label: 'Android Target', sub: d.device_count + ' device(s)', type: 'input', status: d.device_count > 0 ? 'ok' : 'inactive', required: true, probe: 'adb_devices' },
        { x: W*0.24, y: cy, label: 'ADB Bridge', sub: d.adb_ok ? 'Disponible' : 'Non installe', type: 'process', status: d.adb_ok ? 'ok' : 'error', required: true, probe: 'adb_server' },
        { x: W*0.40, y: cy, label: 'Frida Server', sub: d.frida_installed ? (d.frida_active ? 'Injecting' : 'Pret') : 'Non installe', type: 'process', status: d.frida_active ? 'ok' : (d.frida_installed ? 'warning' : 'inactive'), required: true, probe: 'frida_server' },
        { x: W*0.56, y: cy, label: 'SSL Hook', sub: 'SSLContext, OkHttp3', type: 'process', status: d.frida_active ? 'ok' : 'inactive', required: true },
        { x: W*0.74, y: cy, label: 'Unpinned Traffic', sub: 'Bypass active', type: 'output', status: d.frida_active ? 'ok' : 'inactive', required: true },
        { x: W*0.92, y: cy, label: 'Mitmproxy', sub: d.flow_count + ' flows', type: 'output', status: d.mitmproxy_running ? 'ok' : 'inactive', required: false, probe: 'mitmproxy' },
    ];

    const hooks = [
        { x: W*0.30, y: cy + 100, label: 'TrustManager', status: d.frida_active ? 'ok' : 'inactive' },
        { x: W*0.46, y: cy + 100, label: 'Conscrypt', status: d.frida_active ? 'ok' : 'inactive' },
        { x: W*0.62, y: cy + 100, label: 'WebView SSL', status: d.frida_active ? 'ok' : 'inactive' },
    ];

    const labels = ['adb forward', 'frida -U -f', 'JS Injection', 'Cleartext', 'Intercepted'];
    for (let i = 0; i < nodes.length - 1; i++) {
        const fromOk = nodes[i].status !== 'inactive' && nodes[i].status !== 'error';
        const toOk = nodes[i+1].status !== 'inactive' && nodes[i+1].status !== 'error';
        drawCartoArrow(ctx, nodes[i].x + nw/2, nodes[i].y, nodes[i+1].x - nw/2, nodes[i+1].y, labels[i],
            (fromOk && toOk) ? 'active' : 'inactive');
    }

    for (const hook of hooks) {
        drawCartoArrow(ctx, nodes[3].x, nodes[3].y + nh/2, hook.x, hook.y - 20, '', hook.status === 'ok' ? 'success' : 'inactive');
        ctx.beginPath();
        ctx.roundRect(hook.x - 55, hook.y - 18, 110, 36, 6);
        ctx.fillStyle = CARTO_COLORS.bg;
        ctx.fill();
        ctx.setLineDash([4, 3]);
        ctx.strokeStyle = hook.status === 'ok' ? CARTO_COLORS.output : CARTO_COLORS.inactive;
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.font = '11px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = hook.status === 'ok' ? CARTO_COLORS.output : CARTO_COLORS.textDim;
        ctx.fillText(hook.label, hook.x, hook.y);
    }

    for (const n of nodes) {
        const probeInfo = n.probe && p[n.probe] ? p[n.probe] : {};
        drawCartoNode(ctx, n.x, n.y, nw, nh, n.label, n.sub, n.type, n.status === 'ok' ? null : n.status, {
            required: n.required, latency_ms: probeInfo.latency_ms,
        });
    }

    const el = document.getElementById('bp3-status');
    if (el) {
        el.className = 'badge ' + (d.frida_active ? 'badge-success' : d.frida_installed ? 'badge-warning' : 'badge-danger');
        el.textContent = d.frida_active ? 'Injection Active' : d.frida_installed ? 'Pret' : 'Non installe';
    }
}

// --- BP4: Audit IPC ---

function drawBP4() {
    const r = initCartoCanvas('carto-bp4');
    if (!r) return;
    const { ctx, W, H } = r;
    const d = cartoData.bp4_audit;
    const p = cartoData.probes || {};
    const nw = 140, nh = 70;
    const cy = H * 0.38;

    const nodes = [
        { x: W*0.08, y: cy, label: 'Target Package', sub: 'com.example.app', type: 'input', status: d.device_count > 0 ? 'ok' : 'inactive', required: true, probe: 'adb_devices' },
        { x: W*0.26, y: cy, label: 'ADB Shell', sub: 'dumpsys + pm', type: 'process', status: d.adb_ok ? 'ok' : 'error', required: true, probe: 'adb_server' },
        { x: W*0.44, y: cy, label: 'audit_ipc.sh', sub: 'Script analyse', type: 'process', status: 'ok', required: true },
        { x: W*0.62, y: cy, label: 'IPC Scanner', sub: 'Activity/Service/BR/CP', type: 'process', status: 'ok', required: true },
        { x: W*0.82, y: cy, label: 'Audit Report', sub: d.report_count + ' fichier(s)', type: 'output', status: d.report_count > 0 ? 'ok' : 'inactive', required: true },
    ];

    // Optional: Frida for runtime hooks
    const fridaNode = { x: W*0.82, y: cy - 100, label: 'Frida (Runtime)', sub: d.frida_active ? 'Actif' : 'Inactif', type: 'process', status: d.frida_active ? 'ok' : 'inactive', required: false, probe: 'frida_server' };

    const ipcTypes = [
        { x: W*0.30, y: cy + 100, label: 'Activities', icon: 'exported' },
        { x: W*0.46, y: cy + 100, label: 'Services', icon: 'bound/started' },
        { x: W*0.62, y: cy + 100, label: 'Broadcast Recv', icon: 'intent-filter' },
        { x: W*0.78, y: cy + 100, label: 'Content Prov', icon: 'URI exposed' },
    ];

    const labels = ['adb -s <serial>', 'Shell exec', 'Parse manifest', 'Generate'];
    for (let i = 0; i < nodes.length - 1; i++) {
        const fromOk = nodes[i].status !== 'inactive' && nodes[i].status !== 'error';
        const toOk = nodes[i+1].status !== 'inactive' && nodes[i+1].status !== 'error';
        drawCartoArrow(ctx, nodes[i].x + nw/2, nodes[i].y, nodes[i+1].x - nw/2, nodes[i+1].y, labels[i],
            (fromOk && toOk) ? 'active' : 'inactive');
    }

    // Frida link
    drawCartoArrow(ctx, fridaNode.x, fridaNode.y + nh/2, nodes[4].x, nodes[4].y - nh/2, 'Runtime hooks', d.frida_active ? 'success' : 'inactive');

    for (const ipc of ipcTypes) {
        drawCartoArrow(ctx, nodes[3].x, nodes[3].y + nh/2, ipc.x, ipc.y - 22, '', 'active');
        ctx.beginPath();
        ctx.roundRect(ipc.x - 55, ipc.y - 20, 110, 40, 6);
        ctx.fillStyle = CARTO_COLORS.bg;
        ctx.fill();
        ctx.strokeStyle = CARTO_COLORS.warning;
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.font = 'bold 11px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = CARTO_COLORS.warning;
        ctx.fillText(ipc.label, ipc.x, ipc.y - 4);
        ctx.font = '9px JetBrains Mono, monospace';
        ctx.fillStyle = CARTO_COLORS.textDim;
        ctx.fillText(ipc.icon, ipc.x, ipc.y + 10);
    }

    // Frida optional node
    const fridaProbe = p['frida_server'] || {};
    drawCartoNode(ctx, fridaNode.x, fridaNode.y, nw, nh, fridaNode.label, fridaNode.sub, fridaNode.type, fridaNode.status === 'ok' ? null : fridaNode.status, { required: false, latency_ms: fridaProbe.latency_ms });

    for (const n of nodes) {
        const probeInfo = n.probe && p[n.probe] ? p[n.probe] : {};
        drawCartoNode(ctx, n.x, n.y, nw, nh, n.label, n.sub, n.type, n.status === 'ok' ? null : n.status, {
            required: n.required, latency_ms: probeInfo.latency_ms,
        });
    }

    drawCartoWarningBadge(ctx, nodes[4].x + nw/2 - 4, nodes[4].y - nh/2 - 4, d.recent_errors);

    const el = document.getElementById('bp4-status');
    if (el) {
        el.className = 'badge ' + (d.report_count > 0 ? 'badge-success' : 'badge-warning');
        el.textContent = d.report_count > 0 ? d.report_count + ' Rapports' : 'Aucun rapport';
    }
}

// =====================================================
// Cleanup
// =====================================================

async function cleanupLab() {
    if (!confirm('Arreter tous les services et nettoyer le lab ?')) return;
    addLog('warn', 'Nettoyage du lab...');
    await apiPost('/api/cleanup');
    setTimeout(refreshDashboard, 3000);
}

// =====================================================
// Helpers
// =====================================================

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function setToggle(id, checked) {
    const el = document.getElementById(id);
    if (el) el.checked = checked;
}

function esc(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

// =====================================================
// WebSocket
// =====================================================

function initSocket() {
    socket = io();

    socket.on('connect', () => {
        addLog('success', 'WebSocket connecte');
        const dot = document.getElementById('ws-status');
        if (dot) { dot.classList.add('online'); dot.classList.remove('offline'); }
    });

    socket.on('disconnect', () => {
        const dot = document.getElementById('ws-status');
        if (dot) { dot.classList.remove('online'); dot.classList.add('offline'); }
    });

    socket.on('log', (data) => {
        addLog(data.level, data.message);
    });

    socket.on('container_log', (data) => {
        const entry = {
            timestamp: data.timestamp,
            level: data.level,
            message: data.message,
            source: data.container || 'unknown',
        };
        allContainerLogs.push(entry);
        // Keep size manageable
        if (allContainerLogs.length > 1000) {
            allContainerLogs = allContainerLogs.slice(-500);
        }

        // Update full log view if on logs page and filter matches
        const fullEl = document.getElementById('log-console-full');
        if (fullEl && (currentLogFilter === 'all' || currentLogFilter === entry.source)) {
            const activePage = document.querySelector('.page.active');
            if (activePage && activePage.id === 'page-logs') {
                const time = entry.timestamp?.split('T')[1]?.split('.')[0] || '';
                const src = `<span class="log-source">[${esc(entry.source)}]</span> `;
                fullEl.innerHTML += `<div class="log-entry"><span class="log-time">${time}</span>${src}<span class="log-${entry.level}">${esc(entry.message)}</span></div>`;
                if (document.getElementById('log-autoscroll')?.checked) {
                    fullEl.scrollTop = fullEl.scrollHeight;
                }
            }
        }

        // If error, mark node red on topology if visible
        if (data.level === 'error') {
            addLog('error', `[${data.container}] ${data.message}`);
        }
    });

    socket.on('audit_complete', (data) => {
        addLog('success', `Audit ${data.type} termine: ${data.package}`);
        refreshReports();
    });

    socket.on('frida_status', (data) => {
        refreshFridaStatus();
    });
}

// =====================================================
// Init
// =====================================================

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => navigate(item.dataset.page));
    });

    initSocket();
    navigate('dashboard');

    // Auto-refresh
    setInterval(() => {
        const activePage = document.querySelector('.page.active');
        if (activePage) {
            if (activePage.id === 'page-dashboard') refreshDashboard();
        }
    }, 15000);

    // Handle canvas resize
    window.addEventListener('resize', () => {
        if (topoData) drawTopology();
        if (cartoData) { drawBP1(); drawBP2(); drawBP3(); drawBP4(); }
    });
});
