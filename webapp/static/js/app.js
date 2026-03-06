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

    const refreshMap = {
        'dashboard': refreshDashboard,
        'containers': refreshContainers,
        'devices': refreshDevices,
        'audit': refreshReports,
        'logs': refreshLogs,
        'topology': refreshTopology,
        'config': loadConfig,
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
    text: ['listen_host', 'listen_port', 'web_host', 'web_port', 'web_password', 'stream_large_bodies'],
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
            if (activePage.id === 'page-topology') refreshTopology();
        }
    }, 15000);

    // Handle canvas resize
    window.addEventListener('resize', () => {
        if (topoData) drawTopology();
    });
});
