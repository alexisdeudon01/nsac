/**
 * NSAC - Network Security Audit Console
 * Frontend JavaScript
 */

const API = '';
let socket = null;

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

    // Auto-refresh on page load
    const refreshMap = {
        'dashboard': refreshDashboard,
        'containers': refreshContainers,
        'devices': refreshDevices,
        'audit': refreshReports,
        'logs': refreshLogs,
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

    // Stats
    const running = containers ? containers.filter(c => c.State === 'running').length : 0;
    setText('stat-containers', running);
    setText('stat-devices', devices ? devices.length : 0);
    setText('stat-reports', reports ? reports.length : 0);

    // Service statuses
    updateServiceStatus('mobsf-status', containers, 'mobsf');
    updateServiceStatus('mitmproxy-status', containers, 'mitmproxy');

    // Network status
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
            <td><strong>${c.Names || 'N/A'}</strong></td>
            <td><code>${c.Image || ''}</code></td>
            <td>${c.State === 'running'
                ? '<span class="badge badge-success">Running</span>'
                : '<span class="badge badge-danger">Stopped</span>'}</td>
            <td>${c.Ports || ''}</td>
            <td>
                <div class="btn-group">
                    ${c.State === 'running'
                        ? `<button class="btn btn-danger btn-sm" onclick="containerAction('stop','${c.Names}')">Stop</button>
                           <button class="btn btn-warning btn-sm" onclick="containerAction('restart','${c.Names}')">Restart</button>`
                        : `<button class="btn btn-success btn-sm" onclick="containerAction('start','${c.Names}')">Start</button>`}
                    <button class="btn btn-outline btn-sm" onclick="containerLogs('${c.Names}')">Logs</button>
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
                <span class="card-title">${d.model || d.serial}</span>
                <span class="badge badge-success">${d.state}</span>
            </div>
            <p style="font-family:var(--font-mono);font-size:13px;color:var(--text-secondary);">
                ${d.serial}
            </p>
            <div class="btn-group" style="margin-top:16px;">
                <button class="btn btn-primary btn-sm" onclick="loadPackages('${d.serial}')">Packages</button>
                <button class="btn btn-outline btn-sm" onclick="takeScreenshot('${d.serial}')">Screenshot</button>
            </div>
            <div id="packages-${d.serial}" style="margin-top:12px;"></div>
        </div>
    `).join('');
}

async function loadPackages(serial) {
    const packages = await api(`/api/devices/${serial}/packages`);
    const container = document.getElementById(`packages-${serial}`);
    if (!container || !packages) return;

    container.innerHTML = `
        <select class="form-select" id="pkg-select-${serial}" style="margin-bottom:8px;">
            ${packages.map(p => `<option value="${p}">${p}</option>`).join('')}
        </select>
        <div class="btn-group">
            <button class="btn btn-primary btn-sm" onclick="startAudit('${serial}')">Audit IPC</button>
            <button class="btn btn-warning btn-sm" onclick="startFrida('${serial}')">Frida Bypass</button>
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
                <span class="card-title">${r.package}</span>
                <span class="badge badge-info">${r.files.length} fichiers</span>
            </div>
            <div style="margin-top:8px;">
                ${r.files.map(f => `
                    <a href="/api/audit/reports/${r.package}/${f}"
                       target="_blank"
                       style="display:block;color:var(--accent);font-size:13px;font-family:var(--font-mono);padding:4px 0;">
                        ${f}
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
// Logs
// =====================================================

async function refreshLogs() {
    const data = await api('/api/logs?limit=100');
    if (data) renderLogs(data);
}

function renderLogs(logs) {
    const el = document.getElementById('log-console');
    if (!el) return;

    el.innerHTML = logs.map(l => {
        const time = l.timestamp ? l.timestamp.split('T')[1].split('.')[0] : '';
        const cls = `log-${l.level || 'info'}`;
        return `<div class="log-entry"><span class="log-time">${time}</span><span class="${cls}">${l.message}</span></div>`;
    }).join('');

    el.scrollTop = el.scrollHeight;
}

function addLog(level, message) {
    const el = document.getElementById('log-console');
    if (!el) return;
    const time = new Date().toTimeString().split(' ')[0];
    const cls = `log-${level}`;
    el.innerHTML += `<div class="log-entry"><span class="log-time">${time}</span><span class="${cls}">${message}</span></div>`;
    el.scrollTop = el.scrollHeight;
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

// =====================================================
// WebSocket
// =====================================================

function initSocket() {
    socket = io();

    socket.on('connect', () => {
        addLog('success', 'WebSocket connecte');
    });

    socket.on('log', (data) => {
        addLog(data.level, data.message);
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
    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => navigate(item.dataset.page));
    });

    initSocket();
    navigate('dashboard');

    // Auto-refresh every 15s
    setInterval(() => {
        const activePage = document.querySelector('.page.active');
        if (activePage && activePage.id === 'page-dashboard') {
            refreshDashboard();
        }
    }, 15000);
});
