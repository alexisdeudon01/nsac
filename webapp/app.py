#!/usr/bin/env python3
"""
NSAC - Network Security Audit Console
Web app pour controler le lab d'audit Android.
"""

import json
import os
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Configuration ---
BASE_DIR = Path(__file__).parent.parent
REPORTS_DIR = BASE_DIR / "reports"
SCRIPTS_DIR = BASE_DIR
MITMPROXY_CONFIG = BASE_DIR / "mitmproxy" / "config.json"
REPORTS_DIR.mkdir(exist_ok=True)

# Etat global
state = {
    "containers": {},
    "scans": [],
    "frida_active": False,
    "monitor_mode": False,
    "transparent_proxy": False,
    "connected_devices": [],
    "logs": [],
    "container_logs": {},
    "container_errors": {},
}

# Track active log streaming threads
_log_threads = {}
_log_thread_lock = threading.Lock()


def log_event(level, message):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "message": message,
    }
    state["logs"].append(entry)
    state["logs"] = state["logs"][-200:]
    socketio.emit("log", entry)


def run_cmd(cmd, timeout=30):
    """Execute une commande shell et retourne stdout, stderr, returncode."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1
    except Exception as e:
        return "", str(e), 1


# =====================================================
# Container Log Streaming
# =====================================================

def stream_container_logs(container_name):
    """Stream logs from a docker container in real-time via WebSocket."""
    try:
        proc = subprocess.Popen(
            ["docker", "logs", "-f", "--tail", "50", "--timestamps", container_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        while proc.poll() is None:
            line = proc.stdout.readline()
            if line:
                line = line.strip()
                level = "info"
                if any(kw in line.lower() for kw in ["error", "exception", "traceback", "fatal", "critical"]):
                    level = "error"
                    state["container_errors"][container_name] = True
                elif any(kw in line.lower() for kw in ["warn", "warning"]):
                    level = "warn"
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "container": container_name,
                    "level": level,
                    "message": line,
                }
                # Store last 200 lines per container
                if container_name not in state["container_logs"]:
                    state["container_logs"][container_name] = []
                state["container_logs"][container_name].append(entry)
                state["container_logs"][container_name] = state["container_logs"][container_name][-200:]
                socketio.emit("container_log", entry)
    except Exception as e:
        socketio.emit("container_log", {
            "timestamp": datetime.now().isoformat(),
            "container": container_name,
            "level": "error",
            "message": f"Log stream error: {e}",
        })
    finally:
        with _log_thread_lock:
            _log_threads.pop(container_name, None)


def start_log_streaming():
    """Start streaming logs for all running containers."""
    stdout, _, _ = run_cmd("docker ps --format '{{.Names}}'")
    if not stdout:
        return
    for name in stdout.splitlines():
        name = name.strip()
        if not name:
            continue
        with _log_thread_lock:
            if name not in _log_threads or not _log_threads[name].is_alive():
                state["container_errors"][name] = False
                t = threading.Thread(target=stream_container_logs, args=(name,), daemon=True)
                t.start()
                _log_threads[name] = t


def periodic_log_refresh():
    """Periodically check for new containers and start streaming."""
    while True:
        start_log_streaming()
        time.sleep(10)


# =====================================================
# ROUTES - Pages
# =====================================================


@app.route("/")
def index():
    return render_template("index.html")


# =====================================================
# API - Docker / Containers
# =====================================================


@app.route("/api/containers", methods=["GET"])
def get_containers():
    stdout, _, _ = run_cmd("docker ps -a --format '{{json .}}'")
    containers = []
    for line in stdout.splitlines():
        if line.strip():
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    state["containers"] = containers
    return jsonify(containers)


@app.route("/api/containers/<action>", methods=["POST"])
def container_action(action):
    service = request.json.get("service", "")
    if service and service not in ("mobsf", "mitmproxy"):
        return jsonify({"error": "Service invalide"}), 400

    cmd_map = {
        "start": f"docker compose -f {BASE_DIR}/docker-compose.yml up -d {service}",
        "stop": f"docker compose -f {BASE_DIR}/docker-compose.yml stop {service}",
        "restart": f"docker compose -f {BASE_DIR}/docker-compose.yml restart {service}",
        "logs": f"docker compose -f {BASE_DIR}/docker-compose.yml logs --tail=100 {service}",
    }

    if action not in cmd_map:
        return jsonify({"error": "Action invalide"}), 400

    stdout, stderr, code = run_cmd(cmd_map[action], timeout=60)
    log_event("info" if code == 0 else "error", f"Container {action} {service}: {stdout or stderr}")
    # Restart log streaming after start/restart
    if action in ("start", "restart"):
        threading.Thread(target=start_log_streaming, daemon=True).start()
    return jsonify({"stdout": stdout, "stderr": stderr, "code": code})


# =====================================================
# API - Container Logs
# =====================================================


@app.route("/api/container-logs", methods=["GET"])
def get_container_logs():
    """Get stored container logs."""
    container = request.args.get("container", "")
    if container:
        return jsonify(state["container_logs"].get(container, []))
    # Return all logs merged and sorted
    all_logs = []
    for logs in state["container_logs"].values():
        all_logs.extend(logs)
    all_logs.sort(key=lambda x: x.get("timestamp", ""))
    return jsonify(all_logs[-200:])


@app.route("/api/container-errors", methods=["GET"])
def get_container_errors():
    """Get error status per container for topology coloring."""
    return jsonify(state["container_errors"])


# =====================================================
# API - ADB / Devices
# =====================================================


@app.route("/api/devices", methods=["GET"])
def get_devices():
    stdout, _, _ = run_cmd("adb devices -l")
    devices = []
    for line in stdout.splitlines()[1:]:
        if "device" in line and "List" not in line:
            parts = line.split()
            device = {"serial": parts[0], "state": parts[1] if len(parts) > 1 else "unknown"}
            for part in parts[2:]:
                if ":" in part:
                    k, v = part.split(":", 1)
                    device[k] = v
            devices.append(device)
    state["connected_devices"] = devices
    return jsonify(devices)


@app.route("/api/devices/<serial>/packages", methods=["GET"])
def get_packages(serial):
    stdout, _, _ = run_cmd(f"adb -s {serial} shell pm list packages -3")
    packages = [line.replace("package:", "") for line in stdout.splitlines() if line.startswith("package:")]
    return jsonify(sorted(packages))


@app.route("/api/devices/<serial>/screenshot", methods=["GET"])
def get_screenshot(serial):
    path = REPORTS_DIR / "screenshots"
    path.mkdir(exist_ok=True)
    filename = f"screen_{serial}_{int(time.time())}.png"
    run_cmd(f"adb -s {serial} exec-out screencap -p > {path / filename}")
    return send_from_directory(str(path), filename)


# =====================================================
# API - Audit IPC
# =====================================================


@app.route("/api/audit/ipc", methods=["POST"])
def audit_ipc():
    data = request.json
    package = data.get("package", "")
    if not package or not package.replace(".", "").replace("_", "").isalnum():
        return jsonify({"error": "Nom de package invalide"}), 400

    def run_audit():
        log_event("info", f"Audit IPC demarre pour {package}")
        stdout, stderr, code = run_cmd(
            f"bash {SCRIPTS_DIR}/audit_ipc.sh {package}", timeout=120
        )
        log_event(
            "info" if code == 0 else "error",
            f"Audit IPC termine pour {package}",
        )
        socketio.emit("audit_complete", {
            "type": "ipc",
            "package": package,
            "code": code,
            "stdout": stdout,
            "stderr": stderr,
        })

    thread = threading.Thread(target=run_audit, daemon=True)
    thread.start()
    return jsonify({"status": "started", "package": package})


@app.route("/api/audit/reports", methods=["GET"])
def list_reports():
    reports = []
    if REPORTS_DIR.exists():
        for pkg_dir in REPORTS_DIR.iterdir():
            if pkg_dir.is_dir() and pkg_dir.name != "screenshots":
                files = [f.name for f in pkg_dir.iterdir() if f.is_file()]
                reports.append({"package": pkg_dir.name, "files": files})
    return jsonify(reports)


@app.route("/api/audit/reports/<package>/<filename>", methods=["GET"])
def get_report_file(package, filename):
    safe_pkg = "".join(c for c in package if c.isalnum() or c == ".")
    safe_file = "".join(c for c in filename if c.isalnum() or c in "._-")
    report_path = REPORTS_DIR / safe_pkg
    if not report_path.exists():
        return jsonify({"error": "Rapport introuvable"}), 404
    return send_from_directory(str(report_path), safe_file)


# =====================================================
# API - Frida
# =====================================================


@app.route("/api/frida/start", methods=["POST"])
def frida_start():
    data = request.json
    package = data.get("package", "")
    if not package:
        return jsonify({"error": "Package requis"}), 400

    script = str(SCRIPTS_DIR / "frida-ssl-unpinning.js")

    def run_frida():
        state["frida_active"] = True
        log_event("info", f"Frida SSL bypass demarre pour {package}")
        stdout, stderr, code = run_cmd(
            f"frida -U -f {package} -l {script} --no-pause", timeout=300
        )
        state["frida_active"] = False
        socketio.emit("frida_status", {"active": False, "output": stdout or stderr})

    thread = threading.Thread(target=run_frida, daemon=True)
    thread.start()
    return jsonify({"status": "started"})


@app.route("/api/frida/status", methods=["GET"])
def frida_status():
    return jsonify({"active": state["frida_active"]})


# =====================================================
# API - Network (iptables, monitor)
# =====================================================


@app.route("/api/network/transparent", methods=["POST"])
def toggle_transparent():
    enable = request.json.get("enable", False)
    port = 8080

    if enable:
        run_cmd(f"iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port} 2>/dev/null; true")
        run_cmd(f"iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {port} 2>/dev/null; true")
        run_cmd(f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}")
        run_cmd(f"iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {port}")
        run_cmd("sysctl -w net.ipv4.ip_forward=1")
        state["transparent_proxy"] = True
        log_event("info", "Proxy transparent active")
    else:
        run_cmd(f"iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port} 2>/dev/null; true")
        run_cmd(f"iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {port} 2>/dev/null; true")
        state["transparent_proxy"] = False
        log_event("info", "Proxy transparent desactive")

    return jsonify({"transparent_proxy": state["transparent_proxy"]})


@app.route("/api/network/status", methods=["GET"])
def network_status():
    stdout, _, _ = run_cmd("iptables -t nat -L PREROUTING -n 2>/dev/null || echo 'no iptables'")
    return jsonify({
        "transparent_proxy": state["transparent_proxy"],
        "monitor_mode": state["monitor_mode"],
        "iptables": stdout,
    })


# =====================================================
# API - Mitmproxy Interceptions
# =====================================================


@app.route("/api/network/interceptions", methods=["GET"])
def get_interceptions():
    """Get intercepted devices/hosts from mitmproxy."""
    # Try to get flow data from mitmproxy API
    stdout, _, code = run_cmd("curl -s http://127.0.0.1:8081/flows.json 2>/dev/null", timeout=5)
    devices = {}
    if code == 0 and stdout:
        try:
            flows = json.loads(stdout)
            for flow in flows[-50:]:  # Last 50 flows
                req = flow.get("request", {})
                client = flow.get("client_conn", {}) or {}
                host = req.get("host", "unknown")
                client_addr = client.get("address", ["unknown"])[0] if client.get("address") else "unknown"
                if client_addr not in devices:
                    devices[client_addr] = {
                        "ip": client_addr,
                        "hosts": set(),
                        "flow_count": 0,
                    }
                devices[client_addr]["hosts"].add(host)
                devices[client_addr]["flow_count"] += 1
        except (json.JSONDecodeError, TypeError, IndexError):
            pass
    # Convert sets to lists for JSON serialization
    result = []
    for addr, info in devices.items():
        result.append({
            "ip": info["ip"],
            "hosts": list(info["hosts"])[:10],
            "flow_count": info["flow_count"],
        })
    return jsonify(result)


# =====================================================
# API - MobSF Upload
# =====================================================


@app.route("/api/mobsf/upload", methods=["POST"])
def mobsf_upload():
    if "file" not in request.files:
        return jsonify({"error": "Aucun fichier"}), 400

    f = request.files["file"]
    if not f.filename.endswith((".apk", ".ipa", ".appx")):
        return jsonify({"error": "Format invalide (.apk, .ipa, .appx)"}), 400

    upload_dir = REPORTS_DIR / "uploads"
    upload_dir.mkdir(exist_ok=True)
    filepath = upload_dir / f.filename
    f.save(str(filepath))

    # Upload vers MobSF via API
    stdout, stderr, code = run_cmd(
        f'curl -s -F "file=@{filepath}" http://127.0.0.1:8000/api/v1/upload '
        f'-H "Authorization:__mobsf_api_key__"',
        timeout=120,
    )
    log_event("info", f"APK uploade vers MobSF: {f.filename}")
    return jsonify({"status": "uploaded", "filename": f.filename, "mobsf_response": stdout})


# =====================================================
# API - Config
# =====================================================


@app.route("/api/config/mitmproxy", methods=["GET"])
def get_mitmproxy_config():
    """Get current mitmproxy config."""
    try:
        with open(MITMPROXY_CONFIG) as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify(get_default_mitmproxy_config())


@app.route("/api/config/mitmproxy", methods=["POST"])
def save_mitmproxy_config():
    """Save mitmproxy config."""
    config = request.json
    if not config:
        return jsonify({"error": "Config vide"}), 400
    # Validate required fields
    required = ["listen_host", "listen_port", "web_host", "web_port"]
    for field in required:
        if field not in config:
            return jsonify({"error": f"Champ requis manquant: {field}"}), 400
    try:
        MITMPROXY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        with open(MITMPROXY_CONFIG, "w") as f:
            json.dump(config, f, indent=2)
        log_event("info", "Configuration mitmproxy sauvegardee")
        return jsonify({"status": "saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/config/mitmproxy/default", methods=["GET"])
def get_default_config():
    """Get default mitmproxy config."""
    return jsonify(get_default_mitmproxy_config())


def get_default_mitmproxy_config():
    return {
        "listen_host": "0.0.0.0",
        "listen_port": 8080,
        "web_host": "0.0.0.0",
        "web_port": 8081,
        "web_open_browser": False,
        "ssl_insecure": True,
        "upstream_cert": True,
        "stream_large_bodies": "5m",
        "connection_strategy": "lazy",
        "http2": True,
        "anticache": False,
        "anticomp": True,
        "showhost": True,
    }


# =====================================================
# API - Topology data
# =====================================================


@app.route("/api/topology", methods=["GET"])
def get_topology():
    """Get topology data for the network graph."""
    # Get container statuses
    stdout, _, _ = run_cmd("docker ps -a --format '{{json .}}'")
    containers = []
    for line in stdout.splitlines():
        if line.strip():
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    # Get network interface info
    iface_stdout, _, _ = run_cmd("iwconfig 2>/dev/null | head -3 || echo 'no wifi'")
    wifi_info = iface_stdout.split('\n')[0] if iface_stdout else "N/A"

    # Get IP forwarding status
    fwd_stdout, _, _ = run_cmd("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '0'")
    ip_forward = fwd_stdout.strip() == "1"

    # Build nodes
    nodes = []
    edges = []

    # WiFi AP node
    has_wifi_error = False
    if "no wifi" in (iface_stdout or ""):
        has_wifi_error = True
    nodes.append({
        "id": "wifi_ap",
        "label": "WiFi AP",
        "type": "infrastructure",
        "status": "error" if has_wifi_error else "healthy",
        "details": wifi_info,
    })

    # Host machine
    nodes.append({
        "id": "host",
        "label": "NSAC Host",
        "type": "infrastructure",
        "status": "healthy",
        "details": f"IP Forward: {'ON' if ip_forward else 'OFF'}",
    })

    # iptables node
    nodes.append({
        "id": "iptables",
        "label": "iptables NAT",
        "type": "infrastructure",
        "status": "healthy" if state["transparent_proxy"] else "inactive",
        "details": "PREROUTING -> :8080" if state["transparent_proxy"] else "Inactive",
    })

    # Mitmproxy node
    mitm_container = next((c for c in containers if "mitmproxy" in (c.get("Names") or "")), None)
    mitm_running = mitm_container and mitm_container.get("State") == "running"
    mitm_has_error = state["container_errors"].get("mitmproxy", False)
    nodes.append({
        "id": "mitmproxy",
        "label": "Mitmproxy",
        "type": "container",
        "status": "error" if mitm_has_error else ("healthy" if mitm_running else "stopped"),
        "details": ":8080 / Web :8081",
    })

    # MobSF node
    mobsf_container = next((c for c in containers if "mobsf" in (c.get("Names") or "")), None)
    mobsf_running = mobsf_container and mobsf_container.get("State") == "running"
    mobsf_has_error = state["container_errors"].get("mobsf", False)
    nodes.append({
        "id": "mobsf",
        "label": "MobSF",
        "type": "container",
        "status": "error" if mobsf_has_error else ("healthy" if mobsf_running else "stopped"),
        "details": ":8000",
    })

    # Frida node
    nodes.append({
        "id": "frida",
        "label": "Frida",
        "type": "tool",
        "status": "healthy" if state["frida_active"] else "inactive",
        "details": "SSL Bypass" if state["frida_active"] else "Inactive",
    })

    # Edges with traffic info
    edges.append({"from": "wifi_ap", "to": "host", "label": "WiFi Traffic", "speed": "802.11ac"})
    edges.append({"from": "host", "to": "iptables", "label": "NAT Redirect", "speed": "HTTP/HTTPS"})
    edges.append({"from": "iptables", "to": "mitmproxy", "label": "Proxy :8080", "speed": "TCP"})
    edges.append({"from": "mitmproxy", "to": "mobsf", "label": "APK Upload", "speed": "REST API"})
    edges.append({"from": "host", "to": "frida", "label": "USB/ADB", "speed": "adb forward"})

    # Connected devices as nodes
    for dev in state["connected_devices"]:
        dev_id = f"device_{dev['serial']}"
        nodes.append({
            "id": dev_id,
            "label": dev.get("model", dev["serial"]),
            "type": "device",
            "status": "healthy" if dev.get("state") == "device" else "warning",
            "details": dev["serial"],
        })
        edges.append({"from": dev_id, "to": "wifi_ap", "label": "WiFi", "speed": "DHCP"})
        edges.append({"from": "frida", "to": dev_id, "label": "Injection", "speed": "USB"})

    # Intercepted devices
    interception_stdout, _, interception_code = run_cmd(
        "curl -s http://127.0.0.1:8081/flows.json 2>/dev/null | head -c 50000", timeout=3
    )
    intercepted_ips = set()
    if interception_code == 0 and interception_stdout:
        try:
            flows = json.loads(interception_stdout)
            for flow in flows[-30:]:
                client = flow.get("client_conn", {}) or {}
                addr = client.get("address", [None])[0] if client.get("address") else None
                if addr and addr not in intercepted_ips:
                    intercepted_ips.add(addr)
        except (json.JSONDecodeError, TypeError):
            pass

    for ip in intercepted_ips:
        # Check if this IP is already a known device
        known = any(d["serial"] == ip for d in state["connected_devices"])
        if not known:
            node_id = f"intercepted_{ip.replace('.', '_')}"
            nodes.append({
                "id": node_id,
                "label": ip,
                "type": "intercepted",
                "status": "warning",
                "details": "Intercepted device",
            })
            edges.append({"from": node_id, "to": "mitmproxy", "label": "MITM", "speed": "Intercepted"})

    return jsonify({"nodes": nodes, "edges": edges})


# =====================================================
# API - System
# =====================================================


@app.route("/api/system/status", methods=["GET"])
def system_status():
    disk_stdout, _, _ = run_cmd("df -h / | tail -1")
    mem_stdout, _, _ = run_cmd("free -h | grep Mem")
    return jsonify({
        "disk": disk_stdout,
        "memory": mem_stdout,
        "containers": state.get("containers", {}),
        "frida_active": state["frida_active"],
        "transparent_proxy": state["transparent_proxy"],
        "devices": state["connected_devices"],
    })


@app.route("/api/logs", methods=["GET"])
def get_logs():
    limit = request.args.get("limit", 50, type=int)
    return jsonify(state["logs"][-limit:])


@app.route("/api/cleanup", methods=["POST"])
def cleanup():
    log_event("info", "Nettoyage du lab en cours...")
    stdout, stderr, code = run_cmd(f"bash {SCRIPTS_DIR}/cleanup.sh", timeout=60)
    log_event("info" if code == 0 else "error", f"Cleanup: {stdout or stderr}")
    return jsonify({"code": code, "stdout": stdout, "stderr": stderr})


# =====================================================
# WebSocket events
# =====================================================


@socketio.on("connect")
def handle_connect():
    emit("connected", {"status": "ok"})


@socketio.on("request_status")
def handle_status_request():
    emit("status_update", {
        "frida_active": state["frida_active"],
        "transparent_proxy": state["transparent_proxy"],
        "monitor_mode": state["monitor_mode"],
        "devices": state["connected_devices"],
    })


# =====================================================
# Main
# =====================================================

if __name__ == "__main__":
    port = int(os.environ.get("NSAC_PORT", 5000))
    # Start log streaming in background
    threading.Thread(target=periodic_log_refresh, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
