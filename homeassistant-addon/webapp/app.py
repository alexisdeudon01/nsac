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
}


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
    return jsonify({"stdout": stdout, "stderr": stderr, "code": code})


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
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
