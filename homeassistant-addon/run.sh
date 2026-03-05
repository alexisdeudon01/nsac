#!/usr/bin/env bash
#
# run.sh - Entrypoint pour le Home Assistant add-on NSAC
#
set -eo pipefail

echo "========================================"
echo "  NSAC - Network Security Audit Console"
echo "  Home Assistant Add-on"
echo "========================================"

# --- Lire les options depuis HA ---
MOBSF_ENABLED=$(bashio::config 'mobsf_enabled' 2>/dev/null || echo "true")
MITMPROXY_ENABLED=$(bashio::config 'mitmproxy_enabled' 2>/dev/null || echo "true")
AUTO_START=$(bashio::config 'auto_start_services' 2>/dev/null || echo "true")
TRANSPARENT_PROXY=$(bashio::config 'transparent_proxy' 2>/dev/null || echo "false")

echo "[+] Configuration:"
echo "    MobSF:             $MOBSF_ENABLED"
echo "    Mitmproxy:         $MITMPROXY_ENABLED"
echo "    Auto-start:        $AUTO_START"
echo "    Transparent proxy: $TRANSPARENT_PROXY"

# --- Symlink rapports vers /share pour acces HA ---
if [[ -d /share ]]; then
    mkdir -p /share/nsac-reports
    ln -sfn /share/nsac-reports /app/reports
    echo "[+] Rapports sauvegardes dans /share/nsac-reports/"
fi

# --- Demarrer les services Docker si auto-start ---
if [[ "$AUTO_START" == "true" ]]; then
    echo "[+] Demarrage des services Docker..."

    # Generer un docker-compose dynamique selon les options
    COMPOSE_FILE="/app/docker-compose.yml"

    if [[ "$MOBSF_ENABLED" == "true" ]]; then
        echo "[+] Demarrage de MobSF..."
        docker compose -f "$COMPOSE_FILE" up -d mobsf 2>/dev/null || \
            echo "[-] MobSF: echec du demarrage (Docker-in-Docker requis)"
    fi

    if [[ "$MITMPROXY_ENABLED" == "true" ]]; then
        echo "[+] Demarrage de Mitmproxy..."
        docker compose -f "$COMPOSE_FILE" up -d mitmproxy 2>/dev/null || \
            echo "[-] Mitmproxy: echec du demarrage"
    fi
fi

# --- IP forwarding ---
echo "[+] Activation IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

# --- Proxy transparent si active ---
if [[ "$TRANSPARENT_PROXY" == "true" ]]; then
    echo "[+] Activation du proxy transparent..."
    iptables -t nat -D PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 8080 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080 2>/dev/null || true
    iptables -t nat -A PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 8080
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
fi

# --- Preparation certificat mitmproxy ---
CERT_SRC="/root/.mitmproxy/mitmproxy-ca-cert.pem"
if [[ -f "$CERT_SRC" ]]; then
    HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CERT_SRC" 2>/dev/null | head -1)
    mkdir -p /app/certs
    cp "$CERT_SRC" "/app/certs/${HASH}.0"
    echo "[+] Certificat mitmproxy prepare: /app/certs/${HASH}.0"
fi

# --- Lancer le serveur NSAC ---
echo "[+] Demarrage de NSAC Web UI sur le port 5000..."
export NSAC_PORT=5000
cd /app
exec python3 -m webapp.app
