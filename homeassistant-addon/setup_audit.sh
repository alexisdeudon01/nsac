#!/usr/bin/env bash
#
# setup_audit.sh - Deploiement du lab d'audit Android
# Usage: sudo ./setup_audit.sh [--monitor] [--transparent]
#
# Options:
#   --monitor      Active le mode monitor WiFi (airmon-ng)
#   --transparent  Active la redirection transparente iptables vers mitmproxy
#
set -euo pipefail

MITMPROXY_PORT=8080
WIFI_IFACE=""

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# --- Verification des privileges ---
if [[ $EUID -ne 0 ]]; then
    log_error "Ce script doit etre execute en tant que root (sudo)."
    exit 1
fi

# --- Verification des dependances ---
check_deps() {
    local missing=()
    for cmd in docker iw iptables openssl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Dependances manquantes : ${missing[*]}"
        exit 1
    fi
}
check_deps

# --- Parsing des arguments ---
ENABLE_MONITOR=false
ENABLE_TRANSPARENT=false

for arg in "$@"; do
    case "$arg" in
        --monitor)     ENABLE_MONITOR=true ;;
        --transparent) ENABLE_TRANSPARENT=true ;;
        *)             log_warn "Option inconnue : $arg" ;;
    esac
done

# --- IP Forwarding ---
log_info "Activation de l'IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# --- Redirection transparente (optionnel) ---
if $ENABLE_TRANSPARENT; then
    log_info "Mise en place de la redirection transparente vers le port $MITMPROXY_PORT..."

    # Nettoyage des regles existantes pour eviter les doublons
    iptables -t nat -D PREROUTING -p tcp --dport 80  -j REDIRECT --to-port "$MITMPROXY_PORT" 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port "$MITMPROXY_PORT" 2>/dev/null || true

    iptables -t nat -A PREROUTING -p tcp --dport 80  -j REDIRECT --to-port "$MITMPROXY_PORT"
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port "$MITMPROXY_PORT"

    log_info "Redirection HTTP/HTTPS -> port $MITMPROXY_PORT active."
else
    log_warn "Redirection transparente desactivee. Utilisez --transparent pour l'activer."
fi

# --- Lancement de l'infra Docker ---
log_info "Demarrage des conteneurs Docker..."
docker compose up -d

# --- Preparation du certificat mitmproxy pour Android ---
CERT_SRC="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
CERT_DIR="/home/user/android-audit-lab/certs"
mkdir -p "$CERT_DIR"

if [[ -f "$CERT_SRC" ]]; then
    HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CERT_SRC" 2>/dev/null | head -1)
    cp "$CERT_SRC" "$CERT_DIR/${HASH}.0"
    log_info "Certificat mitmproxy prepare : $CERT_DIR/${HASH}.0"
    log_info "Pour l'installer sur un appareil roote :"
    echo "    adb root"
    echo "    adb remount"
    echo "    adb push $CERT_DIR/${HASH}.0 /system/etc/security/cacerts/"
    echo "    adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0"
    echo "    adb reboot"
else
    log_warn "Certificat mitmproxy non trouve ($CERT_SRC)."
    log_warn "Lancez mitmproxy une premiere fois pour le generer, puis relancez ce script."
fi

# --- Mode Monitor WiFi (optionnel) ---
if $ENABLE_MONITOR; then
    if ! command -v airmon-ng &>/dev/null; then
        log_error "airmon-ng non installe. Installez aircrack-ng."
        exit 1
    fi

    WIFI_IFACE=$(iw dev | awk '$1=="Interface"{print $2; exit}')
    if [[ -z "$WIFI_IFACE" ]]; then
        log_error "Aucune interface WiFi detectee."
        exit 1
    fi

    log_info "Interface WiFi detectee : $WIFI_IFACE"
    log_warn "Passage en mode monitor (la connexion WiFi sera interrompue)..."
    airmon-ng check kill
    airmon-ng start "$WIFI_IFACE"

    MON_IFACE="${WIFI_IFACE}mon"
    if iw dev | grep -q "$MON_IFACE"; then
        log_info "Mode monitor actif sur $MON_IFACE"
        log_info "Pour scanner les probe requests :"
        echo "    airodump-ng $MON_IFACE"
    else
        log_error "Echec du passage en mode monitor."
    fi
else
    log_warn "Mode monitor desactive. Utilisez --monitor pour l'activer."
fi

# --- Resume ---
echo ""
log_info "====== Lab d'audit Android pret ======"
echo "  MobSF          : http://127.0.0.1:8000"
echo "  Mitmproxy Web  : http://127.0.0.1:8081"
echo "  Mitmproxy Port : $MITMPROXY_PORT (proxy HTTP/HTTPS)"
echo ""
