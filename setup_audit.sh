#!/usr/bin/env bash
#
# setup_audit.sh - Deploiement du lab d'audit Android
# Usage: sudo ./setup_audit.sh [--monitor] [--transparent] [--mon-iface wlan1] [--net-iface wlan0]
#
# Options:
#   --monitor              Active le mode monitor WiFi (airmon-ng)
#   --transparent          Active la redirection transparente iptables vers mitmproxy
#   --mon-iface <iface>    Interface WiFi pour le mode monitor (ex: wlan1)
#   --net-iface <iface>    Interface WiFi pour la connexion internet (ex: wlan0)
#
# Si non specifiees, le script detecte automatiquement les 2 interfaces WiFi.
# La premiere reste en mode managed (internet), la seconde passe en monitor.
#
set -euo pipefail

MITMPROXY_PORT=8080
MON_IFACE_USER=""
NET_IFACE_USER=""

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

while [[ $# -gt 0 ]]; do
    case "$1" in
        --monitor)     ENABLE_MONITOR=true ;;
        --transparent) ENABLE_TRANSPARENT=true ;;
        --mon-iface)   MON_IFACE_USER="$2"; shift ;;
        --net-iface)   NET_IFACE_USER="$2"; shift ;;
        *)             log_warn "Option inconnue : $1" ;;
    esac
    shift
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

# --- Detection des interfaces WiFi ---
detect_wifi_interfaces() {
    local all_ifaces=()
    while IFS= read -r line; do
        all_ifaces+=("$line")
    done < <(iw dev | awk '$1=="Interface"{print $2}')

    echo "${all_ifaces[@]}"
}

# --- Mode Monitor WiFi (optionnel) ---
NET_IFACE=""
MON_IFACE=""

if $ENABLE_MONITOR; then
    if ! command -v airmon-ng &>/dev/null; then
        log_error "airmon-ng non installe. Installez aircrack-ng."
        exit 1
    fi

    # Recuperer toutes les interfaces WiFi
    WIFI_IFACES=($(detect_wifi_interfaces))
    WIFI_COUNT=${#WIFI_IFACES[@]}

    log_info "Interfaces WiFi detectees ($WIFI_COUNT) : ${WIFI_IFACES[*]}"

    if [[ $WIFI_COUNT -lt 2 ]] && [[ -z "$MON_IFACE_USER" || -z "$NET_IFACE_USER" ]]; then
        log_error "2 interfaces WiFi requises (trouvees: $WIFI_COUNT)."
        log_error "Connectez un adaptateur WiFi USB ou specifiez manuellement :"
        log_error "  --mon-iface wlan1 --net-iface wlan0"
        exit 1
    fi

    # Attribution des interfaces
    if [[ -n "$NET_IFACE_USER" && -n "$MON_IFACE_USER" ]]; then
        # Mode manuel : l'utilisateur a specifie les 2
        NET_IFACE="$NET_IFACE_USER"
        MON_IFACE="$MON_IFACE_USER"
        log_info "Interfaces specifiees manuellement :"
    else
        # Mode auto : la premiere reste en managed, la seconde passe en monitor
        NET_IFACE="${WIFI_IFACES[0]}"
        MON_IFACE="${WIFI_IFACES[1]}"
        log_info "Attribution automatique des interfaces :"
    fi

    log_info "  Internet (managed) : $NET_IFACE"
    log_info "  Monitor (sniffing) : $MON_IFACE"

    # Verifier que les 2 interfaces existent
    if ! iw dev | grep -q "$NET_IFACE"; then
        log_error "Interface $NET_IFACE introuvable."
        exit 1
    fi
    if ! iw dev | grep -q "$MON_IFACE"; then
        log_error "Interface $MON_IFACE introuvable."
        exit 1
    fi

    # Verifier que l'interface reseau est connectee
    if ip link show "$NET_IFACE" | grep -q "state UP"; then
        log_info "$NET_IFACE est UP et connectee."
    else
        log_warn "$NET_IFACE n'est pas UP. Tentative de connexion..."
        ip link set "$NET_IFACE" up 2>/dev/null || true
    fi

    # Passer UNIQUEMENT l'interface monitor en mode monitor
    # On ne touche PAS a l'interface reseau
    log_info "Passage de $MON_IFACE en mode monitor..."
    log_info "$NET_IFACE reste en mode managed (internet actif)."

    # Tuer les processus qui bloquent SEULEMENT sur l'interface monitor
    # On utilise airmon-ng check kill avec precaution
    # D'abord on sauvegarde l'etat de NetworkManager pour l'interface reseau
    NMCLI_AVAILABLE=false
    if command -v nmcli &>/dev/null; then
        NMCLI_AVAILABLE=true
        # Marquer l'interface reseau comme non-geree temporairement par airmon
        NET_CONNECTION=$(nmcli -t -f NAME,DEVICE con show --active | grep "$NET_IFACE" | cut -d: -f1)
    fi

    # Desactiver l'interface monitor avant airmon-ng
    ip link set "$MON_IFACE" down 2>/dev/null || true

    # Passer en mode monitor (sans kill pour preserver la connexion)
    airmon-ng start "$MON_IFACE" 2>/dev/null

    MON_IFACE_RESULT="${MON_IFACE}mon"
    # Certains drivers gardent le meme nom
    if iw dev | grep -q "$MON_IFACE_RESULT"; then
        MON_IFACE="$MON_IFACE_RESULT"
    fi

    # Verifier le mode monitor
    MON_MODE=$(iw dev "$MON_IFACE" info 2>/dev/null | grep "type" | awk '{print $2}')
    if [[ "$MON_MODE" == "monitor" ]]; then
        log_info "Mode monitor actif sur $MON_IFACE"
    else
        log_warn "Mode monitor peut ne pas etre actif sur $MON_IFACE (type: $MON_MODE)"
        log_warn "Certains drivers necessitent : iw dev $MON_IFACE set type monitor"
    fi

    # S'assurer que l'interface reseau est toujours UP
    ip link set "$NET_IFACE" up 2>/dev/null || true
    if $NMCLI_AVAILABLE && [[ -n "${NET_CONNECTION:-}" ]]; then
        nmcli con up "$NET_CONNECTION" 2>/dev/null || true
    fi

    # Verification finale de la connectivite internet
    if ping -c 1 -W 2 -I "$NET_IFACE" 8.8.8.8 &>/dev/null; then
        log_info "Connectivite internet OK via $NET_IFACE"
    else
        log_warn "Pas de connectivite internet via $NET_IFACE."
        log_warn "Verifiez la connexion WiFi sur cette interface."
    fi

    echo ""
    log_info "Pour scanner les probe requests :"
    echo "    airodump-ng $MON_IFACE"
    echo ""
    log_info "Pour cibler un canal specifique :"
    echo "    airodump-ng -c <channel> --bssid <AP_MAC> $MON_IFACE"
    echo ""
    log_info "Pour capturer le trafic :"
    echo "    airodump-ng -c <channel> --bssid <AP_MAC> -w capture $MON_IFACE"

else
    log_warn "Mode monitor desactive. Utilisez --monitor pour l'activer."

    # Detecter l'interface reseau par defaut
    NET_IFACE=$(ip route | awk '/default/{print $5; exit}')
fi

# --- Resume ---
echo ""
log_info "====== Lab d'audit Android pret ======"
echo "  MobSF          : http://127.0.0.1:8000"
echo "  Mitmproxy Web  : http://127.0.0.1:8081"
echo "  Mitmproxy Port : $MITMPROXY_PORT (proxy HTTP/HTTPS)"
echo ""
if [[ -n "$NET_IFACE" ]]; then
    echo "  Interface reseau (internet) : $NET_IFACE"
fi
if [[ -n "$MON_IFACE" ]] && $ENABLE_MONITOR; then
    echo "  Interface monitor (sniffing) : $MON_IFACE"
fi
echo ""
