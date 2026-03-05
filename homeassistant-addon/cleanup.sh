#!/usr/bin/env bash
#
# cleanup.sh - Nettoyage complet du lab d'audit
# Usage: sudo ./cleanup.sh
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "Ce script doit etre execute en tant que root (sudo)."
    exit 1
fi

# --- Arret des conteneurs Docker ---
log_info "Arret des conteneurs Docker..."
docker compose down 2>/dev/null || true

# --- Suppression des regles iptables ---
log_info "Nettoyage des regles iptables..."
iptables -t nat -D PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 8080 2>/dev/null || true
iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080 2>/dev/null || true

# --- Desactivation de l'IP forwarding ---
log_info "Desactivation de l'IP forwarding..."
sysctl -w net.ipv4.ip_forward=0 > /dev/null

# --- Restauration de toutes les interfaces WiFi en mode monitor ---
log_info "Recherche des interfaces en mode monitor..."
while IFS= read -r iface; do
    if [[ -n "$iface" ]]; then
        # Verifier si l'interface est en mode monitor
        MODE=$(iw dev "$iface" info 2>/dev/null | awk '/type/{print $2}')
        if [[ "$MODE" == "monitor" ]]; then
            log_info "Arret du mode monitor sur $iface..."
            airmon-ng stop "$iface" 2>/dev/null || true
        fi
    fi
done < <(iw dev | awk '$1=="Interface"{print $2}')

# Restaurer aussi les interfaces *mon (convention airmon-ng)
for iface in $(iw dev | awk '$1=="Interface" && /mon$/{print $2}'); do
    log_info "Arret du mode monitor sur $iface..."
    airmon-ng stop "$iface" 2>/dev/null || true
done

# --- Redemarrage de NetworkManager ---
if command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        log_info "NetworkManager deja actif."
    else
        log_info "Redemarrage de NetworkManager..."
        systemctl start NetworkManager 2>/dev/null || true
    fi
fi

# Reactiver toutes les interfaces WiFi en mode managed
log_info "Reactivation des interfaces WiFi..."
for iface in $(iw dev | awk '$1=="Interface"{print $2}'); do
    ip link set "$iface" up 2>/dev/null || true
done

# Reconnecter via nmcli si disponible
if command -v nmcli &>/dev/null; then
    nmcli networking on 2>/dev/null || true
    log_info "nmcli networking reactive."
fi

log_info "Nettoyage termine. Toutes les interfaces sont restaurees en mode managed."
