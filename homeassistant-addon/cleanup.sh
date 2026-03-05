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

# --- Restauration du mode WiFi ---
WIFI_IFACE=$(iw dev | awk '$1=="Interface"{print $2; exit}')
if [[ -n "$WIFI_IFACE" ]] && echo "$WIFI_IFACE" | grep -q "mon$"; then
    log_info "Arret du mode monitor sur $WIFI_IFACE..."
    airmon-ng stop "$WIFI_IFACE" 2>/dev/null || true
fi

# --- Redemarrage de NetworkManager ---
if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    log_info "NetworkManager deja actif."
else
    log_info "Redemarrage de NetworkManager..."
    systemctl start NetworkManager 2>/dev/null || true
fi

log_info "Nettoyage termine. Le systeme est restaure."
