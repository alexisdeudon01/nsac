#!/usr/bin/env bash
#
# install_ubuntu.sh - Installation de NSAC sur Ubuntu (20.04 / 22.04 / 24.04)
#
# Usage: sudo ./install_ubuntu.sh
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# --- Verification root ---
if [[ $EUID -ne 0 ]]; then
    log_error "Ce script doit etre execute en tant que root (sudo)."
    exit 1
fi

# --- Detect real user (for non-root installs later) ---
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

log_info "======================================"
log_info "  NSAC - Installation Ubuntu"
log_info "======================================"
log_info "Utilisateur : $REAL_USER"
log_info "Repertoire  : $INSTALL_DIR"

# --- 1. Mise a jour et paquets systeme ---
log_info "Installation des paquets systeme..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    docker.io docker-compose-v2 \
    adb \
    iptables \
    openssl \
    curl \
    iw wireless-tools \
    aircrack-ng \
    net-tools

# --- 2. Docker ---
log_info "Configuration de Docker..."
systemctl enable docker
systemctl start docker
# Ajouter l'utilisateur au groupe docker
if ! groups "$REAL_USER" | grep -q docker; then
    usermod -aG docker "$REAL_USER"
    log_warn "$REAL_USER ajoute au groupe docker. Deconnectez-vous et reconnectez-vous pour que ca prenne effet."
fi

# --- 3. Environnement Python virtuel ---
log_info "Creation de l'environnement Python..."
VENV_DIR="$INSTALL_DIR/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -q -r "$INSTALL_DIR/webapp/requirements.txt"

# --- 4. Frida tools ---
log_info "Installation de frida-tools (peut prendre quelques minutes)..."
"$VENV_DIR/bin/pip" install -q frida-tools

# --- 5. Repertoires ---
mkdir -p "$INSTALL_DIR/reports" "$INSTALL_DIR/certs"

# --- 6. Scripts executables ---
chmod +x "$INSTALL_DIR/setup_audit.sh" \
         "$INSTALL_DIR/cleanup.sh" \
         "$INSTALL_DIR/audit_ipc.sh" \
         "$INSTALL_DIR/run_ubuntu.sh"

# --- 7. Demarrage des conteneurs Docker ---
log_info "Demarrage des conteneurs Docker (MobSF + mitmproxy)..."
cd "$INSTALL_DIR"
docker compose up -d || log_warn "Docker compose a echoue. Verifiez avec: docker compose logs"

# --- 8. Permissions ---
chown -R "$REAL_USER:$REAL_USER" "$INSTALL_DIR/.venv" "$INSTALL_DIR/reports" "$INSTALL_DIR/certs"

# --- Resume ---
echo ""
log_info "======================================"
log_info "  Installation terminee !"
log_info "======================================"
echo ""
echo "  Pour lancer NSAC :"
echo "    cd $INSTALL_DIR"
echo "    sudo ./run_ubuntu.sh"
echo ""
echo "  Ou sans sudo (si Docker est accessible) :"
echo "    ./run_ubuntu.sh"
echo ""
echo "  Services :"
echo "    NSAC Dashboard : http://localhost:5000"
echo "    MobSF          : http://localhost:8000"
echo "    Mitmproxy Web  : http://localhost:8081"
echo ""
echo "  Pour l'audit complet (monitor WiFi + proxy transparent) :"
echo "    sudo ./setup_audit.sh --monitor --transparent"
echo ""
