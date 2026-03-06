#!/usr/bin/env bash
#
# install_ubuntu.sh - Installation de NSAC sur Ubuntu (20.04 / 22.04 / 24.04)
#
# Usage: sudo ./install_ubuntu.sh
#
set -uo pipefail

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

# Paquets essentiels (installes un par un pour eviter les conflits)
ESSENTIAL_PKGS=(python3 python3-pip python3-venv iptables openssl curl net-tools)
OPTIONAL_PKGS=(docker.io docker-compose-v2 adb iw wireless-tools aircrack-ng)

for pkg in "${ESSENTIAL_PKGS[@]}"; do
    apt-get install -y -qq "$pkg" 2>/dev/null || log_warn "Impossible d'installer $pkg (peut-etre deja present)"
done

for pkg in "${OPTIONAL_PKGS[@]}"; do
    apt-get install -y -qq "$pkg" 2>/dev/null || log_warn "Paquet optionnel $pkg non installe (conflit ou indisponible)"
done

# Verifier que python3 est la
if ! command -v python3 &>/dev/null; then
    log_error "python3 est requis mais n'a pas pu etre installe."
    exit 1
fi

# --- 2. Docker ---
log_info "Configuration de Docker..."
if command -v docker &>/dev/null; then
    systemctl enable docker 2>/dev/null || true
    systemctl start docker 2>/dev/null || true
else
    log_warn "Docker non installe. MobSF et mitmproxy ne seront pas disponibles."
    log_warn "Installe Docker manuellement : https://docs.docker.com/engine/install/ubuntu/"
fi
# Ajouter l'utilisateur au groupe docker
if ! groups "$REAL_USER" | grep -q docker; then
    usermod -aG docker "$REAL_USER"
    log_warn "$REAL_USER ajoute au groupe docker. Deconnectez-vous et reconnectez-vous pour que ca prenne effet."
fi

# --- 3. Environnement Python virtuel ---
VENV_DIR="$INSTALL_DIR/.venv"
REQ_FILE="$INSTALL_DIR/webapp/requirements.txt"

if [[ -d "$VENV_DIR" ]]; then
    log_warn "Suppression de l'ancien environnement virtuel..."
    rm -rf "$VENV_DIR"
fi

log_info "Creation de l'environnement virtuel Python..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q

log_info "Installation des librairies depuis requirements.txt..."
"$VENV_DIR/bin/pip" install -q -r "$REQ_FILE"

# Verification des librairies
log_info "Verification des librairies Python..."
MISSING_LIBS=()
while IFS= read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    pkg_name=$(echo "$line" | sed 's/[>=<].*//')
    if ! "$VENV_DIR/bin/pip" show "$pkg_name" &>/dev/null; then
        MISSING_LIBS+=("$pkg_name")
    fi
done < "$REQ_FILE"
if [[ ${#MISSING_LIBS[@]} -gt 0 ]]; then
    log_error "Librairies manquantes apres installation : ${MISSING_LIBS[*]}"
    exit 1
fi
log_info "Toutes les librairies Python sont installees."

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
echo "    Mitmproxy Web  : http://localhost:8081 (token affiche au lancement)"
echo ""
echo "  Pour l'audit complet (monitor WiFi + proxy transparent) :"
echo "    sudo ./setup_audit.sh --monitor --transparent"
echo ""
