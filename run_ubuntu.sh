#!/usr/bin/env bash
#
# run_ubuntu.sh - Lance NSAC sur Ubuntu
#
# Usage: ./run_ubuntu.sh [--no-docker]
#
#   --no-docker   Ne pas demarrer les conteneurs Docker (MobSF/mitmproxy)
#
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# --- Options ---
START_DOCKER=true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-docker) START_DOCKER=false ;;
        *) log_warn "Option inconnue : $1" ;;
    esac
    shift
done

echo "========================================"
echo "  NSAC - Network Security Audit Console"
echo "  Ubuntu Edition"
echo "========================================"

# --- Verifier le venv ---
if [[ ! -d "$VENV_DIR" ]]; then
    log_error "Environnement Python introuvable. Lancez d'abord : sudo ./install_ubuntu.sh"
    exit 1
fi

# --- Demarrer Docker si demande ---
if $START_DOCKER; then
    cd "$SCRIPT_DIR"
    # Arreter les conteneurs existants pour appliquer la config a jour
    if docker compose ps -q 2>/dev/null | grep -q .; then
        log_info "Arret des conteneurs existants..."
        docker compose down 2>/dev/null || true
    fi
    log_info "Demarrage des conteneurs Docker..."
    docker compose up -d --force-recreate 2>/dev/null || log_warn "Docker compose a echoue. Verifiez que Docker est lance."
    log_info "Mitmproxy Web UI : http://localhost:8081/#/flows?token=nsac"
fi

# --- IP Forwarding ---
if [[ $EUID -eq 0 ]]; then
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1 || true
fi

# --- Preparation certificat mitmproxy ---
CERT_SRC="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [[ -f "$CERT_SRC" ]]; then
    HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CERT_SRC" 2>/dev/null | head -1)
    mkdir -p "$SCRIPT_DIR/certs"
    cp "$CERT_SRC" "$SCRIPT_DIR/certs/${HASH}.0"
    log_info "Certificat mitmproxy pret : certs/${HASH}.0"
fi

# --- Lancer NSAC ---
log_info "Demarrage de NSAC Web UI sur http://localhost:5000 ..."
export NSAC_PORT=5000
cd "$SCRIPT_DIR"
exec "$VENV_DIR/bin/python3" -m webapp.app
