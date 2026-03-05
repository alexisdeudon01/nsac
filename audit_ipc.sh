#!/usr/bin/env bash
#
# audit_ipc.sh - Audit des composants IPC Android (activites, services, receivers, providers)
# Usage: ./audit_ipc.sh <package_name>
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <package_name>"
    echo "Exemple: $0 com.target.app"
    exit 1
fi

PKG="$1"
REPORT_DIR="./reports/${PKG}"
mkdir -p "$REPORT_DIR"

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

# Verification ADB
if ! adb devices | grep -q "device$"; then
    echo -e "${RED}[-]${NC} Aucun appareil ADB connecte."
    exit 1
fi

log_info "Audit IPC pour : $PKG"
log_info "Rapport : $REPORT_DIR/"

# --- Dump complet du manifest ---
log_section "Dump du package"
adb shell pm dump "$PKG" > "$REPORT_DIR/full_dump.txt"
log_info "Dump complet sauvegarde dans full_dump.txt"

# --- Extraction des composants exported ---
log_section "Composants exported"

extract_exported() {
    local component_type="$1"
    local label="$2"
    local output_file="$REPORT_DIR/exported_${component_type}.txt"

    grep -A5 "$component_type" "$REPORT_DIR/full_dump.txt" \
        | grep "exported=true" \
        | sed 's/.*\(com\.[^ ]*\).*/\1/' \
        | sort -u > "$output_file" 2>/dev/null || true

    local count
    count=$(wc -l < "$output_file" | tr -d ' ')
    if [[ "$count" -gt 0 ]]; then
        log_warn "$count $label exported trouvee(s) :"
        while IFS= read -r line; do
            echo "    - $line"
        done < "$output_file"
    else
        log_info "Aucun $label exported."
    fi
}

extract_exported "Activity" "activite(s)"
extract_exported "Service" "service(s)"
extract_exported "Receiver" "receiver(s)"
extract_exported "Provider" "provider(s)"

# --- Permissions dangereuses ---
log_section "Permissions declarees"
adb shell pm dump "$PKG" | grep "permission" | sort -u > "$REPORT_DIR/permissions.txt"

DANGEROUS_PERMS=(
    "CAMERA" "RECORD_AUDIO" "READ_CONTACTS" "WRITE_CONTACTS"
    "ACCESS_FINE_LOCATION" "ACCESS_COARSE_LOCATION" "READ_PHONE_STATE"
    "SEND_SMS" "READ_SMS" "READ_EXTERNAL_STORAGE" "WRITE_EXTERNAL_STORAGE"
    "READ_CALL_LOG" "WRITE_CALL_LOG" "INSTALL_PACKAGES"
)

for perm in "${DANGEROUS_PERMS[@]}"; do
    if grep -qi "$perm" "$REPORT_DIR/permissions.txt"; then
        log_warn "Permission dangereuse : $perm"
    fi
done

# --- Content Providers accessibles ---
log_section "Content Providers"
PROVIDERS=$(adb shell content query --uri "content://$PKG/" 2>&1 || true)
echo "$PROVIDERS" > "$REPORT_DIR/content_providers.txt"

if echo "$PROVIDERS" | grep -q "Row:"; then
    log_warn "Content Provider accessible sans permission !"
    echo "$PROVIDERS" | head -5
else
    log_info "Content Provider non accessible ou protege."
fi

# --- Deeplinks / Intent Filters ---
log_section "Deeplinks et Intent Filters"
adb shell pm dump "$PKG" | grep -A10 "intent-filter" | grep -E "(scheme|host|path)" \
    | sort -u > "$REPORT_DIR/deeplinks.txt" 2>/dev/null || true

if [[ -s "$REPORT_DIR/deeplinks.txt" ]]; then
    log_warn "Deeplinks trouves :"
    while IFS= read -r line; do
        echo "    $line"
    done < "$REPORT_DIR/deeplinks.txt"
else
    log_info "Aucun deeplink detecte."
fi

# --- Backup autorise ? ---
log_section "Backup"
if adb shell pm dump "$PKG" | grep -q "ALLOW_BACKUP"; then
    log_warn "android:allowBackup=true -> extraction de donnees possible via adb backup"
else
    log_info "Backup non autorise."
fi

# --- Resume ---
echo ""
log_info "====== Audit IPC termine ======"
log_info "Rapport complet dans : $REPORT_DIR/"
echo ""
echo "Exemples de tests manuels :"
echo ""
echo "  # Lancer une activite exported"
echo "  adb shell am start -n $PKG/.ExportedActivity"
echo ""
echo "  # Envoyer un broadcast"
echo "  adb shell am broadcast -a com.target.CUSTOM_ACTION -n $PKG/.ExportedReceiver"
echo ""
echo "  # Tester un deeplink"
echo "  adb shell am start -a android.intent.action.VIEW -d 'scheme://host/path'"
echo ""
