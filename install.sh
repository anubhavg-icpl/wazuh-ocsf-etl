#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  wazuh-ocsf-etl  —  Installation Script
#
#  Usage:
#    sudo ./install.sh /path/to/wazuh-ocsf-etl
#
#  What this script does:
#    1. Installs the binary to /usr/local/bin/
#    2. Creates a dedicated system user  wazuh-ocsf
#    3. Creates /opt/wazuh-ocsf/{config,state}
#    4. Writes a default .env (you must edit it before starting)
#    5. Copies config/field_mappings.toml (hot-reloaded at runtime)
#    6. Creates /etc/systemd/system/wazuh-ocsf-etl.service
#    7. Enables and starts the service
#
#  Re-running this script on an existing installation is safe — it will
#  update the binary, config, and service unit without destroying state.
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}── $* ──${RESET}"; }

# ── Argument handling ─────────────────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
    # ── Uninstall ──────────────────────────────────────────────────────────
    echo -e "${BOLD}Uninstalling wazuh-ocsf-etl…${RESET}"
    systemctl stop    wazuh-ocsf-etl 2>/dev/null && ok "Service stopped"      || true
    systemctl disable wazuh-ocsf-etl 2>/dev/null && ok "Service disabled"     || true
    rm -f  /etc/systemd/system/wazuh-ocsf-etl.service && ok "Service unit removed" || true
    systemctl daemon-reload
    rm -f  /usr/local/bin/wazuh-ocsf-etl          && ok "Binary removed"      || true
    echo
    warn "Data directory /opt/wazuh-ocsf has NOT been removed."
    warn "To remove it permanently:  rm -rf /opt/wazuh-ocsf"
    warn "To remove the service user: userdel wazuh-ocsf"
    echo
    ok "Uninstall complete."
    exit 0
fi

if [[ $# -lt 1 ]]; then
    echo -e "${BOLD}Usage:${RESET}  sudo $0 <path-to-wazuh-ocsf-etl-binary>"
    echo
    echo "  Examples:"
    echo "    sudo $0 ./target/release/wazuh-ocsf-etl"
    echo "    sudo $0 /tmp/wazuh-ocsf-etl-v2.0.0"
    echo
    echo "  To uninstall:"
    echo "    sudo $0 --uninstall"
    exit 1
fi

BINARY_SRC="$1"

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root.  Try: sudo $0 $*"
fi

# ── Validate binary ───────────────────────────────────────────────────────────
[[ -f "$BINARY_SRC" ]]       || die "Binary not found: $BINARY_SRC"
[[ -x "$BINARY_SRC" ]]       || chmod +x "$BINARY_SRC"
file "$BINARY_SRC" | grep -q "ELF" || \
    die "$BINARY_SRC does not look like an ELF binary (wrong file?)"

# ── Installer-local paths ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_MAPPINGS="${SCRIPT_DIR}/config/field_mappings.toml"

# ── Install paths ─────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/wazuh-ocsf"
BIN_DEST="/usr/local/bin/wazuh-ocsf-etl"
SERVICE_NAME="wazuh-ocsf-etl"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_USER="wazuh-ocsf"
SERVICE_GROUP="wazuh-ocsf"

# ════════════════════════════════════════════════════════════════════════════
header "Step 1 — Install binary"
# ════════════════════════════════════════════════════════════════════════════

# Stop service before replacing binary (if running)
if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    info "Stopping existing service before update…"
    systemctl stop "${SERVICE_NAME}"
fi

install -m 755 "$BINARY_SRC" "$BIN_DEST"
ok "Binary installed → $BIN_DEST"

BINARY_SIZE=$(du -sh "$BIN_DEST" | cut -f1)
info "Binary size: $BINARY_SIZE"

# ════════════════════════════════════════════════════════════════════════════
header "Step 2 — Create system user"
# ════════════════════════════════════════════════════════════════════════════

if ! id -u "${SERVICE_USER}" &>/dev/null; then
    useradd \
        --system \
        --shell /sbin/nologin \
        --home-dir "${INSTALL_DIR}" \
        --comment "Wazuh OCSF ETL service account" \
        "${SERVICE_USER}"
    ok "System user '${SERVICE_USER}' created"
else
    ok "System user '${SERVICE_USER}' already exists — skipping"
fi

# ════════════════════════════════════════════════════════════════════════════
header "Step 3 — Create directory layout under /opt"
# ════════════════════════════════════════════════════════════════════════════

mkdir -p "${INSTALL_DIR}/config"
mkdir -p "${INSTALL_DIR}/state"
ok "Directories created: ${INSTALL_DIR}/{config,state}"

# ════════════════════════════════════════════════════════════════════════════
header "Step 4 — Write .env configuration"
# ════════════════════════════════════════════════════════════════════════════

ENV_FILE="${INSTALL_DIR}/.env"

if [[ -f "$ENV_FILE" ]]; then
    warn ".env already exists → skipping (edit manually: $ENV_FILE)"
else
    cat > "$ENV_FILE" <<'EOF'
# ══════════════════════════════════════════════════════════════════
#  wazuh-ocsf-etl  —  Runtime configuration
#  Edit this file, then run:  systemctl restart wazuh-ocsf-etl
# ══════════════════════════════════════════════════════════════════

# ── ClickHouse connection ─────────────────────────────────────────
CLICKHOUSE_URL=http://localhost:8123
CLICKHOUSE_DATABASE=wazuh_ocsf
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=

# ── Input source ──────────────────────────────────────────────────
# file   — read alerts.json from disk (default)
# zeromq — subscribe to wazuh-analysisd ZeroMQ PUB socket (no disk I/O)
INPUT_MODE=file

# Path to Wazuh alerts JSON (FILE mode only)
ALERTS_FILE=/var/ossec/logs/alerts/alerts.json

# ZeroMQ URI (ZEROMQ mode only)
# ZEROMQ_URI=tcp://localhost:11111

# ── State / config ────────────────────────────────────────────────
STATE_FILE=/opt/wazuh-ocsf/state/alerts.pos
UNMAPPED_FIELDS_FILE=/opt/wazuh-ocsf/state/unmapped_fields.json
FIELD_MAPPINGS_FILE=/opt/wazuh-ocsf/config/field_mappings.toml

# ── First-run behaviour ───────────────────────────────────────────
# true  = start from current end of file (skip historical data)
# false = process entire alerts.json from the beginning
SEEK_TO_END_ON_FIRST_RUN=true

# ── Throughput tuning ─────────────────────────────────────────────
BATCH_SIZE=5000
FLUSH_INTERVAL_SECS=5
CHANNEL_CAP=50000

# ── Data retention ────────────────────────────────────────────────
# Delete rows older than N days (leave empty to keep forever)
DATA_TTL_DAYS=90

# ── OCSF schema validation ────────────────────────────────────────
# Set false during load testing to skip per-event validation
OCSF_VALIDATE=true

# ── Logging ───────────────────────────────────────────────────────
# Levels: error | warn | info | debug | trace
RUST_LOG=info

# ── Special locations (optional) ─────────────────────────────────
# Comma-separated location names routed to shared tables instead
# of per-agent tables.  Example:
# SPECIAL_LOCATIONS=aws_cloudtrail,okta,azure_ad
EOF
    chmod 640 "$ENV_FILE"
    ok ".env created → $ENV_FILE"
    echo
    warn "╔══════════════════════════════════════════════════════════╗"
    warn "║  ACTION REQUIRED: edit .env before starting the service  ║"
    warn "║  ${ENV_FILE}                 ║"
    warn "╚══════════════════════════════════════════════════════════╝"
fi

# ════════════════════════════════════════════════════════════════════════════
header "Step 5 — Deploy field_mappings.toml"
# ════════════════════════════════════════════════════════════════════════════

MAPPINGS_DEST="${INSTALL_DIR}/config/field_mappings.toml"

if [[ -f "$LOCAL_MAPPINGS" ]]; then
    # Preserve existing customisations — only copy if destination is absent
    if [[ -f "$MAPPINGS_DEST" ]]; then
        warn "field_mappings.toml already exists → skipping (preserving your customisations)"
        info "To reset: cp ${LOCAL_MAPPINGS} ${MAPPINGS_DEST}"
    else
        cp "$LOCAL_MAPPINGS" "$MAPPINGS_DEST"
        ok "field_mappings.toml deployed → $MAPPINGS_DEST"
    fi
else
    # Script is running without the source tree — write a minimal default
    if [[ ! -f "$MAPPINGS_DEST" ]]; then
        cat > "$MAPPINGS_DEST" <<'EOF'
# ══════════════════════════════════════════════════════════════════
#  Wazuh → OCSF → ClickHouse  —  Custom Field Mappings
#  This file is hot-reloaded every 10 seconds.  No restart required.
# ══════════════════════════════════════════════════════════════════

[meta]
# OCSF schema version this deployment targets.
ocsf_version = "1.7.0"

# ── Custom decoder field mappings ─────────────────────────────────
# Map fields from your own decoders to OCSF columns.
#
# [field_mappings]
# "data.win.eventdata.ipAddress" = "src_ip"
# "data.srcip"                   = "src_ip"
# "data.dstip"                   = "dst_ip"
EOF
        ok "Minimal field_mappings.toml written → $MAPPINGS_DEST"
    else
        ok "field_mappings.toml already exists — skipping"
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
header "Step 6 — Set file permissions"
# ════════════════════════════════════════════════════════════════════════════

chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}/config"
chmod 750 "${INSTALL_DIR}/state"
chmod 640 "${INSTALL_DIR}/config/field_mappings.toml"
ok "Ownership: ${SERVICE_USER}:${SERVICE_GROUP} → ${INSTALL_DIR}"

# Add wazuh-ocsf to the wazuh group so it can read alerts.json
if getent group wazuh &>/dev/null; then
    usermod -aG wazuh "${SERVICE_USER}"
    ok "Added '${SERVICE_USER}' to the 'wazuh' group (alerts.json access)"
else
    warn "'wazuh' group not found — if Wazuh is on this host, run:"
    warn "    usermod -aG wazuh ${SERVICE_USER}"
fi

# ════════════════════════════════════════════════════════════════════════════
header "Step 7 — Install systemd service unit"
# ════════════════════════════════════════════════════════════════════════════

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Wazuh → OCSF → ClickHouse ETL pipeline
Documentation=https://github.com/yash22091/wazuh-ocsf-etl
After=network.target
# Uncomment if ClickHouse runs on the same host:
# After=network.target clickhouse-server.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${BIN_DEST}
Restart=on-failure
RestartSec=5s

# Allow time to flush in-flight data on stop
TimeoutStopSec=30

# Hard resource limits
LimitNOFILE=65536
MemoryMax=512M

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}/state
ReadOnlyPaths=/var/ossec/logs/alerts ${INSTALL_DIR}/config
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"
ok "Service unit written → $SERVICE_FILE"

# ════════════════════════════════════════════════════════════════════════════
header "Step 8 — Reload systemd and enable service"
# ════════════════════════════════════════════════════════════════════════════

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
ok "Service enabled (starts on boot)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Installation complete!${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo
echo -e "  Binary       : ${CYAN}${BIN_DEST}${RESET}"
echo -e "  Install dir  : ${CYAN}${INSTALL_DIR}${RESET}"
echo -e "  Config       : ${CYAN}${INSTALL_DIR}/.env${RESET}"
echo -e "  Field map    : ${CYAN}${INSTALL_DIR}/config/field_mappings.toml${RESET}"
echo -e "  State dir    : ${CYAN}${INSTALL_DIR}/state/${RESET}"
echo -e "  Service unit : ${CYAN}${SERVICE_FILE}${RESET}"
echo -e "  Service user : ${CYAN}${SERVICE_USER}${RESET}"
echo
echo -e "${BOLD}Next steps:${RESET}"
echo -e "  1. Edit the configuration file:"
echo -e "       ${CYAN}nano ${INSTALL_DIR}/.env${RESET}"
echo
echo -e "  2. Start the service:"
echo -e "       ${CYAN}systemctl start ${SERVICE_NAME}${RESET}"
echo
echo -e "  3. Watch live logs:"
echo -e "       ${CYAN}journalctl -u ${SERVICE_NAME} -f${RESET}"
echo
echo -e "  4. Check service status:"
echo -e "       ${CYAN}systemctl status ${SERVICE_NAME}${RESET}"
echo
echo -e "  To uninstall:  ${CYAN}sudo ./install.sh --uninstall${RESET}"
echo
