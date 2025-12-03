#!/usr/bin/env bash
# retriever-full-setup.sh
# One-shot, idempotent installer for F1 Box (UPDATED: Wi-Fi + Bluetooth Kismet sources & Tailscale up)
# - Prompts ONLY for registration code (unless --skip-register and secrets already exist)
# - Registers to server and stores .system_config as /etc/retriever/secrets.json
# - Installs/updates: AWS CLI, Tailscale (+ tailscale up), Prometheus node exporter, Zabbix agent
# - Installs Realtek 8812AU driver (aircrack-ng realtek-rtl88xxau) via DKMS (idempotent)
# - Installs Kismet (runs as root) and builds kismet_site.conf with:
#     * all Wi-Fi Realtek dongles (wlx* USB IFs in monitor mode)
#     * all Bluetooth HCI devices (hci0, hci1, …)
# - Clones repo 404AP/project-box-hawk → /opt/kismet_retriever & /opt/milesight_retriever (venvs + services)
# - Sets S3 uploader service for data dirs (if s3_bucket in secrets)

set -euo pipefail

# --- CLI flags ---------------------------------------------------------------
SKIP_REGISTER=0
SKIP_AWS=0
SKIP_TAILSCALE=0
SKIP_KISMET=0
SKIP_S3_CRON=0
SKIP_ZABBIX=0
SKIP_NODE_EXPORTER=0
SKIP_REBOOT=0  # reserved for future use

for arg in "$@"; do
  case "$arg" in
    --skip-register)      SKIP_REGISTER=1 ;;
    --skip-aws)           SKIP_AWS=1 ;;
    --skip-tailscale)     SKIP_TAILSCALE=1 ;;
    --skip-kismet)        SKIP_KISMET=1 ;;
    --skip-s3-cron)       SKIP_S3_CRON=1 ;;
    --skip-zabbix)        SKIP_ZABBIX=1 ;;
    --skip-node-exporter) SKIP_NODE_EXPORTER=1 ;;
    --skip-reboot)        SKIP_REBOOT=1 ;;
    -h|--help)
      cat <<EOF
Usage: $0 [options]

Options:
  --skip-register        Use existing /etc/retriever/secrets.json (no API call)
  --skip-aws             Skip AWS CLI install/config
  --skip-tailscale       Do not touch Tailscale at all (no install, no tailscale up)
  --skip-kismet          Skip Kismet install/config and kismet.service
  --skip-s3-cron         Skip configuring S3 uploader service
  --skip-zabbix          Skip Zabbix agent install/config
  --skip-node-exporter   Skip Prometheus node exporter
  --skip-reboot          Reserved (no reboot currently performed)
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

# --- sudo wrapper -------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then SUDO="sudo"; else SUDO=""; fi

# --- constants ----------------------------------------------------------------
: "${REGISTER_URL:=http://ec2-18-218-124-246.us-east-2.compute.amazonaws.com/api/register/box}"

# Realtek 8812AU driver repo (aircrack-ng)
: "${RTL8812AU_REPO:=https://github.com/aircrack-ng/rtl8812au.git}"

STATE_DIR="/etc/retriever"
SECRETS_JSON="$STATE_DIR/secrets.json"
RUNTIME_JSON="$STATE_DIR/runtime.json"
SETUP_LOG="/var/log/retriever-setup.log"

KISMET_CONF_DIR="/etc/kismet"
KISMET_SITE="$KISMET_CONF_DIR/kismet_site.conf"
KISMET_MAIN="$KISMET_CONF_DIR/kismet.conf"
KISMET_LOG_DIR="/var/log/kismet"
KISMET_SVC="/etc/systemd/system/kismet.service"

REPO_SLUG="404AP/project-box-hawk"
REPO_URL_BASE="https://github.com/${REPO_SLUG}.git"
KISMET_APP_DIR="/opt/kismet_retriever"
MILESIGHT_APP_DIR="/opt/milesight_retriever"
KISMET_DATA_DIR="$KISMET_APP_DIR/data"
MILESIGHT_DATA_DIR="$MILESIGHT_APP_DIR/data"
CRON_TAG="# retriever-s3-sync"

# --- logging ------------------------------------------------------------------
$SUDO mkdir -p "$STATE_DIR" "$(dirname "$SETUP_LOG")" "$KISMET_LOG_DIR"
$SUDO chmod 700 "$STATE_DIR" || true
$SUDO touch "$SETUP_LOG" && $SUDO chmod 640 "$SETUP_LOG" || true
exec > >(tee -a "$SETUP_LOG") 2>&1

echo "==> Retriever setup start $(date -Is)"
echo "==> REGISTER_URL=$REGISTER_URL"
echo "==> Flags: skip_register=$SKIP_REGISTER skip_aws=$SKIP_AWS skip_tailscale=$SKIP_TAILSCALE skip_kismet=$SKIP_KISMET skip_s3_cron=$SKIP_S3_CRON"

# --- baseline packages --------------------------------------------------------
$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
  ca-certificates curl wget gnupg lsb-release unzip jq rsync \
  openssh-server python3 python3-venv python3-pip \
  dkms git build-essential linux-headers-"$(uname -r)" \
  bluetooth bluez libbluetooth-dev ubertooth iw wireless-tools || true

$SUDO systemctl enable --now ssh || true

# --- stop previous services (best-effort) ------------------------------------
# NOTE: we deliberately do NOT touch tailscaled when --skip-tailscale is set
for svc in kismet kismet_listener milesight_api kismet_retriever milesight_retriever \
           zabbix-agent prometheus-node-exporter retriever-upload.service; do
  $SUDO systemctl stop "$svc" 2>/dev/null || true
  $SUDO systemctl disable "$svc" 2>/dev/null || true
done

if [[ "$SKIP_TAILSCALE" -eq 0 ]]; then
  $SUDO systemctl stop tailscaled 2>/dev/null || true
  $SUDO systemctl disable tailscaled 2>/dev/null || true
else
  echo "==> --skip-tailscale: leaving existing tailscaled service alone."
fi

# --- registration -------------------------------------------------------------
if [[ "$SKIP_REGISTER" -eq 0 ]]; then
  read -rp "Enter Registration Code: " REG_CODE
  [[ -z "$REG_CODE" ]] && { echo "Registration code required."; exit 1; }

  PRIMARY_IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')"
  PRIMARY_MAC="$(ip link show dev "$PRIMARY_IFACE" 2>/dev/null | awk '/link\/ether/{print $2}')"
  : "${PRIMARY_MAC:=UNKNOWN}"
  FIRMWARE="$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "1.0.0")"

  REQ_JSON=$(jq -n --arg code "$REG_CODE" --arg mac "$PRIMARY_MAC" --arg fv "$FIRMWARE" \
    '{registration_code:$code, mac_address:$mac, firmware_version:$fv}')
  echo "==> Register payload:"; echo "$REQ_JSON" | jq .

  RESP_FILE="/tmp/registration_response.json"
  $SUDO curl -sS --connect-timeout 5 --max-time 20 --retry 2 --retry-delay 1 \
    -H 'Content-Type: application/json' -d "$REQ_JSON" "$REGISTER_URL" -o "$RESP_FILE"

  jq -e . "$RESP_FILE" >/dev/null 2>&1 || { echo "[error] invalid JSON from server"; cat "$RESP_FILE"; exit 1; }
  [[ "$(jq -r '.success // false' "$RESP_FILE")" == "true" ]] || { echo "[error] registration failed"; jq . "$RESP_FILE"; exit 1; }

  HOSTNAME_NEW="$(jq -r '.hostname // empty' "$RESP_FILE")"
  [[ -n "$HOSTNAME_NEW" && "$HOSTNAME_NEW" != "null" ]] && $SUDO hostnamectl set-hostname "$HOSTNAME_NEW"

  $SUDO mkdir -p "$STATE_DIR"
  jq -e '.system_config' "$RESP_FILE" >/dev/null 2>&1 \
    && $SUDO jq -r '.system_config' "$RESP_FILE" > "$SECRETS_JSON" \
    || { echo "[error] missing system_config"; jq . "$RESP_FILE"; exit 1; }
  $SUDO chmod 600 "$SECRETS_JSON"
else
  echo "==> --skip-register: Skipping server registration; using existing $SECRETS_JSON"
  if [[ ! -f "$SECRETS_JSON" ]]; then
    echo "[ERROR] --skip-register used but $SECRETS_JSON does not exist."
    exit 1
  fi
fi

[[ -f "$RUNTIME_JSON" ]] || $SUDO bash -c "echo '{\"camera_ips\":[]}' > $RUNTIME_JSON && chmod 600 $RUNTIME_JSON"
echo "==> Secrets keys: $(jq -r 'keys|join(", ")' "$SECRETS_JSON")"

# --- AWS CLI v2 ---------------------------------------------------------------
if [[ "$SKIP_AWS" -eq 0 ]]; then
  echo "==> AWS CLI v2"
  TMPD="$($SUDO mktemp -d)"
  $SUDO curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o "$TMPD/awscliv2.zip"
  $SUDO unzip -q "$TMPD/awscliv2.zip" -d "$TMPD"
  if command -v aws >/dev/null 2>&1; then
    $SUDO bash "$TMPD/aws/install" --update || true
  else
    $SUDO bash "$TMPD/aws/install" || true
  fi
  $SUDO rm -rf "$TMPD"

  AWS_DIR="/root/.aws"; $SUDO mkdir -p "$AWS_DIR" && $SUDO chmod 700 "$AWS_DIR"
  AKI="$(jq -r '.aws_access_key_id // empty' "$SECRETS_JSON")"
  ASK="$(jq -r '.aws_secret_access_key // empty' "$SECRETS_JSON")"
  AREG="$(jq -r '.aws_region // "us-east-1"' "$SECRETS_JSON")"
  if [[ -n "$AKI" && -n "$ASK" ]]; then
    $SUDO tee "$AWS_DIR/credentials" >/dev/null <<EOF
[default]
aws_access_key_id=$AKI
aws_secret_access_key=$ASK
EOF
    $SUDO chmod 600 "$AWS_DIR/credentials"
    $SUDO tee "$AWS_DIR/config" >/dev/null <<EOF
[default]
region=$AREG
output=json
EOF
    $SUDO chmod 600 "$AWS_DIR/config"
  fi
else
  echo "==> --skip-aws: Skipping AWS CLI install/config."
fi

# --- Tailscale (install + up) -------------------------------------------------
if [[ "$SKIP_TAILSCALE" -eq 0 ]]; then
  echo "==> Tailscale"
  $SUDO curl -fsSL https://tailscale.com/install.sh | $SUDO bash -s -- || true
  $SUDO systemctl enable --now tailscaled || true
  TS_KEY="$(jq -r '.tailscale_auth_key // empty' "$SECRETS_JSON")"
  if [[ -n "$TS_KEY" && "$TS_KEY" != "null" ]]; then
    # retry-friendly tailscale up
    $SUDO tailscale up --authkey "$TS_KEY" --hostname "$(hostname)" --reset || true
    $SUDO tailscale up --authkey "$TS_KEY" --hostname "$(hostname)" || true
  else
    echo "==> No tailscale_auth_key in secrets; skipping tailscale up."
  fi
else
  echo "==> --skip-tailscale: Skipping Tailscale install and configuration."
fi

# --- Prometheus node exporter -------------------------------------------------
if [[ "$SKIP_NODE_EXPORTER" -eq 0 ]]; then
  echo "==> Prometheus Node Exporter"
  $SUDO apt-get install -y prometheus-node-exporter || true
  $SUDO systemctl enable --now prometheus-node-exporter || true
else
  echo "==> --skip-node-exporter: Skipping node exporter install."
fi

# --- Realtek 8812AU DKMS (patched & fixed) -----------------------------------
echo "==> Realtek 8812AU DKMS (patched & fixed)"

DRV_CLONE="/usr/src/rtl8812au"
# Wipe old clone
if [[ -d "$DRV_CLONE" ]]; then
  $SUDO rm -rf "$DRV_CLONE"
fi

# Clone the repo
$SUDO git clone --depth 1 "$RTL8812AU_REPO" "$DRV_CLONE"

# Extract package name/version directly from dkms.conf (robust; no funky awk quoting)
PN="$($SUDO grep -E '^PACKAGE_NAME' "$DRV_CLONE/dkms.conf" | head -1 | cut -d= -f2 | tr -d ' "')" || true
PV="$($SUDO grep -E '^PACKAGE_VERSION' "$DRV_CLONE/dkms.conf" | head -1 | cut -d= -f2 | tr -d ' "')" || true

echo "Detected DKMS module: ${PN:-UNKNOWN} / ${PV:-UNKNOWN}"

if [[ -n "${PN:-}" && -n "${PV:-}" ]]; then
  DKMS_DIR="/usr/src/${PN}-${PV}"

  # Rename cloned source to the expected DKMS directory
  $SUDO rm -rf "$DKMS_DIR" 2>/dev/null || true
  $SUDO mv "$DRV_CLONE" "$DKMS_DIR"

  # Remove any old DKMS entries
  $SUDO dkms remove -m "$PN" -v "$PV" --all 2>/dev/null || true

  # Add/build/install for the current kernel
  $SUDO dkms add -m "$PN" -v "$PV" || true
  $SUDO dkms build -m "$PN" -v "$PV" || true
  $SUDO dkms install -m "$PN" -v "$PV" || true

  $SUDO depmod -a

  # Try loading module with most common names
  $SUDO modprobe "$PN" 2>/dev/null || \
  $SUDO modprobe 8812au 2>/dev/null || \
  $SUDO modprobe 88XXau 2>/dev/null || \
  $SUDO modprobe rtl8812au 2>/dev/null || true

  echo "==> Installed 8812AU modules:"
  $SUDO find /lib/modules/"$(uname -r)" -type f -name '*8812*au*.ko' -print 2>/dev/null || true
else
  echo "[WARN] Could not parse PACKAGE_NAME / PACKAGE_VERSION from dkms.conf; skipping DKMS registration."
fi

# --- Kismet install & cumulative Wi-Fi + Bluetooth config ---------------------
if [[ "$SKIP_KISMET" -eq 0 ]]; then
  echo "==> Kismet install & config"
  CODENAME="$($SUDO lsb_release -cs || echo jammy)"
  $SUDO wget -qO- https://www.kismetwireless.net/repos/kismet-release.gpg.key | $SUDO gpg --dearmor > /usr/share/keyrings/kismet-archive-keyring.gpg
  $SUDO tee /etc/apt/sources.list.d/kismet.list >/dev/null <<EOF
deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/${CODENAME} ${CODENAME} main
EOF
  $SUDO apt-get update
  $SUDO apt-get install -y kismet kismet-capture-linux-bluetooth || true

  $SUDO mkdir -p "$KISMET_CONF_DIR" "$KISMET_LOG_DIR"
  $SUDO chown -R root:root "$KISMET_CONF_DIR" "$KISMET_LOG_DIR"
  $SUDO chmod 755 "$KISMET_LOG_DIR" || true

  # Ensure main config with explicit include and configdir (trailing slash)
  $SUDO tee "$KISMET_MAIN" >/dev/null <<'EOF'
configdir=/etc/kismet
logprefix=/var/log/kismet
allowplugins=true
include=/etc/kismet/kismet_site.conf
httpd_home=/usr/share/kismet/httpd
EOF
  $SUDO chmod 644 "$KISMET_MAIN"

  # --- Build kismet_site.conf cumulatively (Wi-Fi + BT) ------------------------
  # Any wlx* is considered a USB Wi-Fi dongle; we do NOT fall back to builtin NICs.
  # We will:
  #   - Use existing wlx* monitor interfaces directly
  #   - Convert wlx* managed interfaces into monitor mode (in-place or via IFmon)
  EXCLUDE_IF_REGEX='^(wlo1|wlp2s0)$'   # internal NICs; do not touch

  WIFI_SOURCES=()
  WIFI_BASE_IFACES=()

  # Parse iw dev output: "iface type" lines
  while read -r IFACE TYPE; do
    # Only care about wlx* (USB) and not excluded ones
    if [[ "$IFACE" =~ ^wlx ]] && ! [[ "$IFACE" =~ $EXCLUDE_IF_REGEX ]]; then
      if [[ "$TYPE" == "monitor" ]]; then
        # already monitor; just use it
        WIFI_SOURCES+=("$IFACE")
      elif [[ "$TYPE" == "managed" ]]; then
        # managed; we will try to convert/create a monitor
        WIFI_BASE_IFACES+=("$IFACE")
      fi
    fi
  done < <($SUDO iw dev 2>/dev/null | awk '/Interface/ {iface=$2} /type/ {print iface, $2}')

  if [[ ${#WIFI_SOURCES[@]} -eq 0 && ${#WIFI_BASE_IFACES[@]} -eq 0 ]]; then
    echo "==> No wlx* USB Wi-Fi dongles detected; Kismet will run without Wi-Fi sources."
  else
    echo "==> Found USB Wi-Fi IFs (managed): ${WIFI_BASE_IFACES[*]:-none}"
    echo "==> Existing monitor IFs:          ${WIFI_SOURCES[*]:-none}"
  fi

  # For each managed wlx*, create or convert to a monitor interface and add to sources
  for IF in "${WIFI_BASE_IFACES[@]}"; do
    MON="${IF}mon"

    # If a dedicated MON iface already exists, just bring it up and use it
    if $SUDO iw dev 2>/dev/null | awk '/Interface/ {n=$2} /type/ {if ($2=="monitor" && n=="'"$MON"'") {print; exit}}' | grep -q .; then
      $SUDO ip link set "$MON" up 2>/dev/null || true
      WIFI_SOURCES+=("$MON")
      continue
    fi

    # Otherwise, try to convert the base iface to monitor in-place first
    $SUDO ip link set "$IF" down 2>/dev/null || true
    if $SUDO iw dev "$IF" set type monitor 2>/dev/null; then
      $SUDO ip link set "$IF" up 2>/dev/null || true
      # Confirm it's now monitor
      if $SUDO iw dev 2>/dev/null | awk '/Interface/ {n=$2} /type/ {if ($2=="monitor" && n=="'"$IF"'") {print; exit}}' | grep -q .; then
        WIFI_SOURCES+=("$IF")
        continue
      fi
    fi

    # If in-place conversion failed, fall back to creating a separate MON iface
    if ! $SUDO iw dev 2>/dev/null | awk '/Interface/ {n=$2} /type/ {if ($2=="monitor" && n=="'"$MON"'") {print; exit}}' | grep -q .; then
      $SUDO iw dev "$IF" interface add "$MON" type monitor 2>/dev/null || true
      $SUDO ip link set "$MON" up 2>/dev/null || true
    fi

    # Verify the MON iface exists as monitor and add it
    if $SUDO iw dev 2>/dev/null | awk '/Interface/ {n=$2} /type/ {if ($2=="monitor" && n=="'"$MON"'") {print; exit}}' | grep -q .; then
      WIFI_SOURCES+=("$MON")
    fi
  done

  echo "==> Wi-Fi monitor sources: ${WIFI_SOURCES[*]:-none}"

  # Detect Bluetooth HCI adapters (hci0, hci1, ...)
  BT_SOURCES=()
  if [[ -d /sys/class/bluetooth ]]; then
    while read -r HCI; do
      [[ -n "$HCI" ]] && BT_SOURCES+=("$HCI")
    done < <(ls /sys/class/bluetooth 2>/dev/null || true)
  fi
  echo "==> Bluetooth sources: ${BT_SOURCES[*]:-none}"

  # Write kismet_site.conf (Wi-Fi + BT sources only; main config already set httpd_home, etc.)
  $SUDO tee "$KISMET_SITE" >/dev/null <<'EOF'
# Auto-generated by retriever installer
logprefix=/var/log/kismet
allowplugins=true
# Default User
httpd_username=admin
httpd_password=admin123
httpd_jwt_key=7951B0B010E99E9AF0A957712E649338
helper_binary_path=/usr/bin/
# Wi-Fi and Bluetooth sources appended below
EOF

  for SRC in "${WIFI_SOURCES[@]}"; do
    echo "source=${SRC}:name=${SRC}" | $SUDO tee -a "$KISMET_SITE" >/dev/null
  done
  for H in "${BT_SOURCES[@]}"; do
    echo "source=${H}:name=${H}" | $SUDO tee -a "$KISMET_SITE" >/dev/null
  done
  $SUDO chmod 644 "$KISMET_SITE"
  # --------------------- end Wi-Fi+BT block; next is systemd unit -------------

  # --- Kismet HTTPD user + config location (admin/admin123) ------------------
  # Make Kismet use /etc/kismet as HOME so ~/.kismet lives under /etc
  # and never under /root; then create an admin user non-interactively.
  if [[ ! -e "$KISMET_CONF_DIR/.kismet" ]]; then
    $SUDO ln -s "$KISMET_CONF_DIR" "$KISMET_CONF_DIR/.kismet" 2>/dev/null || true
  fi

  echo "==> Creating Kismet admin user 'admin' with password 'admin123'"
  # Use HOME override so kismet_httpd.conf ends up under /etc/kismet/.kismet/
  # (which symlinks back into /etc/kismet)
  $SUDO HOME="$KISMET_CONF_DIR" timeout 20 kismet --no-ncurses --create-user "admin:admin123:admin" >/dev/null 2>&1 || true

  echo "==> Ensuring Kismet HTTPD config is persistent..."

  # Make sure /root/.kismet exists
  $SUDO mkdir -p /root/.kismet
  $SUDO chown root:root /root/.kismet
  $SUDO chmod 700 /root/.kismet

  # Delete any conflicting files
  if [[ -f /root/.kismet/kismet_httpd.conf ]]; then
    $SUDO rm -f /root/.kismet/kismet_httpd.conf
  fi

  # Symlink to our managed config
  $SUDO ln -s /etc/kismet/kismet_httpd.conf /root/.kismet/kismet_httpd.conf

  echo "==> Linked /etc/kismet/kismet_httpd.conf → /root/.kismet/kismet_httpd.conf"
  # systemd unit (run Kismet as root, with HOME=/etc/kismet)
  $SUDO tee "$KISMET_SVC" >/dev/null <<'EOF'
[Unit]
Description=Kismet Wireless IDS (root)
After=network-online.target
Wants=network-online.target

[Service]
User=root
Group=root
Environment=HOME=/etc/kismet
ExecStart=/usr/bin/kismet --no-ncurses --config=/etc/kismet/kismet.conf
WorkingDirectory=/root
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now kismet || true
else
  echo "==> --skip-kismet: Skipping Kismet install and configuration."
fi

# --- Zabbix Agent (official repo for Ubuntu 24.04) ----------------------------
if [[ "$SKIP_ZABBIX" -eq 0 ]]; then
  echo "==> Zabbix Agent (Zabbix 7.2 for Ubuntu 24.04)"

  ZBX_DEB_URL="https://repo.zabbix.com/zabbix/7.2/release/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest_7.2+ubuntu24.04_all.deb"
  TMPZ="$($SUDO mktemp -d)"

  # Install repo if zabbix-agent is missing
  if ! apt-cache show zabbix-agent >/dev/null 2>&1; then
    echo "==> Adding Zabbix repo..."
    $SUDO wget -qO "$TMPZ/zabbix-release.deb" "$ZBX_DEB_URL" || {
      echo "[WARN] Failed to download Zabbix repo package."
    }

    if [[ -f "$TMPZ/zabbix-release.deb" ]]; then
      $SUDO dpkg -i "$TMPZ/zabbix-release.deb" || echo "[WARN] dpkg install of Zabbix repo failed."
      $SUDO apt-get update || true
    fi
  fi

  $SUDO rm -rf "$TMPZ"

  # Install Zabbix Agent if available
  if apt-cache show zabbix-agent >/dev/null 2>&1; then
    echo "==> Installing zabbix-agent..."
    $SUDO apt-get install -y zabbix-agent || echo "[WARN] zabbix-agent installation failed."

    ZBX_CONF="/etc/zabbix/zabbix_agentd.conf"
    _raw_server="$(jq -r '.zabbix_server // empty' "$SECRETS_JSON" 2>/dev/null || echo "")"
    ZBX_SERVER="$(echo "$_raw_server" | sed -E 's#^[a-z]+://##; s#/.*$##')"
    ZBX_HOSTNAME="$(hostname)"
    ZBX_METADATA="$(jq -r '.zabbix_hostmetadata // "Linux Server"' "$SECRETS_JSON" 2>/dev/null || echo "Linux Server")"

    # Apply configuration only if config file exists
    if [[ -f "$ZBX_CONF" ]]; then
      echo "==> Configuring zabbix-agent..."
      $SUDO sed -i -e "/^ServerActive=/d" -e "/^Hostname=/d" -e "/^HostMetadata=/d" "$ZBX_CONF"

      [[ -n "$ZBX_SERVER" ]] && echo "ServerActive=$ZBX_SERVER" | $SUDO tee -a "$ZBX_CONF" >/dev/null
      echo "Hostname=$ZBX_HOSTNAME"     | $SUDO tee -a "$ZBX_CONF" >/dev/null
      echo "HostMetadata=$ZBX_METADATA" | $SUDO tee -a "$ZBX_CONF" >/dev/null

      $SUDO systemctl enable --now zabbix-agent || true
      echo "==> Zabbix Agent installed & running."
    else
      echo "[WARN] zabbix_agentd.conf missing after installation."
    fi
  else
    echo "[WARN] zabbix-agent package still not available after adding repo."
  fi
else
  echo "==> --skip-zabbix: Skipping Zabbix agent."
fi

# --- deploy project-box-hawk apps --------------------------------------------
echo "==> Deploy apps from ${REPO_SLUG}"
WORKDIR="$($SUDO mktemp -d)"
GH_TOKEN="$(jq -r '.github_token // empty' "$SECRETS_JSON" 2>/dev/null || echo "")"
REPO_URL="$REPO_URL_BASE"
[[ -n "$GH_TOKEN" && "$GH_TOKEN" != "null" ]] && REPO_URL="https://${GH_TOKEN}:x-oauth-basic@github.com/${REPO_SLUG}.git"
$SUDO git clone --depth 1 "$REPO_URL" "$WORKDIR/repo" || { echo "[error] clone failed"; rm -rf "$WORKDIR"; exit 1; }

$SUDO install -d "$KISMET_APP_DIR" "$MILESIGHT_APP_DIR"
$SUDO rsync -a --delete "$WORKDIR/repo/kismet_retriever/"    "$KISMET_APP_DIR/" || true
$SUDO rsync -a --delete "$WORKDIR/repo/milesight_retriever/" "$MILESIGHT_APP_DIR/" || true

# Install uploader script from repo root to /usr/local/bin
if [[ -f "$WORKDIR/repo/retriever-upload-gz.sh" ]]; then
  echo "==> Installing retriever-upload-gz.sh to /usr/local/bin"
  $SUDO install -m 755 "$WORKDIR/repo/retriever-upload-gz.sh" /usr/local/bin/retriever-upload-gz.sh
else
  echo "[WARN] retriever-upload-gz.sh not found in repo root; uploader service may not work."
fi

rm -rf "$WORKDIR"

for appdir in "$KISMET_APP_DIR" "$MILESIGHT_APP_DIR"; do
  if [[ -f "$appdir/requirements.txt" ]]; then
    $SUDO python3 -m venv "$appdir/.venv"
    $SUDO "$appdir/.venv/bin/pip" install -U pip wheel setuptools
    $SUDO "$appdir/.venv/bin/pip" install -r "$appdir/requirements.txt" || true
  fi
done

$SUDO tee /etc/systemd/system/kismet_retriever.service >/dev/null <<EOF
[Unit]
Description=Kismet Retriever
After=network-online.target
Wants=network-online.target
[Service]
WorkingDirectory=$KISMET_APP_DIR
ExecStart=$KISMET_APP_DIR/.venv/bin/python -m kismet_retriever
Environment=RETRIEVER_SECRETS=$SECRETS_JSON
Environment=RETRIEVER_RUNTIME=$RUNTIME_JSON
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

$SUDO tee /etc/systemd/system/milesight_retriever.service >/dev/null <<EOF
[Unit]
Description=Milesight Retriever
After=network-online.target
Wants=network-online.target
[Service]
WorkingDirectory=$MILESIGHT_APP_DIR
ExecStart=$MILESIGHT_APP_DIR/.venv/bin/python -m milesight_retriever
Environment=RETRIEVER_SECRETS=$SECRETS_JSON
Environment=RETRIEVER_RUNTIME=$RUNTIME_JSON
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

$SUDO systemctl daemon-reload
$SUDO systemctl enable --now kismet_retriever milesight_retriever || true

# --- S3 uploader service + timer (replaces cron entirely) ---------------------
if [[ "$SKIP_S3_CRON" -eq 0 ]]; then
  echo "==> Installing S3 upload service + timer"

  # Ensure data directories exist
  $SUDO mkdir -p "$KISMET_DATA_DIR" "$MILESIGHT_DATA_DIR"

  # Ensure uploader script exists (repo should copy it to /usr/local/bin)
  if [[ -f /usr/local/bin/retriever-upload-gz.sh ]]; then
    echo "==> Uploader script present at /usr/local/bin/retriever-upload-gz.sh"
    $SUDO chmod +x /usr/local/bin/retriever-upload-gz.sh
  else
    echo "==> ERROR: retriever-upload-gz.sh missing — S3 uploads will fail."
  fi

  # --- Create the systemd service ------------------------------------------
  echo "==> Creating retriever-upload.service"
  $SUDO tee /etc/systemd/system/retriever-upload.service >/dev/null <<'EOF'
[Unit]
Description=Retriever S3 GZ uploader
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/retriever-upload-gz.sh
Nice=10
EOF

  # --- Create the systemd timer --------------------------------------------
  echo "==> Creating retriever-upload.timer"
  $SUDO tee /etc/systemd/system/retriever-upload.timer >/dev/null <<'EOF'
[Unit]
Description=Run Retriever S3 uploader every minute

[Timer]
OnBootSec=30sec
OnUnitActiveSec=60sec
AccuracySec=10sec
Unit=retriever-upload.service
Persistent=true

[Install]
WantedBy=timers.target
EOF

  # Reload, enable, and start timer
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now retriever-upload.timer || {
    echo "==> ERROR: Failed to start retriever-upload.timer"
  }

  echo "==> S3 upload service & timer installed and active."
else
  echo "==> --skip-s3-cron: Skipping S3 uploader service + timer."
fi

# --- summary ------------------------------------------------------------------
echo
echo "========================"
echo " Retriever setup complete"
echo "========================"
echo "Hostname:            $(hostname)"
echo "Kismet:              $(systemctl is-active kismet 2>/dev/null || echo inactive) / $(systemctl is-enabled kismet 2>/dev/null || echo disabled)"
echo "kismet_retriever:    $(systemctl is-active kismet_retriever 2>/dev/null || echo inactive)"
echo "milesight_retriever: $(systemctl is-active milesight_retriever 2>/dev/null || echo inactive)"
echo "Zabbix agent:        $(systemctl is-active zabbix-agent 2>/dev/null || echo inactive)"
echo "Uploader Service:   $(systemctl is-active retriever-upload.service 2>/dev/null || echo inactive)"
echo "Uploader Timer:     $(systemctl is-active retriever-upload.timer 2>/dev/null || echo inactive)"
echo "Node exporter:       $(systemctl is-active prometheus-node-exporter 2>/dev/null || echo inactive)"
if [[ "$SKIP_TAILSCALE" -eq 0 ]]; then
  echo "Tailscale:           $(systemctl is-active tailscaled 2>/dev/null || echo inactive)"
else
  echo "Tailscale:           skipped (--skip-tailscale)"
fi
echo "S3 uploader:         $(systemctl is-active retriever-upload.service 2>/dev/null || echo inactive)"
echo
echo "Kismet Web UI:"
echo "  URL:   http://<box-ip>:2501/"
echo "  Login: admin / admin123"
echo
echo "Logs:"
echo "  - Kismet:     journalctl -u kismet -n 120 --no-pager"
echo "  - Installer:  $SETUP_LOG"
echo

# (No reboot is currently performed; --skip-reboot is reserved for future behavior)
