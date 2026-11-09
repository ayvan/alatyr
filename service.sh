#!/bin/sh
# Install alatyr as an autostart service.
#
#   macOS:  ./service.sh install      LaunchAgent, starts at user login
#           sudo ./service.sh install LaunchDaemon, starts at boot
#   Linux:  sudo ./service.sh install systemd unit, starts at boot
#
#   ./service.sh uninstall | status | logs   (use sudo if installed with sudo)
set -e
DIR=$(cd "$(dirname "$0")" && pwd)
BIN="$DIR/alatyr"
CFG="$DIR/config.yaml"
NAME=alatyr
LABEL=com.alatyr
LOG="$DIR/alatyr.out.log"

[ -x "$BIN" ] || { echo "alatyr binary not found in $DIR"; exit 1; }
[ -f "$CFG" ] || { echo "config.yaml not found in $DIR"; exit 1; }

mac_plist() {
  if [ "$(id -u)" = 0 ]; then
    echo "/Library/LaunchDaemons/$LABEL.plist"
  else
    echo "$HOME/Library/LaunchAgents/$LABEL.plist"
  fi
}
mac_domain() {
  if [ "$(id -u)" = 0 ]; then echo system; else echo "gui/$(id -u)"; fi
}

mac() {
  plist=$(mac_plist)
  case "$1" in
  install)
    mkdir -p "$(dirname "$plist")"
    user_key=""
    if [ "$(id -u)" = 0 ] && [ -n "$SUDO_USER" ]; then
      user_key="<key>UserName</key><string>$SUDO_USER</string>"
    fi
    cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$BIN</string><string>--config</string><string>$CFG</string></array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
  $user_key
</dict>
</plist>
PLIST
    launchctl bootout "$(mac_domain)/$LABEL" 2>/dev/null || true
    launchctl bootstrap "$(mac_domain)" "$plist"
    echo "installed $plist; logs: $LOG"
    ;;
  uninstall)
    launchctl bootout "$(mac_domain)/$LABEL" 2>/dev/null || true
    rm -f "$plist"
    echo "removed $plist"
    ;;
  status) launchctl print "$(mac_domain)/$LABEL" | head -20 ;;
  logs) tail -n 100 -f "$LOG" ;;
  *) usage ;;
  esac
}

linux() {
  unit=/etc/systemd/system/$NAME.service
  case "$1" in
  install)
    [ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
    run_user=${SUDO_USER:-root}
    cat > "$unit" <<UNIT
[Unit]
Description=Alatyr AmneziaWG relay
After=network-online.target
Wants=network-online.target

[Service]
User=$run_user
WorkingDirectory=$DIR
ExecStart=$BIN --config $CFG
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now "$NAME"
    echo "installed $unit (runs as $run_user); logs: journalctl -u $NAME -f"
    ;;
  uninstall)
    [ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
    systemctl disable --now "$NAME" 2>/dev/null || true
    rm -f "$unit"
    systemctl daemon-reload
    echo "removed $unit"
    ;;
  status) systemctl status "$NAME" --no-pager ;;
  logs) journalctl -u "$NAME" -f ;;
  *) usage ;;
  esac
}

usage() { echo "usage: $0 install|uninstall|status|logs"; exit 1; }

case "$(uname -s)" in
  Darwin) mac "$1" ;;
  Linux) linux "$1" ;;
  *) echo "unsupported OS; on Windows use autostart-windows.vbs"; exit 1 ;;
esac
