#!/bin/zsh
# Builds Nexio.app (the Mac receiver) and installs it as a LaunchAgent (starts at login).
set -euo pipefail
cd "${0:A:h}"

APP="$HOME/Applications/Nexio.app"
BIN="$APP/Contents/MacOS/nexio-mac"
DATA_DIR="$HOME/Library/Application Support/Nexio"
LABEL="com.nexio.mac"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

mkdir -p "$DATA_DIR" "$HOME/Library/LaunchAgents" "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O NexioMac.swift -o "$BIN"
cp Info.plist "$APP/Contents/Info.plist"
cp AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
codesign --force --sign - "$APP"
rm -f "$DATA_DIR/nexio-mac"   # binary location used by older versions

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$BIN</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>$DATA_DIR/nexio.log</string>
  <key>StandardErrorPath</key><string>$DATA_DIR/nexio.log</string>
</dict>
</plist>
PLIST

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

echo "Installed $APP"
echo "Pairing code: $("$BIN" pair)"
echo "Logs: $DATA_DIR/nexio.log"
