#!/bin/zsh
set -eu

script_dir="${0:A:h}"
workflow_root="${1:-$HOME/Documents/Fiore3-Document-Privacy}"
dpps_bin="${DPPS_BIN:-${script_dir:h:h}/.venv/bin/dpps}"
label="com.fiore3.document-privacy-sanitizer"
plist="$HOME/Library/LaunchAgents/$label.plist"

if [[ ! -x "$dpps_bin" ]]; then
  print -u2 "dpps was not found at $dpps_bin. Set DPPS_BIN to the installed executable."
  exit 1
fi

"$dpps_bin" init "$workflow_root"
mkdir -p "$HOME/Library/LaunchAgents" "$workflow_root/Logs"

escaped_runner=${script_dir//&/&amp;}/process-and-notify.sh
escaped_root=${workflow_root//&/&amp;}
escaped_dpps=${dpps_bin//&/&amp;}

cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array>
    <string>$escaped_runner</string>
    <string>$escaped_root</string>
    <string>$escaped_dpps</string>
  </array>
  <key>WatchPaths</key>
  <array><string>$escaped_root/Incoming</string></array>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>$escaped_root/Logs/launchd.out.log</string>
  <key>StandardErrorPath</key><string>$escaped_root/Logs/launchd.err.log</string>
</dict>
</plist>
PLIST

/bin/launchctl bootout "gui/$UID/$label" 2>/dev/null || true
/bin/launchctl bootstrap "gui/$UID" "$plist"
/bin/launchctl enable "gui/$UID/$label"
print "Watch folder installed: $workflow_root/Incoming"
print "Clean outputs use privacy-safe filenames. Originals and reports are preserved."
