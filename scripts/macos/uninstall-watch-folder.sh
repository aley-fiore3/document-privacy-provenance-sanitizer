#!/bin/zsh
set -eu

label="com.fiore3.document-privacy-sanitizer"
plist="$HOME/Library/LaunchAgents/$label.plist"
/bin/launchctl bootout "gui/$UID/$label" 2>/dev/null || true
if [[ -f "$plist" ]]; then
  /bin/mv "$plist" "$HOME/.Trash/$label.plist"
fi
print "Watch service removed. Workflow documents were left in place."
