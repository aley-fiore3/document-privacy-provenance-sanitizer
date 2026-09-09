#!/bin/zsh
set -eu

workflow_root="$1"
dpps_bin="$2"
mkdir -p "$workflow_root/Logs"

if "$dpps_bin" process-once "$workflow_root" --privacy-names >> "$workflow_root/Logs/processor.log" 2>&1; then
  /usr/bin/osascript -e 'display notification "New documents were processed. Check Clean and Review." with title "Fiore3 Document Privacy"' || true
else
  /usr/bin/osascript -e 'display notification "Processing needs attention. Check Review and Logs." with title "Fiore3 Document Privacy"' || true
  exit 1
fi
