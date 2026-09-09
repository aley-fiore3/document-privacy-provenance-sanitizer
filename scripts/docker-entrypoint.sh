#!/bin/sh
set -eu

# Keep malware definitions current for long-running containers. Processing
# still fails closed if clamscan itself is unavailable or returns an error.
freshclam --daemon --checks=12 >/tmp/freshclam.log 2>&1 || true

if [ "${1:-}" = "serve" ]; then
  shift
  set -- uvicorn dpps.api:app --host 0.0.0.0 --port "${PORT:-8080}" --no-server-header "$@"
fi

exec gosu dpps "$@"
