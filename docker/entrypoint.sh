#!/bin/sh
# Starts as root only to make /data owned by PUID:PGID, then drops privileges before Node runs.
# Started as non-root (e.g. podman --userns=keep-id), it leaves ownership alone; the server checks
# /data is writable and stops with a clear message if not.
set -eu
DATA_DIR="${DATA_DIR:-/data}"
fail() { echo "authwapi-entrypoint: $*" >&2; exit 1; }
if [ "$(id -u)" = "0" ]; then
  PUID="${PUID:-1000}"
  PGID="${PGID:-1000}"
  case "$PUID$PGID" in *[!0-9]*) fail "PUID and PGID must be numbers";; esac
  # Numeric comparison, so "00" counts as 0 too.
  [ "$PUID" -ne 0 ] && [ "$PGID" -ne 0 ] || fail "PUID/PGID 0 would run the server as root; pick a normal user"
  [ ! -L "$DATA_DIR" ] || fail "$DATA_DIR is a symlink; mount a real folder"
  mkdir -p "$DATA_DIR"
  # -h changes symlinks themselves, never their targets; -xdev stays on this mount.
  find "$DATA_DIR" -xdev \( ! -user "$PUID" -o ! -group "$PGID" \) -exec chown -h "$PUID:$PGID" {} +
  exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups node /app/src/server.ts
fi
exec node /app/src/server.ts
