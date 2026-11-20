#!/usr/bin/env bash
# Linux container checks for the AuthWAPI image: data-folder ownership and modes, rootless podman, SELinux,
# refused PUID/symlinks, and crash safety of the database under SIGKILL.
#
#   scripts/container-check.sh            # all checks
#   scripts/container-check.sh 2 5        # only some (the image is always built)
#
# Rootful checks use `docker` on /var/run/docker.sock if it is usable, else `sudo docker`, else `sudo podman`.
# sudo runs non-interactively; to give it a password, set SUDO_PASSWORD_FILE to a file holding it.
# Temp folders go under $TMPDIR (default /tmp), never $HOME. Port 4199 on 127.0.0.1.
set -uo pipefail

PORT=4199
BASE_URL="http://localhost:$PORT"
RUN_ID="acheck-$$"
IMG="localhost/authwapi-check:$$"
CYCLES="${CYCLES:-50}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/authwapi-check.XXXXXX")"
FAILS=0
CONTAINERS=()

say() { printf '%s\n' "$*"; }
pass() { say "PASS [$1] $2"; }
fail() { say "FAIL [$1] $2"; FAILS=$((FAILS + 1)); }

# --- rootful engine -------------------------------------------------------------------------------------
SUDO=(sudo -n)
if [ -n "${SUDO_PASSWORD_FILE:-}" ]; then
  printf '#!/bin/sh\nexec cat "%s"\n' "$SUDO_PASSWORD_FILE" > "$T/askpass"
  chmod 700 "$T/askpass"
  export SUDO_ASKPASS="$T/askpass"
  SUDO=(sudo -A)
fi
ROOTFUL=()
if docker -H unix:///var/run/docker.sock info >/dev/null 2>&1; then
  ROOTFUL=(docker -H unix:///var/run/docker.sock)
elif "${SUDO[@]}" docker -H unix:///var/run/docker.sock info >/dev/null 2>&1; then
  ROOTFUL=("${SUDO[@]}" docker -H unix:///var/run/docker.sock)
elif "${SUDO[@]}" podman info >/dev/null 2>&1; then
  ROOTFUL=("${SUDO[@]}" podman)
fi
rootful() { "${ROOTFUL[@]}" "$@"; }

cleanup() {
  for c in "${CONTAINERS[@]}"; do
    podman rm -f "$c" >/dev/null 2>&1
    [ ${#ROOTFUL[@]} -gt 0 ] && rootful rm -f "$c" >/dev/null 2>&1
  done
  podman rmi -f "$IMG" >/dev/null 2>&1
  [ ${#ROOTFUL[@]} -gt 0 ] && rootful rmi -f "$IMG" >/dev/null 2>&1
  rm -rf "$T" 2>/dev/null || podman unshare rm -rf "$T" 2>/dev/null || say "WARN: could not remove $T"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

name() { local n="$RUN_ID-$1"; CONTAINERS+=("$n"); printf '%s' "$n"; }

# Waits for /health; $1 = engine command prefix (rootful|podman), $2 = container.
wait_health() {
  local i
  for i in $(seq 1 60); do
    if curl -fsS "$BASE_URL/health" 2>/dev/null | grep -q '"ok"'; then return 0; fi
    [ "$($1 inspect -f '{{.State.Running}}' "$2" 2>/dev/null)" = "true" ] || return 1
    sleep 0.5
  done
  return 1
}

# Signs up, then checks the outbox JSON is readable by this user, and ownership/modes of the whole folder.
assert_data() { # $1 check id, $2 data dir, $3 email
  local id="$1" dir="$2" code f bad
  code=$(curl -s -o "$T/signup.out" -w '%{http_code}' -X POST "$BASE_URL/api/auth/sign-up/email" \
    -H "origin: $BASE_URL" -H 'content-type: application/json' \
    -d "{\"email\":\"$3\",\"password\":\"correct-horse-battery-staple\",\"name\":\"Check\"}")
  [ "$code" = 200 ] && pass "$id" "sign-up HTTP $code" || { fail "$id" "sign-up HTTP $code: $(head -c 300 "$T/signup.out")"; return; }
  for _ in $(seq 1 20); do f=$(find "$dir/outbox" -type f -name '*.json' 2>/dev/null | head -1); [ -n "$f" ] && break; sleep 0.5; done
  if [ -n "$f" ] && python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); assert sys.argv[2] in json.dumps(m)' "$f" "$3" 2>/dev/null; then
    pass "$id" "outbox $(basename "$f") readable by $(id -un), mentions $3"
  else
    fail "$id" "no readable outbox JSON for $3 (found: ${f:-none})"
  fi
  bad=$(find "$dir" \( ! -user "$(id -u)" -o ! -group "$(id -g)" \) -printf '%u:%g %p\n' 2>&1)
  [ -z "$bad" ] && pass "$id" "all files owned by $(id -un):$(id -gn)" || fail "$id" "not owned by host user: $bad"
  bad=$(find "$dir" \( -type d ! -perm 0700 -o -type f ! -perm 0600 \) -printf '%m %p\n' 2>&1)
  [ -z "$bad" ] && pass "$id" "dirs 0700, files 0600 ($(find "$dir" | wc -l) entries)" || fail "$id" "wrong modes: $bad"
}

# --- checks -----------------------------------------------------------------------------------------------
check1() {
  local dir="$T/c1/data" c
  if [ ${#ROOTFUL[@]} -eq 0 ]; then fail 1 "no rootful engine (docker socket, sudo docker, sudo podman all unusable)"; return; fi
  say "-- 1: rootful (${ROOTFUL[*]}), missing bind folder"
  mkdir -p "$T/c1"
  c=$(name c1)
  rootful run -d --name "$c" -p "127.0.0.1:$PORT:4000" -e BASE_URL="$BASE_URL" \
    -e PUID="$(id -u)" -e PGID="$(id -g)" -v "$dir:/data" "$IMG" >/dev/null
  if wait_health rootful "$c"; then pass 1 "/health ok"; else fail 1 "/health never ok: $(rootful logs "$c" 2>&1 | tail -5)"; rootful rm -f "$c" >/dev/null; return; fi
  assert_data 1 "$dir" "c1@example.test"
  rootful rm -f "$c" >/dev/null
}

check2() {
  local dir="$T/c2/data" c
  say "-- 2: rootless podman --userns=keep-id :Z, folder from mkdir -p"
  mkdir -p "$dir"
  c=$(name c2)
  podman run -d --name "$c" --userns=keep-id -p "127.0.0.1:$PORT:4000" -e BASE_URL="$BASE_URL" -v "$dir:/data:Z" "$IMG" >/dev/null
  if wait_health podman "$c"; then pass 2 "/health ok"; else fail 2 "/health never ok: $(podman logs "$c" 2>&1 | tail -5)"; podman rm -f "$c" >/dev/null; return; fi
  assert_data 2 "$dir" "c2@example.test"
  podman rm -f "$c" >/dev/null
}

check3() {
  local dir="$T/c3/data" c rc out
  say "-- 3: SELinux, rootless podman keep-id with and without :Z"
  if [ "$(getenforce 2>/dev/null)" != Enforcing ]; then fail 3 "SELinux is '$(getenforce 2>&1)', not Enforcing; cannot run this check"; return; fi
  mkdir -p "$dir"
  c=$(name c3a)
  out=$(timeout 60 podman run --name "$c" --userns=keep-id -e BASE_URL="$BASE_URL" -v "$dir:/data" "$IMG" 2>&1); rc=$?
  podman rm -f "$c" >/dev/null 2>&1
  if [ $rc -ne 0 ] && grep -q 'not writable' <<<"$out"; then
    pass 3 "without :Z refused (exit $rc): $(grep -m1 'failed to start' <<<"$out")"
    grep -qiE 'selinux|:Z' <<<"$out" && pass 3 "error names SELinux/:Z" \
      || fail 3 "error does not mention SELinux or :Z (it suggests --userns=keep-id, which is already set)"
  else
    fail 3 "without :Z: exit $rc, output: $(tail -5 <<<"$out")"
  fi
  c=$(name c3b)
  podman run -d --name "$c" --userns=keep-id -p "127.0.0.1:$PORT:4000" -e BASE_URL="$BASE_URL" -v "$dir:/data:Z" "$IMG" >/dev/null
  if wait_health podman "$c"; then pass 3 "with :Z /health ok"; else fail 3 "with :Z /health never ok: $(podman logs "$c" 2>&1 | tail -5)"; fi
  podman rm -f "$c" >/dev/null
}

check4() {
  local base="$T/c4" c rc out
  say "-- 4: PUID=00 and symlinked data folder refused"
  mkdir -p "$base/real" && ln -s real "$base/link"
  if [ ${#ROOTFUL[@]} -eq 0 ]; then
    fail 4 "no rootful engine; PUID and the entrypoint symlink check only run as root"
  else
    c=$(name c4a)
    out=$(timeout 60 "${ROOTFUL[@]}" run --name "$c" -e PUID=00 -e BASE_URL="$BASE_URL" -v "$T/c4/puid:/data" "$IMG" 2>&1); rc=$?
    rootful rm -f "$c" >/dev/null 2>&1
    [ $rc -ne 0 ] && grep -q 'would run the server as root' <<<"$out" \
      && pass 4 "PUID=00 refused (exit $rc): $out" || fail 4 "PUID=00: exit $rc, output: $(tail -5 <<<"$out")"
    c=$(name c4b)
    out=$(timeout 60 "${ROOTFUL[@]}" run --name "$c" -e PUID="$(id -u)" -e PGID="$(id -g)" -e DATA_DIR=/mnt/link -e BASE_URL="$BASE_URL" -v "$base:/mnt" "$IMG" 2>&1); rc=$?
    rootful rm -f "$c" >/dev/null 2>&1
    [ $rc -ne 0 ] && grep -q 'is a symlink' <<<"$out" \
      && pass 4 "rootful: symlinked DATA_DIR refused (exit $rc): $out" || fail 4 "rootful symlink: exit $rc, output: $(tail -5 <<<"$out")"
  fi
  c=$(name c4c)
  out=$(timeout 60 podman run --name "$c" --userns=keep-id -e DATA_DIR=/mnt/link -e BASE_URL="$BASE_URL" -v "$base:/mnt:Z" "$IMG" 2>&1); rc=$?
  podman rm -f "$c" >/dev/null 2>&1
  [ $rc -ne 0 ] && grep -q 'is a symlink' <<<"$out" \
    && pass 4 "rootless: symlinked DATA_DIR refused (exit $rc): $(grep -m1 symlink <<<"$out")" || fail 4 "rootless symlink: exit $rc, output: $(tail -5 <<<"$out")"
  [ -z "$(ls -A "$base/real")" ] && pass 4 "nothing created in the link target" || fail 4 "link target not empty: $(ls -A "$base/real")"
}

check5() {
  local dir="$T/c5/data" c i j res ok=0 lastusers=0
  say "-- 5: $CYCLES kill-during-write cycles (rootless podman keep-id :Z bind mount)"
  mkdir -p "$dir"
  for i in $(seq 1 "$CYCLES"); do
    c=$(name "c5-$i")
    podman run -d --name "$c" --userns=keep-id -p "127.0.0.1:$PORT:4000" -e BASE_URL="$BASE_URL" -v "$dir:/data:Z" "$IMG" >/dev/null
    if ! wait_health podman "$c"; then fail 5 "cycle $i: /health never ok: $(podman logs "$c" 2>&1 | tail -5)"; podman rm -f "$c" >/dev/null; return; fi
    for j in $(seq 1 20); do
      curl -s -o /dev/null -m 10 -X POST "$BASE_URL/api/auth/sign-up/email" -H "origin: $BASE_URL" \
        -H 'content-type: application/json' -d "{\"email\":\"k$i-$j@example.test\",\"password\":\"correct-horse-battery-staple\",\"name\":\"K\"}" &
    done
    sleep "0.$((RANDOM % 6 + 1))$((RANDOM % 10))"  # 0.10-0.69s into the burst
    podman kill -s KILL "$c" >/dev/null
    wait
    podman rm -f "$c" >/dev/null
    res=$(podman run --rm --userns=keep-id -v "$dir:/data:Z" --entrypoint node "$IMG" --input-type=module -e "
      import Database from 'better-sqlite3';
      const db = new Database('/data/authwapi.db');
      const r = db.pragma('integrity_check', { simple: true });
      const n = db.prepare('select count(*) as n from user').get().n;
      db.close();
      console.log(r + ' ' + n);" 2>&1)
    if [ "${res%% *}" = ok ]; then ok=$((ok + 1)); lastusers="${res##* }"; else fail 5 "cycle $i: integrity_check: $res"; fi
    say "   cycle $i: $res"
  done
  [ "$ok" -eq "$CYCLES" ] && pass 5 "$ok/$CYCLES integrity_check ok, $lastusers users committed across kills" \
    || fail 5 "$ok/$CYCLES integrity_check ok"
}

# --- main -------------------------------------------------------------------------------------------------
say "podman: $(podman --version)"
[ ${#ROOTFUL[@]} -gt 0 ] && say "rootful: ${ROOTFUL[*]}: $(rootful --version)" || say "rootful: none usable"
say "SELinux: $(getenforce 2>&1)"
say "-- build $IMG"
if ! podman build -q -t "$IMG" "$ROOT_DIR" >"$T/build.log" 2>&1; then tail -20 "$T/build.log"; fail build "podman build"; exit 1; fi
pass build "image built"
if [ ${#ROOTFUL[@]} -gt 0 ] && ! podman save "$IMG" 2>/dev/null | rootful load >/dev/null; then fail build "loading image into rootful engine"; ROOTFUL=(); fi

for n in "${@:-1 2 3 4 5}"; do for k in $n; do "check$k"; done; done

say "-- $FAILS failure(s)"
[ "$FAILS" -eq 0 ]
