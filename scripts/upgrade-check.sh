#!/usr/bin/env bash
# Rootless Podman check of upgrading a populated instance and rolling back a broken migration.
set -Eeuo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
source scripts/check-lib.sh
CHECK=upgrade
STEP='prepare upgrade fixture'
check_init

cleanup() {
  podman rm -f "$RUN_ID" >/dev/null 2>&1 || true
  podman rmi "$RUN_ID:old" "$RUN_ID:current" "$RUN_ID:broken" >/dev/null 2>&1 || true
  rm -rf "$T"
}
trap cleanup EXIT

latest=(migrations/[0-9][0-9][0-9][0-9]_*.sql)
case $# in
  0)
    if git show-ref --verify --quiet refs/tags/v0.2.0; then
      from=v0.2.0
    else
      migration_commit=$(git log -1 --diff-filter=A --format=%H -- "${latest[-1]}")
      from=${migration_commit:?latest migration must be tracked}^
    fi
    ;;
  2) [[ $1 == --from ]] || check_fail 'usage: scripts/upgrade-check.sh [--from <git-ref>]'; from=$2 ;;
  *) check_fail 'usage: scripts/upgrade-check.sh [--from <git-ref>]' ;;
esac
from=$(git rev-parse --verify --end-of-options "$from^{commit}")

mkdir "$T/old" "$T/data" "$T/broken" "$T/failed-data"
# Preserve the entrypoint's executable mode despite the private fixture umask.
git archive "$from" | tar -xp -C "$T/old"
old=("$T/old"/migrations/[0-9][0-9][0-9][0-9]_*.sql)
[[ -f $T/old/src/cli.ts ]] || check_fail '--from must support the OAuth client CLI'
for migration in "${old[@]}"; do
  [[ -f migrations/${migration##*/} ]] || check_fail "current image is missing ${migration##*/}"
done
pending=()
for migration in "${latest[@]}"; do
  [[ -f $T/old/$migration ]] || pending+=("${migration##*/}")
done
((${#pending[@]} > 0)) || check_fail 'no pending migrations for --from; choose an older ref'

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
AUTH="http://localhost:$PORT"
SERVER=$RUN_ID
request() { curl -q --noproxy '*' --resolve "localhost:$PORT:127.0.0.1" "$@"; }
run_image() {
  podman run -d --name "$SERVER" --userns=keep-id -p "127.0.0.1:$PORT:4000" \
    -e "BASE_URL=$AUTH" -e "PUID=$PUID" -e "PGID=$PGID" -v "$1:/data:Z" "$RUN_ID:$2" >/dev/null
}
sign_in() {
  http_status 200 "$(cat <<EOF
data = "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
EOF
  )" "$AUTH/api/auth/sign-in/email" -H "Origin: $AUTH" -H 'Content-Type: application/json'
  jq -er --arg email "$EMAIL" '.user | select(.email == $email and .emailVerified == true) | .id' "$T/body"
}
compare_db() {
  # SQLite's online backup can change internal page metadata. Compare schema and rows.
  python3 - "$1" "$2" <<'PY'
from pathlib import Path
import sqlite3
import sys

def snapshot(path):
    with sqlite3.connect(Path(path).as_uri() + '?mode=ro', uri=True) as db:
        assert db.execute('PRAGMA quick_check').fetchall() == [('ok',)]
        return list(db.iterdump())

assert snapshot(sys.argv[1]) == snapshot(sys.argv[2]), 'database differs from backup'
PY
}

STEP='build the previous and current images'
podman build -q -t "$RUN_ID:old" "$T/old" >"$T/build-old.log" 2>&1
podman build -q -t "$RUN_ID:current" "$ROOT" >"$T/build-current.log" 2>&1

STEP='start the previous image'
run_image "$T/data" old
wait_health "$AUTH"
make_verified_user "$AUTH" "$T/data"
STEP='sign in and register a client on the previous image'
user_id=$(sign_in)
auth_cli create --name 'Upgrade check' --redirect-uri http://localhost:3000/callback >"$T/client" 2>"$T/cli-error"
client_id=$(awk '$1 == "client_id:" {print $2}' "$T/client")
[[ -n $client_id ]]
podman stop -t 5 "$SERVER" >/dev/null
podman rm "$SERVER" >/dev/null
check_pass "previous image ${from:0:12}: verified user signed in and OAuth client registered"
cp "$T/data/authwapi.db" "$T/previous.db"
cp -p "$T/data/secret" "$T/previous.secret"

STEP='start the current image on the previous data folder'
run_image "$T/data" current
wait_health "$AUTH"
STEP='check applied migrations and the pre-upgrade backup pair'
for migration in "${pending[@]}"; do
  cmp "$ROOT/migrations/$migration" "$T/data/migrations/$migration"
done
# clients list also checks the database migration ledger against every migration in the image.
auth_cli list >"$T/clients" 2>"$T/cli-error"
backups=("$T/data/backups"/before-"${pending[0]%.sql}"-*.db)
[[ ${#backups[@]} == 1 ]]
compare_db "$T/previous.db" "${backups[0]}"
cmp -s "$T/previous.secret" "${backups[0]%.db}.secret"
cmp -s "$T/previous.secret" "$T/data/secret"
check_pass "current image applied ${pending[*]} and backed up the previous database and secret"

STEP='verify the preserved user and client'
[[ $(sign_in) == "$user_id" ]]
grep -Fxq "$client_id  Upgrade check" "$T/clients"
podman stop -t 5 "$SERVER" >/dev/null
podman rm "$SERVER" >/dev/null
check_pass 'the same user can sign in and the OAuth client still exists'

STEP='build the image with a broken migration in a temporary context'
cp -a Dockerfile .dockerignore package.json package-lock.json src migrations docker "$T/broken/"
broken=9999_upgrade_check.sql
[[ ! -e $T/broken/migrations/$broken ]]
cat >"$T/broken/migrations/$broken" <<'SQL'
CREATE TABLE upgrade_check_rollback (id INTEGER);
INSERT INTO upgrade_check_missing VALUES (1);
SQL
podman build -q -t "$RUN_ID:broken" "$T/broken" >"$T/build-broken.log" 2>&1
cp -a "$T/data/." "$T/failed-data/"

STEP='check that the broken image refused to start and named its backup'
run_image "$T/failed-data" broken
[[ $(timeout 30 podman wait "$SERVER") == 1 ]]
backups=("$T/failed-data/backups"/before-"${broken%.sql}"-*.db)
[[ ${#backups[@]} == 1 ]]
podman logs "$SERVER" >"$T/refusal" 2>&1
grep -F "AuthWAPI failed to start: Migration $broken failed, so the whole upgrade was rolled back" "$T/refusal" \
  | grep -Fq "A backup from before the upgrade is at /data/backups/${backups[0]##*/}."
check_pass 'broken migration refused startup and named the pre-migration database backup'

STEP='compare the failed database with the backup and original database'
[[ ! -e $T/failed-data/migrations/$broken ]]
compare_db "$T/failed-data/authwapi.db" "${backups[0]}"
cmp -s "$T/data/authwapi.db" "$T/failed-data/authwapi.db"
cmp -s "$T/data/secret" "${backups[0]%.db}.secret"
check_pass 'failed upgrade left the database byte-for-byte unchanged and its contents match the backup'
