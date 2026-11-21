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
  local status=$?
  ((status == 0)) || check_failure_context "$RUN_ID"
  podman rm -f "$RUN_ID" >/dev/null 2>&1 || true
  podman rmi "$RUN_ID:old" "$RUN_ID:current" "$RUN_ID:broken" >/dev/null 2>&1 || true
  rm -rf "$T"
}
trap cleanup EXIT

latest=(migrations/[0-9][0-9][0-9][0-9]_*.sql)
case $# in
  0)
    # Default: this branch just before the newest migration reached it, so there is always a pending migration.
    # Follow first parents: a migration can arrive (or be renumbered) in a merge commit.
    migration_commit=$(git rev-list --first-parent HEAD -- "${latest[-1]}" | tail -n 1)
    from=${migration_commit:?latest migration must be tracked}^
    ;;
  2) [[ $1 == --from ]] || check_fail 'usage: scripts/upgrade-check.sh [--from <git-ref>]'; from=$2 ;;
  *) check_fail 'usage: scripts/upgrade-check.sh [--from <git-ref>]' ;;
esac
from=$(git rev-parse --verify --end-of-options "$from^{commit}")

mkdir "$T/old" "$T/data" "$T/broken" "$T/failed-data" "$T/snapshot"
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

SERVER=$RUN_ID
run_image() {
  podman run -d --name "$SERVER" --userns=keep-id -e "BASE_URL=$AUTH" -e "PUID=$PUID" -e "PGID=$PGID" \
    -v "$1:/data:Z" "${@:3}" "$RUN_ID:$2" >/dev/null
}
stop_server() {
  podman stop -t 5 "$SERVER" >/dev/null
  podman rm "$SERVER" >/dev/null
}
sign_in() {
  http_status 200 "$(cat <<EOF
data = "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
EOF
  )" "$AUTH/api/auth/sign-in/email" -H "Origin: $AUTH" -H 'Content-Type: application/json'
  jq -er --arg email "$EMAIL" '.user | select(.email == $email and .emailVerified == true) | .id' "$T/body"
}
# Writes check-db.mjs output for a copy of database $3 to $1 (mode $2). The output holds hashes: compare, never print.
db_json() {
  local out=$1 mode=$2 db=$3
  rm -rf "$T/db"
  mkdir "$T/db"
  cp scripts/check-db.mjs "$T/db/"
  cp "$db" "$T/db/check.db"
  [[ ! -e $db-wal ]] || cp "$db-wal" "$T/db/check.db-wal"
  podman run --rm --userns=keep-id --network=none --image-volume=ignore --entrypoint node -v "$T/db:/db:Z" \
    "$RUN_ID:current" /db/check-db.mjs "$mode" /db/check.db "${@:4}" >"$out" 2>"$T/db-error" \
    || check_fail "$STEP ($(<"$T/db-error"))"
}
same_db() {
  db_json "$T/a.json" dump "$1"
  db_json "$T/b.json" dump "$2"
  cmp -s "$T/a.json" "$T/b.json"
}

STEP='build the previous and current images'
podman build -q -t "$RUN_ID:old" "$T/old" >"$T/build-old.log" 2>&1
podman build -q -t "$RUN_ID:current" "$ROOT" >"$T/build-current.log" 2>&1
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
AUTH="http://localhost:$PORT"
request() { curl -q --noproxy '*' --resolve "localhost:$PORT:127.0.0.1" "$@"; }
publish=(-p "127.0.0.1:$PORT:4000")

STEP='start the previous image'
run_image "$T/data" old "${publish[@]}"
wait_health "$AUTH"
make_verified_user "$AUTH" "$T/data"
STEP='sign in and register a client on the previous image'
user_id=$(sign_in)
auth_cli create --name 'Upgrade check' --redirect-uri http://localhost:3000/callback >"$T/client" 2>"$T/cli-error"
client_id=$(awk '$1 == "client_id:" {print $2}' "$T/client")
client_secret=$(awk '$1 == "client_secret:" {print $2}' "$T/client")
[[ -n $client_id && -n $client_secret ]]
stop_server
STEP='snapshot the previous data folder and its user, account, client and session rows'
cp -a "$T/data/." "$T/snapshot/"
db_json "$T/rows-before.json" rows "$T/snapshot/authwapi.db" "$EMAIL" "$client_id"
check_pass "previous image ${from:0:12}: verified user signed in and OAuth client registered"

STEP='start the current image on the previous data folder'
run_image "$T/data" current "${publish[@]}"
wait_health "$AUTH"
STEP='check applied migrations and the pre-upgrade backup pair'
for migration in "${pending[@]}"; do
  cmp "$ROOT/migrations/$migration" "$T/data/migrations/$migration"
done
# clients list also checks the database migration ledger against every migration in the image.
auth_cli list >"$T/clients" 2>"$T/cli-error"
grep -Fxq "$client_id  Upgrade check" "$T/clients"
stop_server
backups=("$T/data/backups"/before-"${pending[0]%.sql}"-*.db)
[[ ${#backups[@]} == 1 ]]
same_db "$T/snapshot/authwapi.db" "${backups[0]}"
cmp -s "$T/snapshot/secret" "${backups[0]%.db}.secret"
cmp -s "$T/snapshot/secret" "$T/data/secret"
check_pass "current image applied ${pending[*]} and backed up the previous database and secret"

STEP='compare the user, credential account, OAuth client and session rows after the upgrade'
db_json "$T/rows-after.json" rows "$T/data/authwapi.db" "$EMAIL" "$client_id"
cmp -s "$T/rows-before.json" "$T/rows-after.json" || check_fail "$STEP (rows differ)"
check_pass 'user, password hash, OAuth client (redirect URIs, secret hash) and sessions match the previous data'

STEP='restart the current image and use the preserved user and client'
run_image "$T/data" current "${publish[@]}"
wait_health "$AUTH"
[[ $(sign_in) == "$user_id" ]]
basic=$(printf '%s:%s' "$client_id" "$client_secret" | base64 -w0)
introspect() {
  http_status "$1" "$(printf 'header = "Authorization: Basic %s"\n' "$2")" "$AUTH/api/auth/oauth2/introspect" \
    --data-urlencode token=upgrade-check-dummy
}
introspect 200 "$basic"
jq -e '.active == false' "$T/body" >/dev/null
introspect 401 "$(printf '%s:wrong-secret' "$client_id" | base64 -w0)"
stop_server
backups=("$T/data/backups"/*.db)
[[ ${#backups[@]} == 1 ]]
check_pass 'restart took no new backup; the same user signs in and the client authenticates with its secret'

STEP='build the image with a broken migration in a temporary context'
cp -a Dockerfile .dockerignore LICENSE package.json package-lock.json src migrations docker "$T/broken/"
broken=9999_upgrade_check.sql
[[ ! -e $T/broken/migrations/$broken ]]
cat >"$T/broken/migrations/$broken" <<'SQL'
CREATE TABLE upgrade_check_rollback (id INTEGER);
INSERT INTO upgrade_check_missing VALUES (1);
SQL
podman build -q -t "$RUN_ID:broken" "$T/broken" >"$T/build-broken.log" 2>&1
# Start from the previous data folder, so the good pending migrations run in the same upgrade as the broken one.
cp -a "$T/snapshot/." "$T/failed-data/"

STEP='check that the broken image refused to start and named its backup'
run_image "$T/failed-data" broken
[[ $(timeout 30 podman wait "$SERVER") == 1 ]]
backups=("$T/failed-data/backups"/before-"${pending[0]%.sql}"-*.db)
[[ ${#backups[@]} == 1 ]]
podman logs "$SERVER" >"$T/refusal" 2>&1
grep -F "AuthWAPI failed to start: Migration $broken failed, so the whole upgrade was rolled back" "$T/refusal" \
  | grep -Fq "A backup from before the upgrade is at /data/backups/${backups[0]##*/}."
check_pass "broken migration refused startup after ${pending[*]} and named the pre-upgrade database backup"

STEP='compare the failed database with the previous database and the backup'
for migration in "${pending[@]}" "$broken"; do
  [[ ! -e $T/failed-data/migrations/$migration ]]
done
cmp -s "$T/snapshot/authwapi.db" "$T/failed-data/authwapi.db"
same_db "$T/snapshot/authwapi.db" "${backups[0]}"
cmp -s "$T/snapshot/secret" "$T/failed-data/secret"
cmp -s "$T/snapshot/secret" "${backups[0]%.db}.secret"
check_pass "failed upgrade rolled back ${pending[*]} too: the database is byte-for-byte the previous one and matches the backup"
