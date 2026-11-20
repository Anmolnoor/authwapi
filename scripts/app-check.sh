#!/usr/bin/env bash
# Rootless Podman OIDC check. All HTTP traffic goes through a third container on authwapi-net.
set -Eeuo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
source scripts/check-lib.sh
CHECK=app
STEP='prepare app fixture'
check_init

NETWORK=authwapi-net
AUTH=http://authwapi:4000
BOOTSTRAP=http://authwapi.localhost:4000
APP=http://app.localhost:3000
API=http://app:3000
CURL_IMAGE=docker.io/curlimages/curl:8.17.0
SERVER=authwapi
RUN_LABEL="org.authwapi.check=$RUN_ID"
server_id= driver_id= network_id=
cleanup() {
  # Podman may create a container before failing to start it and returning its ID.
  local id
  for id in $(podman ps -aq --filter "label=$RUN_LABEL"); do
    podman rm -f "$id" >/dev/null 2>&1 || true
  done
  [[ -z $network_id ]] || podman network rm "$NETWORK" >/dev/null 2>&1 || true
  podman rmi "$RUN_ID:server" >/dev/null 2>&1 || true
  rm -rf "$T"
}
trap cleanup EXIT

mkdir "$T/data" "$T/state"
cp -r examples/sample-app "$T/sample-app"
request() {
  podman exec -i "$driver_id" curl -q --noproxy '*' \
    --connect-to authwapi.localhost:4000:authwapi:4000 --connect-to app.localhost:3000:app:3000 "$@"
}
start_auth() {
  podman run -d --name "$SERVER" --label "$RUN_LABEL" --network "$NETWORK" --userns=keep-id \
    -e "BASE_URL=$1" -e "PUID=$PUID" -e "PGID=$PGID" -v "$T/data:/data:Z" "${@:2}" "$RUN_ID:server"
}

STEP='build AuthWAPI and start the curl container on authwapi-net'
podman build -q -t "$RUN_ID:server" "$ROOT" >"$T/build.log" 2>&1
podman pull --policy=missing "$CURL_IMAGE" >"$T/pull.log" 2>&1
network_id=$(podman network create --internal "$NETWORK")
driver_id=$(podman run -d --name "$RUN_ID" --label "$RUN_LABEL" --network "$NETWORK" --entrypoint /bin/sh \
  "$CURL_IMAGE" -c 'exec sleep 1800')

# The real issuer uses a container hostname. Boot once with a .localhost issuer to verify the local fixture
# through the outbox. The isolated network has no mail egress when restarted with the non-loopback issuer.
STEP='start AuthWAPI in outbox mode'
server_id=$(start_auth "$BOOTSTRAP")
wait_health "$BOOTSTRAP"
make_verified_user "$BOOTSTRAP" "$T/data"
STEP='restart AuthWAPI on the container issuer'
podman stop -t 5 "$server_id" >/dev/null
podman rm "$server_id" >/dev/null
server_id=
server_id=$(start_auth "$AUTH" -e RESEND_API_KEY=test-disabled -e EMAIL_FROM=check@example.test)
wait_health "$AUTH"

STEP='register the sample app as the data-folder owner'
auth_cli create --name 'Sample app' --redirect-uri "$APP/callback" \
  --resource "$API/api" --resource "$API/other-api" >"$T/client" 2>"$T/cli-error"
client_id=$(awk '$1 == "client_id:" {print $2}' "$T/client")
awk '$1 == "client_secret:" {print $2}' "$T/client" >"$T/state/client-secret"
[[ -n $client_id && -s $T/state/client-secret ]]
basic=$(printf '%s:%s' "$client_id" "$(<"$T/state/client-secret")" | base64 -w0)
check_pass 'verified user via the outbox and registered the OAuth client as the data-folder owner'

STEP='start the sample app on a separate hostname'
podman run -d --name app --label "$RUN_LABEL" --network "$NETWORK" --userns=keep-id --entrypoint node \
  -v "$T/sample-app:/app/examples/sample-app:ro,Z" -v "$T/state:/check:Z" \
  -e "ISSUER=$AUTH" -e "APP_ORIGIN=$APP" -e "API_ORIGIN=$API" -e "CLIENT_ID=$client_id" \
  -e PORT=3000 -e CLIENT_SECRET_FILE=/check/client-secret -e CHECK_TOKENS_DIR=/check \
  "$RUN_ID:server" examples/sample-app/server.mjs >/dev/null
wait_health "$APP"

browser=(-b /tmp/cookies -c /tmp/cookies -H 'Accept: text/html' -H 'Sec-Fetch-Mode: navigate')
location() {
  local target
  target=$(awk 'tolower($1) == "location:" { sub(/\r$/, "", $2); print $2; exit }' "$T/headers")
  [[ $target != /* ]] || target="$1$target"
  printf '%s\n' "$target"
}
url_config() { printf 'url = "%s"\n' "$1"; }
oauth_form() {
  python3 - "$T/body" <<'PY'
from html import unescape
from pathlib import Path
import re
import sys

form = re.search(r'name="oauth_query" value="([^"]+)"', Path(sys.argv[1]).read_text())
assert form, 'missing OAuth form field'
print(unescape(form[1]))
PY
}

authorize() {
  http_status 302 '' "$APP/login$1" "${browser[@]}"
  http_status 302 "$(url_config "$(location "$APP")")" "${browser[@]}"
}
consent_and_callback() {
  local consent
  consent=$(location "$AUTH")
  [[ $consent == "$AUTH/consent?"* ]]
  http_status 200 "$(url_config "$consent")" "${browser[@]}"
  http_status 303 "$(printf 'data-urlencode = "oauth_query=%s"\n' "$(oauth_form)")" \
    "$AUTH/consent" "${browser[@]}" -H "Origin: $AUTH" --data-urlencode accept=yes
  local callback
  callback=$(location "$AUTH")
  [[ $callback == "$APP/callback?"* ]]
  http_status 200 "$(url_config "$callback")" "${browser[@]}"
  jq -e --arg email "$EMAIL" --arg api "$API/$1" \
    '.email == $email and .emailVerified == true and .resource == $api and (.sub | length > 0)' "$T/body" >/dev/null
}

STEP='follow the authorize redirect to the hosted sign-in form'
authorize ''
login=$(location "$AUTH")
[[ $login == "$AUTH/sign-in?"* ]]
http_status 200 "$(url_config "$login")" "${browser[@]}"
STEP='submit hosted sign-in and allow consent'
http_status 303 "$(printf 'data-urlencode = "oauth_query=%s"\ndata-urlencode = "password=%s"\n' "$(oauth_form)" "$PASSWORD")" \
  "$AUTH/sign-in" "${browser[@]}" -H "Origin: $AUTH" --data-urlencode "email=$EMAIL"
STEP='exchange the PKCE code, verify ID-token audience, and call the API'
consent_and_callback api
sub=$(jq -er '.sub' "$T/body")
check_pass 'hosted sign-in and consent returned a PKCE code; app verified the ID token and called the JWT-protected API'

STEP='obtain a genuine access token for the other audience'
authorize '?other=1'
consent_and_callback other-api
other=$(jq -er '.access_token' "$T/state/other.json")
STEP='present the other audience access token to the primary API'
http_status 401 "$(printf 'header = "Authorization: Bearer %s"\n' "$other")" "$API/api"
jq -e '.error == "wrong_audience"' "$T/body" >/dev/null
check_pass 'API returned 401 for a validly signed access token issued to the other resource'

STEP='confirm the browser session and present its cookie to the API'
http_status 200 '' "$AUTH/api/auth/get-session" "${browser[@]}"
jq -e --arg sub "$sub" '.user.id == $sub' "$T/body" >/dev/null
cookie=$(podman exec "$driver_id" awk -F '\t' \
  '$1 ~ /^(#HttpOnly_)?authwapi$/ && $6 ~ /session_token$/ {print $6 "=" $7}' /tmp/cookies)
[[ -n $cookie ]]
http_status 401 "$(printf 'header = "Cookie: %s"\n' "$cookie")" "$API/api"
jq -e '.error == "bearer_required"' "$T/body" >/dev/null
check_pass 'API returned 401 when sent the valid browser session cookie without a bearer token'

oauth() {
  http_status "$1" "$(printf 'header = "Authorization: Basic %s"\ndata-urlencode = "%s"\n' "$basic" "$3")" \
    "$AUTH/api/auth/oauth2/$2" "${@:4}"
}
introspect() {
  oauth 200 introspect "token=$1"
  jq -e ".active == $2" "$T/body" >/dev/null
}
refresh() {
  oauth "$1" token "refresh_token=$2" --data-urlencode grant_type=refresh_token
}

STEP='confirm that the access tokens are active and the offline refresh token rotates'
access=$(jq -er '.access_token' "$T/state/primary.json")
offline=$(jq -er 'select(.scope | split(" ") | index("offline_access")) | .refresh_token' "$T/state/primary.json")
introspect "$access" true
introspect "$other" true
refresh 200 "$offline"
rotated=$(jq -er 'select(.scope | split(" ") | index("offline_access")) | .refresh_token' "$T/body")
[[ $rotated != "$offline" ]]
check_pass 'both access tokens introspected as active and the offline_access refresh token rotated'

STEP='sign out on AuthWAPI and check the browser session ended'
http_status 303 '' "$AUTH/sign-out" "${browser[@]}" -H "Origin: $AUTH" --data ''
http_status 200 '' "$AUTH/api/auth/get-session" "${browser[@]}"
jq -e '. == null' "$T/body" >/dev/null
STEP='verify that sign-out invalidated both access tokens and the rotated refresh token'
introspect "$access" false
introspect "$other" false
refresh 400 "$rotated"
jq -e '.error == "invalid_grant"' "$T/body" >/dev/null
check_pass 'sign-out ended the browser session; both access tokens introspected inactive and the offline_access refresh was refused'
