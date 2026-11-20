#!/usr/bin/env bash
# SAML round trip against a real identity provider (M4b): SimpleSAMLphp in a container, AuthWAPI's image in another,
# both rootless podman. An agent registers the IdP from its metadata over the admin MCP; curl then plays the browser
# through AuthWAPI's SP-initiated flow (AuthnRequest, IdP login form, signed response posted to the ACS) and checks
# that a new, unverified user is signed in, bound to the IdP's persistent NameID. Then the same response, posted
# again, is refused (replay).
#
#   scripts/saml-idp-check.sh
#
# Needs podman, curl, python3, and `npm ci` done in this checkout (the MCP client and better-sqlite3 run on the host).
# Temp folders go under $TMPDIR (default /tmp), never $HOME. Free ports on 127.0.0.1, picked per run.
set -uo pipefail

# kenchan0130/simplesamlphp 1.19.9 (SimpleSAMLphp 1.19.9), multi-arch index, pinned by digest.
IDP_IMAGE="docker.io/kenchan0130/simplesamlphp@sha256:3c6ed4b8c6bdc86bb131c802ddc35f6311cb91df7f8412f50b8f159c4c19fab0"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
PORT=$(free_port)
IDP_PORT=$(free_port)
BASE_URL="http://localhost:$PORT"
IDP_URL="http://localhost:$IDP_PORT"
# Containers publish on 127.0.0.1 only; pin curl there so "localhost" can't reach something on ::1 instead.
CURL=(curl -sS --resolve "localhost:$PORT:127.0.0.1" --resolve "localhost:$IDP_PORT:127.0.0.1")
RUN_ID="samlcheck-$$"
IMG="localhost/authwapi-samlcheck:$$"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/authwapi-samlcheck.XXXXXX")"
FAILS=0
CONTAINERS=()
SLUG=check
PROVIDER="sso-$SLUG"
ACS="$BASE_URL/api/auth/sso/saml2/sp/acs/$PROVIDER"
SP_ENTITY="$BASE_URL/api/auth/sso/saml2/sp/metadata?providerId=$PROVIDER"
NAMEID=u-1001
EMAIL=user1@example.com

say() { printf '%s\n' "$*"; }
pass() { say "PASS [$1] $2"; }
fail() { say "FAIL [$1] $2"; FAILS=$((FAILS + 1)); }

cleanup() {
  for c in "${CONTAINERS[@]}"; do podman rm -f "$c" >/dev/null 2>&1; done
  podman rmi -f "$IMG" >/dev/null 2>&1
  rm -rf "$T" 2>/dev/null || podman unshare rm -rf "$T" 2>/dev/null || say "WARN: could not remove $T"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Sets C to a container name and registers it for cleanup (never call it in $(...): see container-check.sh).
name() { C="$RUN_ID-$1"; CONTAINERS+=("$C"); }

# Waits until $2 answers 200; $1 = container (stops waiting if it exits).
wait_up() {
  local i
  for i in $(seq 1 90); do
    [ "$(podman inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ] || return 1
    [ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$2" 2>/dev/null)" = 200 ] && return 0
    sleep 0.5
  done
  return 1
}

# A hidden form field's value from an HTML page ($1 file, $2 field name), HTML entities decoded.
field() {
  python3 -c 'import html,re,sys
m = re.search(r"<input[^>]*name=\"%s\"[^>]*value=\"([^\"]*)\"" % re.escape(sys.argv[2]), open(sys.argv[1]).read()) or \
    re.search(r"<input[^>]*value=\"([^\"]*)\"[^>]*name=\"%s\"" % re.escape(sys.argv[2]), open(sys.argv[1]).read())
print(html.unescape(m.group(1)) if m else "")' "$1" "$2"
}
# A form's action URL ($1 file), HTML entities decoded.
form_action() { python3 -c 'import html,re,sys; m=re.search(r"<form[^>]*action=\"([^\"]*)\"", open(sys.argv[1]).read()); print(html.unescape(m.group(1)) if m else "")' "$1"; }

# --- the identity provider ----------------------------------------------------------------------------
# One user with a stable uid (the persistent NameID) and an email; signed assertions (and responses), RSA-SHA256;
# the NameID is the uid, as a persistent NameID, for AuthWAPI's SP entity ID.
mkdir -p "$T/idp" "$T/data"
cat >"$T/idp/authsources.php" <<'PHP'
<?php
$config = [
    'admin' => ['core:AdminPassword'],
    'example-userpass' => [
        'exampleauth:UserPass',
        'user1:password' => ['uid' => ['u-1001'], 'email' => ['user1@example.com']],
    ],
];
PHP
cat >"$T/idp/saml20-sp-remote.php" <<'PHP'
<?php
$metadata[getenv('SIMPLESAMLPHP_SP_ENTITY_ID')] = [
    'AssertionConsumerService' => getenv('SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE'),
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    'saml20.sign.assertion' => true,
    'saml20.sign.response' => true,
    'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'authproc' => [
        10 => ['class' => 'saml:AttributeNameID', 'attribute' => 'uid', 'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'],
    ],
];
PHP
chmod 644 "$T/idp/"*.php

say "podman: $(podman --version)"
say "-- build $IMG"
if ! podman build -q -t "$IMG" "$ROOT_DIR" >"$T/build.log" 2>&1; then tail -20 "$T/build.log"; fail build "podman build"; exit 1; fi
pass build "image built"

say "-- identity provider ($IDP_IMAGE)"
name idp; IDP_C=$C
podman run -d --name "$IDP_C" -p "127.0.0.1:$IDP_PORT:8080" \
  -e SIMPLESAMLPHP_SP_ENTITY_ID="$SP_ENTITY" -e SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE="$ACS" \
  -v "$T/idp/authsources.php:/var/www/simplesamlphp/config/authsources.php:ro,Z" \
  -v "$T/idp/saml20-sp-remote.php:/var/www/simplesamlphp/metadata/saml20-sp-remote.php:ro,Z" \
  "$IDP_IMAGE" >/dev/null || { fail idp "container did not start"; exit 1; }
IDP_METADATA_URL="$IDP_URL/simplesaml/saml2/idp/metadata.php"
if wait_up "$IDP_C" "$IDP_METADATA_URL"; then pass idp "metadata served"; else fail idp "never up: $(podman logs "$IDP_C" 2>&1 | tail -5)"; exit 1; fi
"${CURL[@]}" -o "$T/idp-metadata.xml" "$IDP_METADATA_URL"
grep -q 'SingleSignOnService' "$T/idp-metadata.xml" && pass idp "metadata has an SSO service" || { fail idp "metadata: $(head -c 300 "$T/idp-metadata.xml")"; exit 1; }

say "-- AuthWAPI (rootless, keep-id), IdP origin trusted (loopback http test IdP)"
name sp; SP_C=$C
podman run -d --name "$SP_C" --userns=keep-id -p "127.0.0.1:$PORT:4000" -e BASE_URL="$BASE_URL" \
  -e ALLOWED_HOSTS="localhost:$IDP_PORT" -v "$T/data:/data:Z" "$IMG" >/dev/null || { fail sp "container did not start"; exit 1; }
if wait_up "$SP_C" "$BASE_URL/health"; then pass sp "/health ok"; else fail sp "never up: $(podman logs "$SP_C" 2>&1 | tail -5)"; exit 1; fi

# --- an agent registers the IdP over MCP ---------------------------------------------------------------
say "-- register $PROVIDER over the admin MCP"
if (cd "$ROOT_DIR" && BASE_URL="$BASE_URL" KEY_FILE="$T/data/bootstrap-admin-key" METADATA="$T/idp-metadata.xml" SLUG="$SLUG" \
  node --input-type=module -e "
import { readFileSync } from 'node:fs';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
const connect = async (key) => {
  const c = new Client({ name: 'saml-idp-check', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } });
  await c.connect(new StreamableHTTPClientTransport(new URL(process.env.BASE_URL + '/mcp'), { requestInit: { headers: { authorization: 'Bearer ' + key } } }));
  return c;
};
const call = async (c, name, args) => {
  const r = await c.callTool({ name, arguments: args });
  const data = JSON.parse(r.content[0].text);
  if (r.isError) throw new Error(name + ': ' + JSON.stringify(data));
  return data;
};
const boot = await connect(readFileSync(process.env.KEY_FILE, 'utf8').trim());
const write = await connect((await call(boot, 'mint_agent_key', { scope: 'write' })).key);
const owner = await call(write, 'create_user', { email: 'owner@check.test', name: 'Owner', password: 'correct horse battery', emailVerified: true });
const org = await call(write, 'create_org', { name: 'Check', slug: 'check', ownerUserId: owner.user.id });
const { provider } = await call(write, 'register_sso_provider', {
  protocol: 'saml', organizationId: org.organization.id, slug: process.env.SLUG, domain: 'example.com', idpMetadata: readFileSync(process.env.METADATA, 'utf8'),
});
console.log(JSON.stringify(provider));
process.exit(0);
" >"$T/provider.json" 2>"$T/register.err"); then
  pass register "$(cat "$T/provider.json")"
else
  fail register "$(tail -5 "$T/register.err")"; exit 1
fi
python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); assert (p["acsUrl"], p["spEntityId"]) == (sys.argv[2], sys.argv[3]), p' "$T/provider.json" "$ACS" "$SP_ENTITY" \
  && pass register "ACS URL and SP entity ID are the ones the IdP was configured with" || fail register "unexpected ACS URL or SP entity ID"
"${CURL[@]}" -o "$T/sp-metadata.xml" "$SP_ENTITY"
grep -q 'WantAssertionsSigned="true"' "$T/sp-metadata.xml" && pass register "SP metadata wants signed assertions" || fail register "SP metadata: $(head -c 300 "$T/sp-metadata.xml")"

# --- the browser -----------------------------------------------------------------------------------------
say "-- SP-initiated sign-in as $EMAIL"
SPJAR="$T/sp.jar"; IDPJAR="$T/idp.jar"
"${CURL[@]}" -c "$SPJAR" -b "$SPJAR" -o "$T/start.json" -X POST "$BASE_URL/api/auth/sign-in/sso" -H "origin: $BASE_URL" \
  -H 'content-type: application/json' -H 'accept: application/json' -d "{\"email\":\"$EMAIL\",\"callbackURL\":\"/\",\"errorCallbackURL\":\"/sign-in\"}"
SSO_URL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("url",""))' "$T/start.json")
case "$SSO_URL" in "$IDP_URL/simplesaml/saml2/idp/SSOService.php?"*) pass browser "redirected to the IdP with an AuthnRequest";; *) fail browser "start: $(head -c 300 "$T/start.json")"; exit 1;; esac
# The IdP's login form (after its own redirects).
LOGIN_URL=$("${CURL[@]}" -L -c "$IDPJAR" -b "$IDPJAR" -o "$T/login.html" -w '%{url_effective}' "$SSO_URL")
AUTHSTATE=$(field "$T/login.html" AuthState)
[ -n "$AUTHSTATE" ] && pass browser "IdP login form" || { fail browser "no login form at $LOGIN_URL: $(head -c 300 "$T/login.html")"; exit 1; }
# Log in; the IdP answers with the auto-submitting form that posts the signed response to the ACS.
"${CURL[@]}" -L -c "$IDPJAR" -b "$IDPJAR" -o "$T/post.html" "${LOGIN_URL%%\?*}" \
  --data-urlencode username=user1 --data-urlencode password=password --data-urlencode "AuthState=$AUTHSTATE"
ACTION=$(form_action "$T/post.html"); SAML_RESPONSE=$(field "$T/post.html" SAMLResponse); RELAY=$(field "$T/post.html" RelayState)
[ "$ACTION" = "$ACS" ] && [ -n "$SAML_RESPONSE" ] && pass browser "IdP posts a SAMLResponse to the ACS" || { fail browser "no response form (action '$ACTION'): $(head -c 300 "$T/post.html")"; exit 1; }
printf %s "$SAML_RESPONSE" | base64 -d >"$T/response.xml" 2>/dev/null
grep -q 'nameid-format:persistent' "$T/response.xml" && grep -q 'rsa-sha256' "$T/response.xml" && pass browser "persistent NameID, RSA-SHA256" \
  || fail browser "response lacks a persistent NameID or RSA-SHA256"
post_acs() { # $1 jar, $2 output; prints status and Location
  "${CURL[@]}" -c "$1" -b "$1" -o "$2" -w '%{http_code} %{redirect_url}' -X POST "$ACS" -H "origin: $IDP_URL" -H 'accept: text/html' -H 'sec-fetch-mode: navigate' \
    --data-urlencode "SAMLResponse=$SAML_RESPONSE" --data-urlencode "RelayState=$RELAY"
}
BACK=$(post_acs "$SPJAR" "$T/acs.out")
[ "$BACK" = "302 $BASE_URL/" ] && pass browser "ACS signs in and redirects to /" || fail browser "ACS answered '$BACK': $(head -c 300 "$T/acs.out")"
"${CURL[@]}" -b "$SPJAR" -o "$T/session.json" -H 'accept: application/json' "$BASE_URL/api/auth/get-session"
python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); assert s and s["user"]["email"] == sys.argv[2], s' "$T/session.json" "$EMAIL" \
  && pass browser "session for $EMAIL" || fail browser "session: $(head -c 300 "$T/session.json")"

# --- what AuthWAPI stored, and a replay -----------------------------------------------------------------
STORED=$(cd "$ROOT_DIR" && node -e "
const db = new (require('better-sqlite3'))(process.argv[1], { readonly: true });
const u = db.prepare('select id, emailVerified from user where email = ?').get(process.argv[2]);
const a = u && db.prepare('select providerId, accountId from account where userId = ?').get(u.id);
const m = u && db.prepare('select role from member where userId = ?').get(u.id);
console.log(u ? [u.emailVerified, a?.providerId, a?.accountId, m?.role].join(' ') : 'none');
db.close();" "$T/data/authwapi.db" "$EMAIL" 2>&1)
[ "$STORED" = "0 $PROVIDER $NAMEID member" ] && pass stored "unverified email, bound to ($PROVIDER, $NAMEID), org member" || fail stored "got '$STORED'"
REPLAY=$(post_acs "$T/replay.jar" "$T/replay.out")
case "$REPLAY" in "302 "*error=*) pass replay "the same response again is refused (${REPLAY#302 })";; *) fail replay "replay answered '$REPLAY'";; esac

say "-- $FAILS failure(s)"
[ "$FAILS" -eq 0 ]
