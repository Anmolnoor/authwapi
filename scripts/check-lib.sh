# Shared helpers for the rootless Podman exit checks. Source from a Bash script.

check_fail() { printf 'FAIL [%s] %s\n' "$CHECK" "$*" >&2; exit 1; }
check_pass() { printf 'PASS [%s] %s\n' "$CHECK" "$*"; }

check_init() {
  umask 077
  shopt -s nullglob inherit_errexit
  T=$(mktemp -d "${TMPDIR:-/tmp}/authwapi-$CHECK.XXXXXX")
  RUN_ID=${T##*/}
  RUN_ID=${RUN_ID,,} # OCI repository names must be lowercase.
  PUID=$(id -u)
  PGID=$(id -g)
  trap 'if ((BASH_SUBSHELL == 0)); then check_fail "$STEP (line $LINENO)"; fi' ERR
  trap 'exit 130' INT TERM
  EMAIL=check@example.test
  PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
}

# Curl configs go over stdin. URLs containing codes, cookies and authorization headers stay out of argv.
# Results stay in the temp directory. On a mismatch report only the status and the step.
http_status() {
  local expected=$1 config=$2 status
  shift 2
  status=$(request --silent --show-error --max-time 10 --config - --dump-header - --output - \
    --write-out '%{http_code}' "$@" <<<"$config" >"$T/response" 2>"$T/curl-error" && tail -c 3 "$T/response")
  [[ $status == "$expected" ]] || check_fail "$STEP (HTTP $status, expected $expected)"
  python3 - "$T" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
headers, body = (root / 'response').read_bytes()[:-3].split(b'\r\n\r\n', 1)
(root / 'headers').write_bytes(headers)
(root / 'body').write_bytes(body)
PY
}

wait_health() {
  local url=$1 i
  for ((i=0; i<60; i++)); do
    if request --silent --fail --max-time 1 "$url/health" 2>/dev/null | jq -e '.status == "ok"' >/dev/null 2>&1; then
      return
    fi
    sleep 0.5
  done
  check_fail "$STEP (/health did not become ready)"
}

make_verified_user() {
  local auth=$1 data=$2 files=() link i
  STEP='sign up by API'
  http_status 200 "$(cat <<EOF
data = "{\"name\":\"Container check\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
EOF
  )" "$auth/api/auth/sign-up/email" -H "Origin: $auth" -H 'Content-Type: application/json'
  STEP='verify email using the outbox link'
  for ((i=0; i<40; i++)); do
    files=("$data"/outbox/*.json)
    ((${#files[@]})) && break
    sleep 0.25
  done
  ((${#files[@]} == 1)) || check_fail 'expected one verification email in the outbox'
  link=$(jq -er '.text | capture("(?<url>https?://[^[:space:]]+)").url' "${files[0]}")
  [[ $link == "$auth/api/auth/verify-email?"* ]] || check_fail 'unexpected verification URL in outbox'
  http_status 200 "$(printf 'url = "%s"\n' "$link")"
  http_status 200 "$(printf 'url = "%s"\ndata-urlencode = "password=%s"\n' "$link" "$PASSWORD")" -H "Origin: $auth"
  grep -q 'Email verified' "$T/body" || check_fail 'verification form did not confirm success'
}

# On failure, print what explains it before cleanup deletes $T: the last HTTP response and the tail of each
# named container's log. Tokens, cookies and other long secrets are redacted.
check_failure_context() {
  local name
  redact() {
    sed -E -e 's/^(set-cookie|authorization|cookie):.*/\1: [redacted]/I' \
      -e 's/eyJ[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*){1,2}/[jwt]/g' -e 's/[A-Za-z0-9_%+\/=-]{24,}/[redacted]/g'
  }
  if [[ -s $T/response || -s $T/curl-error ]]; then
    printf -- '--- last HTTP response (%s)\n' "${STEP:-}" >&2
    cat "$T/response" "$T/curl-error" 2>/dev/null | head -c 4000 | redact >&2 || true
    printf '\n' >&2
  fi
  for name in "$T"/pull.log "$T"/cli-error; do
    [[ -s $name ]] || continue
    printf -- '--- tail of %s\n' "${name##*/}" >&2
    tail -n 20 "$name" | redact >&2 || true
  done
  if [[ ${STEP:-} == build* ]]; then
    for name in "$T"/build*.log; do
      printf -- '--- tail of %s\n' "${name##*/}" >&2
      tail -n 20 "$name" | redact >&2 || true
    done
  fi
  for name in "$@"; do
    printf -- '--- podman logs --tail 40 %s\n' "$name" >&2
    podman logs --tail 40 "$name" 2>&1 | redact >&2 || true
  done
}

auth_cli() { podman exec --user "$PUID:$PGID" "$SERVER" node src/cli.ts clients "$@"; }
