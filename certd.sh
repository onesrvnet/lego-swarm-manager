#!/usr/bin/env bash
# certd — discovers domains from Swarm service labels, issues/renews LE certs
# via lego (DNS-01), and generates a Traefik dynamic TLS config.
set -euo pipefail

: "${ACME_EMAIL:?set ACME_EMAIL}"
: "${DNS_PROVIDER:?set DNS_PROVIDER (lego provider name, e.g. cloudflare, hetzner)}"
CERT_DIR="${CERT_DIR:-/letsencrypt}"          # shared (Ceph) volume
LEGO_PATH="${LEGO_PATH:-$CERT_DIR/lego}"      # lego state (accounts + certs)
DYNAMIC_FILE="${DYNAMIC_FILE:-$CERT_DIR/traefik-tls.yml}"
INTERVAL="${INTERVAL:-300}"                   # seconds between runs
RENEW_DAYS="${RENEW_DAYS:-30}"
ACME_SERVER="${ACME_SERVER:-https://acme-v02.api.letsencrypt.org/directory}"
# Optional: comma-separated wildcard zones you always want, e.g. "*.hypeserv.com,*.osrv.eu"
STATIC_DOMAINS="${STATIC_DOMAINS:-}"
# Comma-separated zones whose (sub)domains use DNS-01. Anything else falls back
# to HTTP-01 via lego's internal challenge server (Traefik must route
# /.well-known/acme-challenge/ to this container on HTTP_CHALLENGE_PORT).
DNS_ZONES="${DNS_ZONES:-}"
HTTP_CHALLENGE_PORT="${HTTP_CHALLENGE_PORT:-8402}"
# Optional: regex of domains to ignore (e.g. internal ones)
EXCLUDE_REGEX="${EXCLUDE_REGEX:-}"
# Reachability preflight — probe a domain before EVERY ACME call so a
# not-yet-configured host can't burn Let's Encrypt's failed-validation quota
# (5 per hostname per hour) and lock out the whole account. Set PREFLIGHT=0
# to disable.
PREFLIGHT="${PREFLIGHT:-1}"
DNS_RESOLVER="${DNS_RESOLVER:-1.1.1.1}"        # resolver for probes ("" = system)
HTTP_PROBE_TIMEOUT="${HTTP_PROBE_TIMEOUT:-5}"  # seconds per HTTP reachability probe
# HTTP-01 self-test: serve a random token on HTTP_CHALLENGE_PORT and fetch it
# back THROUGH the public domain. Only a full round-trip proves the
# acme-challenge route actually reaches THIS container (a domain resolving to a
# different host still answers :80 but would fail the real challenge). Set 0 to
# fall back to a bare :80 reachability check.
HTTP_SELFTEST="${HTTP_SELFTEST:-1}"

log() { echo "[$(date -Is)] $*"; }

is_valid_domain() {
  # Strict FQDN check: labels/rules are untrusted input (compound rules,
  # unbalanced parens, HostRegexp, etc. can produce garbage) — never hand
  # anything unvalidated to lego.
  local d="$1"
  [[ "$d" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}

discover_domains() {
  # Pull Host(`...`) values out of every service's traefik router rules.
  docker service ls -q | xargs -r docker service inspect 2>/dev/null \
    | jq -r '
        .[].Spec |
        ((.Labels // {}) + (.TaskTemplate.ContainerSpec.Labels // {})) |
        to_entries[] |
        select(.key | test("^traefik\\.http\\.routers\\..*\\.rule$")) |
        .value' \
    | grep -oP 'Host\(\s*`[^`]+`(\s*,\s*`[^`]+`)*\s*\)' \
    | grep -oP '`\K[^`]+' \
    | sort -u
}

covered_by_wildcard() {
  # $1=domain — true if a STATIC_DOMAINS wildcard covers it (one level deep)
  local d="$1" w base
  IFS=',' read -ra ws <<< "$STATIC_DOMAINS"
  for w in "${ws[@]}"; do
    [[ "$w" == \*.* ]] || continue
    base="${w#\*.}"
    # foo.base matches *.base ; base itself does too (we issue SAN base below)
    if [[ "$d" == "$base" || ( "$d" == *".$base" && "${d%.$base}" != *.* ) ]]; then
      return 0
    fi
  done
  return 1
}

challenge_for() {
  # $1=domain — echoes "dns" if under one of DNS_ZONES, else "http"
  local d="$1" z
  IFS=',' read -ra zs <<< "$DNS_ZONES"
  for z in "${zs[@]}"; do
    [[ -z "$z" ]] && continue
    if [[ "$d" == "$z" || "$d" == *".$z" ]]; then echo dns; return; fi
  done
  echo http
}

lego_cert_file() {
  # lego stores certs as <domain>.crt with * replaced by _
  echo "$LEGO_PATH/certificates/$(echo "$1" | sed 's/\*/_/g').crt"
}

_dig() {
  # dig wrapper that honours DNS_RESOLVER (empty = system resolver)
  local args=(+short +time=3 +tries=2)
  [[ -n "$DNS_RESOLVER" ]] && args+=("@$DNS_RESOLVER")
  dig "${args[@]}" "$@" 2>/dev/null
}

dns_zone_resolvable() {
  # $1=domain — true if some parent zone answers NS (i.e. the zone is delegated
  # in public DNS). Walks up labels so it works without a Public Suffix List and
  # doesn't require the (sub)domain itself to exist yet — DNS-01 only needs the
  # zone so lego can place the _acme-challenge TXT.
  local name="${1#\*.}"
  while :; do
    [[ -n "$(_dig NS "$name")" ]] && return 0
    [[ "$name" != *.*.* ]] && return 1   # down to the apex, give up
    name="${name#*.}"
  done
}

cert_needs_renew() {
  # $1=cert file — true if missing, unparseable, or within RENEW_DAYS of expiry.
  # Lets us skip the probe+lego call entirely for healthy certs (no ACME work).
  local crt="$1" end end_epoch now_epoch
  [[ -f "$crt" ]] || return 0
  end="$(openssl x509 -enddate -noout -in "$crt" 2>/dev/null | cut -d= -f2)"
  [[ -n "$end" ]] || return 0
  end_epoch="$(date -d "$end" +%s 2>/dev/null)" || return 0
  now_epoch="$(date +%s)"
  (( (end_epoch - now_epoch) / 86400 <= RENEW_DAYS ))
}

http_selftest() {
  # $1=domain — true only if an HTTP-01 challenge would actually reach THIS
  # container. Serves a random token on HTTP_CHALLENGE_PORT (the same port +
  # /.well-known/acme-challenge path lego uses and Traefik routes to us) and
  # fetches it back through the PUBLIC domain. A byte-exact round-trip is the
  # only proof the route lands here — a domain that resolves to a different host
  # answers :80 but returns something else (or 404), so we skip it and never
  # spend Let's Encrypt validation quota on a challenge that can't succeed.
  local domain="$1" token doc body rc=1 pid i
  token="probe-$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 24)"
  [[ "$token" == probe- ]] && token="probe-fallback"   # /dev/urandom missing
  doc="$(mktemp -d)"
  mkdir -p "$doc/.well-known/acme-challenge"
  printf '%s' "$token" > "$doc/.well-known/acme-challenge/$token"

  busybox httpd -f -p "0.0.0.0:$HTTP_CHALLENGE_PORT" -h "$doc" &
  pid=$!
  # wait for the listener to come up (max ~2s) via a loopback fetch
  for i in $(seq 1 10); do
    curl -fsS -o /dev/null --max-time 1 \
      "http://127.0.0.1:$HTTP_CHALLENGE_PORT/.well-known/acme-challenge/$token" 2>/dev/null && break
    sleep 0.2
  done
  body="$(curl -fsS --max-time "$HTTP_PROBE_TIMEOUT" \
        "http://$domain/.well-known/acme-challenge/$token" 2>/dev/null || true)"
  [[ "$body" == "$token" ]] && rc=0

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -rf "$doc"
  return $rc
}

preflight_ok() {
  # usage: preflight_ok <challenge:dns|http> <domain>
  # Reachability probe gating every ACME call. DNS-01 needs the zone delegated;
  # HTTP-01 needs the acme-challenge route to actually reach THIS container.
  [[ "$PREFLIGHT" == "1" ]] || return 0
  local challenge="$1" domain="$2" probe="${2#\*.}"

  if [[ "$challenge" == "dns" ]]; then
    if dns_zone_resolvable "$domain"; then return 0; fi
    log "preflight: skip $domain — no delegated DNS zone for $probe (not in DNS yet)"
    return 1
  fi

  # HTTP-01 — must resolve first, then prove the challenge lands on us.
  if [[ -z "$(_dig A "$probe")$(_dig AAAA "$probe")" ]]; then
    log "preflight: skip $domain — no A/AAAA record (DNS not pointed here yet)"
    return 1
  fi
  if [[ "$HTTP_SELFTEST" == "1" ]]; then
    if http_selftest "$probe"; then return 0; fi
    log "preflight: skip $domain — acme-challenge round-trip did not reach this container (domain served elsewhere or not routed to :$HTTP_CHALLENGE_PORT)"
    return 1
  fi
  # fallback: bare :80 reachability — does NOT prove the challenge reaches us.
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time "$HTTP_PROBE_TIMEOUT" \
         "http://$probe/.well-known/acme-challenge/certd-preflight" 2>/dev/null || true)"
  if [[ -z "$code" || "$code" == "000" ]]; then
    log "preflight: skip $domain — no HTTP response on :80 (not routed here yet)"
    return 1
  fi
  return 0
}

ensure_cert() {
  # usage: ensure_cert <challenge:dns|http> <domain> [extra lego args...]
  local challenge="$1" domain="$2"; shift 2
  local extra_args=("$@")
  local chal_args=()
  if [[ "$challenge" == "dns" ]]; then
    chal_args=(--dns "$DNS_PROVIDER")
  else
    chal_args=(--http --http.port ":$HTTP_CHALLENGE_PORT")
  fi
  local crt; crt="$(lego_cert_file "$domain")"

  # Healthy existing cert → no ACME work, so no probe and no lego call.
  [[ -f "$crt" ]] && ! cert_needs_renew "$crt" && return 0

  # Everything past here contacts ACME → gate on reachability first so we never
  # spend failed-validation quota on a domain that can't complete the challenge.
  if ! preflight_ok "$challenge" "$domain"; then
    [[ -f "$crt" ]] && log "preflight failed for $domain — keeping existing cert, retry next cycle"
    return 0
  fi

  if [[ -f "$crt" ]]; then
    # renew is a no-op unless within RENEW_DAYS of expiry
    lego --accept-tos --email "$ACME_EMAIL" --server "$ACME_SERVER" \
         "${chal_args[@]}" --path "$LEGO_PATH" \
         --domains "$domain" "${extra_args[@]}" \
         renew --days "$RENEW_DAYS" --no-random-sleep \
      || log "WARN: renew failed for $domain ($challenge)"
  else
    log "issuing new cert for $domain via ${challenge}-01"
    lego --accept-tos --email "$ACME_EMAIL" --server "$ACME_SERVER" \
         "${chal_args[@]}" --path "$LEGO_PATH" \
         --domains "$domain" "${extra_args[@]}" \
         run \
      || log "WARN: issuance failed for $domain ($challenge)"
  fi
}

generate_dynamic_config() {
  local tmp="$DYNAMIC_FILE.tmp"
  {
    echo "# generated by certd $(date -Is) — do not edit"
    echo "tls:"
    echo "  certificates:"
    local crt key
    for crt in "$LEGO_PATH"/certificates/*.crt; do
      [[ -e "$crt" ]] || continue
      [[ "$crt" == *.issuer.crt ]] && continue
      key="${crt%.crt}.key"
      [[ -f "$key" ]] || continue
      echo "    - certFile: $crt"
      echo "      keyFile: $key"
    done
  } > "$tmp"
  # atomic-ish swap so Traefik never reads a half-written file
  mv "$tmp" "$DYNAMIC_FILE"
}

run_once() {
  local domains d
  local raw valid=() bad=()
  raw="$(discover_domains || true)"
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    if is_valid_domain "$d"; then
      valid+=("$d")
    else
      bad+=("$d")
    fi
  done <<< "$raw"
  domains="$(printf '%s\n' "${valid[@]:-}")"
  log "discovered: ${valid[*]:-none}"
  [[ ${#bad[@]} -gt 0 ]] && log "WARN: skipped invalid domain(s) from rule parsing: ${bad[*]} — check 'traefik.http.routers.*.rule' labels for compound/negated rules"

  # static/wildcard certs first
  if [[ -n "$STATIC_DOMAINS" ]]; then
    IFS=',' read -ra ws <<< "$STATIC_DOMAINS"
    for w in "${ws[@]}"; do
      if [[ "$w" == \*.* ]]; then
        ensure_cert dns "$w" --domains "${w#\*.}"   # wildcards require DNS-01
      else
        ensure_cert "$(challenge_for "$w")" "$w"
      fi
    done
  fi

  # per-domain certs for anything not wildcard-covered
  for d in $domains; do
    [[ -n "$EXCLUDE_REGEX" ]] && [[ "$d" =~ $EXCLUDE_REGEX ]] && continue
    covered_by_wildcard "$d" && continue
    ensure_cert "$(challenge_for "$d")" "$d"
  done

  generate_dynamic_config
  log "cycle done, $(ls "$LEGO_PATH"/certificates/*.crt 2>/dev/null | grep -vc issuer || echo 0) certs active"
}

mkdir -p "$LEGO_PATH"
# HTTP-01 self-test needs busybox httpd; downgrade loudly rather than silently
# skipping every HTTP domain if the applet is unavailable.
if [[ "$PREFLIGHT" == "1" && "$HTTP_SELFTEST" == "1" ]] \
   && ! busybox --list 2>/dev/null | grep -qx httpd; then
  log "WARN: busybox httpd unavailable — disabling HTTP-01 self-test, falling back to bare :80 check"
  HTTP_SELFTEST=0
fi
log "certd starting (interval ${INTERVAL}s, provider $DNS_PROVIDER)"
while true; do
  run_once || log "WARN: cycle failed"
  sleep "$INTERVAL"
done