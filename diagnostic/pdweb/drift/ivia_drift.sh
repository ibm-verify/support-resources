#!/usr/bin/env bash
# ivia_drift.sh - configuration drift detector for IBM Verify Identity Access (IVIA)
# Uses only curl + jq against the LMI REST API. Read-only: it never changes the appliance.
#
# Environment:
#   IVIA_HOST       required, LMI base URL, e.g. https://ivia.example.com:9443
#   IVIA_USER       LMI user (default: admin)
#   IVIA_PASS       LMI password (prompted if unset)
#   IVIA_CACERT     CA bundle for TLS verification (recommended)
#   IVIA_INSECURE   set to 1 to skip TLS verification (lab use only)
#   IVIA_TIMEOUT    per-request tim:eout in seconds (default: 30)
#   DRIFT_IGNORE_KEYS  regex of entry keys to ignore when comparing (node-specific keys)
#   DRIFT_MASK_KEYS    regex of entry keys whose values are masked in snapshots
#
# Exit codes: 0 no drift, 1 drift found, 2 usage/connection error.
#
# This tool is used to detect configuration differences between two nodes.
# To use, first set the environments above for first node being compared:
#   export IVIA_HOST=<your LMI for NodeA>
#   export IVIA_USER=<your LMI admin for NodeA>
#   export IVIA_PASS=<your LMI password for NodeA>
#
# Generate NodeA snapshot which will be used to compare vs second node
#   ./ivia_drift.sh snapshot -o nodeA
#
# Set the environments above for second node being compared:
#   export IVIA_HOST=<your LMI for NodeB>
#   export IVIA_USER=<your LMI admin for NodeB>
#   export IVIA_PASS=<your LMI password for NodeB>
#
# Generate NodeB snapshot to compare vs NodeA
#   ./ivia_drift.sh snapshot -o nodeB
#
# Once NodeA and NodeB snapshots are created, run the compare command.
#   ./ivia_drift.sh compare nodeA nodeB
#
set -uo pipefail

IGNORE_KEYS="${DRIFT_IGNORE_KEYS:-azn-server-name|pd-user-pwd|bind-pwd|network-interface|server-name|listen-interface}"
MASK_KEYS="${DRIFT_MASK_KEYS:-pwd|passw|secret|token}"
RUNTIME_FIELDS='["current_requests","total_requests","operation_state","server_state","server_uuid","active_worker_threads"]'

die() { echo "ERROR: $*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed"; }
need curl; need jq

usage() {
  cat >&2 <<'EOF'
Usage: ivia_drift.sh <command> [args]

  status                        reverse proxy instances and their reported state
  pending                       LMI changes saved but not deployed (config != runtime)
  junctions [instance]          live junction/back-end server state; flags non-running servers
  snapshot [-o dir] [instance...]
                                save current stanza entries and junction definitions
  compare [--raw] <dirA> <dirB> diff two snapshots (e.g. baseline vs now, or node A vs node B),
                                grouped per stanza/junction; --raw gives a plain unified diff
  check <baseline_dir>          fresh snapshot vs baseline + pending changes + junction health

In compare output: '-' = only in <dirA> (first argument), '+' = only in <dirB> (second), '~' = value changed.
EOF
  exit 2
}

# ---- REST helper -------------------------------------------------------------
setup_auth() {
  [[ -n "${IVIA_HOST:-}" ]] || die "IVIA_HOST is not set (e.g. https://ivia.example.com:9443)"
  IVIA_USER="${IVIA_USER:-admin}"
  if [[ -z "${IVIA_PASS:-}" ]]; then
    read -rsp "Password for ${IVIA_USER}@${IVIA_HOST}: " IVIA_PASS </dev/tty || die "no password"
    echo >&2
  fi
  export IVIA_HOST IVIA_USER IVIA_PASS IVIA_CACERT IVIA_INSECURE IVIA_TIMEOUT
  CURL_OPTS=(-s --max-time "${IVIA_TIMEOUT:-30}")
  if [[ -n "${IVIA_CACERT:-}" ]]; then
    CURL_OPTS+=(--cacert "$IVIA_CACERT")
  elif [[ "${IVIA_INSECURE:-0}" == 1 ]]; then
    CURL_OPTS+=(-k)
  fi
}

# GET <path>; credentials go through a curl config on stdin so they never appear in `ps`.
# api: fails on HTTP errors. api_raw: never fails on HTTP errors, prints body then "\n<http_code>".
_auth_cfg() {
  local u="${IVIA_USER}:${IVIA_PASS}"
  u="${u//\\/\\\\}"; u="${u//\"/\\\"}"
  printf 'user = "%s"\n' "$u"
}
api() { _auth_cfg | curl "${CURL_OPTS[@]}" -f -K - -H 'Accept: application/json' "${IVIA_HOST%/}$1"; }
api_raw() { _auth_cfg | curl "${CURL_OPTS[@]}" -w '\n%{http_code}' -K - -H 'Accept: application/json' "${IVIA_HOST%/}$1"; }

# One request up front so connection and login problems give one clear message
# instead of an error per call later.
preflight() {
  local raw rc code
  raw=$(api_raw /wga/reverseproxy); rc=$?
  [[ $rc -eq 0 ]] || die "cannot connect to $IVIA_HOST (curl exit $rc; check IVIA_HOST, network, TLS: IVIA_CACERT or IVIA_INSECURE=1)"
  code="${raw##*$'\n'}"
  case "$code" in
    200) ;;
    401|403) die "login rejected by $IVIA_HOST (HTTP $code) for user '$IVIA_USER'" ;;
    *) die "unexpected HTTP $code from $IVIA_HOST/wga/reverseproxy" ;;
  esac
}

urlenc() { jq -rn --arg s "$1" '$s|@uri'; }

list_instances() { api /wga/reverseproxy | jq -r '.[].id'; }

# ---- snapshot ----------------------------------------------------------------
# Normalise one junction: the LMI returns "servers" as one string, servers separated by '#',
# fields by ';', key/value by '!'. Output: "servers" becomes an array of objects, "id" is set.
JQ_NORMALISE='
  def parse_servers:
    if type=="string" then
      split("#") | map(select(length>0) | split(";") | map(select(length>0) | split("!")
        | {key: .[0], value: (.[1:] | join("!"))}) | from_entries)
    elif type=="array" then . else [] end;
  .servers |= parse_servers | . + {id: (.id // .junction_point)}'

# Detailed junction list; falls back to one request per junction on older firmware.
junctions_json() {
  local inst="$1" j id one
  if j=$(api "/wga/reverseproxy/$inst/junctions?detailed=true" 2>/dev/null) &&
     jq -e 'type=="array" and (map(has("junction_point"))|all)' >/dev/null 2>&1 <<<"$j"; then
    jq "[.[] | $JQ_NORMALISE]" <<<"$j"; return 0
  fi
  j=$(api "/wga/reverseproxy/$inst/junctions") || return 1
  jq -r '.[] | (.id // .junction_point)' <<<"$j" | while IFS= read -r id; do
    one=$(api "/wga/reverseproxy/$inst/junctions?junctions_id=$(urlenc "$id")") || continue
    jq "(if type==\"array\" then .[0] else . end) | . + {id: \"$id\"} | $JQ_NORMALISE" <<<"$one"
  done | jq -s '.'
}

# Fetch one stanza into <outdir>/<checksum>.part as "[stanza] key = value" lines
# (values sorted, secrets masked). Run in parallel by snapshot_instance via xargs.
fetch_stanza() {
  local inst="$1" outdir="$2" stanza="$3" enc f raw code body
  enc=$(urlenc "$stanza")
  f="$outdir/$(printf '%s' "$stanza" | od -An -tx1 | tr -d ' \n').part"
  raw=$(api_raw "/wga/reverseproxy/$inst/configuration/stanza/$enc") || { printf '\nWARN: request failed for stanza %s of %s\n' "'$stanza'" "$inst" >&2; return; }
  code="${raw##*$'\n'}"; body="${raw%$'\n'*}"
  case "$code" in
    200) { printf '[%s]\n' "$stanza"
           jq -r --arg s "$stanza" --arg mask "$MASK_KEYS" '
             to_entries[] | .key as $k
             | (.value | if type=="array" then . else [.] end | map(tostring) | sort)[] as $v
             | "[\($s)] \($k) = \(if ($k|test($mask;"i")) then "********" else $v end)"' <<<"$body"
         } > "$f" ;;
    404) printf '[%s]\n' "$stanza" > "$f" ;;   # listed but empty
    *)   printf '\nWARN: HTTP %s reading stanza %s of %s\n' "$code" "'$stanza'" "$inst" >&2 ;;
  esac
  printf '.' >&2   # progress: one dot per stanza
}

snapshot_instance() {
  local inst="$1" out="$2" parts
  mkdir -p "$out/$inst"
  parts=$(mktemp -d) || die "cannot create temp dir"
  printf "Reading '%s' " "$inst" >&2
  api "/wga/reverseproxy/$inst/configuration/stanza" | jq -j '.[] | ., "\u0000"' |
    xargs -0 -n1 -P "${IVIA_PARALLEL:-8}" "$SELF" _stanza "$inst" "$parts"
  cat "$parts"/*.part 2>/dev/null | LC_ALL=C sort > "$out/$inst/config.txt"
  rm -rf "$parts"

  junctions_json "$inst" | jq -r --argjson rt "$RUNTIME_FIELDS" '
    def val: if type=="string" then . else tojson end;
    .[] | . as $j | ($j.id // $j.junction_point) as $id
    | ( $j | del(.servers) | to_entries[] | select(.key as $k | $rt | index($k) | not)
        | "junction \($id) \(.key)=\(.value|val)" ),
      ( ($j.servers // [])[] | . as $s
        | "\($s.server_hostname):\($s.server_port)" as $sid
        | to_entries[] | select(.key as $k | $rt | index($k) | not)
        | "junction \($id) server \($sid) \(.key)=\(.value|val)" )' |
    LC_ALL=C sort > "$out/$inst/junctions.txt" || printf '\nWARN: could not read junctions of %s\n' "$inst" >&2
  printf '. done\n' >&2
}

# Exit with a clear message if any name is not a reverse proxy instance on the appliance.
validate_instances() {
  local live name
  live=$(list_instances) || die "cannot list reverse proxy instances"
  for name in "$@"; do
    grep -qxF -- "$name" <<<"$live" ||
      die "'$name' is not a reverse proxy instance. Available: $(tr '\n' ' ' <<<"$live")"
  done
}

cmd_snapshot() {
  local out="" insts=()
  while [[ $# -gt 0 ]]; do
    case "$1" in -o) out="$2"; shift 2 ;; *) insts+=("$1"); shift ;; esac
  done
  [[ -n "$out" ]] || out="./ivia-snapshot-$(echo "$IVIA_HOST" | sed -E 's#^https?://##; s#[:/]#_#g')-$(date +%Y%m%d-%H%M%S)"
  if [[ ${#insts[@]} -gt 0 ]]; then
    validate_instances "${insts[@]}"
  else
    while IFS= read -r i; do insts+=("$i"); done < <(list_instances)
  fi
  [[ ${#insts[@]} -gt 0 ]] || die "no reverse proxy instances found"
  mkdir -p "$out"
  printf 'host=%s\ntime=%s\n' "$IVIA_HOST" "$(date -u +%FT%TZ)" > "$out/meta.txt"
  local i
  for i in "${insts[@]}"; do
    snapshot_instance "$i" "$out"
  done
  echo "Snapshot saved to $out" >&2
  echo "$out"
}

# ---- compare -----------------------------------------------------------------
filtered() { grep -vE "^\[[^]]*\] ($IGNORE_KEYS) = " "$1" || true; }

# Reads diff lines ("-[stanza] key = value" / "+junction /app ...") on stdin and prints them
# grouped per stanza (or per junction) with change counts. Output is deterministic (input is sorted).
# $1 and $2 are the names shown for the "-" side and the "+" side ("only in <name>").
group_diff() {
  LA="$1" LB="$2" awk '
    BEGIN { la = ENVIRON["LA"]; lb = ENVIRON["LB"] }
    function trim(s) { sub(/^ +/, "", s); sub(/ +$/, "", s); return s }
    function join(s, v) { return (s == "") ? v : s ", " v }
    {
      sign = substr($0, 1, 1); rest = substr($0, 2)
      if (rest ~ /^\[/)            { match(rest, /^\[[^]]*\]/); g = substr(rest, 1, RLENGTH); detail = trim(substr(rest, RLENGTH + 1)) }
      else if (rest ~ /^junction /) { split(rest, f, " "); g = "junction " f[2]; detail = trim(substr(rest, length(g) + 1)) }
      else                          { g = "(other)"; detail = trim(rest) }
      if (!(g in seen)) { seen[g] = 1; order[++ng] = g }
      if (detail == "") { hdr[g] = sign; next }          # bare "[stanza]" line: stanza only in one snapshot
      i = index(detail, "=")
      if (i > 0) { k = trim(substr(detail, 1, i - 1)); v = trim(substr(detail, i + 1)) } else { k = detail; v = "" }
      kk = g SUBSEP k
      if (!(kk in kseen)) { kseen[kk] = 1; nk[g]++; key[g, nk[g]] = k }
      if (sign == "-") minus[kk] = join(minus[kk], v); else plus[kk] = join(plus[kk], v)
    }
    END {
      for (n = 1; n <= ng; n++) {
        g = order[n]; ch = ad = rm = 0; delete line; nl = 0
        for (j = 1; j <= nk[g]; j++) {
          k = key[g, j]; kk = g SUBSEP k
          hm = (kk in minus); hp = (kk in plus)
          if (hm && hp)      { ch++; line[++nl] = "   ~ " k ": " minus[kk] "  ->  " plus[kk] }
          else if (hp)       { ad++; line[++nl] = "   + " k " = " plus[kk] }
          else               { rm++; line[++nl] = "   - " k " = " minus[kk] }
        }
        # whole stanza/junction only in one snapshot: bare "[stanza]" header line, or the junction "id" entry
        kid = g SUBSEP "id"
        if (g ~ /^junction / && (kid in plus) && !(kid in minus)) hdr[g] = "+"
        if (g ~ /^junction / && (kid in minus) && !(kid in plus)) hdr[g] = "-"
        what = (g ~ /^junction /) ? "junction" : "stanza"
        if (hdr[g] == "+")      { sa++; st = what " only in " lb ", " ad (ad == 1 ? " entry" : " entries") }
        else if (hdr[g] == "-") { sr++; st = what " only in " la ", " rm (rm == 1 ? " entry" : " entries") }
        else {
          sm++; st = ""
          if (ch) st = st ch " changed"
          if (ad) st = st (st == "" ? "" : ", ") ad " only in " lb
          if (rm) st = st (st == "" ? "" : ", ") rm " only in " la
        }
        print "== " g "  (" st ")"
        for (j = 1; j <= nl; j++) print line[j]
        tc += ch; ta += ad; tr += rm
      }
      printf "Summary: %d group(s) differ (%d modified, %d only in %s, %d only in %s); entries: %d changed, %d only in %s, %d only in %s\n", \
             ng, sm, sa, lb, sr, la, tc, ta, lb, tr, la
    }'
}

cmd_compare() {
  local raw=0 a b rc=0 d inst f out kind
  if [[ "${1:-}" == "--raw" ]]; then raw=1; shift; fi
  a="${1:-}"; b="${2:-}"
  [[ -d "$a" && -d "$b" ]] || die "compare needs two snapshot directories"
  for d in "$a"/*/; do
    inst=$(basename "$d")
    if [[ ! -d "$b/$inst" ]]; then echo "DRIFT: instance '$inst' only in $a"; rc=1; continue; fi
    for f in config.txt junctions.txt; do
      if [[ $raw -eq 1 ]]; then
        diff -u --label "${LABEL_A:-$a}/$inst/$f" --label "${LABEL_B:-$b}/$inst/$f" \
          <(filtered "$a/$inst/$f") <(filtered "$b/$inst/$f") || rc=1
      else
        out=$(diff -U0 <(filtered "$a/$inst/$f") <(filtered "$b/$inst/$f") | grep -E '^[-+][^-+]' || true)
        [[ -n "$out" ]] || continue
        rc=1
        kind="configuration"; [[ "$f" == junctions.txt ]] && kind="junctions"
        printf '### instance %s, %s  ("-" = only in %s, "+" = only in %s)\n' "$inst" "$kind" "${LABEL_A:-$a}" "${LABEL_B:-$b}"
        group_diff "${LABEL_A:-$a}" "${LABEL_B:-$b}" <<<"$out"
        echo
      fi
    done
  done
  for d in "$b"/*/; do
    inst=$(basename "$d")
    [[ -d "$a/$inst" ]] || { echo "DRIFT: instance '$inst' only in $b"; rc=1; }
  done
  [[ $rc -eq 0 ]] && echo "No configuration drift between ${LABEL_A:-$a} and ${LABEL_B:-$b}."
  return $rc
}

# ---- runtime-side checks -----------------------------------------------------
cmd_status() {
  api /wga/reverseproxy | jq -r '.[] | [.id, ("started=" + ((.started // "?")|tostring)), ("enabled=" + ((.enabled // "?")|tostring))] | @tsv'
}

cmd_pending() {
  local r n
  r=$(api /isam/pending_changes) || return 2
  n=$(jq -r '(.changes // []) | length' <<<"$r" 2>/dev/null || echo "?")
  if [[ "$n" == "0" ]]; then
    echo "OK: no undeployed LMI changes."
    return 0
  fi
  echo "DRIFT: $n LMI change(s) saved but not deployed; running servers do not have them yet."
  jq . <<<"$r"
  return 1
}

cmd_junctions() {
  local insts=("$@") i rc=0 out
  [[ ${#insts[@]} -gt 0 ]] || while IFS= read -r i; do insts+=("$i"); done < <(list_instances)
  for i in "${insts[@]}"; do
    echo "== instance: $i (junction / server / server_state / operation_state)"
    out=$(junctions_json "$i" | jq -r '
      .[] | (.id // .junction_point) as $id
      | if ((.servers // []) | length) == 0 then [$id, "(no servers)", "-", "-"]
        else (.servers[] | [$id, "\(.server_hostname):\(.server_port)", (.server_state // "?"), (.operation_state // "?")]) end
      | @tsv') || { echo "ERROR: cannot read junctions of $i" >&2; rc=1; continue; }
    printf '%s\n' "$out" | awk -F'\t' '
      { flag = ($2 !~ /^\(/ && (tolower($3) != "running" || tolower($4) != "online")) ? "  <-- CHECK" : ""
        printf "%s\t%s\t%s\t%s%s\n", $1, $2, $3, $4, flag; if (flag != "") bad = 1 }
      END { exit bad }' | column -t -s "$(printf '\t')" || rc=1
  done
  return $rc
}

cmd_check() {
  local base="${1:-}" tmp rc=0 insts=() d name live
  [[ -d "$base" ]] || die "check needs a baseline snapshot directory"
  tmp=$(mktemp -d) || die "cannot create temp dir"
  trap 'rm -rf "$tmp"' RETURN
  live=$(list_instances) || die "cannot list reverse proxy instances"
  # Only read instances that still exist; ones missing from the appliance show up as drift in the compare.
  for d in "$base"/*/; do
    name=$(basename "$d")
    if grep -qxF -- "$name" <<<"$live"; then insts+=("$name"); fi
  done
  [[ ${#insts[@]} -gt 0 ]] ||
    die "no instance directories in '$base' match this appliance (is it a snapshot made by 'snapshot'? instances here: $(tr '\n' ' ' <<<"$live"))"
  for d in "${insts[@]}"; do snapshot_instance "$d" "$tmp"; done
  echo "--- 1. configuration: baseline vs current"
  LABEL_A="baseline" LABEL_B="current" cmd_compare "$base" "$tmp" || rc=1
  echo "--- 2. undeployed LMI changes"
  cmd_pending || rc=1
  echo "--- 3. live junction state"
  cmd_junctions "${insts[@]}" || rc=1
  return $rc
}

# ---- main --------------------------------------------------------------------
[[ $# -ge 1 ]] || usage
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cmd="$1"; shift
case "$cmd" in
  _stanza) setup_auth; fetch_stanza "$@" ;;   # internal: parallel worker
  compare) cmd_compare "$@" ;;   # offline: no appliance access needed
  status|pending|junctions|snapshot|check)
    setup_auth
    preflight
    "cmd_$cmd" "$@"
    rc=$?
    [[ $rc -eq 22 ]] && { echo "ERROR: appliance request failed (HTTP error; check IVIA_HOST, credentials, permissions)" >&2; rc=2; }
    exit $rc ;;
  *) usage ;;
esac
