#!/usr/bin/env bash
# Run on the separate SIEM machine. Does not execute samples or change Windows policy.
set -Eeuo pipefail

LAB_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
STACK=splunk
FLEET=auto
LIVE=0
CHECK_ONLY=0
STOP=0
TIMEOUT=600

usage() {
  cat <<'HELP'
Usage: bash scripts/start-siem.sh [options]
  --stack both|splunk|elastic   Default: splunk (one phase at a time on this host)
  --fleet auto|on|off           Auto starts Fleet if its local settings exist
  --live                       Require private advertised and Docker bind IPv4 addresses
  --check-only                 Validate settings and Compose; do not start/pull anything
  --stop                       Stop selected services while preserving data volumes
  --timeout SECONDS            Health-wait limit, 30..1800 (default: 600)
  --help

Requires Bash, Python 3, Docker with Compose v2, and existing Docker daemon access.
Initializes a missing infra/.env with random local secrets; preserves an existing file.
Configure its private addresses before live use. Fleet's first enrollment/policy setup
is still done in Kibana. Start Windows collection separately inside the disposable VM.
HELP
}
fail() { printf '%s\n' "ERROR: $*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --stack|--fleet|--timeout)
      (($# >= 2)) || fail "Missing value for $1"
      case "$1" in --stack) STACK=$2;; --fleet) FLEET=$2;; --timeout) TIMEOUT=$2;; esac
      shift 2;;
    --live) LIVE=1; shift;;
    --check-only) CHECK_ONLY=1; shift;;
    --stop) STOP=1; shift;;
    --help|-h) usage; exit 0;;
    *) fail "Unknown option: $1";;
  esac
done
[[ $STACK =~ ^(both|splunk|elastic)$ ]] || fail 'Invalid --stack'
[[ $FLEET =~ ^(auto|on|off)$ ]] || fail 'Invalid --fleet'
[[ $TIMEOUT =~ ^[0-9]+$ ]] && ((TIMEOUT >= 30 && TIMEOUT <= 1800)) || fail 'Invalid --timeout'
((CHECK_ONLY == 0 || STOP == 0)) || fail '--check-only and --stop cannot be combined'
[[ $STACK != splunk || $FLEET != on ]] || fail 'Fleet requires the Elastic stack'
command -v docker >/dev/null || fail 'Install Docker/Compose on the SIEM machine first'
PYTHON=python3
command -v "$PYTHON" >/dev/null || PYTHON=python
command -v "$PYTHON" >/dev/null || fail 'Python 3 is required for safe local settings handling'
docker compose version >/dev/null || fail 'Docker Compose v2 is unavailable'

# Parse data as data: never source/eval an .env file, and never print its secrets.
SETTINGS=$("$PYTHON" - "$LAB_ROOT" "$STACK" "$FLEET" "$LIVE" "$STOP" <<'PY'
import ipaddress, os, pathlib, re, secrets, sys
root, stack, fleet, live, stopping = sys.argv[1:]
path = pathlib.Path(root) / 'infra/.env'
if not path.exists():
    if stopping == '1':
        raise SystemExit('No infra/.env exists; nothing was initialized for --stop.')
    text = path.with_name('.env.example').read_text(encoding='utf-8-sig')
    for key in ('ELASTIC_PASSWORD','KIBANA_PASSWORD','KIBANA_ENCRYPTION_KEY','SPLUNK_PASSWORD'):
        text = text.replace(key + '=GENERATE_WITH_INITIALIZER', key + '=' + secrets.token_hex(32))
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        print('Created infra/.env with private random credentials; existing files are preserved.', file=sys.stderr)
values = {}
for line in path.read_text(encoding='utf-8-sig').splitlines():
    if line.strip() and not line.lstrip().startswith('#') and '=' in line:
        key, value = line.split('=', 1)
        values[key.strip()] = value.strip().strip('"\'')
for key in ('STACK_VERSION','SPLUNK_VERSION'):
    if not re.fullmatch(r'[A-Za-z0-9._-]+', values.get(key, '')):
        raise SystemExit('Set a valid ' + key + ' in infra/.env')
for key in ('ELASTIC_PASSWORD','KIBANA_PASSWORD','KIBANA_ENCRYPTION_KEY','SPLUNK_PASSWORD'):
    value = values.get(key, '')
    if not value or value == 'GENERATE_WITH_INITIALIZER':
        raise SystemExit('Initialize local credentials; missing/uninitialized ' + key)
fleet_ready = bool(values.get('FLEET_SERVER_SERVICE_TOKEN') and values.get('FLEET_SERVER_POLICY_ID'))
if fleet == 'on' and not fleet_ready:
    raise SystemExit('Configure Fleet Server policy ID and service token in local infra/.env first; see docs/03-elastic.md')
use_fleet = stack != 'splunk' and (fleet == 'on' or (fleet == 'auto' and fleet_ready))
if live == '1' and stopping != '1':
    try:
        server = ipaddress.IPv4Address(values.get('LAB_SERVER_IP', ''))
        bind = ipaddress.IPv4Address(values.get('DATA_BIND_IP', ''))
        private_ranges = tuple(ipaddress.IPv4Network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
        valid = any(server in net for net in private_ranges) and any(bind in net for net in private_ranges)
    except ValueError:
        valid = False
    if not valid:
        raise SystemExit('For --live, set LAB_SERVER_IP to the private endpoint-facing TLS address and DATA_BIND_IP to the private Docker-host bind address. They may differ for WSL NAT forwarding; see docs/setup/02-network.md.')
print('1' if use_fleet else '0')
PY
) || fail 'Local settings validation failed'

COMPOSE=(docker compose --env-file "$LAB_ROOT/infra/.env" -f "$LAB_ROOT/infra/docker-compose.yml")
SERVICES=()
if [[ $STACK == both || $STACK == splunk ]]; then
  COMPOSE+=(--profile splunk)
  SERVICES+=(splunk)
fi
if [[ $STACK == both || $STACK == elastic ]]; then
  COMPOSE+=(--profile elastic)
  SERVICES+=(es01 kibana)
fi
if [[ $SETTINGS == 1 ]]; then
  COMPOSE+=(--profile fleet)
  SERVICES+=(fleet-server)
fi
"${COMPOSE[@]}" config --quiet
if ((CHECK_ONLY)); then
  printf 'Configuration validated only. Selected services: %s\n' "${SERVICES[*]}"
  exit 0
fi
docker info >/dev/null 2>&1 || fail 'Docker daemon is unavailable; start it on the SIEM machine'
if ((STOP)); then
  "${COMPOSE[@]}" stop "${SERVICES[@]}"
  printf '%s\n' 'Selected services stopped. Persistent data and certificates preserved.'
  exit 0
fi
printf 'Starting: %s\n' "${SERVICES[*]}"
"${COMPOSE[@]}" up -d "${SERVICES[@]}"
printf '%s\n' 'Waiting for container health checks. Windows collection has not started.'
deadline=$((SECONDS + TIMEOUT))
for service in "${SERVICES[@]}"; do
  while :; do
    cid=$("${COMPOSE[@]}" ps -a -q "$service")
    [[ -n $cid ]] || fail "No container found for $service"
    state=$(docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid")
    [[ $state == 'running|healthy' ]] && break
    case "$state" in
      *'|unhealthy'|exited'|'*|dead'|'*) fail "$service is $state; inspect its Compose logs locally";;
      *'|none') fail "$service has no health check; use this project's updated Compose file";;
    esac
    ((SECONDS < deadline)) || fail "Timed out waiting for $service; inspect its Compose logs locally"
    sleep 3
  done
  printf 'Healthy: %s\n' "$service"
done
printf '%s\n' 'SIEM service health checks passed. Endpoint enrollment and ingestion still require the benign pilot.'
if [[ $STACK != elastic ]]; then printf '%s\n' 'Splunk UI: http://127.0.0.1:8000'; fi
if [[ $STACK != splunk ]]; then
  printf '%s\n' 'Kibana UI: https://localhost:5601 (trust the public lab CA)'
  if [[ $SETTINGS == 0 ]]; then
    printf '%s\n' 'Fleet Server not started: complete docs/03-elastic.md, then rerun with --fleet on.'
  fi
fi
if ((LIVE == 0)); then printf '%s\n' 'No --live check requested. Verify private data bindings before remote forwarding.'; fi
printf '%s\n' 'Next: run Start-LabCollection.ps1 in the disposable Windows VM; wait for READY before manual specimen activity.'
