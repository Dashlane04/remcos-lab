#!/usr/bin/env bash
# Hermetic fake Docker tests. No Docker daemon, images, containers, or real .env accessed.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT=$(mktemp -d "$ROOT/data/raw/QA-MOCK-SIEM.XXXXXX")
mkdir -p "$TEST_ROOT/scripts" "$TEST_ROOT/infra" "$TEST_ROOT/bin"
cp "$ROOT/scripts/start-siem.sh" "$TEST_ROOT/scripts/"
cp "$ROOT/infra/.env.example" "$TEST_ROOT/infra/"
cp "$ROOT/infra/docker-compose.yml" "$TEST_ROOT/infra/"
export FAKE_DOCKER_CALLS="$TEST_ROOT/docker-calls.txt"
export PATH="$TEST_ROOT/bin:$PATH"
cat >"$TEST_ROOT/bin/docker" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_DOCKER_CALLS"
case "$1" in
  info) exit 0;;
  inspect) printf '%s\n' "${FAKE_HEALTH:-running|healthy}"; exit 0;;
  compose)
    shift
    if [[ ${1:-} == version ]]; then exit 0; fi
    while (($#)); do
      case "$1" in
        --env-file|-f|--profile) shift 2;;
        config|up|stop) exit 0;;
        ps) printf 'fake-%s\n' "${!#}"; exit 0;;
        *) printf 'Unexpected fake Docker arguments\n' >&2; exit 70;;
      esac
    done;;
esac
exit 71
MOCK
chmod +x "$TEST_ROOT/bin/docker"
run() { bash "$TEST_ROOT/scripts/start-siem.sh" "$@" >"$TEST_ROOT/result.txt" 2>&1; }
fail() { printf 'FAIL: %s\n' "$*" >&2; cat "$TEST_ROOT/result.txt" >&2; exit 1; }

run --check-only || fail 'check-only failed'
grep -q 'Selected services: splunk$' "$TEST_ROOT/result.txt" || fail 'default must select Splunk only on this host'
[[ -f $TEST_ROOT/infra/.env ]] || fail 'missing local initialization'
if grep -q 'GENERATE_WITH_INITIALIZER' "$TEST_ROOT/infra/.env"; then fail 'secret placeholders retained'; fi
if grep -Eq '(^| )up( |$)' "$FAKE_DOCKER_CALLS"; then fail 'check-only started services'; fi
before=$(sha256sum "$TEST_ROOT/infra/.env")
run --check-only || fail 'second check-only failed'
[[ $(sha256sum "$TEST_ROOT/infra/.env") == "$before" ]] || fail 'existing settings changed'
if run --live --check-only; then fail 'localhost data binding accepted for live use'; fi
if run --stack elastic --fleet on --check-only; then fail 'Fleet accepted missing credentials'; fi

# WSL NAT requires a private advertised Windows address distinct from the WSL bind IP.
PYTHON=python3
command -v "$PYTHON" >/dev/null || PYTHON=python
"$PYTHON" - "$TEST_ROOT/infra/.env" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]); text=path.read_text()
text=text.replace('LAB_SERVER_IP=192.168.56.10','LAB_SERVER_IP=10.10.10.1')
text=text.replace('DATA_BIND_IP=127.0.0.1','DATA_BIND_IP=172.19.102.172')
path.write_text(text)
PY
run --live --check-only || fail 'separate private WSL advertised/bind addresses rejected'
"$PYTHON" - "$TEST_ROOT/infra/.env" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]); text=path.read_text().replace('DATA_BIND_IP=172.19.102.172','DATA_BIND_IP=0.0.0.0')
path.write_text(text)
PY
if run --live --check-only; then fail 'wildcard binding accepted for live use'; fi

PYTHON=python3
command -v "$PYTHON" >/dev/null || PYTHON=python
"$PYTHON" - "$TEST_ROOT/infra/.env" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]); text=path.read_text()
text=text.replace('DATA_BIND_IP=0.0.0.0','DATA_BIND_IP=172.19.102.172')
text=text.replace('FLEET_SERVER_SERVICE_TOKEN=','FLEET_SERVER_SERVICE_TOKEN=SYNTHETIC_TOKEN')
text=text.replace('FLEET_SERVER_POLICY_ID=','FLEET_SERVER_POLICY_ID=SYNTHETIC_POLICY')
path.write_text(text)
PY
run --stack both --live --fleet on || fail 'mock healthy service startup failed'
grep -q 'up -d splunk es01 kibana fleet-server' "$FAKE_DOCKER_CALLS" || fail 'wrong service selection'
grep -q 'SIEM service health checks passed' "$TEST_ROOT/result.txt" || fail 'healthy result not reported'
if grep -q 'SYNTHETIC_TOKEN' "$TEST_ROOT/result.txt"; then fail 'credential leaked'; fi
export FAKE_HEALTH='running|unhealthy'
if run --live; then fail 'unhealthy services incorrectly passed'; fi
unset FAKE_HEALTH
run --stop || fail 'non-destructive stop failed'
if grep -Eq '(^| )down( |$)|volume rm' "$FAKE_DOCKER_CALLS"; then fail 'destructive volume operation'; fi
printf '%s\n' 'PASS: fake-Docker check-only/no-start, secret initialization/preservation, split WSL private addresses, localhost/wildcard/Fleet gates, health readiness/failure, and volume-preserving stop.'
printf 'Synthetic fixture only: %s\n' "$TEST_ROOT"
