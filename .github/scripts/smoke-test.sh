#!/bin/bash
# smoke-test.sh BINARY: checks a release binary on the machine that runs it, offline.
#
# It prints its help, creates a CA in a temporary directory, proxies a plain HTTP request to a
# local origin (python3 -m http.server on 127.0.0.1), serves the CA page of http://wirust.test/
# and, with --ui, answers the API only with the token. Everything listens on 127.0.0.1 and
# everything it starts is stopped on exit. Used by .github/workflows/release.yml; runs locally
# too: .github/scripts/smoke-test.sh target/release/wirust
set -euo pipefail

bin=${1:?usage: smoke-test.sh BINARY}
python=$(command -v python3 || command -v python)
work=$(mktemp -d)
pids=()
cleanup() {
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

free_port() {
    "$python" -I -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

fail() {
    echo "FAIL: $*" >&2
    echo "--- wirust output:" >&2
    cat "$work/proxy.log" >&2 || true
    exit 1
}

"$bin" --help >"$work/help.txt"
grep -q 'wirust' "$work/help.txt" || fail "--help does not name wirust"
echo "ok   --help"

ca=$("$bin" ca path --config-dir "$work/cfg")
[ -s "$ca" ] || fail "ca path printed '$ca', which is not a file"
"$bin" ca show --config-dir "$work/cfg" | grep -q 'BEGIN CERTIFICATE' || fail "ca show prints no PEM"
echo "ok   CA created and shown"

mkdir -p "$work/site"
echo 'hello from the origin' >"$work/site/index.txt"
origin=$(free_port)
"$python" -I -m http.server "$origin" --bind 127.0.0.1 --directory "$work/site" >"$work/origin.log" 2>&1 &
pids+=($!)

proxy=$(free_port)
ui=$(free_port)
"$bin" --listen "127.0.0.1:$proxy" --ui "127.0.0.1:$ui" --config-dir "$work/cfg" >"$work/proxy.log" 2>&1 &
pids+=($!)

for _ in $(seq 1 100); do
    if grep -q 'token=' "$work/proxy.log" 2>/dev/null &&
        curl -fsS -o /dev/null "http://127.0.0.1:$origin/index.txt" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
token=$(grep -o 'token=[0-9a-f]*' "$work/proxy.log" | head -n 1 | cut -d= -f2)
[ -n "$token" ] || fail "no UI token in the start-up banner"

body=$(curl -fsS --max-time 20 -x "http://127.0.0.1:$proxy" "http://127.0.0.1:$origin/index.txt") ||
    fail "a request through the proxy failed"
[ "$body" = 'hello from the origin' ] || fail "the body through the proxy was '$body'"
echo "ok   plain HTTP through the proxy"

curl -fsS --max-time 20 -x "http://127.0.0.1:$proxy" -o "$work/magic.html" http://wirust.test/ ||
    fail "http://wirust.test/ through the proxy failed"
grep -qi 'certificate' "$work/magic.html" || fail "the wirust.test page does not offer the CA"
echo "ok   http://wirust.test/ CA page"

status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "http://127.0.0.1:$ui/api/v1/flows")
[ "$status" = 401 ] || [ "$status" = 403 ] || fail "the API without a token answered $status"
curl -fsS --max-time 20 -H "Authorization: Bearer $token" "http://127.0.0.1:$ui/api/v1/flows" |
    grep -q 'index.txt' || fail "the API does not list the flow"
echo "ok   API refuses without the token and lists the flow with it"

echo "smoke test passed: $bin"
