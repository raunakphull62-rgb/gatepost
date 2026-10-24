#!/usr/bin/env bash
# Gatepost regression: vet, build, full test suite, then the live demo
# walkthrough. Prints a pass/fail summary; exits nonzero on any failure.
# Requires .env with DATABASE_URL (tests and the demo server read it; the
# file's contents are never printed).
set -u
cd "$(dirname "$0")/.."

pass=0; fail=0
run() { # run <name> <cmd...>
  local name="$1" log="/tmp/gatepost-regress-$2.log"; shift 2
  if "$@" >"$log" 2>&1; then
    echo "PASS $name"; pass=$((pass+1))
  else
    echo "FAIL $name — see $log"; fail=$((fail+1))
    tail -n 20 "$log" | sed 's/^/    /'
  fi
}

[ -f .env ] || { echo "no .env (needs DATABASE_URL); create it yourself — never paste it in chat" >&2; exit 2; }

run go-vet   vet  go vet ./...
run go-build build go build ./...
run go-test  test  go test -count=1 ./...
run demo     demo  bash scripts/demo-auth.sh
run domains-demo domains bash scripts/demo-domains.sh
run nodes-demo nodes bash scripts/demo-nodes.sh

echo
echo "=== regression: $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
