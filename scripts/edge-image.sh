#!/usr/bin/env bash
# B3b item 1: edge image smoke test. Builds nothing (docker compose build is
# run separately when the Dockerfile changes): verifies the running edge
#   - was built with the compiled-in plugins (coraza + souin/cache),
#   - redirects HTTP to HTTPS,
#   - serves HTTPS with the internal CA,
#   - does not advertise HTTP/3.
# Uses the dev compose's host ports (8081->80, 8445->443 — 80/443 belong to
# the untouched v1-era edge containers; see progress.md).
cd "$(dirname "$0")/.."
DC="sudo -n docker compose -f deploy/dev/compose.yaml"
UP=0
if [ "$(sudo -n docker compose -f deploy/dev/compose.yaml ps -q edge 2>/dev/null | wc -l)" -eq 0 ]; then
  UP=1; $DC up -d --quiet-pull >/dev/null 2>&1 || { echo "FAIL: edge did not start"; exit 2; }
  sleep 3
fi
# let automatic issuance of the bootstrap site's certificate settle
for _ in $(seq 1 20); do
  [ "$(curl -sk -o /dev/null -w '%{http_code}' --resolve localhost:8445:127.0.0.1 https://localhost:8445/)" = "200" ] && break
  sleep 0.5
done

PASS=0 FAIL=0
check() { # check <desc> <got> <want>
  if [ "$2" = "$3" ]; then echo "PASS $1"; PASS=$((PASS+1));
  else echo "FAIL $1 (want $3, got $2)"; FAIL=$((FAIL+1)); fi
}

MODS=$($DC exec -T edge caddy list-modules 2>/dev/null)
check "caddy core v2.11.7" "$($DC exec -T edge caddy version 2>/dev/null | cut -d' ' -f1)" "v2.11.7"
check "coraza-caddy v2 compiled in (http.handlers.waf)" "$(printf '%s' "$MODS" | grep -c '^http.handlers.waf$')" "1"
check "souin cache compiled in (http.handlers.cache)" "$(printf '%s' "$MODS" | grep -c '^http.handlers.cache$')" "1"
check "souin admin api compiled in (admin.api.souin)" "$(printf '%s' "$MODS" | grep -c '^admin.api.souin$')" "1"

R=$(curl -s --resolve localhost:8081:127.0.0.1 http://localhost:8081/foo -o /dev/null -w '%{http_code} %{redirect_url}')
check "HTTP->HTTPS redirect" "$R" "308 https://localhost/foo"
check "HTTPS 200 via internal CA" "$(curl -sk -o /dev/null -w '%{http_code}' --resolve localhost:8445:127.0.0.1 https://localhost:8445/)" "200"
check "no Alt-Svc (HTTP/3 off)" "$(curl -skI --resolve localhost:8445:127.0.0.1 https://localhost:8445/ | grep -ci alt-svc)" "0"

if [ "$UP" = 1 ]; then $DC down >/dev/null 2>&1; fi
echo "=== edge-image: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
