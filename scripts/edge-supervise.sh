#!/usr/bin/env bash
# Keeps the dev edge stack running: a systemd timer reconciles the compose
# project (docker compose up -d) every ~15s, in dependency order (edge
# healthy -> poller). Why not just restart policies, evidenced 2026-10-28 on
# this daemon (docker 29.1.3):
#   - `docker kill` STOPS the container's restart-manager by design (operator
#     intent) — the killed edge never comes back on its own;
#   - a self-exit DOES arm the restart-manager, but a restart whose START
#     fails (the poller cannot join a dead edge's network namespace) aborts
#     the retry loop entirely ("restartmanger wait error").
# `docker compose up -d` reconciles desired state and starts exited
# containers — the one mechanism that covers both. The poller's
# GP_EDGE_ADMIN_GRACE exit (apply.go) is what turns a zombie poller (alive
# in an orphaned network namespace) into an exited one this timer can start.
#
# Modes: install | remove | on | off | status | reconcile (timer's ExecStart)
set -u
cd "$(dirname "$0")/.."
UNIT=gatepost-edge-supervise
SERVICE=/etc/systemd/system/$UNIT.service
TIMER=/etc/systemd/system/$UNIT.timer
OFF=deploy/dev/.supervise-off
COMPOSE="$PWD/deploy/dev/compose.yaml"
APIBASE=http://172.17.0.1:8090   # the pinned, egress-allowlisted API address
SUDO=""; [ "$(id -u)" = 0 ] || SUDO=sudo

reconcile() {
  [ -f "$OFF" ] && exit 0 # operator (or an acceptance run) turned it off
  exec env GP_EDGE_ISSUER=internal GP_EDGE_API_BASE="$APIBASE" \
    docker compose -f "$COMPOSE" --profile poller up -d
}

case "${1:-status}" in
  install)
    $SUDO tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=Gatepost edge compose reconcile (bring killed edge/poller containers back)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=$PWD/scripts/edge-supervise.sh reconcile

[Install]
WantedBy=multi-user.target
EOF
    $SUDO tee "$TIMER" >/dev/null <<EOF
[Unit]
Description=Reconcile the Gatepost edge stack every ~15s

[Timer]
OnBootSec=30s
OnUnitActiveSec=15s
Persistent=true

[Install]
WantedBy=timers.target
EOF
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable --now $UNIT.timer
    echo "installed: $UNIT.timer (reconcile every ~15s; '$0 off' disables, '$0 on' re-enables)"
    ;;
  remove)
    $SUDO systemctl disable --now $UNIT.timer 2>/dev/null
    $SUDO rm -f "$SERVICE" "$TIMER"
    $SUDO systemctl daemon-reload
    echo "removed (stack no longer supervised)"
    ;;
  off) touch "$OFF" && echo "supervision off ($OFF present)" ;;
  on)  rm -f "$OFF" && echo "supervision on" ;;
  reconcile) reconcile ;;
  status)
    systemctl is-enabled $UNIT.timer 2>/dev/null || true
    systemctl list-timers $UNIT.timer --no-pager | sed -n '1,3p'
    [ -f "$OFF" ] && echo "supervision: OFF ($OFF present)" || echo "supervision: on"
    $SUDO docker ps -a --filter name=gatepost-edge-dev --format '{{.Names}}: {{.Status}}'
    ;;
  *) echo "usage: $0 {install|remove|on|off|status|reconcile}" >&2; exit 2 ;;
esac
