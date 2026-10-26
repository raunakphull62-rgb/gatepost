#!/usr/bin/env bash
# Gatepost edge egress firewall (B3b item 5). Blocks the edge containers'
# OUTBOUND traffic to private, loopback, link-local and metadata ranges so a
# hostile snapshot or a compromised edge cannot probe the network it runs in:
#
#   10.0.0.0/8  172.16.0.0/12  192.168.0.0/16  169.254.0.0/16 (metadata)  100.64.0.0/10  127.0.0.0/8
#   the docker bridge gateway and every address the host itself owns
#   IPv6: fc00::/7  fe80::/10  ::1  ::ffff:0:0/96 (v4-mapped)
#
# What is ALLOWED from the edge (everything else): the control-plane API at
# EDGE_EGRESS_API (an explicit IP:PORT setting — on the dev server the API is
# a private address, so this is the ONE deliberate exception, never a blanket
# allow), and the public internet — public DNS, ACME and origins are public
# destinations and fall through to the final RETURN.
#
# Where it hooks, and why TWO jump points:
#   - DOCKER-USER — docker's reserved chain, traversed by all routed
#     container traffic (edge → internet, edge → other networks).
#   - INPUT — traffic the edge sends to addresses the HOST itself owns (the
#     bridge gateway, the host's IPs) is locally delivered, not forwarded, so
#     DOCKER-USER can never see it; br_netfilter is not loaded on this box
#     (and local delivery hits INPUT even when it is).
# Every jump rule is scoped: -s EDGE_EGRESS_SUBNET (v4) / -i EDGE_EGRESS_BRIDGE
# (v6), so SSH, the host itself and every other container (gatepost-auth-pg)
# are untouched. Inbound traffic to the edge (ACME HTTP-01) never matches.
#
# Settings (env):
#   EDGE_EGRESS_API      IP:PORT of the control-plane API the poller needs.
#                        REQUIRED for dry-run/apply/persist. Fail loud.
#   EDGE_EGRESS_SUBNET   the edge compose network's subnet. The compose file
#                        pins it to 172.28.0.0/24; override only if you
#                        changed the pin.      (default 172.28.0.0/24)
#   EDGE_EGRESS_BRIDGE   the pinned bridge name, used as the v6 scope.
#                                                     (default br-gpedge)
#   EDGE_EGRESS_HOST_ADDRS  space-separated extra host addresses to block
#                        explicitly (default: every IPv4 of this host).
#
# Usage:
#   sudo bash scripts/edge-egress.sh dry-run    print the exact rules, change nothing
#   sudo bash scripts/edge-egress.sh apply     install (idempotent: remove-then-add)
#   sudo bash scripts/edge-egress.sh remove    uninstall completely (+disable the unit)
#   sudo bash scripts/edge-egress.sh persist   apply now AND re-apply at boot (systemd)
#
# In-container probe matrix (requirement 5), run from deploy/dev:
#   docker compose exec edge wget -T 3 -t 1 http://169.254.169.254/   # refuse
#   docker compose exec edge wget -T 3 -t 1 http://10.0.0.1/          # refuse
#   docker compose exec edge wget -T 3 -t 1 http://192.168.1.1/       # refuse
#   docker compose exec edge wget -T 3 -t 1 http://172.16.0.1/        # refuse
#   docker compose exec edge wget -T 3 -t 1 http://172.31.25.3:22/    # refuse (host)
#   docker compose exec edge wget -T 3 -t 1 http://1.1.1.1/           # pass (public)
#   docker compose exec edge wget -T 3 -t 1 http://$API/               # pass (allowlist)
set -u

CHAIN=GATEPOST-EGRESS
SUBNET="${EDGE_EGRESS_SUBNET:-172.28.0.0/24}"
BRIDGE="${EDGE_EGRESS_BRIDGE:-br-gpedge}"
UNIT=gatepost-edge-egress.service
UNIT_PATH="/etc/systemd/system/$UNIT"
dry=0
mode="${1:-}"

die() { echo "edge-egress: $*" >&2; exit 1; }
usage() { sed -n 's/^# \{0,1\}//p' "$0" >/dev/null; die "usage: $0 dry-run|apply|remove|persist"; }

# run: execute the command, or only print it in dry-run mode.
run() {
  if [ "$dry" = 1 ]; then printf '%s\n' "$*"; else "$@"; fi
}

case "$mode" in
  dry-run|apply|remove|persist) ;;
  *) usage ;;
esac
[ "$mode" = dry-run ] && dry=1
if [ "$mode" != remove ] && [ "$dry" = 0 ]; then
  [ "$(id -u)" -eq 0 ] || die "apply/persist need root (sudo) for iptables — dry-run does not"
fi

# ---- settings ---------------------------------------------------------------

API="${EDGE_EGRESS_API:-}"
API_IP="" ; API_PORT=""
if [ "$mode" != remove ]; then
  case "$API" in
    *:*) API_IP="${API%:*}"; API_PORT="${API##*:}" ;;
  esac
  [ -n "$API_IP" ] && [ -n "$API_PORT" ] \
    || die "EDGE_EGRESS_API must be IP:PORT (the poller's control-plane API) — never a blanket allow"
  echo "$API_IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
    || die "EDGE_EGRESS_API host must be an IPv4 literal (resolution drift in a firewall rule is a footgun), got '$API_IP'"
  echo "$API_PORT" | grep -Eq '^[0-9]+$' || die "EDGE_EGRESS_API port must be numeric, got '$API_PORT'"
fi

# The host's own addresses, explicitly (the private ones are inside the range
# blocks too — these rules make the intent visible in iptables -S).
host_addrs() {
  if [ -n "${EDGE_EGRESS_HOST_ADDRS:-}" ]; then
    echo "$EDGE_EGRESS_HOST_ADDRS" | tr ' ' '\n'
  else
    hostname -I 2>/dev/null | tr ' ' '\n'
    ip -4 -o addr show docker0 2>/dev/null | awk '{print $4}' | cut -d/ -f1
  fi | sort -u | grep -v '^$'
}

# ---- removal (ours only) ----------------------------------------------------

# delete_refs <iptables-bin> <chain>: remove every rule in <chain> that
# jumps to ours, whatever its match spec — remove must work even if the
# settings changed since apply. Skipped in dry-run: nothing of ours exists
# when printing, and apply's internal remove pass is a no-op on a clean box.
delete_refs() {
  local ipt="$1" chain="$2" spec n=0
  [ "$dry" = 1 ] && return 0
  while :; do
    spec="$("$ipt" -S "$chain" 2>/dev/null | grep -- "-j $CHAIN" | head -1)"
    [ -z "$spec" ] && return 0
    # Word-splitting is DELIBERATE: the spec is our own -S output — jump
    # rules we created, no quoted arguments, no glob characters.
    # shellcheck disable=SC2086
    "$ipt" ${spec/-A /-D }
    n=$((n+1))
    if [ "$n" -ge 4 ]; then # at most one jump per chain ever exists
      echo "edge-egress: jump rules in $chain did not clear after $n deletions — stopping" >&2
      return 0
    fi
  done
}

remove_rules() {
  local ipt
  for ipt in iptables ip6tables; do
    command -v "$ipt" >/dev/null 2>&1 || continue
    delete_refs "$ipt" DOCKER-USER
    delete_refs "$ipt" INPUT
    if [ "$dry" = 1 ]; then
      run "$ipt" -F "$CHAIN"
      run "$ipt" -X "$CHAIN"
    else
      # A first run has nothing of ours to flush — that is expected, not an
      # error worth printing.
      "$ipt" -F "$CHAIN" 2>/dev/null
      "$ipt" -X "$CHAIN" 2>/dev/null
    fi
  done
  if [ "$dry" = 0 ] && [ "$mode" = remove ]; then
    if systemctl list-unit-files "$UNIT" >/dev/null 2>&1 && systemctl is-enabled "$UNIT" >/dev/null 2>&1; then
      systemctl disable --now "$UNIT" && rm -f "$UNIT_PATH" && systemctl daemon-reload
      echo "edge-egress: systemd unit $UNIT disabled and removed"
    fi
  fi
}

# ---- install ----------------------------------------------------------------

install_rules() {
  local addr
  run iptables -N "$CHAIN"
  # REPLY TRAFFIC FIRST: the edge's responses to connections the host (its
  # docker-proxy, DNAT) or the network initiated are kernel-tracked state and
  # must never be filtered — without this the published host ports (8081/8445)
  # hang, because every reply packet with dst on the host matches the host-IP
  # pin rules below. NEW connections the edge initiates stay filtered.
  run iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  # The API allowlist NEXT: it is private (dev server), so it must precede
  # the 172.16/12 block below it.
  run iptables -A "$CHAIN" -p tcp -d "$API_IP" --dport "$API_PORT" -j ACCEPT
  for range in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 \
               100.64.0.0/10 127.0.0.0/8; do
    run iptables -A "$CHAIN" -d "$range" -j REJECT
  done
  for addr in $(host_addrs); do
    run iptables -A "$CHAIN" -d "$addr" -j REJECT
  done
  run iptables -A "$CHAIN" -j RETURN
  # v4 scope: the edge compose subnet only.
  run iptables -I DOCKER-USER -s "$SUBNET" -j "$CHAIN"
  run iptables -I INPUT -s "$SUBNET" -j "$CHAIN"

  # IPv6 equivalents. The edge network is v4-only (no v6 subnet exists), so
  # the scope is the pinned bridge interface. No global v6 in the containers
  # means these are inert there today — they hold the line if v6 ever lands.
  if command -v ip6tables >/dev/null 2>&1; then
    run ip6tables -N "$CHAIN"
    run ip6tables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    run ip6tables -A "$CHAIN" -d ::ffff:0:0/96 -j REJECT  # v4-mapped, as in egress.go
    run ip6tables -A "$CHAIN" -d fc00::/7 -j REJECT
    run ip6tables -A "$CHAIN" -d fe80::/10 -j REJECT
    run ip6tables -A "$CHAIN" -d ::1 -j REJECT
    run ip6tables -A "$CHAIN" -j RETURN
    run ip6tables -I DOCKER-USER -i "$BRIDGE" -j "$CHAIN"
    run ip6tables -I INPUT -i "$BRIDGE" -j "$CHAIN"
  else
    echo "edge-egress: ip6tables not found — IPv6 equivalents NOT installed" >&2
  fi
}

install_hooks() {
  iptables -L DOCKER-USER >/dev/null 2>&1 \
    || die "DOCKER-USER does not exist — is docker running? (apply after docker starts)"
}

# ---- modes ------------------------------------------------------------------

case "$mode" in
  remove)
    remove_rules
    [ "$dry" = 0 ] && echo "edge-egress: removed"
    ;;
  dry-run)
    echo "# edge-egress dry-run — exact commands apply would run (in order):"
    remove_rules
    install_rules
    ;;
  apply)
    remove_rules
    install_hooks
    install_rules
    echo "edge-egress: applied (subnet $SUBNET, allowlist $API_IP:$API_PORT)"
    ;;
  persist)
    [ "$dry" = 0 ] && install_hooks
    SCRIPT="$(readlink -f "$0")"
    if [ "$dry" = 1 ]; then
      cat <<EOF
[Unit]
Description=Gatepost edge egress firewall (edge containers → private ranges blocked)
After=docker.service
Wants=docker.service

[Service]
Type=oneshot
Environment=EDGE_EGRESS_API=$API
Environment=EDGE_EGRESS_SUBNET=$SUBNET
Environment=EDGE_EGRESS_BRIDGE=$BRIDGE
ExecStart=$SCRIPT apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
      exit 0
    fi
    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=Gatepost edge egress firewall (edge containers → private ranges blocked)
After=docker.service
Wants=docker.service

[Service]
Type=oneshot
Environment=EDGE_EGRESS_API=$API
Environment=EDGE_EGRESS_SUBNET=$SUBNET
Environment=EDGE_EGRESS_BRIDGE=$BRIDGE
ExecStart=$SCRIPT apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$UNIT"
    systemctl --no-pager --lines=0 status "$UNIT" | head -3
    echo "edge-egress: persists across reboot via $UNIT (After=docker.service)"
    ;;
esac
