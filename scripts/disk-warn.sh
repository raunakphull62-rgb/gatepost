#!/usr/bin/env bash
# Disk warning (item 6): one line on stderr when the filesystem holding the
# edge's state and logs is at or over the threshold — 80% by default — and
# total silence (exit 0) when it is not. Cron/timer friendly: a quiet disk
# must produce no output at all, and a full disk must never make the MONITOR
# fail (exit 0 either way); acting on the message is the operator's step.
# Knobs: DISK_WARN_PATH (default /), DISK_WARN_THRESHOLD (default 80).
set -u

path="${DISK_WARN_PATH:-/}"
threshold="${DISK_WARN_THRESHOLD:-80}"

pct=$(df -P "$path" 2>/dev/null | awk 'NR==2 {gsub(/%/,""); print $5}')
case "$pct" in
  ''|*[!0-9]*)
    echo "disk-warn: cannot read usage of $path — check the mount" >&2
    exit 0
    ;;
esac

if [ "$pct" -ge "$threshold" ]; then
  echo "disk-warn: $path is at ${pct}% (threshold ${threshold}%) — rotate or enlarge before the edge's logs and snapshots eat the disk" >&2
fi
exit 0
