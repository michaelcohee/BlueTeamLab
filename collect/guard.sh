#!/bin/zsh
# Disk guard. Started by lab.sh as root. Every 5 minutes it logs lab-data size and free
# disk; if lab data > CAP or free disk < FLOOR it stops all collectors and exits.
# Defaults: 3 GB cap, 4 GB floor. Override with LAB_CAP_GB / LAB_FLOOR_GB.
emulate -L zsh
VD=${1:-${VERTICALDATA:-$HOME/VerticalData}}
RUN=$VD/run
CAP_KB=$(( ${LAB_CAP_GB:-3} * 1024 * 1024 ))
FLOOR_KB=$(( ${LAB_FLOOR_GB:-4} * 1024 * 1024 ))
INTERVAL=${LAB_GUARD_SECS:-300}

trap 'exit 0' INT TERM

while true; do
  used=$(du -sk "$VD" 2>/dev/null | awk '{print $1}')
  free=$(df -k "$VD" | awk 'NR==2{print $4}')
  print -r -- "$(date -u +%FT%TZ) used_kb=$used free_kb=$free cap_kb=$CAP_KB floor_kb=$FLOOR_KB"
  if (( used > CAP_KB || free < FLOOR_KB )); then
    print -r -- "$(date -u +%FT%TZ) LIMIT HIT — stopping collectors (run 'collect/lab.sh stop' to compress and close the session)"
    for p in osq eslogger zeek-lo0 zeek; do
      [[ -f $RUN/$p.pid ]] && kill -INT "$(cat $RUN/$p.pid)" 2>/dev/null
    done
    [[ -f $RUN/session ]] && touch "$(cat $RUN/session)/LIMIT_HIT"
    exit 1
  fi
  sleep $INTERVAL &
  wait $!
done
