#!/bin/zsh
# Disk + time guard. Started by lab.sh as root. Every INTERVAL seconds it:
#   - logs lab-data size and free disk;
#   - PREDICTS the next tick from the last growth delta and stops early if the next tick
#     would breach the cap or floor (so a fast writer can't overshoot between checks);
#   - stops at the hard cap / floor;
#   - stops when the optional max run time is reached (clean finish, not an abort);
#   - gzips rotated logs from earlier hours so disk use stays flat during a long capture.
# Stops are signalled to the collectors; lab.sh stop then compresses and closes the session.
#
# Env: LAB_CAP_GB (3), LAB_FLOOR_GB (4), LAB_GUARD_SECS (60), LAB_MAX_SECS (0 = no limit).
emulate -L zsh
setopt err_return no_unset
VD=${1:-${VERTICALDATA:-$HOME/VerticalData}}
RUN=$VD/run
CAP_KB=$(( ${LAB_CAP_GB:-3} * 1024 * 1024 ))
FLOOR_KB=$(( ${LAB_FLOOR_GB:-4} * 1024 * 1024 ))
INTERVAL=${LAB_GUARD_SECS:-60}
MAX_SECS=${LAB_MAX_SECS:-0}

trap 'exit 0' INT TERM

start_epoch=$(date +%s)
last_used=-1   # -1 = first tick: measure the rate before predicting from it
stop_collectors() {
  for p in osq eslogger zeek-lo0 zeek; do
    [[ -f $RUN/$p.pid ]] && kill -INT "$(cat $RUN/$p.pid)" 2>/dev/null
  done
}
session() { [[ -f $RUN/session ]] && cat $RUN/session; }

sweep_compress() {
  # Compress finished logs from previous hours without touching the current hour's active files.
  local S=$(session)
  [[ -z $S ]] && return
  local cur="osquery-$(date -u +%Y%m%dT%H).jsonl"
  find "$S" -type f \( -name '*.log' -o -name '*.jsonl' \) ! -name "$cur" ! -name 'eslogger_exec.jsonl' \
    -mmin +60 2>/dev/null | while read -r f; do
      [[ $f == *.gz ]] || gzip -9 "$f" 2>/dev/null &
    done
}

while true; do
  used=$(du -sk "$VD" 2>/dev/null | awk '{print $1}'); : ${used:=0}
  free=$(df -k "$VD" | awk 'NR==2{print $4}'); : ${free:=0}
  if (( last_used < 0 )); then delta=0; else delta=$(( used - last_used )); fi
  (( delta < 0 )) && delta=0
  elapsed=$(( $(date +%s) - start_epoch ))
  print -r -- "$(date -u +%FT%TZ) used_kb=$used free_kb=$free delta_kb=$delta elapsed_s=$elapsed cap_kb=$CAP_KB floor_kb=$FLOOR_KB"

  reason=""
  if (( used > CAP_KB || free < FLOOR_KB )); then
    reason="LIMIT HIT (cap/floor reached)"
  elif (( used + delta > CAP_KB || free - delta < FLOOR_KB )); then
    # one more interval at the current growth rate would breach a limit — stop now with margin
    reason="PREDICTIVE STOP (next interval would breach cap/floor at current write rate)"
  fi
  if [[ -n $reason ]]; then
    print -r -- "$(date -u +%FT%TZ) $reason — stopping collectors"
    [[ -f $RUN/session ]] && touch "$(session)/LIMIT_HIT"
    stop_collectors
    exit 1
  fi
  if (( MAX_SECS > 0 && elapsed >= MAX_SECS )); then
    print -r -- "$(date -u +%FT%TZ) MAX TIME reached (${elapsed}s >= ${MAX_SECS}s) — stopping collectors (clean finish)"
    [[ -f $RUN/session ]] && touch "$(session)/MAX_TIME_DONE"
    stop_collectors
    exit 0
  fi

  sweep_compress
  last_used=$used
  sleep $INTERVAL &
  wait $!
done
