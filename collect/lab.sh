#!/bin/zsh
# detection-lab collector control (macOS). Read-only collection; nothing leaves the Mac.
#
#   collect/lab.sh start [--lo0] [--hours N]   start collectors (+ optional auto-stop)
#   collect/lab.sh stop            stop everything, compress the session, fix ownership
#   collect/lab.sh status          what is running, session size, health, guard log tail
#   collect/lab.sh dryrun [MIN]    start, wait MIN minutes (default 5), stop, print sizes
#
# --lo0 adds a second Zeek on the loopback interface. Use it for emulation runs:
# Zeek on en0 cannot see traffic to 127.0.0.1.
# --hours N arms the guard to stop collection automatically after N hours (clean finish).
#
# start preflights osquery + eslogger (Full Disk Access) and aborts if a collector dies at
# launch — it never reports success on a partial collection.
#
# Data: $VERTICALDATA (default ~/VerticalData). Never inside a git repo.
set -u
emulate -L zsh
setopt no_nomatch   # a non-matching glob (e.g. missing *.stderr) must expand empty, not error

VD=${VERTICALDATA:-$HOME/VerticalData}
HERE=${0:A:h}
RUN=$VD/run
IFACE=${LAB_IFACE:-en0}

die() { print -u2 "lab.sh: $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing $1 (see PHASE0.md)"; }

session_dir() { [[ -f $RUN/session ]] && cat $RUN/session; }

is_running() { [[ -f $1 ]] && sudo kill -0 "$(cat $1)" 2>/dev/null; }

# Refuse a data dir inside a git work tree: walk from it to / looking for .git (dir OR file).
# A plain substring check ("/.git") misses the common case of a normal path under a repo.
refuse_repo() {
  local p=${1:A}
  while true; do
    [[ -e $p/.git ]] && die "VERTICALDATA ($1) is inside the git repo at $p — raw logs must stay out of git"
    [[ $p == / ]] && break
    p=${p:h}
  done
}

# Zeek's own networks, so conn.log carries local_orig/local_resp (the normalizer trusts those
# for direction). Covers RFC-1918, CGNAT, loopback, link-local and IPv6 ULA. The Mac's own
# GLOBAL IPv6 prefix is not here, so outbound global IPv6 may still read as "other" until you
# add your delegated prefix (see docs/SCHEMA.md).
LOCAL_NETS='Site::local_nets += { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, fd00::/8, fe80::/10, ::1/128 }'

preflight_osquery() {
  # Fail before opening a session if any required table/column errors on this macOS version.
  local q
  for q in \
    "SELECT pid,parent,name,path,uid,start_time,threads FROM processes LIMIT 1" \
    "SELECT pid,remote_address,remote_port,state FROM process_open_sockets LIMIT 1" \
    "SELECT pid,port,protocol FROM listening_ports LIMIT 1" \
    "SELECT label,path,program,run_at_load FROM launchd LIMIT 1" \
    "SELECT name,path,type,source FROM startup_items LIMIT 1"; do
    osqueryi --json "$q" >/dev/null 2>$RUN/preflight.err \
      || die "osquery preflight failed: $q\n$(cat $RUN/preflight.err)"
  done
  rm -f $RUN/preflight.err
}

preflight_eslogger() {
  # eslogger needs root + Full Disk Access for the terminal. A short probe surfaces the
  # permission error now, instead of silently collecting nothing for 24 hours.
  local probe=$RUN/eslogger.probe
  sudo zsh -c "exec eslogger exec" >/dev/null 2>$probe &
  local ppid=$!
  sleep 2
  sudo kill -INT $ppid 2>/dev/null; wait $ppid 2>/dev/null
  sudo pkill -INT -x eslogger 2>/dev/null   # reap the probe child if sudo left it behind
  if grep -qiE 'not permitted|full disk|entitlement|ERROR|denied' $probe; then
    local msg="$(cat $probe)"; rm -f $probe
    die "eslogger probe failed (grant the terminal Full Disk Access, then reopen it):\n$msg"
  fi
  rm -f $probe
}

healthcheck() {
  # After launch, every collector pid must be alive. If any died at startup, abort the whole
  # session and show its stderr — start must never report success on a partial collection.
  local S=$1 p dead=()
  for p in zeek zeek-lo0 eslogger osq guard; do
    [[ -f $RUN/$p.pid ]] || continue
    is_running $RUN/$p.pid || dead+=$p
  done
  if (( ${#dead} )); then
    print -u2 "lab.sh: collectors failed to start: ${dead[*]}"
    for p in $dead; do print -u2 "--- $p stderr ---"; tail -5 $S/$p*.stderr 2>/dev/null; done
    _kill_all; sudo chown -R "$USER" $S 2>/dev/null; rm -f $RUN/session
    die "aborted; no session left running"
  fi
}

_kill_all() {
  local p
  for p in guard osq eslogger zeek-lo0 zeek; do
    [[ -f $RUN/$p.pid ]] || continue
    sudo kill -INT "$(cat $RUN/$p.pid)" 2>/dev/null
    rm -f $RUN/$p.pid
  done
}

start() {
  local lo0=0 max_secs=0
  while [[ ${1:-} == --* ]]; do
    case $1 in
      --lo0) lo0=1 ;;
      --hours) shift; max_secs=$(( ${1:?--hours needs a number} * 3600 )) ;;
      *) die "unknown start option: $1" ;;
    esac
    shift
  done
  need zeek; need osqueryi; need eslogger
  [[ -n "$(session_dir)" ]] && die "a session is already active: $(session_dir) (run stop first)"
  refuse_repo "$VD"
  mkdir -p $RUN $VD/raw; chmod 700 $VD
  sudo -v || die "sudo needed for zeek, eslogger, osquery"

  preflight_osquery
  preflight_eslogger

  local stamp=$(date -u +%Y%m%dT%H%M%SZ)
  local S=$VD/raw/$stamp
  mkdir -p $S/zeek-$IFACE
  print -r -- $S > $RUN/session
  # Session metadata the normalizer needs. Host name is the proc_key prefix.
  {
    print -r -- "{\"session\":\"$stamp\",\"host\":\"$(scutil --get LocalHostName 2>/dev/null || hostname -s)\","\
"\"iface\":\"$IFACE\",\"lo0\":$lo0,\"max_secs\":$max_secs,\"macos\":\"$(sw_vers -productVersion)\",\"started\":\"$(date -u +%FT%TZ)\"}"
  } > $S/session.json

  # Each daemon writes its own PID (exec keeps the PID) so stop can signal it directly.
  # Zeek rotates its logs hourly so a long capture does not grow one unbounded file; the guard
  # gzips rotated files from previous hours.
  sudo zsh -c "cd '$S/zeek-$IFACE' && echo \$\$ > '$RUN/zeek.pid' && exec zeek -C -i $IFACE LogAscii::use_json=T Log::default_rotation_interval=3600sec '$LOCAL_NETS'" \
    > $S/zeek-$IFACE.stderr 2>&1 &
  if (( lo0 )); then
    mkdir -p $S/zeek-lo0
    sudo zsh -c "cd '$S/zeek-lo0' && echo \$\$ > '$RUN/zeek-lo0.pid' && exec zeek -C -i lo0 LogAscii::use_json=T Log::default_rotation_interval=3600sec '$LOCAL_NETS'" \
      > $S/zeek-lo0.stderr 2>&1 &
  fi
  sudo zsh -c "echo \$\$ > '$RUN/eslogger.pid' && exec eslogger exec > '$S/eslogger_exec.jsonl'" \
    2> $S/eslogger.stderr &
  sudo zsh -c "echo \$\$ > '$RUN/osq.pid' && exec '$HERE/osq_loop.sh' '$S'" \
    > $S/osq.stderr 2>&1 &
  # Guard runs as root so it can stop root collectors without a later sudo prompt.
  touch $VD/guard.log
  sudo LAB_MAX_SECS=$max_secs zsh -c "echo \$\$ > '$RUN/guard.pid' && exec '$HERE/guard.sh' '$VD'" >> $VD/guard.log 2>&1 &

  sleep 4
  healthcheck $S
  (( max_secs > 0 )) && print "auto-stop armed: guard will stop collection after $(( max_secs / 3600 )) h"
  status
}

stop() {
  local S=$(session_dir)
  [[ -z $S ]] && { print "no active session"; return 0; }
  for p in guard osq eslogger zeek-lo0 zeek; do
    [[ -f $RUN/$p.pid ]] || continue
    sudo kill -INT "$(cat $RUN/$p.pid)" 2>/dev/null
  done
  sleep 3
  for p in guard osq eslogger zeek-lo0 zeek; do
    [[ -f $RUN/$p.pid ]] || continue
    sudo kill -0 "$(cat $RUN/$p.pid)" 2>/dev/null && sudo kill -TERM "$(cat $RUN/$p.pid)" 2>/dev/null
    rm -f $RUN/$p.pid
  done
  sudo chown -R "$USER" $S
  # Compress finished logs. The normalizer reads .gz transparently and raw_ref keeps
  # pointing at the uncompressed name; Horizontal looks for NAME or NAME.gz.
  find $S -type f \( -name '*.log' -o -name '*.jsonl' \) -size +0 ! -name '*.gz' -exec gzip -9 {} \;
  local outcome="clean"
  [[ -f $S/LIMIT_HIT ]] && outcome="aborted_disk_limit"
  [[ -f $S/MAX_TIME_DONE ]] && outcome="max_time_reached"
  [[ -f $S/UNHEALTHY ]] && outcome="${outcome}+unhealthy_source"
  print -r -- "{\"stopped\":\"$(date -u +%FT%TZ)\",\"outcome\":\"$outcome\"}" > $S/stopped.json
  rm -f $RUN/session
  print "stopped: $S  (outcome: $outcome)"
  [[ $outcome != clean ]] && print "  NOTE: this session did not finish cleanly — do not treat it as a full capture."
  du -sh $S
}

status() {
  local S=$(session_dir)
  print "session: ${S:-none}"
  for p in zeek zeek-lo0 eslogger osq guard; do
    [[ -f $RUN/$p.pid ]] || continue
    if is_running $RUN/$p.pid; then print "  $p: running (pid $(cat $RUN/$p.pid))"
    else print "  $p: NOT running — check $S/$p*.stderr"; fi
  done
  if [[ -n $S ]]; then
    [[ -f $S/UNHEALTHY ]] && print "  !! UNHEALTHY: $(tail -1 $S/UNHEALTHY) (osquery lost a source — see $S/osq.stderr)"
    [[ -f $S/LIMIT_HIT ]] && print "  !! LIMIT_HIT: guard stopped collection early (disk cap/floor). Run 'lab.sh stop'."
    [[ -f $S/MAX_TIME_DONE ]] && print "  >> MAX_TIME_DONE: capture window reached. Run 'lab.sh stop'."
    du -sh $S; ls -la $S
  fi
  print "lab data total: $(du -sh $VD | cut -f1)   free disk: $(df -h $VD | awk 'NR==2{print $4}')"
  [[ -f $VD/guard.log ]] && tail -2 $VD/guard.log
}

dryrun() {
  local m=${1:-5}
  start
  print "dry run: collecting for $m minute(s)…"
  sleep $(( m * 60 ))
  local S=$(session_dir)
  stop
  print "\nper-source size after $m min:"
  du -sh $S/* | sort -h
  print "\n24 h estimate ≈ (total above) × $(( 1440 / m ))"
}

case ${1:-} in
  start) shift; start "$@" ;;
  stop) stop ;;
  status) status ;;
  dryrun) shift; dryrun "$@" ;;
  *) print "usage: lab.sh start [--lo0] | stop | status | dryrun [MIN]"; exit 2 ;;
esac
