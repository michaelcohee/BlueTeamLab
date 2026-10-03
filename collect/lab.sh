#!/bin/zsh
# detection-lab collector control (macOS). Read-only collection; nothing leaves the Mac.
#
#   collect/lab.sh start [--lo0]   start Zeek(en0) + eslogger exec + osquery sampler + guard
#   collect/lab.sh stop            stop everything, compress the session, fix ownership
#   collect/lab.sh status          what is running, session size, guard log tail
#   collect/lab.sh dryrun [MIN]    start, wait MIN minutes (default 5), stop, print sizes
#
# --lo0 adds a second Zeek on the loopback interface. Use it for emulation runs:
# Zeek on en0 cannot see traffic to 127.0.0.1.
#
# Data: $VERTICALDATA (default ~/VerticalData). Never inside a git repo.
set -u
emulate -L zsh

VD=${VERTICALDATA:-$HOME/VerticalData}
HERE=${0:A:h}
RUN=$VD/run
IFACE=${LAB_IFACE:-en0}

die() { print -u2 "lab.sh: $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing $1 (see PHASE0.md)"; }

session_dir() { [[ -f $RUN/session ]] && cat $RUN/session; }

is_running() { [[ -f $1 ]] && sudo kill -0 "$(cat $1)" 2>/dev/null; }

start() {
  local lo0=0; [[ ${1:-} == --lo0 ]] && lo0=1
  need zeek; need osqueryi; need eslogger
  [[ -n "$(session_dir)" ]] && die "a session is already active: $(session_dir) (run stop first)"
  [[ $VD == *"/.git"* ]] && die "VERTICALDATA must not be inside a git repo"
  mkdir -p $RUN $VD/raw; chmod 700 $VD
  sudo -v || die "sudo needed for zeek, eslogger, osquery"

  local stamp=$(date -u +%Y%m%dT%H%M%SZ)
  local S=$VD/raw/$stamp
  mkdir -p $S/zeek-$IFACE
  print -r -- $S > $RUN/session
  # Session metadata the normalizer needs. Host name is the proc_key prefix.
  {
    print -r -- "{\"session\":\"$stamp\",\"host\":\"$(scutil --get LocalHostName 2>/dev/null || hostname -s)\","\
"\"iface\":\"$IFACE\",\"lo0\":$lo0,\"macos\":\"$(sw_vers -productVersion)\",\"started\":\"$(date -u +%FT%TZ)\"}"
  } > $S/session.json

  # Each daemon writes its own PID (exec keeps the PID) so stop can signal it directly.
  sudo zsh -c "cd '$S/zeek-$IFACE' && echo \$\$ > '$RUN/zeek.pid' && exec zeek -C -i $IFACE LogAscii::use_json=T" \
    > $S/zeek-$IFACE.stderr 2>&1 &
  if (( lo0 )); then
    mkdir -p $S/zeek-lo0
    sudo zsh -c "cd '$S/zeek-lo0' && echo \$\$ > '$RUN/zeek-lo0.pid' && exec zeek -C -i lo0 LogAscii::use_json=T" \
      > $S/zeek-lo0.stderr 2>&1 &
  fi
  sudo zsh -c "echo \$\$ > '$RUN/eslogger.pid' && exec eslogger exec > '$S/eslogger_exec.jsonl'" \
    2> $S/eslogger.stderr &
  sudo zsh -c "echo \$\$ > '$RUN/osq.pid' && exec '$HERE/osq_loop.sh' '$S'" \
    > $S/osq.stderr 2>&1 &
  # Guard runs as root so it can stop root collectors without a later sudo prompt.
  touch $VD/guard.log
  sudo zsh -c "echo \$\$ > '$RUN/guard.pid' && exec '$HERE/guard.sh' '$VD'" >> $VD/guard.log 2>&1 &

  sleep 3
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
  find $S -type f \( -name '*.log' -o -name '*.jsonl' \) -size +0 -exec gzip -9 {} \;
  print -r -- "{\"stopped\":\"$(date -u +%FT%TZ)\"}" > $S/stopped.json
  rm -f $RUN/session
  print "stopped: $S"
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
  [[ -n $S ]] && { du -sh $S; ls -la $S; }
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
