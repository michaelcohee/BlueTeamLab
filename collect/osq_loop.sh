#!/bin/zsh
# osquery sampler. Started by lab.sh as root. Every LAB_OSQ_SECS (default 60) it runs
# the queries below and appends ONE line per table per sample:
#   {"t":"<table>","capture_ts":"<UTC>","rows":[...osquery rows...]}
# Files are split by UTC hour (osquery-YYYYMMDDTHH.jsonl); finished hours are gzipped.
emulate -L zsh
S=${1:?session dir}
INTERVAL=${LAB_OSQ_SECS:-60}

typeset -A Q
# processes first: the normalizer uses it to give socket rows a start time (proc_key).
Q[processes]="SELECT pid, parent AS ppid, name, path, uid, start_time, threads FROM processes"
Q[process_open_sockets]="SELECT pid, family, protocol, local_address, local_port, remote_address, remote_port, state, path FROM process_open_sockets WHERE remote_port != 0 OR state = 'LISTEN'"
Q[listening_ports]="SELECT pid, port, protocol, address, path FROM listening_ports"
Q[launchd]="SELECT label, path, program, program_arguments, run_at_load, keep_alive, disabled, username FROM launchd"
Q[startup_items]="SELECT name, path, args, type, source, status, username FROM startup_items"
ORDER=(processes process_open_sockets listening_ports launchd startup_items)

trap 'exit 0' INT TERM
last_hour=""
while true; do
  ts=$(date -u +%FT%TZ)
  hour=$(date -u +%Y%m%dT%H)
  out=$S/osquery-$hour.jsonl
  if [[ -n $last_hour && $hour != $last_hour && -f $S/osquery-$last_hour.jsonl ]]; then
    gzip -9 "$S/osquery-$last_hour.jsonl" &
  fi
  last_hour=$hour
  for t in $ORDER; do
    # Capture exit status AND output. A failed query (bad table/permission) must NOT be
    # silently written as an empty result — that would hide a lost source. On failure we
    # record an error marker row and raise the UNHEALTHY flag that lab.sh status reports.
    rows=$(osqueryi --json "${Q[$t]}" 2>>$S/osq.stderr)
    rc=$?
    rows=${rows//$'\n'/}
    if (( rc != 0 )); then
      print -r -- "$(date -u +%FT%TZ) osquery query failed (rc=$rc) for table: $t" >> $S/osq.stderr
      print -r -- "UNHEALTHY osquery $t rc=$rc $(date -u +%FT%TZ)" >> $S/UNHEALTHY
      print -r -- "{\"t\":\"$t\",\"capture_ts\":\"$ts\",\"error\":\"query_failed\",\"rc\":$rc,\"rows\":[]}" >> $out
    else
      [[ -z $rows ]] && rows='[]'
      print -r -- "{\"t\":\"$t\",\"capture_ts\":\"$ts\",\"rows\":$rows}" >> $out
    fi
  done
  sleep $INTERVAL &
  wait $!
done
