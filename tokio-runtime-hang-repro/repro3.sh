#!/bin/bash
# Drive real reverse-forwarder-client pairs against local server, churn user traffic,
# kill/restart client pairs periodically (mimic prod restart cadence), watch server.
set -u
CLIENT=/home/peter/project/agent-code/wfuzz-utils/target/release/reverse-forwarder-client
SRV_PORT=19090
LOG=/home/peter/.tmp/opencode/mq-core/repro3.log
STATUS=http://127.0.0.1:${SRV_PORT}/mq/status

log(){ echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }

start_pair(){
  local p1=$1 p2=$2
  log "start pair ports $p1/$p2"
  "$CLIENT" --server "ws://127.0.0.1:${SRV_PORT}/forward/ws" --reverse-port "$p1" --local-addr "127.0.0.1:4096" >>$LOG 2>&1 &
  C1=$!
  "$CLIENT" --server "ws://127.0.0.1:${SRV_PORT}/forward/ws" --reverse-port "$p2" --local-addr "127.0.0.1:8000" >>$LOG 2>&1 &
  C2=$!
}

churn(){
  # user traffic: connect to tunnel and hang up (like caddy agent requests)
  for _ in $(seq 1 12); do
    (exec 3<>/dev/tcp/127.0.0.1/19701; echo hi >&3; sleep 0.6) 2>/dev/null
    (exec 3<>/dev/tcp/127.0.0.1/19801; echo hi >&3; sleep 0.6) 2>/dev/null
  done
}

check_srv(){
  local code
  code=$(curl -sS -m 4 -o /dev/null -w "%{http_code}" "$STATUS" 2>/dev/null)
  echo "$code"
}

# main
: > "$LOG"
log "=== repro3 start ==="
C1=""; C2=""
PORT1=19701; PORT2=19801
for cycle in $(seq 1 12); do
  start_pair $PORT1 $PORT2
  for i in $(seq 1 30); do
    sleep 1
    code=$(check_srv)
    if [ "$code" != "200" ]; then
      log "!!! FREEZE at cycle $cycle step $i (status=$code)"
      exit 1
    fi
    churn 2>/dev/null
  done
  # kill pair -> tunnels drop -> grace period 60s -> restart with new ports
  kill $C1 $C2 2>/dev/null; wait $C1 $C2 2>/dev/null
  sleep 2
  PORT1=$((PORT1+2)); PORT2=$((PORT2+2))
  log "cycle $cycle done ($PORT1/$PORT2)"
done
log "=== no freeze in 12 cycles (12 min of prod-like load) ==="
