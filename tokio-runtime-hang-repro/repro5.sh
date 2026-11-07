#!/bin/bash
# Full-stack mimic: status poll + MQ sessions + overlapping tunnel pairs. 15 min.
set -u
CLIENT=/home/peter/project/agent-code/wfuzz-utils/target/release/reverse-forwarder-client
D=/home/peter/.tmp/opencode/mq-core/repro6
mkdir -p "$D"
LOG=$D/run.log
STATUS=http://127.0.0.1:19090/mq/status
: > "$LOG"
log(){ echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }

poll_loop(){
  local fails=0
  while kill -0 $1 2>/dev/null; do
    local code
    code=$(curl -sS -m 3 -o /dev/null -w "%{http_code}" "$STATUS" 2>/dev/null)
    if [ "$code" != "200" ]; then
      fails=$((fails+1))
      log "poll fail x$fails ($code)"
      [ "$fails" -ge 3 ] && { log "!!! SERVER FROZEN"; echo FROZEN > $D/result; }
    else
      fails=0
    fi
    sleep 4
  done
}

mq_sessions(){
  for i in 0 1 2 3; do
    for typ in web client; do
      (exec 3<>/dev/tcp/127.0.0.1/19090; printf "GET /ws?id=%d&clientType=%s&messageType=testConfig&domain=protocolTest HTTP/1.1\r\nHost: 127.0.0.1:19090\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" "$i" "$typ" >&3; read -rs -t 1 <&3 || true; exec 3<&- 3>&-) 2>/dev/null
    done
  done
}
launch_pair(){ # $1 portA $2 portB $3 label
  log "launch pair $3 ($1/$2)"
  "$CLIENT" --server ws://127.0.0.1:19090/forward/ws --reverse-port "$1" --local-addr 127.0.0.1:4096 >> "$D/cl-$3-a.log" 2>&1 &
  echo $! >> "$D/pids"
  "$CLIENT" --server ws://127.0.0.1:19090/forward/ws --reverse-port "$2" --local-addr 127.0.0.1:8000 >> "$D/cl-$3-b.log" 2>&1 &
  echo $! >> "$D/pids"
}

churn(){ for _ in 1 2 3; do (exec 3<>/dev/tcp/127.0.0.1/$1; printf x >&3; sleep 0.4) 2>/dev/null; done }

# --- main
log "repro6 start"
launch_pair 19700 19702 A
sleep 30
churn 19700; churn 19702
mq_sessions
log "A settled"
# B joins while A alive
launch_pair 19720 19722 B
sleep 5
# check B upgrades completed (server log lines)
for p in 19720 19722; do
  req=$(grep -ac "remote_port=$p" "$D/../srv.log" 2>/dev/null || echo 0)
  rsp=$(grep -a "remote_port=$p" "$D/../srv.log" 2>/dev/null | grep -ac "101" || echo 0)
  log "B port $p req=$req resp101=$rsp"
  if [ "$req" -gt 0 ] && [ "$rsp" -eq 0 ]; then
    log "!! $p registered but no 101 -> retry in 11s"
    sleep 6
    "$CLIENT" --server ws://127.0.0.1:19090/forward/ws --reverse-port "$p" --local-addr 127.0.0.1:8000 >> "$D/cl-B-retry.log" 2>&1 &
    echo $! >> "$D/pids"
    sleep 15
    log "post-retry status probe done"
  fi
done
# kill B (like prod B got stuck/abandoned), A keeps running
pkill -f "reverse-port 1972" 2>/dev/null
sleep 5
churn 19700; churn 19702; mq_sessions
# A continues + new pair C joins
launch_pair 19740 19742 C
sleep 20
log "C joined; churn"
churn 19700; churn 19702; churn 19740; churn 19742; mq_sessions
# A dies (like prod old client restarts), C stays
pkill -f "reverse-port 1970" 2>/dev/null
sleep 10
launch_pair 19760 19762 D
sleep 12
churn 19760; churn 19762; churn 19740; churn 19742; mq_sessions
log "phase 1 done @ $(date +%H:%M:%S)"
sleep 60
churn 19760; churn 19762; mq_sessions
log "phase 2 done"
sleep 60
log "phase 3 done (15min mark if no FROZEN)"
ls "$D/result" 2>/dev/null || log "NO FREEZE"
log "repro6 end"
