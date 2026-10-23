#!/bin/bash
# repro10.sh (v9)：彻底无 caddy 对照 —— 客户端直连 8080、探针只打 8080、
# 环境中无 caddy/10200；末尾清理残留客户端进程
set -u
CLIENT=/home/peter/project/agent-code/wfuzz-utils/target/release/reverse-forwarder-client
SRV=192.168.7.1
BASE1=8250
BASE2=9250
D=/home/peter/.tmp/opencode/mq-core/repro10
mkdir -p "$D"
LOG=$D/driver.log; MON=$D/mon.log; ALERT=$D/alert.txt
: > "$LOG"; : > "$MON"; rm -f "$ALERT"; : > "$D/pids"; : > "$D/ports.txt"
log(){ echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }

freezebegin(){
  local f=0
  while true; do
    C1=$(curl -s -m 4 -o /dev/null -w "%{http_code}" http://$SRV:8080/mq/status 2>/dev/null)
    echo "$(date +%H:%M:%S) probe8080=$C1" >> "$MON"
    if [ "$C1" = "200" ]; then f=0; else f=$((f+1)); fi
    if [ "$f" -ge 3 ]; then
      echo "FROZEN $(date +%H:%M:%S) direct8080=$C1" > "$ALERT"
      log "!!! FROZEN at $(date +%H:%M:%S)"
      return 1
    fi
    sleep 2
  done
}

pair(){
  "$CLIENT" --server "ws://$SRV:8080/forward/ws" --reverse-port "$1" --local-addr "127.0.0.1:1" >> "$D/cl-$3.log" 2>&1 &
  echo $! >> "$D/pids"
  "$CLIENT" --server "ws://$SRV:8080/forward/ws" --reverse-port "$2" --local-addr "127.0.0.1:1" >> "$D/cl-$3.log" 2>&1 &
  echo $! >> "$D/pids"
  echo "$1 $2" >> "$D/ports.txt"
}

cleanup(){
  cat "$D/pids" 2>/dev/null | xargs -r kill 2>/dev/null
  pkill -f "reverse-forwarder-client" 2>/dev/null
  : > "$D/pids"
}
trap cleanup EXIT

log "=== repro10 start ($(date +%H:%M:%S)) NO-CADDY overlap-pair mode ==="
freezebegin & MONPID=$!
i=0
while [ $i -lt 30 ]; do
  A=$((BASE1+i)); B=$((BASE2+i))
  pair "$A" "$B" "pair$i"
  sleep $((RANDOM%6+7))
  i=$((i+1))
  [ -f "$ALERT" ] && { log "abort: frozen"; break; }
done
log "=== repro10 finished ($(date +%H:%M:%S)), pairs: $i ==="
kill $MONPID 2>/dev/null
exit 0
