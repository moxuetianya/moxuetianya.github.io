#!/bin/bash
# 重叠对复现（repro8）：旧隧道对存活时叠加注册新对——命中生产冻结模式
set -u
CLIENT=/home/peter/project/agent-code/wfuzz-utils/target/release/reverse-forwarder-client
SRV=192.168.7.1
BASE1=8250
BASE2=9250
D=/home/peter/.tmp/opencode/mq-core/repro8
mkdir -p "$D"
LOG=$D/driver.log
MON=$D/mon.log
ALERT=$D/alert.txt
: > "$LOG"; : > "$MON"; rm -f "$ALERT"
log(){ echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }

freezebegin(){
  local f=0
  while true; do
    C1=$(curl -s -m 4 -o /dev/null -w "%{http_code}" http://$SRV:10200/mq/status 2>/dev/null)
    echo "$(date +%H:%M:%S) probe=$C1" >> "$MON"
    if [ "$C1" = "200" ]; then f=0; else f=$((f+1)); fi
    if [ "$f" -ge 3 ]; then
      echo "FROZEN $(date +%H:%M:%S) caddy=$C1" > "$ALERT"
      log "!!! FROZEN at $(date +%H:%M:%S)"
      return 1
    fi
    sleep 2
  done
}

pair(){ # 启动新对（不杀旧对）
  "$CLIENT" --server "ws://$SRV:10200/forward/ws" --reverse-port "$1" --local-addr "127.0.0.1:1" >> "$D/cl-$3.log" 2>&1 &
  echo $! >> "$D/pids"
  "$CLIENT" --server "ws://$SRV:10200/forward/ws" --reverse-port "$2" --local-addr "127.0.0.1:1" >> "$D/cl-$3.log" 2>&1 &
  echo $! >> "$D/pids"
  echo "$1 $2" >> "$D/ports.txt"
}

log "=== repro8 start ($(date +%H:%M:%S)) overlap-pair mode ==="
: > "$D/pids"; : > "$D/ports.txt"
freezebegin & MONPID=$!
i=0
while [ $i -lt 30 ]; do
  A=$((BASE1+i)); B=$((BASE2+i))
  pair "$A" "$B" "pair$i"
  sleep $((RANDOM%6+7))
  i=$((i+1))
  [ -f "$ALERT" ] && { log "abort: frozen"; break; }
done
log "=== repro8 finished ($(date +%H:%M:%S)), pairs started: $i, alive pids: $(wc -l < "$D/pids") ==="
kill $MONPID 2>/dev/null
exit 0
