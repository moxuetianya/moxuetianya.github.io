#!/bin/bash
# 复现 driver：真实隧道客户端对，经 caddy 10200 注册（与生产同构），冻结自动取证
set -u
CLIENT=/home/peter/project/agent-code/wfuzz-utils/target/release/reverse-forwarder-client
SRV=192.168.7.1
BASE1=8210   # agent 端口基线（8210/8211…）
BASE2=9210   # vscode 端口基线
D=/home/peter/.tmp/opencode/mq-core/repro7
mkdir -p "$D"
LOG=$D/driver.log
MON=$D/mon.log
ALERT=$D/alert.txt
: > "$LOG"; : > "$MON"; rm -f "$ALERT"
log(){ echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }

# 探针：全链路(10200/caddy) + 直连(8080)；连续3次失败=冻结
freezebegin(){
  local f=0
  while true; do
    C1=$(curl -s -m 4 -o /dev/null -w "%{http_code}" http://$SRV:10200/mq/status 2>/dev/null)
    C2=$(curl -s -m 3 -o /dev/null -w "%{http_code}" http://$SRV:8080/mq/status 2>/dev/null)
    echo "$(date +%H:%M:%S) $C1 $C2" >> "$MON"
    if [ "$C1" = "200" ]; then f=0; else f=$((f+1)); fi
    if [ "$f" -ge 3 ]; then
      echo "FROZEN $(date +%H:%M:%S) caddy=$C1 direct=$C2" > "$ALERT"
      log "!!! FROZEN at $(date +%H:%M:%S) (caddy=$C1 direct=$C2)"
      return 1
    fi
    sleep 2
  done
}

pair(){ # $1 portA $2 portB $3 tag
  "$CLIENT" --server "ws://$SRV:10200/forward/ws" --reverse-port "$1" --local-addr "127.0.0.1:1" >> "$D/cl-$3.log" 2>&1 &
  echo $! >> "$D/pids"
  "$CLIENT" --server "ws://$SRV:10200/forward/ws" --reverse-port "$2" --local-addr "127.0.0.1:1" >> "$D/cl-$3.log" 2>&1 &
  echo $! >> "$D/pids"
}

killpairs(){ cat "$D/pids" 2>/dev/null | xargs -r kill; : > "$D/pids"; }

log "=== repro7 start ($(date +%H:%M:%S)) ==="
: > "$D/pids"
freezebegin & MONPID=$!
i=0
while [ $i -lt 30 ]; do
  A=$((BASE1+i)); B=$((BASE2+i))
  pair "$A" "$B" "pair$i"
  S=$((RANDOM%4+3))
  sleep $S
  killpairs
  sleep $((RANDOM%2+1))
  i=$((i+1))
  [ -f "$ALERT" ] && { log "abort: frozen"; kill $MONPID 2>/dev/null; exit 1; }
done
killpairs
log "=== repro7 finished ($(date +%H:%M:%S)) ==="
kill $MONPID 2>/dev/null
exit 0
