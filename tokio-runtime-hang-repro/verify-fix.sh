#!/bin/bash
# verify-fix.sh — 修复后冻结验证驱动（重叠对注册 + /mq/status 探针）
#
# 背景：修复前 repro8.sh（旧对不杀、每轮叠加注册新对）30 轮内必然冻结
#（3/3 命中，冻结签名：日志 "inserting <port>" 后全静默、/mq/status 无响应）。
# 本脚本是同一驱动形态的"验证版"：判定失败 = 探针 3 连非 200 → alert.txt。
#
# 用法：
#   # 1) 启动被测 message-queue-enhance（RUST_LOG 非必填，建议 info）
#   RUST_LOG=info nohup ./target/debug/message-queue-enhance \
#       --host 127.0.0.1 --listen 18080 >> /tmp/verify-fix/server.log 2>&1 &
#   # 2) 跑驱动（参数均有默认值，按需覆盖）
#   SRV=127.0.0.1 PORT=18080 CLIENT=./target/debug/reverse-forwarder-client \
#       bash verify-fix.sh
#
# 通过标准：pairs 跑满 ROUNDS、全程 probe=200、无 alert.txt（OUT=/tmp/verify-fix）。
set -u
CLIENT=${CLIENT:-./target/debug/reverse-forwarder-client}
SRV=${SRV:-127.0.0.1}
PORT=${PORT:-18080}
BASE1=${BASE1:-18250}
BASE2=${BASE2:-19250}
ROUNDS=${ROUNDS:-30}
OUT=${OUT:-/tmp/verify-fix}
mkdir -p "$OUT"
LOG=$OUT/driver.log; MON=$OUT/mon.log; ALERT=$OUT/alert.txt
: > "$LOG"; : > "$MON"; rm -f "$ALERT"; : > "$OUT/pids"
log(){ echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }

freezebegin(){               # 冻结判定：连续 3 次探针非 200
  local f=0
  while true; do
    local c
    c=$(curl -s -m 4 -o /dev/null -w "%{http_code}" "http://$SRV:$PORT/mq/status" 2>/dev/null)
    echo "$(date +%H:%M:%S) probe=$c" >> "$MON"
    if [ "$c" = "200" ]; then f=0; else f=$((f+1)); fi
    if [ "$f" -ge 3 ]; then
      echo "FROZEN $(date +%H:%M:%S) probe=$c" > "$ALERT"
      log "!!! FROZEN at $(date +%H:%M:%S)"
      return 1
    fi
    sleep 2
  done
}
pair(){                      # 启动新对（不杀旧对），模仿生产"旧对存活时新对注册"
  "$CLIENT" --server "ws://$SRV:$PORT/forward/ws" --reverse-port "$1" --local-addr "127.0.0.1:1" >> "$OUT/cl-$3.log" 2>&1 &
  echo $! >> "$OUT/pids"
  "$CLIENT" --server "ws://$SRV:$PORT/forward/ws" --reverse-port "$2" --local-addr "127.0.0.1:1" >> "$OUT/cl-$3.log" 2>&1 &
  echo $! >> "$OUT/pids"
}
cleanup(){                   # 只杀记录在案的 PID；兜底按进程名（勿用 pkill -f，避免自杀）
  cat "$OUT/pids" 2>/dev/null | xargs -r kill 2>/dev/null
  pkill -x reverse-forwarder-client 2>/dev/null
  : > "$OUT/pids"
}
trap cleanup EXIT

log "=== verify-fix start ($(date +%H:%M:%S)) overlap-pair, rounds=$ROUNDS, probe=$SRV:$PORT ==="
freezebegin & MONPID=$!
i=0
while [ $i -lt "$ROUNDS" ]; do
  pair "$((BASE1+i))" "$((BASE2+i))" "pair$i"
  sleep $((RANDOM%6+7))       # 每轮 7-12s（模仿生产双对注册节奏）
  i=$((i+1))
  [ -f "$ALERT" ] && { log "abort: frozen"; break; }
done
kill "$MONPID" 2>/dev/null
pkill -x reverse-forwarder-client 2>/dev/null
log "=== verify-fix finished ($(date +%H:%M:%S)), pairs=$i ==="

if [ -f "$ALERT" ]; then
  echo "RESULT: FROZEN (see $ALERT)"
  exit 1
fi
if [ "$i" -ge "$ROUNDS" ] && grep -q "probe=200" "$MON"; then
  echo "RESULT: OK (no freeze, pairs=$i/$ROUNDS)"
else
  echo "RESULT: UNKNOWN (pairs=$i/$ROUNDS)"
  exit 1
fi
exit 0
