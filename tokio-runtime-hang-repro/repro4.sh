#!/bin/bash
# Deterministic replayer of the freeze pattern:
#   pair A (old set, stays alive) | new pair B joins while A alive
#   one of B's upgrades must "stick" (logged request, no 101) -> 11s retry -> freeze?
set -u
CLIENT=/home/peter/project/agent-code/wfuzz-utils/target/release/reverse-forwarder-client
SRV_PORT=19090
D=/home/peter/.tmp/opencode/mq-core/repro5
mkdir -p "$D"
LOG=$D/run.log
SRVLOG=$D/server-tail.log
STATUS=http://127.0.0.1:${SRV_PORT}/mq/status
: > "$LOG"

log(){ echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }
up(){ curl -sS -m 4 -o /dev/null -w "%{http_code}" "$STATUS" 2>/dev/null; }

pair_start(){ # $1 portA $2 portB $3 label
  log "START pair $3 ($1/$2)"
  "$CLIENT" --server "ws://127.0.0.1:${SRV_PORT}/forward/ws" --reverse-port "$1" --local-addr "127.0.0.1:4096" >> "$D/cl-$3-a.log" 2>&1 &
  echo $! >> "$D/closed-pids"
  "$CLIENT" --server "ws://127.0.0.1:${SRV_PORT}/forward/ws" --reverse-port "$2" --local-addr "127.0.0.1:8000" >> "$D/cl-$3-b.log" 2>&1 &
  echo $! >> "$D/closed-pids"
}

churn(){ # port
  local p=$1
  for _ in 1 2 3; do
    (exec 3<>/dev/tcp/127.0.0.1/$p; printf x >&3; sleep 0.5) 2>/dev/null
  done
}

sniff_stuck(){ # report if server2.log has "request method" without following 101 for our port
  local port=$1
  local wait=$2
  sleep "$wait"
  local n101 nreq
  nreq=$(grep -c "remote_port=$port" $SRVLOG 2>/dev/null || true)
  echo "req=$nreq"
}

# fresh server
kill $(cat /home/peter/.tmp/opencode/mq-core/server.pid) 2>/dev/null
sleep 1
/home/peter/.tmp/opencode/mq-core/message-queue-enhance --listen $SRV_PORT >> $D/server.log 2>&1 &
echo $! > /home/peter/.tmp/opencode/mq-core/server.pid
sleep 1.5

log "server up $SRV_PORT"
PA=19700; PB=19720; PC=19740
pair_start $PA $((PA+2)) "A"
sleep 3
log "A churn..."
for i in 1 2 3 4 5 6; do churn $PA; churn $((PA+2)); done
log "status after A: $(up)"

# B arrives while A alive
pair_start $PB $((PB+2)) "B"
sleep 6
log "B settled, status: $(up)"

# detect stuck: any B port without 101 in server log
STUCK=""
for p in $PB $((PB+2)); do
  reqc=$(grep -c "remote_port=$p" $D/server.log)
  rspc=$(grep -c "remote_port=$p" $D/server.log | xargs -I{} true)
  rsp101=$(grep "remote_port=$p" $D/server.log | grep -c "response status: 101")
  log "port $p: request=$reqc response101=$rsp101"
  if [ "$reqc" -gt 0 ] && [ "$rsp101" -eq 0 ]; then STUCK=$p; fi
done

if [ -n "$STUCK" ]; then
  log "!! port $STUCK stuck (documented request, no 101)"
  log "client retry after 11s..."
  sleep 8  # mimic the 11s client backoff
  "$CLIENT" --server "ws://127.0.0.1:${SRV_PORT}/forward/ws" --reverse-port "$STUCK" --local-addr "127.0.0.1:8000" >> "$D/cl-B-retry.log" 2>&1 &
  echo $! >> "$D/closed-pids"
  sleep 20
  log "post-retry status: $(up)"
else
  log "B pair clean"
fi

# keep A pair alive & churn a bit more
churn $PA; churn $((PA+2))
log "final status: $(up)"
sleep 5
log "final status2: $(up)"
log "=== repro5 done ==="
