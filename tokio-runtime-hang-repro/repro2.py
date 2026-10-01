#!/usr/bin/env python3
"""All-feature repro: MQ sessions + reverse tunnels + reconnect + aborts, 10 min."""
import socket, struct, sys, time, json, urllib.request, threading

HOST, PORT = "127.0.0.1", 19090
STATUS = "http://127.0.0.1:19090/mq/status"
FREEZE = threading.Event()


def status_ok():
    try:
        with urllib.request.urlopen(STATUS, timeout=2) as r:
            b = r.read()
            return r.status == 200 and len(b) > 500
    except Exception:
        return False


def monitor():
    fails = 0
    while not FREEZE.is_set():
        ok = status_ok()
        if not ok:
            fails += 1
            print(f"[warn] status fail x{fails} @ {time.time():.1f}", flush=True)
            if fails >= 3:
                print(f"FREEZE CONFIRMED @ {time.time()}", flush=True)
                FREEZE.set()
                return
        else:
            fails = 0
        time.sleep(1)


class WS:
    def __init__(self, remote_port, half_close=False, idle=False, rst=False):
        self.sock = socket.create_connection((HOST, PORT), timeout=5)
        self.host = HOST
        req = (
            f"GET /forward/ws?remote_port={remote_port}&local_addr=127.0.0.1%3A4096 HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: " + "dGhlIHNhbXBsZSBub25jZQ==" + "\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        self.sock.sendall(req)
        self.buf = b""
        if rst:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack("ii", 1, 0))
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            return
        if half_close:
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            return
        if idle:
            return  # leave conn open, client never completes handshake
        self.sock.settimeout(3)
        while b"\r\n\r\n" not in self.buf:
            c = self.sock.recv(4096)
            if not c:
                break
            self.buf += c
        if not self.buf.startswith(b"HTTP/1.1 101"):
            raise RuntimeError("no 101")

    def send_frame(self, op, payload=b""):
        if self.sock is None:
            return
        mask = b"\x01\x02\x03\x04"
        masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        self.sock.sendall(bytes([0x80 | op, 0x80 | len(payload)]) + mask + masked)

    def send_cmd(self, cmd, sid, payload=b""):
        self.send_frame(0x2, struct.pack("<I", sid) + bytes([cmd, 0]) + payload)

    def close(self):
        if not self.sock:
            return
        try:
            self.sock.close()
        except OSError:
            pass


def mq_session(client_type):
    q = f"id=1&clientType={client_type}&messageType=testConfig&domain=protocolTest"
    s = socket.create_connection((HOST, PORT), timeout=5)
    h = (
        f"GET /ws?{q} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    s.sendall(h)
    s.settimeout(2)
    try:
        return s.recv(64)
    except socket.timeout:
        return b"timeout"


def data_conn(port):
    try:
        c = socket.create_connection((HOST, port), timeout=3)
        c.settimeout(3)
        try:
            c.sendall(b"probe")
        except OSError:
            pass
        time.sleep(0.2)
        c.close()
    except OSError:
        pass


def phase_mq():
    for _ in range(5):
        mq_session("web")
        mq_session("client")


def phase_tunnels():
    ok = []
    for i in range(4):
        try:
            w = WS(19100 + i)
            ok.append(w)
        except Exception as e:
            print("tunnel fail", e)
    time.sleep(0.5)
    for i, w in enumerate(ok):
        w.send_cmd(0x05, 1)  # ConnError churn
        data_conn(19100 + i)
    return ok


def phase_abort_storm():
    for i in range(25):
        WS(19200 + (i % 7), rst=True)
        if i % 3 == 0:
            WS(19300 + (i % 9), half_close=True)
        if i % 7 == 3:
            WS(19400 + i, idle=True)  # abandon mid-handshake
    time.sleep(1)


def phase_reconnect():
    sid = "1" * 16
    try:
        s = socket.create_connection((HOST, PORT), timeout=3)
        h = (
            f"GET /forward/ws?remote_port=19500&local_addr=127.0.0.1%3A4096&tunnel_id={sid} HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        s.sendall(h)
        s.settimeout(2)
        try:
            r = s.recv(128)
            # 404/409 expected (no tunnel registered); any status fine
        except socket.timeout:
            pass
        s.close()
    except OSError:
        pass


def main():
    thr = threading.Thread(target=monitor, daemon=True)
    thr.start()
    print(f"[t0] start @ {time.time():.1f}")
    wallets = []
    for cycle in range(20):
        if FREEZE.is_set():
            print(f"FROZE at cycle {cycle}")
            return 1
        phase_mq()
        phase_abort_storm()
        phase_reconnect()
        phase_tunnels()
        print(f"[t{cycle}] cycle {cycle} done @ {time.time()-t0:.1f}s", flush=True)
        time.sleep(2)
    print("NO FREEZE in 10min")
    return 0


t0 = time.time()
sys.exit(main())
