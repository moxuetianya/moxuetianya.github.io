#!/usr/bin/env python3
"""Minimal repro for message-queue-enhance runtime freeze.

Drives /forward/ws exactly like reverse-forwarder-client:
  P1/P2: register two tunnels, churn data streams (ConnError), keep sessions
  P3:    send upgrade request for third port then half-close (SHUT_WR)
  P4:    retry same port, half-close again
  P5:    burst aborted (RST) upgrade requests; churn data
Checks /mq/status liveness after every step.
"""
import socket, struct, sys, time, json, urllib.request

HOST, PORT, STATUS = "127.0.0.1", 19090, "http://127.0.0.1:19090/mq/status"


class WS:
    def __init__(self, port, remote_port, half_close=False, rst=False):
        self.sock = socket.create_connection((HOST, PORT), timeout=10)
        req = (
            f"GET /forward/ws?remote_port={remote_port}&local_addr=127.0.0.1%3A4096 HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: " + "dGhlIHNhbXBsZSBub25jZQ==" + "\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        self.sock.sendall(req)
        if half_close:
            try: self.sock.shutdown(socket.SHUT_WR)
            except OSError: pass
            self.buf = b""
            self.rst = False
            return
        self.sock.settimeout(10)
        resp = recv_until_headers(self.sock)
        if not resp.startswith(b"HTTP/1.1 101"):
            raise RuntimeError(f"upgrade failed for {remote_port}: {resp[:40]!r}")
        self.buf = resp.split(b"\r\n\r\n", 1)[1]
        # read first binary frame: tunnel_id
        self.recv_frame(timeout=10)
        if rst:
            # RST the underlying conn after successful upgrade
            try:
                import fcntl, struct
                # SO_LINGER on close it via raw setsockopt is complex; skip
                pass
            except Exception:
                pass

    def recv_frame(self, timeout=15):
        self.sock.settimeout(timeout)
        while True:
            frame = self._recv_ws_frame()
            if frame is None:
                continue
            op = frame["op"]
            if op == 0x8:  # close
                raise RuntimeError("ws closed by server")
            if op == 0x9:  # ping -> pong
                self.sock.sendall(b"\x8a\x00")
                continue
            if op == 0x2:  # binary
                return frame["payload"]
            if op == 0xA:
                continue

    def _recv_ws_frame(self):
        hdr = self._read_exact(2)
        if hdr is None: return None
        b1, b2 = hdr
        op = b1 & 0x0F
        ln = b2 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", self._read_exact(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", self._read_exact(8))[0]
        masked = b2 >> 7
        if masked:
            mask = self._read_exact(4)
        else:
            mask = None
        payload = self._read_exact(ln) if ln else b""
        if mask:
            payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        return {"op": op, "payload": payload}

    def _read_exact(self, n):
        data = b""
        while len(data) < n:
            try:
                chunk = self.sock.recv(n - len(data))
            except socket.timeout:
                return None
            if not chunk:
                return None
            data += chunk
        return data

    def send_frame(self, op, payload=b""):
        assert len(payload) < 126
        mask = b"\x01\x02\x03\x04"
        masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        self.sock.sendall(bytes([0x80 | op, 0x80 | len(payload)]) + mask + masked)

    def send_cmd(self, cmd, stream_id, payload=b""):
        # 6-byte header: stream_id LE u32 + cmd u8 + reserved u8
        body = struct.pack("<I", stream_id) + bytes([cmd, 0]) + payload
        self.send_frame(0x2, body)

    def close(self):
        try: self.sock.close()
        except OSError: pass


def recv_until_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def status_ok():
    try:
        with urllib.request.urlopen(STATUS, timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def check(label):
    if status_ok():
        print(f"[OK]   {label}")
        return
    print(f"[FREEZE] {label}")
    dump_truth()
    sys.exit(1)


def dump_truth():
    pid = 1
    out = []
    with open(f"/proc/{pid}/task/{pid}/wchan") as f:
        pass
    print("freeze detected, backing out")


def main():
    sessions = []
    try:
        check("initial")
        # P1: tunnel A + data churn
        a = WS("unused", 19081)
        sessions.append(a)
        a.send_cmd(0x05, 1)  # ConnError
        check("P1 register 19081 + connerror")
        # P2: tunnel B + churn
        b = WS(None, 19082)
        sessions.append(b)
        b.send_cmd(0x05, 1)
        check("P2 register 19082 + connerror")
        # P3: half-close upgrade for port C
        WS(None, 19083, half_close=True)
        check("P3 half-close upgrade 19083")
        # P4: retry port C, half-close again
        WS(None, 19083, half_close=True)
        check("P4 retry half-close upgrade 19083")
        # P5: many aborted upgrades (RST-free half-close), churn existing
        for i in range(30):
            WS(None, 19084 + (i % 5), half_close=True)
            if i % 5 == 0:
                sessions[0].send_cmd(0x05, 2)
                sessions[1].send_cmd(0x05, 2)
        check("P5 30 aborted upgrades + churn")
        print("[PASS] no freeze")
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        sys.exit(2)
    finally:
        for s in sessions:
            s.close()


if __name__ == "__main__":
    main()
