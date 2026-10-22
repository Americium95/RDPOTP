"""Minimal RFC 6455 WebSocket client.  Pure stdlib -- no third party deps.

Used to talk to a persistent headless Chrome over the Chrome DevTools Protocol.
Only what CDP needs is implemented: the HTTP Upgrade handshake, masked
client->text frames, unmasked server->text frames, fragmentation, ping/pong
and close.  TLS is not supported here because CDP is used over a loopback
plain TCP port.

References: RFC 6455 sections 4.1 (client opening handshake), 5.1 (framing),
5.3 (client-to-server masking), 5.5 (opcodes).
"""

import base64
import hashlib
import os
import socket
import struct

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


class WebSocketError(Exception):
    pass


class WebSocketClosed(WebSocketError):
    pass


def _recv_exact(sock, n):
    """Read exactly n bytes or raise WebSocketClosed."""
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise WebSocketClosed("peer closed after %d/%d bytes" % (len(out), n))
        out += chunk
    return bytes(out)


def _recv_line(sock):
    """Read one CRLF terminated line (for the HTTP handshake response)."""
    out = bytearray()
    while not out.endswith(b"\r\n"):
        b = _recv_exact(sock, 1)
        out += b
        if len(out) > 65536:
            raise WebSocketError("handshake line too long")
    return bytes(out)


class WebSocket:
    """A blocking WebSocket client connection."""

    def __init__(self, sock):
        self.sock = sock
        self._frag = bytearray()   # continuation payload accumulator
        self._frag_op = 0
        self.closed = False

    # ---------- handshake ----------
    @classmethod
    def connect(cls, url, timeout=15.0):
        """Open a WebSocket to ws://host:port/path  (no TLS)."""
        if not url.startswith("ws://"):
            raise WebSocketError("only ws:// is supported, got %r" % url)
        rest = url[len("ws://"):]
        if "/" in rest:
            hostport, path = rest.split("/", 1)
            path = "/" + path
        else:
            hostport, path = rest, "/"
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s)
        else:
            host, port = hostport, 80

        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            key = base64.b64encode(os.urandom(16)).decode("ascii")
            req = (
                "GET %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: %s\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n"
            ) % (path, host, port, key)
            sock.sendall(req.encode("ascii"))

            status = _recv_line(sock).decode("latin-1")
            if " 101" not in status:
                raise WebSocketError("handshake refused: %s" % status.strip())
            headers = {}
            while True:
                line = _recv_line(sock)
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("latin-1").partition(":")
                headers[name.strip().lower()] = value.strip()

            accept = headers.get("sec-websocket-accept", "")
            expect = base64.b64encode(
                hashlib.sha1((key + _GUID).encode("ascii")).digest()
            ).decode("ascii")
            if accept != expect:
                raise WebSocketError("bad Sec-WebSocket-Accept: %r" % accept)
        except Exception:
            sock.close()
            raise
        sock.settimeout(timeout)
        return cls(sock)

    # ---------- framing ----------
    def _send_frame(self, opcode, payload=b""):
        if self.closed:
            raise WebSocketClosed("already closed")
        header = bytearray()
        header.append(0x80 | (opcode & 0x0F))       # FIN + opcode
        mask_bit = 0x80
        n = len(payload)
        if n < 126:
            header.append(mask_bit | n)
        elif n < 65536:
            header.append(mask_bit | 126)
            header += struct.pack(">H", n)
        else:
            header.append(mask_bit | 127)
            header += struct.pack(">Q", n)
        mask = os.urandom(4)
        header += mask
        # RFC 6455 5.3: client frames MUST be masked, key XORed per byte.
        masked = bytearray(payload)
        for i in range(len(masked)):
            masked[i] ^= mask[i & 3]
        self.sock.sendall(bytes(header) + bytes(masked))

    def _read_frame(self):
        """Read one raw frame; returns (fin, opcode, payload)."""
        b1, b2 = _recv_exact(self.sock, 2)
        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", _recv_exact(self.sock, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", _recv_exact(self.sock, 8))[0]
        mask = _recv_exact(self.sock, 4) if masked else None
        payload = _recv_exact(self.sock, n) if n else b""
        if mask:
            payload = bytes(payload[i] ^ mask[i & 3] for i in range(len(payload)))
        return fin, opcode, payload

    # ---------- messages ----------
    def send_text(self, text):
        self._send_frame(OP_TEXT, text.encode("utf-8"))

    def send_json(self, obj):
        import json
        self.send_text(json.dumps(obj, separators=(",", ":")))

    def recv(self):
        """Receive one complete text/binary message.

        Control frames (ping/pong/close) are handled transparently.
        Returns (opcode, payload_bytes); raises WebSocketClosed on close.
        """
        while True:
            fin, opcode, payload = self._read_frame()

            if opcode == OP_PING:
                self._send_frame(OP_PONG, payload)
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_CLOSE:
                self.closed = True
                try:
                    self._send_frame(OP_CLOSE, payload[:2])
                except OSError:
                    pass
                raise WebSocketClosed("close frame received")

            if opcode in (OP_TEXT, OP_BINARY):
                if fin:
                    return opcode, payload
                self._frag = bytearray(payload)
                self._frag_op = opcode
                continue

            if opcode == OP_CONT:
                self._frag += payload
                if fin:
                    return self._frag_op, bytes(self._frag)
                continue

            raise WebSocketError("unsupported opcode 0x%x" % opcode)

    def recv_text(self):
        opcode, payload = self.recv()
        if opcode != OP_TEXT:
            payload = payload.decode("utf-8", "replace")
        else:
            payload = payload.decode("utf-8", "replace")
        return payload

    def recv_json(self):
        import json
        return json.loads(self.recv_text())

    def close(self):
        if self.closed:
            return
        try:
            self._send_frame(OP_CLOSE, struct.pack(">H", 1000))
        except OSError:
            pass
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass
